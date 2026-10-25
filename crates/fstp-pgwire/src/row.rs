//! Result rows, columns and prepared statement descriptions.

use std::fmt;
use std::sync::Arc;

use crate::error::{Error, ErrorKind};
use crate::proto::backend::{DataRow, FieldDescription};
use crate::types::{FromSql, Type};

/// One result column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    name: String,
    type_: Type,
    table_oid: u32,
    column_id: i16,
    type_modifier: i32,
}

impl Column {
    pub(crate) fn from_field(f: &FieldDescription) -> Column {
        Column {
            name: f.name.clone(),
            type_: Type::from_oid(f.type_oid),
            table_oid: f.table_oid,
            column_id: f.column_id,
            type_modifier: f.type_modifier,
        }
    }

    /// The column name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The column's type.
    #[must_use]
    pub fn type_(&self) -> Type {
        self.type_
    }

    /// The OID of the source table, or 0.
    #[must_use]
    pub fn table_oid(&self) -> u32 {
        self.table_oid
    }

    /// The attribute number in the source table, or 0.
    #[must_use]
    pub fn column_id(&self) -> i16 {
        self.column_id
    }

    /// The type modifier, for example the length of a `varchar(n)` plus 4.
    #[must_use]
    pub fn type_modifier(&self) -> i32 {
        self.type_modifier
    }
}

/// A prepared statement's description: parameter and result types.
#[derive(Clone)]
pub struct Statement {
    pub(crate) inner: Arc<StatementInner>,
}

pub(crate) struct StatementInner {
    pub(crate) name: String,
    pub(crate) sql: &'static str,
    pub(crate) params: Vec<Type>,
    pub(crate) columns: Arc<[Column]>,
}

impl Statement {
    /// The SQL text.
    #[must_use]
    pub fn sql(&self) -> &'static str {
        self.inner.sql
    }

    /// The parameter types the server inferred.
    #[must_use]
    pub fn params(&self) -> &[Type] {
        &self.inner.params
    }

    /// The result columns. Empty for statements that return no rows.
    #[must_use]
    pub fn columns(&self) -> &[Column] {
        &self.inner.columns
    }
}

impl fmt::Debug for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Statement")
            .field("name", &self.inner.name)
            .field("params", &self.inner.params)
            .field("columns", &self.inner.columns.len())
            .finish_non_exhaustive()
    }
}

/// Identifies a column by position or name.
pub trait ColumnIndex: fmt::Display {
    /// The position of this column in `columns`, if any.
    fn index_in(&self, columns: &[Column]) -> Option<usize>;
}

impl ColumnIndex for usize {
    fn index_in(&self, columns: &[Column]) -> Option<usize> {
        (*self < columns.len()).then_some(*self)
    }
}

impl ColumnIndex for &str {
    fn index_in(&self, columns: &[Column]) -> Option<usize> {
        columns.iter().position(|c| c.name == *self)
    }
}

/// One result row. Values are decoded on access with [`Row::get`].
///
/// [`fmt::Debug`] shows the column names only, never values (R-NF-02).
#[derive(Clone)]
pub struct Row {
    columns: Arc<[Column]>,
    data: DataRow,
}

impl fmt::Debug for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Row")
            .field(
                "columns",
                &self.columns.iter().map(Column::name).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl Row {
    pub(crate) fn new(columns: Arc<[Column]>, data: DataRow) -> Row {
        Row { columns, data }
    }

    /// Approximate heap bytes this row holds on its own. The column list is
    /// shared by every row of a result, so it does not count.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.data.heap_bytes()
    }

    /// The columns.
    #[must_use]
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// The number of values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True when the row has no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Decodes the value at `index` (a position or a column name) as `T`.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::ColumnNotFound`] when no column matches.
    /// - [`ErrorKind::TypeMismatch`] when `T` does not accept the column type.
    /// - [`ErrorKind::Decode`] when the value is malformed, or NULL and `T`
    ///   is not an `Option`.
    pub fn get<T: FromSql>(&self, index: impl ColumnIndex) -> Result<T, Error> {
        let Some(i) = index.index_in(&self.columns) else {
            return Err(Error::new(
                ErrorKind::ColumnNotFound,
                format!("no column {index}"),
            ));
        };
        let column = self
            .columns
            .get(i)
            .ok_or_else(|| Error::new(ErrorKind::ColumnNotFound, format!("no column {index}")))?;
        if !T::accepts(column.type_) {
            return Err(Error::new(
                ErrorKind::TypeMismatch,
                format!(
                    "column {i} ({}) has type {} which {} does not accept",
                    column.name,
                    column.type_,
                    std::any::type_name::<T>()
                ),
            ));
        }
        let raw = self
            .data
            .get(i)
            .ok_or_else(|| Error::protocol("row has fewer values than columns"))?;
        T::from_sql_nullable(column.type_, raw).map_err(|e| {
            Error::with_source(
                ErrorKind::Decode,
                format!("column {i} ({}) of type {}", column.name, column.type_),
                e,
            )
        })
    }

    /// The raw binary value at position `index`: `None` when out of range,
    /// `Some(None)` for SQL NULL.
    #[must_use]
    pub fn raw(&self, index: usize) -> Option<Option<&[u8]>> {
        self.data.get(index)
    }

    /// Decodes a `json` or `jsonb` column under explicit parse limits.
    ///
    /// # Errors
    ///
    /// As for [`Row::get`].
    pub fn get_json_with(
        &self,
        index: impl ColumnIndex,
        limits: &fstp_json::ParseLimits,
    ) -> Result<Option<fstp_json::Value>, Error> {
        let Some(i) = index.index_in(&self.columns) else {
            return Err(Error::new(
                ErrorKind::ColumnNotFound,
                format!("no column {index}"),
            ));
        };
        let ty =
            self.columns.get(i).map(Column::type_).ok_or_else(|| {
                Error::new(ErrorKind::ColumnNotFound, format!("no column {index}"))
            })?;
        if ty != Type::JSONB && ty != Type::JSON {
            return Err(Error::new(
                ErrorKind::TypeMismatch,
                format!("column {i} has type {ty}, not json or jsonb"),
            ));
        }
        match self.data.get(i).flatten() {
            None => Ok(None),
            Some(raw) => crate::types::decode_json_with(ty, raw, limits)
                .map(Some)
                .map_err(|e| Error::with_source(ErrorKind::Decode, format!("column {i}"), e)),
        }
    }
}
