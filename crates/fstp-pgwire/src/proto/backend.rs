//! Backend (server to client) messages: framing, decoding and encoding.
//!
//! Every message is a type byte, a 32-bit length that counts itself, and a
//! body. [`decode_frame`] checks the type byte and the length before any of
//! the body arrives: unknown types fail at once, fixed-size messages must
//! announce their exact size, and nothing longer than
//! [`DecodeLimits::max_message_len`] is buffered. [`BackendMessage::parse`]
//! then consumes the body exactly, so trailing bytes are an error too.
//!
//! COPY and function call messages are recognised but decoded as
//! [`BackendMessage::Unsupported`]. The connection treats them as protocol
//! errors and marks itself broken.

use std::fmt;

use crate::error::Error;
use crate::proto::cursor::Cursor;

/// Limits applied while framing and decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Largest message body accepted, in bytes.
    pub max_message_len: usize,
    /// Largest number of columns in a RowDescription or DataRow.
    pub max_columns: usize,
    /// Largest number of parameter types in a ParameterDescription.
    pub max_parameters: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_message_len: 64 << 20,
            max_columns: 1664,
            max_parameters: 65_535,
        }
    }
}

/// Buffer capacity that the decoder and the session's write buffer keep
/// between messages.
pub const RETAINED_BUFFER_CAPACITY: usize = 64 << 10;

/// Capacity above which an idle buffer shrinks back to
/// [`RETAINED_BUFFER_CAPACITY`]. One large message therefore does not pin
/// its memory for the life of the connection.
pub(crate) const SHRINK_BUFFER_ABOVE: usize = 4 * RETAINED_BUFFER_CAPACITY;

/// The type bytes of every backend message this decoder recognises.
const KNOWN_TAGS: &[u8] = b"RKSZ123tTnDCIsENAvGHWdcV";

/// The exact body length of fixed-size messages.
fn fixed_body_len(tag: u8) -> Option<usize> {
    match tag {
        b'Z' => Some(1),
        b'K' => Some(8),
        b'1' | b'2' | b'3' | b'n' | b'I' | b's' | b'c' => Some(0),
        _ => None,
    }
}

/// Checks the header at the start of `buf` and reports a complete message.
///
/// Returns `Ok(None)` while more bytes are needed, and `Ok(Some((tag,
/// body_len)))` once `buf` holds the whole message of `5 + body_len` bytes.
///
/// # Errors
///
/// Returns an [`ErrorKind::Protocol`](crate::ErrorKind::Protocol) error for
/// an unknown type byte, a length below 4, a fixed-size message with the
/// wrong length, or a body longer than `max_body_len`. These checks run as
/// soon as the first five bytes are present.
pub fn decode_frame(buf: &[u8], max_body_len: usize) -> Result<Option<(u8, usize)>, Error> {
    let Some(&tag) = buf.first() else {
        return Ok(None);
    };
    if !KNOWN_TAGS.contains(&tag) {
        return Err(Error::protocol(format!("unknown message type 0x{tag:02x}")));
    }
    let Some(len_bytes) = buf.get(1..5) else {
        return Ok(None);
    };
    let mut len = [0u8; 4];
    len.copy_from_slice(len_bytes);
    let len = u32::from_be_bytes(len);
    if !(4..=0x7fff_ffff).contains(&len) {
        return Err(Error::protocol(format!(
            "message '{}' has an invalid length {len}",
            tag_char(tag)
        )));
    }
    let body_len = usize::try_from(len.saturating_sub(4))
        .map_err(|_| Error::protocol("message length does not fit in memory"))?;
    if let Some(fixed) = fixed_body_len(tag)
        && body_len != fixed
    {
        return Err(Error::protocol(format!(
            "message '{}' must have a {fixed}-byte body, not {body_len}",
            tag_char(tag)
        )));
    }
    if body_len > max_body_len {
        return Err(Error::protocol(format!(
            "message '{}' of {body_len} bytes exceeds the limit of {max_body_len} bytes",
            tag_char(tag)
        )));
    }
    if buf.len().saturating_sub(5) < body_len {
        return Ok(None);
    }
    Ok(Some((tag, body_len)))
}

fn tag_char(tag: u8) -> char {
    if tag.is_ascii_graphic() {
        char::from(tag)
    } else {
        '?'
    }
}

/// The transaction status reported by ReadyForQuery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionStatus {
    /// Not in a transaction block (`I`).
    Idle,
    /// In a transaction block (`T`).
    InTransaction,
    /// In a failed transaction block (`E`). Statements fail until the block
    /// ends.
    Failed,
}

impl TransactionStatus {
    fn byte(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }
}

/// An authentication request (message type `R`).
#[derive(Clone, PartialEq, Eq)]
pub enum Authentication {
    /// Authentication succeeded (code 0).
    Ok,
    /// Kerberos V5 (code 2). Never supported.
    KerberosV5,
    /// Cleartext password (code 3).
    CleartextPassword,
    /// MD5 password with a salt (code 5). Never supported.
    Md5Password {
        /// The salt.
        salt: [u8; 4],
    },
    /// SCM credentials (code 6). Obsolete and never supported.
    ScmCredential,
    /// GSSAPI (code 7). Never supported.
    Gss,
    /// GSSAPI or SSPI continuation (code 8). Never supported.
    GssContinue {
        /// Mechanism data.
        data: Vec<u8>,
    },
    /// SSPI (code 9). Never supported.
    Sspi,
    /// SASL with the listed mechanisms (code 10).
    Sasl {
        /// Mechanism names in the server's order of preference.
        mechanisms: Vec<String>,
    },
    /// SASL challenge (code 11).
    SaslContinue {
        /// Mechanism data, such as a SCRAM server-first-message.
        data: Vec<u8>,
    },
    /// SASL outcome (code 12).
    SaslFinal {
        /// Mechanism data, such as a SCRAM server-final-message.
        data: Vec<u8>,
    },
}

impl fmt::Debug for Authentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Authentication::Ok => f.write_str("Ok"),
            Authentication::KerberosV5 => f.write_str("KerberosV5"),
            Authentication::CleartextPassword => f.write_str("CleartextPassword"),
            Authentication::Md5Password { .. } => f.write_str("Md5Password"),
            Authentication::ScmCredential => f.write_str("ScmCredential"),
            Authentication::Gss => f.write_str("Gss"),
            Authentication::GssContinue { data } => write!(f, "GssContinue({} bytes)", data.len()),
            Authentication::Sspi => f.write_str("Sspi"),
            Authentication::Sasl { mechanisms } => write!(f, "Sasl({mechanisms:?})"),
            Authentication::SaslContinue { data } => {
                write!(f, "SaslContinue({} bytes)", data.len())
            }
            Authentication::SaslFinal { data } => write!(f, "SaslFinal({} bytes)", data.len()),
        }
    }
}

/// One column of a RowDescription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    /// The column name.
    pub name: String,
    /// The OID of the source table, or 0.
    pub table_oid: u32,
    /// The attribute number in the source table, or 0.
    pub column_id: i16,
    /// The OID of the column's data type.
    pub type_oid: u32,
    /// The type's size (`pg_type.typlen`). Negative for variable width.
    pub type_size: i16,
    /// The type modifier (`pg_attribute.atttypmod`).
    pub type_modifier: i32,
    /// The format code: 0 for text, 1 for binary. In a statement
    /// description it is always 0, because the format is not yet chosen.
    pub format: i16,
}

/// The values of one result row (message type `D`).
///
/// The row keeps the message body and the position of each value in it.
/// [`fmt::Debug`] shows only the column count, because values are data
/// (R-NF-02).
#[derive(Clone, PartialEq, Eq)]
pub struct DataRow {
    body: Vec<u8>,
    ranges: Vec<Option<(usize, usize)>>,
}

impl DataRow {
    /// Builds a row from values, for test servers and round-trip checks.
    ///
    /// # Errors
    ///
    /// Returns an error when there are more than 65535 values or a value is
    /// longer than `i32::MAX` bytes.
    pub fn from_values(values: &[Option<&[u8]>]) -> Result<DataRow, Error> {
        let count = u16::try_from(values.len())
            .map_err(|_| Error::protocol("a DataRow holds at most 65535 values"))?;
        let mut body = Vec::new();
        body.extend_from_slice(&count.to_be_bytes());
        let mut ranges = Vec::with_capacity(values.len());
        for v in values {
            match v {
                None => {
                    body.extend_from_slice(&(-1i32).to_be_bytes());
                    ranges.push(None);
                }
                Some(bytes) => {
                    let len = i32::try_from(bytes.len())
                        .map_err(|_| Error::protocol("a value is longer than i32::MAX bytes"))?;
                    body.extend_from_slice(&len.to_be_bytes());
                    let start = body.len();
                    body.extend_from_slice(bytes);
                    ranges.push(Some((start, body.len())));
                }
            }
        }
        Ok(DataRow { body, ranges })
    }

    /// The number of values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// True when the row has no values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Value `index`: `None` when out of range, `Some(None)` for SQL NULL.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<Option<&[u8]>> {
        let range = self.ranges.get(index)?;
        Some(range.and_then(|(start, end)| self.body.get(start..end)))
    }

    /// The size of the message body in bytes.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Approximate heap bytes this row holds: the capacity of its two
    /// buffers, each rounded up to 16 bytes plus 16 bytes of allocator
    /// overhead.
    pub(crate) fn heap_bytes(&self) -> usize {
        let ranges = self
            .ranges
            .capacity()
            .saturating_mul(std::mem::size_of::<Option<(usize, usize)>>());
        allocation_cost(self.body.capacity()).saturating_add(allocation_cost(ranges))
    }

    fn parse(body: &[u8], limits: &DecodeLimits) -> Result<DataRow, Error> {
        let mut c = Cursor::new(body, "DataRow");
        let count = usize::from(c.u16()?);
        if count > limits.max_columns {
            return Err(Error::protocol(format!(
                "DataRow has {count} columns, more than the limit of {}",
                limits.max_columns
            )));
        }
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            let len = c.i32()?;
            if len == -1 {
                ranges.push(None);
                continue;
            }
            let len = usize::try_from(len)
                .map_err(|_| Error::protocol("DataRow has a negative value length"))?;
            let start = c.position();
            c.take(len)?;
            ranges.push(Some((start, c.position())));
        }
        c.finish()?;
        Ok(DataRow {
            body: body.to_vec(),
            ranges,
        })
    }
}

/// The approximate memory one heap allocation of `bytes` takes.
fn allocation_cost(bytes: usize) -> usize {
    if bytes == 0 {
        return 0;
    }
    bytes.div_ceil(16).saturating_mul(16).saturating_add(16)
}

impl fmt::Debug for DataRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataRow")
            .field("columns", &self.ranges.len())
            .finish_non_exhaustive()
    }
}

/// The fields of an ErrorResponse or NoticeResponse: a type byte and a
/// value each. [`fmt::Debug`] shows only the type bytes (R-NF-02).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ErrorFields(pub Vec<(u8, Vec<u8>)>);

impl fmt::Debug for ErrorFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let types: String = self.0.iter().map(|(t, _)| tag_char(*t)).collect();
        write!(f, "ErrorFields({types})")
    }
}

impl ErrorFields {
    fn parse(body: &[u8], what: &'static str) -> Result<ErrorFields, Error> {
        let mut c = Cursor::new(body, what);
        let mut fields = Vec::new();
        loop {
            let ty = c.u8()?;
            if ty == 0 {
                break;
            }
            let value = c.cstr()?;
            fields.push((ty, value.to_vec()));
        }
        c.finish()?;
        Ok(ErrorFields(fields))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for (ty, value) in &self.0 {
            out.push(*ty);
            out.extend_from_slice(value);
            out.push(0);
        }
        out.push(0);
    }
}

/// A decoded backend message.
///
/// [`fmt::Debug`] never prints row values, error fields, notification
/// payloads or authentication data (R-NF-02).
#[derive(Clone, PartialEq, Eq)]
pub enum BackendMessage {
    /// `R`: an authentication request or outcome.
    Authentication(Authentication),
    /// `K`: the cancellation key of this session.
    BackendKeyData {
        /// The backend process id.
        process_id: i32,
        /// The secret key.
        secret_key: i32,
    },
    /// `S`: a run-time parameter value.
    ParameterStatus {
        /// Parameter name.
        name: String,
        /// Parameter value.
        value: String,
    },
    /// `Z`: the server is ready for a new request.
    ReadyForQuery(TransactionStatus),
    /// `1`: Parse completed.
    ParseComplete,
    /// `2`: Bind completed.
    BindComplete,
    /// `3`: Close completed.
    CloseComplete,
    /// `t`: the parameter types of a prepared statement.
    ParameterDescription(Vec<u32>),
    /// `T`: the columns of a result.
    RowDescription(Vec<FieldDescription>),
    /// `n`: the statement returns no rows.
    NoData,
    /// `D`: one row.
    DataRow(DataRow),
    /// `C`: a command completed, with its tag such as `INSERT 0 1`.
    CommandComplete(String),
    /// `I`: the statement was empty.
    EmptyQueryResponse,
    /// `s`: Execute stopped at its row limit.
    PortalSuspended,
    /// `E`: an error.
    ErrorResponse(ErrorFields),
    /// `N`: a notice. This client discards notices and never logs them.
    NoticeResponse(ErrorFields),
    /// `A`: a LISTEN/NOTIFY notification.
    NotificationResponse {
        /// The notifying backend's process id.
        process_id: i32,
        /// The channel name.
        channel: String,
        /// The payload.
        payload: String,
    },
    /// `v`: the server does not support the requested minor version or
    /// protocol options.
    NegotiateProtocolVersion {
        /// The newest minor version the server supports.
        newest_minor: i32,
        /// The protocol options it did not recognise.
        unrecognized: Vec<String>,
    },
    /// `G`, `H`, `W`, `d`, `c` or `V`: COPY or function call messages. This
    /// client does not support them.
    Unsupported {
        /// The message type byte.
        tag: u8,
        /// The raw body.
        body: Vec<u8>,
    },
}

impl fmt::Debug for BackendMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendMessage::Authentication(a) => write!(f, "Authentication({a:?})"),
            BackendMessage::BackendKeyData { process_id, .. } => {
                write!(f, "BackendKeyData {{ process_id: {process_id}, .. }}")
            }
            BackendMessage::ParameterStatus { name, .. } => {
                write!(f, "ParameterStatus {{ name: {name:?}, .. }}")
            }
            BackendMessage::ReadyForQuery(s) => write!(f, "ReadyForQuery({s:?})"),
            BackendMessage::ParseComplete => f.write_str("ParseComplete"),
            BackendMessage::BindComplete => f.write_str("BindComplete"),
            BackendMessage::CloseComplete => f.write_str("CloseComplete"),
            BackendMessage::ParameterDescription(t) => write!(f, "ParameterDescription({t:?})"),
            BackendMessage::RowDescription(fields) => {
                write!(f, "RowDescription({} fields)", fields.len())
            }
            BackendMessage::NoData => f.write_str("NoData"),
            BackendMessage::DataRow(r) => write!(f, "{r:?}"),
            BackendMessage::CommandComplete(tag) => write!(f, "CommandComplete({tag:?})"),
            BackendMessage::EmptyQueryResponse => f.write_str("EmptyQueryResponse"),
            BackendMessage::PortalSuspended => f.write_str("PortalSuspended"),
            BackendMessage::ErrorResponse(e) => write!(f, "ErrorResponse({e:?})"),
            BackendMessage::NoticeResponse(e) => write!(f, "NoticeResponse({e:?})"),
            BackendMessage::NotificationResponse { process_id, .. } => {
                write!(f, "NotificationResponse {{ process_id: {process_id}, .. }}")
            }
            BackendMessage::NegotiateProtocolVersion { newest_minor, .. } => {
                write!(
                    f,
                    "NegotiateProtocolVersion {{ newest_minor: {newest_minor}, .. }}"
                )
            }
            BackendMessage::Unsupported { tag, body } => {
                write!(f, "Unsupported('{}', {} bytes)", tag_char(*tag), body.len())
            }
        }
    }
}

impl BackendMessage {
    /// Decodes the body of a message of type `tag`.
    ///
    /// The body must be consumed exactly. Strings that the client
    /// interprets must be UTF-8; error and notice field values may be any
    /// bytes, because they can arrive before the client encoding is set.
    ///
    /// # Errors
    ///
    /// Returns an [`ErrorKind::Protocol`](crate::ErrorKind::Protocol) error
    /// for any malformed body.
    pub fn parse(tag: u8, body: &[u8], limits: &DecodeLimits) -> Result<BackendMessage, Error> {
        let msg = match tag {
            b'R' => BackendMessage::Authentication(parse_auth(body)?),
            b'K' => {
                let mut c = Cursor::new(body, "BackendKeyData");
                let process_id = c.i32()?;
                let secret_key = c.i32()?;
                c.finish()?;
                BackendMessage::BackendKeyData {
                    process_id,
                    secret_key,
                }
            }
            b'S' => {
                let mut c = Cursor::new(body, "ParameterStatus");
                let name = c.cstr_utf8()?.to_owned();
                let value = c.cstr_utf8()?.to_owned();
                c.finish()?;
                BackendMessage::ParameterStatus { name, value }
            }
            b'Z' => {
                let mut c = Cursor::new(body, "ReadyForQuery");
                let status = match c.u8()? {
                    b'I' => TransactionStatus::Idle,
                    b'T' => TransactionStatus::InTransaction,
                    b'E' => TransactionStatus::Failed,
                    _ => return Err(Error::protocol("ReadyForQuery has an unknown status")),
                };
                c.finish()?;
                BackendMessage::ReadyForQuery(status)
            }
            b'1' => empty(body, "ParseComplete", BackendMessage::ParseComplete)?,
            b'2' => empty(body, "BindComplete", BackendMessage::BindComplete)?,
            b'3' => empty(body, "CloseComplete", BackendMessage::CloseComplete)?,
            b'n' => empty(body, "NoData", BackendMessage::NoData)?,
            b'I' => empty(
                body,
                "EmptyQueryResponse",
                BackendMessage::EmptyQueryResponse,
            )?,
            b's' => empty(body, "PortalSuspended", BackendMessage::PortalSuspended)?,
            b't' => {
                let mut c = Cursor::new(body, "ParameterDescription");
                let count = usize::from(c.u16()?);
                if count > limits.max_parameters {
                    return Err(Error::protocol(format!(
                        "ParameterDescription has {count} parameters, more than the limit of {}",
                        limits.max_parameters
                    )));
                }
                let mut types = Vec::with_capacity(count.min(c.remaining() / 4));
                for _ in 0..count {
                    types.push(c.u32()?);
                }
                c.finish()?;
                BackendMessage::ParameterDescription(types)
            }
            b'T' => BackendMessage::RowDescription(parse_row_description(body, limits)?),
            b'D' => BackendMessage::DataRow(DataRow::parse(body, limits)?),
            b'C' => {
                let mut c = Cursor::new(body, "CommandComplete");
                let tag = c.cstr_utf8()?.to_owned();
                c.finish()?;
                BackendMessage::CommandComplete(tag)
            }
            b'E' => BackendMessage::ErrorResponse(ErrorFields::parse(body, "ErrorResponse")?),
            b'N' => BackendMessage::NoticeResponse(ErrorFields::parse(body, "NoticeResponse")?),
            b'A' => {
                let mut c = Cursor::new(body, "NotificationResponse");
                let process_id = c.i32()?;
                let channel = c.cstr_utf8()?.to_owned();
                let payload = c.cstr_utf8()?.to_owned();
                c.finish()?;
                BackendMessage::NotificationResponse {
                    process_id,
                    channel,
                    payload,
                }
            }
            b'v' => {
                let mut c = Cursor::new(body, "NegotiateProtocolVersion");
                let newest_minor = c.i32()?;
                let count = c.i32()?;
                let count = usize::try_from(count).map_err(|_| {
                    Error::protocol("NegotiateProtocolVersion has a negative count")
                })?;
                let mut unrecognized = Vec::with_capacity(count.min(c.remaining()));
                for _ in 0..count {
                    unrecognized.push(c.cstr_utf8()?.to_owned());
                }
                c.finish()?;
                BackendMessage::NegotiateProtocolVersion {
                    newest_minor,
                    unrecognized,
                }
            }
            b'G' | b'H' | b'W' | b'd' | b'c' | b'V' => BackendMessage::Unsupported {
                tag,
                body: body.to_vec(),
            },
            _ => {
                return Err(Error::protocol(format!("unknown message type 0x{tag:02x}")));
            }
        };
        Ok(msg)
    }

    /// The message type byte.
    #[must_use]
    pub fn tag(&self) -> u8 {
        match self {
            BackendMessage::Authentication(_) => b'R',
            BackendMessage::BackendKeyData { .. } => b'K',
            BackendMessage::ParameterStatus { .. } => b'S',
            BackendMessage::ReadyForQuery(_) => b'Z',
            BackendMessage::ParseComplete => b'1',
            BackendMessage::BindComplete => b'2',
            BackendMessage::CloseComplete => b'3',
            BackendMessage::ParameterDescription(_) => b't',
            BackendMessage::RowDescription(_) => b'T',
            BackendMessage::NoData => b'n',
            BackendMessage::DataRow(_) => b'D',
            BackendMessage::CommandComplete(_) => b'C',
            BackendMessage::EmptyQueryResponse => b'I',
            BackendMessage::PortalSuspended => b's',
            BackendMessage::ErrorResponse(_) => b'E',
            BackendMessage::NoticeResponse(_) => b'N',
            BackendMessage::NotificationResponse { .. } => b'A',
            BackendMessage::NegotiateProtocolVersion { .. } => b'v',
            BackendMessage::Unsupported { tag, .. } => *tag,
        }
    }

    /// Appends the complete wire form of this message to `out`.
    ///
    /// Encoding a message that [`BackendMessage::parse`] returned yields the
    /// original bytes. Test servers use this to speak the protocol.
    ///
    /// # Errors
    ///
    /// Returns an error when a string contains NUL, a count exceeds its
    /// field, or the message is longer than `i32::MAX` bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let start = out.len();
        out.push(self.tag());
        out.extend_from_slice(&[0, 0, 0, 0]);
        match self {
            BackendMessage::Authentication(a) => encode_auth(a, out)?,
            BackendMessage::BackendKeyData {
                process_id,
                secret_key,
            } => {
                out.extend_from_slice(&process_id.to_be_bytes());
                out.extend_from_slice(&secret_key.to_be_bytes());
            }
            BackendMessage::ParameterStatus { name, value } => {
                put_cstr(out, name.as_bytes())?;
                put_cstr(out, value.as_bytes())?;
            }
            BackendMessage::ReadyForQuery(s) => out.push(s.byte()),
            BackendMessage::ParseComplete
            | BackendMessage::BindComplete
            | BackendMessage::CloseComplete
            | BackendMessage::NoData
            | BackendMessage::EmptyQueryResponse
            | BackendMessage::PortalSuspended => {}
            BackendMessage::ParameterDescription(types) => {
                put_count(out, types.len())?;
                for t in types {
                    out.extend_from_slice(&t.to_be_bytes());
                }
            }
            BackendMessage::RowDescription(fields) => {
                put_count(out, fields.len())?;
                for f in fields {
                    put_cstr(out, f.name.as_bytes())?;
                    out.extend_from_slice(&f.table_oid.to_be_bytes());
                    out.extend_from_slice(&f.column_id.to_be_bytes());
                    out.extend_from_slice(&f.type_oid.to_be_bytes());
                    out.extend_from_slice(&f.type_size.to_be_bytes());
                    out.extend_from_slice(&f.type_modifier.to_be_bytes());
                    out.extend_from_slice(&f.format.to_be_bytes());
                }
            }
            BackendMessage::DataRow(row) => out.extend_from_slice(&row.body),
            BackendMessage::CommandComplete(tag) => put_cstr(out, tag.as_bytes())?,
            BackendMessage::ErrorResponse(fields) | BackendMessage::NoticeResponse(fields) => {
                for (ty, value) in &fields.0 {
                    if *ty == 0 || value.contains(&0) {
                        return Err(Error::protocol("error field contains NUL"));
                    }
                }
                fields.encode(out);
            }
            BackendMessage::NotificationResponse {
                process_id,
                channel,
                payload,
            } => {
                out.extend_from_slice(&process_id.to_be_bytes());
                put_cstr(out, channel.as_bytes())?;
                put_cstr(out, payload.as_bytes())?;
            }
            BackendMessage::NegotiateProtocolVersion {
                newest_minor,
                unrecognized,
            } => {
                out.extend_from_slice(&newest_minor.to_be_bytes());
                let n = i32::try_from(unrecognized.len())
                    .map_err(|_| Error::protocol("too many protocol options"))?;
                out.extend_from_slice(&n.to_be_bytes());
                for o in unrecognized {
                    put_cstr(out, o.as_bytes())?;
                }
            }
            BackendMessage::Unsupported { body, .. } => out.extend_from_slice(body),
        }
        backpatch_len(out, start)
    }
}

fn empty(body: &[u8], what: &'static str, msg: BackendMessage) -> Result<BackendMessage, Error> {
    Cursor::new(body, what).finish()?;
    Ok(msg)
}

fn parse_auth(body: &[u8]) -> Result<Authentication, Error> {
    let mut c = Cursor::new(body, "Authentication");
    let code = c.i32()?;
    let auth = match code {
        0 => Authentication::Ok,
        2 => Authentication::KerberosV5,
        3 => Authentication::CleartextPassword,
        5 => {
            let mut salt = [0u8; 4];
            salt.copy_from_slice(c.take(4)?);
            Authentication::Md5Password { salt }
        }
        6 => Authentication::ScmCredential,
        7 => Authentication::Gss,
        8 => Authentication::GssContinue {
            data: c.rest().to_vec(),
        },
        9 => Authentication::Sspi,
        10 => {
            let mut mechanisms = Vec::new();
            loop {
                let name = c.cstr_utf8()?;
                if name.is_empty() {
                    break;
                }
                mechanisms.push(name.to_owned());
            }
            Authentication::Sasl { mechanisms }
        }
        11 => Authentication::SaslContinue {
            data: c.rest().to_vec(),
        },
        12 => Authentication::SaslFinal {
            data: c.rest().to_vec(),
        },
        _ => {
            return Err(Error::protocol(format!(
                "unknown authentication request code {code}"
            )));
        }
    };
    c.finish()?;
    Ok(auth)
}

fn encode_auth(a: &Authentication, out: &mut Vec<u8>) -> Result<(), Error> {
    let code: i32 = match a {
        Authentication::Ok => 0,
        Authentication::KerberosV5 => 2,
        Authentication::CleartextPassword => 3,
        Authentication::Md5Password { .. } => 5,
        Authentication::ScmCredential => 6,
        Authentication::Gss => 7,
        Authentication::GssContinue { .. } => 8,
        Authentication::Sspi => 9,
        Authentication::Sasl { .. } => 10,
        Authentication::SaslContinue { .. } => 11,
        Authentication::SaslFinal { .. } => 12,
    };
    out.extend_from_slice(&code.to_be_bytes());
    match a {
        Authentication::Md5Password { salt } => out.extend_from_slice(salt),
        Authentication::GssContinue { data }
        | Authentication::SaslContinue { data }
        | Authentication::SaslFinal { data } => out.extend_from_slice(data),
        Authentication::Sasl { mechanisms } => {
            for m in mechanisms {
                if m.is_empty() {
                    return Err(Error::protocol("empty SASL mechanism name"));
                }
                put_cstr(out, m.as_bytes())?;
            }
            out.push(0);
        }
        _ => {}
    }
    Ok(())
}

fn parse_row_description(
    body: &[u8],
    limits: &DecodeLimits,
) -> Result<Vec<FieldDescription>, Error> {
    let mut c = Cursor::new(body, "RowDescription");
    let count = usize::from(c.u16()?);
    if count > limits.max_columns {
        return Err(Error::protocol(format!(
            "RowDescription has {count} columns, more than the limit of {}",
            limits.max_columns
        )));
    }
    let mut fields = Vec::with_capacity(count.min(c.remaining() / 19));
    for _ in 0..count {
        let name = c.cstr_utf8()?.to_owned();
        let table_oid = c.u32()?;
        let column_id = c.i16()?;
        let type_oid = c.u32()?;
        let type_size = c.i16()?;
        let type_modifier = c.i32()?;
        let format = c.i16()?;
        if format != 0 && format != 1 {
            return Err(Error::protocol("RowDescription has an unknown format code"));
        }
        fields.push(FieldDescription {
            name,
            table_oid,
            column_id,
            type_oid,
            type_size,
            type_modifier,
            format,
        });
    }
    c.finish()?;
    Ok(fields)
}

fn put_cstr(out: &mut Vec<u8>, s: &[u8]) -> Result<(), Error> {
    if s.contains(&0) {
        return Err(Error::protocol("string contains NUL"));
    }
    out.extend_from_slice(s);
    out.push(0);
    Ok(())
}

fn put_count(out: &mut Vec<u8>, n: usize) -> Result<(), Error> {
    let n = u16::try_from(n).map_err(|_| Error::protocol("count exceeds 65535"))?;
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

/// Writes the length of the message that starts at `start` into its header.
pub(crate) fn backpatch_len(out: &mut [u8], start: usize) -> Result<(), Error> {
    let len_at = start.saturating_add(1);
    let len = out.len().saturating_sub(len_at);
    let len = i32::try_from(len).map_err(|_| Error::protocol("message exceeds i32::MAX bytes"))?;
    let end = len_at.saturating_add(4);
    let slot = out
        .get_mut(len_at..end)
        .ok_or_else(|| Error::protocol("message header missing"))?;
    slot.copy_from_slice(&len.to_be_bytes());
    Ok(())
}

/// A streaming decoder: push bytes in, take whole messages out.
///
/// The result does not depend on how the input is split into pushes. The
/// buffer holds at most one incomplete message plus the last push. After a
/// large message, the buffer shrinks back to [`RETAINED_BUFFER_CAPACITY`]
/// once little data is buffered.
#[derive(Debug)]
pub struct BackendDecoder {
    buf: Vec<u8>,
    start: usize,
    limits: DecodeLimits,
}

impl BackendDecoder {
    /// A decoder with the given limits.
    #[must_use]
    pub fn new(limits: DecodeLimits) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            limits,
        }
    }

    /// Replaces the limits, for example after authentication.
    pub fn set_limits(&mut self, limits: DecodeLimits) {
        self.limits = limits;
    }

    /// The current limits.
    #[must_use]
    pub fn limits(&self) -> DecodeLimits {
        self.limits
    }

    /// Appends received bytes.
    pub fn push(&mut self, data: &[u8]) {
        if self.start > 0 && (self.start >= self.buf.len() || self.start >= 1 << 16) {
            self.buf.drain(..self.start.min(self.buf.len()));
            self.start = 0;
        }
        let needed = self.buf.len().saturating_add(data.len());
        if self.buf.capacity() > SHRINK_BUFFER_ABOVE && needed <= RETAINED_BUFFER_CAPACITY {
            self.buf.shrink_to(RETAINED_BUFFER_CAPACITY);
        }
        self.buf.extend_from_slice(data);
    }

    /// Bytes received but not yet decoded.
    #[must_use]
    pub fn buffered(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or_default()
    }

    /// Decodes the next complete message, if one is buffered.
    ///
    /// # Errors
    ///
    /// Returns the framing or decoding error. The decoder must not be used
    /// after an error, because the stream position is lost.
    pub fn next_message(&mut self) -> Result<Option<BackendMessage>, Error> {
        let pending = self.buf.get(self.start..).unwrap_or_default();
        let Some((tag, body_len)) = decode_frame(pending, self.limits.max_message_len)? else {
            return Ok(None);
        };
        let end = body_len.saturating_add(5);
        let body = pending
            .get(5..end)
            .ok_or_else(|| Error::protocol("frame shorter than announced"))?;
        let msg = BackendMessage::parse(tag, body, &self.limits)?;
        self.start = self.start.saturating_add(end);
        Ok(Some(msg))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn decode_all(bytes: &[u8]) -> Result<Vec<BackendMessage>, Error> {
        let mut d = BackendDecoder::new(DecodeLimits::default());
        d.push(bytes);
        let mut out = Vec::new();
        while let Some(m) = d.next_message()? {
            out.push(m);
        }
        Ok(out)
    }

    #[test]
    fn th26_unknown_tag_fails_before_the_length() {
        assert!(decode_frame(b"Q", 100).is_err());
        assert!(decode_frame(b"\x00", 100).is_err());
        assert_eq!(decode_frame(b"Z", 100).unwrap(), None);
    }

    #[test]
    fn th26_fixed_size_messages_must_announce_their_size() {
        assert!(decode_frame(&frame(b'Z', b"II"), 100).is_err());
        assert!(decode_frame(b"Z\x7f\xff\xff\xff", 1 << 30).is_err());
        assert!(decode_frame(&frame(b'1', b"x"), 100).is_err());
        assert_eq!(
            decode_frame(&frame(b'Z', b"I"), 100).unwrap(),
            Some((b'Z', 1))
        );
    }

    #[test]
    fn th26_lengths_are_checked() {
        assert!(decode_frame(b"C\x00\x00\x00\x03", 100).is_err());
        assert!(decode_frame(b"C\x80\x00\x00\x00", usize::MAX).is_err());
        assert!(decode_frame(b"D\x00\x00\x01\x00", 100).is_err());
        assert_eq!(decode_frame(b"D\x00\x00\x00\x68", 100).unwrap(), None);
    }

    #[test]
    fn th26_trailing_bytes_are_rejected() {
        assert!(decode_all(&frame(b'C', b"SELECT 1\0x")).is_err());
        assert!(decode_all(&frame(b'R', b"\0\0\0\0\0")).is_err());
        assert!(decode_all(&frame(b'S', b"a\0b\0\0")).is_err());
    }

    #[test]
    fn th26_data_row_lengths_are_checked() {
        // Two columns announced, one present.
        assert!(decode_all(&frame(b'D', b"\x00\x02\x00\x00\x00\x01x")).is_err());
        // Negative length other than -1.
        assert!(decode_all(&frame(b'D', b"\x00\x01\xff\xff\xff\xfe")).is_err());
        // Value runs past the end.
        assert!(decode_all(&frame(b'D', b"\x00\x01\x00\x00\x00\x05ab")).is_err());
        let ok = decode_all(&frame(b'D', b"\x00\x02\xff\xff\xff\xff\x00\x00\x00\x02ab")).unwrap();
        let BackendMessage::DataRow(row) = &ok[0] else {
            panic!("not a row");
        };
        assert_eq!(row.get(0), Some(None));
        assert_eq!(row.get(1), Some(Some(&b"ab"[..])));
        assert_eq!(row.get(2), None);
    }

    #[test]
    fn th26_column_limit_applies() {
        let limits = DecodeLimits {
            max_message_len: 1000,
            max_columns: 1,
            max_parameters: 1,
        };
        let mut d = BackendDecoder::new(limits);
        d.push(&frame(b'D', b"\x00\x02\xff\xff\xff\xff\xff\xff\xff\xff"));
        assert!(d.next_message().is_err());
    }

    /// TH-26: the parameter count of a ParameterDescription is bounded by a
    /// configurable limit, like every other count.
    #[test]
    fn review_pg_paramdesc_ignores_max_columns() {
        let mut body = vec![0u8, 5];
        for _ in 0..5 {
            body.extend_from_slice(&23u32.to_be_bytes());
        }
        let wire = frame(b't', &body);
        for (max_parameters, ok) in [(1, false), (4, false), (5, true)] {
            let limits = DecodeLimits {
                max_message_len: 1 << 20,
                max_columns: 1664,
                max_parameters,
            };
            let mut d = BackendDecoder::new(limits);
            d.push(&wire);
            let m = d.next_message();
            assert_eq!(m.is_ok(), ok, "max_parameters {max_parameters}: {m:?}");
        }
        assert_eq!(
            decode_all(&wire).unwrap(),
            vec![BackendMessage::ParameterDescription(vec![23; 5])]
        );
    }

    /// One large message must not pin a large buffer for the life of the
    /// connection.
    #[test]
    fn review_pg_buffers_never_shrink() {
        let big = vec![b'x'; 1 << 20];
        let mut body = vec![0u8, 1];
        body.extend_from_slice(&u32::try_from(big.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&big);
        let mut d = BackendDecoder::new(DecodeLimits::default());
        d.push(&frame(b'D', &body));
        assert!(matches!(
            d.next_message().unwrap(),
            Some(BackendMessage::DataRow(_))
        ));
        assert!(d.buf.capacity() >= 1 << 20);
        d.push(&frame(b'Z', b"I"));
        assert!(
            d.buf.capacity() <= SHRINK_BUFFER_ABOVE,
            "{}",
            d.buf.capacity()
        );
        assert_eq!(
            d.next_message().unwrap(),
            Some(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        );
        // A partial large message keeps its buffer until it is complete.
        let large = frame(b'D', &body);
        d.push(&large[..large.len() / 2]);
        d.push(&large[large.len() / 2..]);
        assert!(matches!(
            d.next_message().unwrap(),
            Some(BackendMessage::DataRow(_))
        ));
    }

    #[test]
    fn messages_round_trip_through_encode() {
        let msgs = vec![
            BackendMessage::Authentication(Authentication::Sasl {
                mechanisms: vec!["SCRAM-SHA-256-PLUS".into(), "SCRAM-SHA-256".into()],
            }),
            BackendMessage::Authentication(Authentication::SaslContinue {
                data: b"r=abc,s=c2FsdA==,i=4096".to_vec(),
            }),
            BackendMessage::Authentication(Authentication::Md5Password { salt: *b"salt" }),
            BackendMessage::BackendKeyData {
                process_id: 7,
                secret_key: -9,
            },
            BackendMessage::ParameterStatus {
                name: "client_encoding".into(),
                value: "UTF8".into(),
            },
            BackendMessage::ReadyForQuery(TransactionStatus::Failed),
            BackendMessage::ParameterDescription(vec![23, 25]),
            BackendMessage::RowDescription(vec![FieldDescription {
                name: "x".into(),
                table_oid: 1,
                column_id: 2,
                type_oid: 23,
                type_size: 4,
                type_modifier: -1,
                format: 1,
            }]),
            BackendMessage::DataRow(DataRow::from_values(&[None, Some(b"v")]).unwrap()),
            BackendMessage::CommandComplete("INSERT 0 1".into()),
            BackendMessage::ErrorResponse(ErrorFields(vec![(b'S', b"ERROR".to_vec())])),
            BackendMessage::NotificationResponse {
                process_id: 1,
                channel: "c".into(),
                payload: "p".into(),
            },
            BackendMessage::NegotiateProtocolVersion {
                newest_minor: 0,
                unrecognized: vec!["_pq_.x".into()],
            },
            BackendMessage::Unsupported {
                tag: b'G',
                body: vec![0, 0, 0],
            },
        ];
        let mut wire = Vec::new();
        for m in &msgs {
            m.encode(&mut wire).unwrap();
        }
        assert_eq!(decode_all(&wire).unwrap(), msgs);
        // Byte-at-a-time pushes give the same result.
        let mut d = BackendDecoder::new(DecodeLimits::default());
        let mut out = Vec::new();
        for b in &wire {
            d.push(std::slice::from_ref(b));
            while let Some(m) = d.next_message().unwrap() {
                out.push(m);
            }
        }
        assert_eq!(out, msgs);
    }

    /// R-NF-02: Debug output never shows values.
    #[test]
    fn r_nf_02_debug_hides_values() {
        let row = BackendMessage::DataRow(DataRow::from_values(&[Some(b"canary")]).unwrap());
        let err = BackendMessage::ErrorResponse(ErrorFields(vec![(b'D', b"canary".to_vec())]));
        let note = BackendMessage::NotificationResponse {
            process_id: 1,
            channel: "c".into(),
            payload: "canary".into(),
        };
        let shown = format!("{row:?} {err:?} {note:?}");
        assert!(!shown.contains("canary"), "{shown}");
    }
}
