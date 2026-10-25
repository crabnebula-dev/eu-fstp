//! `json!` builds values; `json_struct!` maps structs with named fields.

/// Builds a [`Value`](crate::Value) from JSON-like syntax.
///
/// Literals `null`, `true` and `false`, arrays and objects nest freely. Any
/// other element or member value is a Rust expression converted with
/// [`ToJson`](crate::ToJson). Member names are string literals or
/// parenthesised expressions that convert into `String`. A repeated name keeps
/// its first position and takes the last value, as
/// [`Object::insert`](crate::Object::insert) does.
///
/// Floats have no [`ToJson`](crate::ToJson) implementation, so a float
/// literal does not compile. Use [`Decimal`](crate::Decimal) for amounts, or
/// [`Number::from_f64`](crate::Number::from_f64) for a measured quantity.
///
/// ```
/// use fstp_json::json;
/// let deadline = "2026-11-30";
/// let v = json!({
///     "call": "SuperSAFE",
///     "open": true,
///     "budget": 150000,
///     "tags": ["data", null, (1 + 2)],
///     ("dead" .to_owned() + "line"): deadline,
///     "nested": {"empty": [], "obj": {}},
/// });
/// assert_eq!(
///     v.to_compact(),
///     r#"{"call":"SuperSAFE","open":true,"budget":150000,"tags":["data",null,3],"deadline":"2026-11-30","nested":{"empty":[],"obj":{}}}"#
/// );
/// ```
#[macro_export]
macro_rules! json {
    (null) => {
        $crate::Value::Null
    };
    (true) => {
        $crate::Value::Bool(true)
    };
    (false) => {
        $crate::Value::Bool(false)
    };
    ([]) => {
        $crate::Value::Array($crate::Array::new())
    };
    ([ $($tt:tt)+ ]) => {{
        let mut array = $crate::Array::new();
        $crate::__json_array!(array ($($tt)+));
        $crate::Value::Array(array)
    }};
    ({}) => {
        $crate::Value::Object($crate::Object::new())
    };
    ({ $($tt:tt)+ }) => {{
        let mut object = $crate::Object::new();
        $crate::__json_object!(object ($($tt)+));
        $crate::Value::Object(object)
    }};
    ($other:expr) => {
        $crate::ToJson::to_json(&$other)
    };
}

/// Internal: pushes the elements of a `json!` array.
#[doc(hidden)]
#[macro_export]
macro_rules! __json_array {
    ($a:ident ()) => {};
    ($a:ident (null $(, $($rest:tt)*)?)) => {
        $a.push($crate::json!(null));
        $crate::__json_array!($a ($($($rest)*)?));
    };
    ($a:ident (true $(, $($rest:tt)*)?)) => {
        $a.push($crate::json!(true));
        $crate::__json_array!($a ($($($rest)*)?));
    };
    ($a:ident (false $(, $($rest:tt)*)?)) => {
        $a.push($crate::json!(false));
        $crate::__json_array!($a ($($($rest)*)?));
    };
    ($a:ident ([$($inner:tt)*] $(, $($rest:tt)*)?)) => {
        $a.push($crate::json!([$($inner)*]));
        $crate::__json_array!($a ($($($rest)*)?));
    };
    ($a:ident ({$($inner:tt)*} $(, $($rest:tt)*)?)) => {
        $a.push($crate::json!({$($inner)*}));
        $crate::__json_array!($a ($($($rest)*)?));
    };
    ($a:ident ($value:expr $(, $($rest:tt)*)?)) => {
        $a.push($crate::json!($value));
        $crate::__json_array!($a ($($($rest)*)?));
    };
}

/// Internal: inserts the members of a `json!` object.
#[doc(hidden)]
#[macro_export]
macro_rules! __json_object {
    ($o:ident ()) => {};
    ($o:ident ($key:literal : $($rest:tt)*)) => {
        $crate::__json_member!($o (::std::string::String::from($key)) ($($rest)*));
    };
    ($o:ident (($key:expr) : $($rest:tt)*)) => {
        $crate::__json_member!($o (::std::string::String::from($key)) ($($rest)*));
    };
}

/// Internal: inserts one member value, then continues with the rest.
#[doc(hidden)]
#[macro_export]
macro_rules! __json_member {
    ($o:ident ($key:expr) (null $(, $($rest:tt)*)?)) => {
        $o.insert($key, $crate::json!(null));
        $crate::__json_object!($o ($($($rest)*)?));
    };
    ($o:ident ($key:expr) (true $(, $($rest:tt)*)?)) => {
        $o.insert($key, $crate::json!(true));
        $crate::__json_object!($o ($($($rest)*)?));
    };
    ($o:ident ($key:expr) (false $(, $($rest:tt)*)?)) => {
        $o.insert($key, $crate::json!(false));
        $crate::__json_object!($o ($($($rest)*)?));
    };
    ($o:ident ($key:expr) ([$($inner:tt)*] $(, $($rest:tt)*)?)) => {
        $o.insert($key, $crate::json!([$($inner)*]));
        $crate::__json_object!($o ($($($rest)*)?));
    };
    ($o:ident ($key:expr) ({$($inner:tt)*} $(, $($rest:tt)*)?)) => {
        $o.insert($key, $crate::json!({$($inner)*}));
        $crate::__json_object!($o ($($($rest)*)?));
    };
    ($o:ident ($key:expr) ($value:expr $(, $($rest:tt)*)?)) => {
        $o.insert($key, $crate::json!($value));
        $crate::__json_object!($o ($($($rest)*)?));
    };
}

/// Implements [`ToJson`](crate::ToJson) and [`FromJson`](crate::FromJson)
/// for a struct with named fields.
///
/// List every field with `required` or `optional`, optionally followed by
/// `= "name"` to use a different member name. A raw identifier such as
/// `r#type` maps to the member name `type`:
///
/// - A `required` field must be present. It may hold any type that
///   implements both traits, including `Option<T>`, which then accepts
///   `null` but not absence.
/// - An `optional` field must have type `Option<T>`. Absence and `null` both
///   read as `None`, and `None` is omitted on output.
///
/// Members not listed are rejected. Write `allow_unknown` after the struct
/// name to ignore them instead. Errors carry the path of the failing value,
/// such as `$.calls[2].deadline`.
///
/// ```
/// use fstp_json::{FromJson, ToJson, json, json_struct};
///
/// #[derive(Debug, PartialEq)]
/// struct Call { id: u32, title: String, deadline: Option<String> }
/// json_struct!(Call { required id, required title = "name", optional deadline });
///
/// #[derive(Debug, PartialEq)]
/// struct Programme { calls: Vec<Call> }
/// json_struct!(Programme { required calls });
///
/// let v = json!({"calls": [{"id": 1, "name": "Open call"}]});
/// let p = Programme::from_json(&v).unwrap();
/// assert_eq!(p.calls[0].deadline, None);
/// assert_eq!(p.to_json(), v);
///
/// let bad = json!({"calls": [{"id": 1, "name": "A"}, {"id": 2, "name": "B", "deadline": 7}]});
/// let err = Programme::from_json(&bad).unwrap_err();
/// assert_eq!(err.path().to_string(), "$.calls[1].deadline");
/// assert_eq!(err.to_string(), "$.calls[1].deadline: expected a string, found number");
///
/// let extra = json!({"calls": [], "x": 1});
/// assert!(Programme::from_json(&extra).is_err());
/// ```
#[macro_export]
macro_rules! json_struct {
    ($name:ident $($flag:ident)? { $($kind:ident $field:ident $(= $key:literal)?),* $(,)? }) => {
        impl $crate::ToJson for $name {
            fn to_json(&self) -> $crate::Value {
                let mut object = $crate::Object::new();
                $(
                    $crate::__json_put!($kind object, $crate::__json_key!($field $(= $key)?), &self.$field);
                )*
                $crate::Value::Object(object)
            }
        }

        impl $crate::FromJson for $name {
            fn from_json(
                value: &$crate::Value,
            ) -> ::core::result::Result<Self, $crate::FromJsonError> {
                let object = $crate::typed::expect_object(value)?;
                if $crate::__json_deny_unknown!($($flag)?) {
                    const FIELDS: &[&str] = &[$($crate::__json_key!($field $(= $key)?)),*];
                    $crate::typed::reject_unknown(object, FIELDS)?;
                }
                ::core::result::Result::Ok(Self {
                    $(
                        $field: $crate::__json_get!($kind object, $crate::__json_key!($field $(= $key)?)),
                    )*
                })
            }
        }
    };
}

/// Internal: the member name of a `json_struct!` field.
#[doc(hidden)]
#[macro_export]
macro_rules! __json_key {
    ($field:ident) => {
        const { $crate::typed::field_name(::core::stringify!($field)) }
    };
    ($field:ident = $key:literal) => {
        $key
    };
}

/// Internal: whether unknown members are rejected.
#[doc(hidden)]
#[macro_export]
macro_rules! __json_deny_unknown {
    () => {
        true
    };
    (allow_unknown) => {
        false
    };
}

/// Internal: writes one `json_struct!` field.
#[doc(hidden)]
#[macro_export]
macro_rules! __json_put {
    (required $o:ident, $key:expr, $value:expr) => {
        $o.insert($key, $crate::ToJson::to_json($value));
    };
    (optional $o:ident, $key:expr, $value:expr) => {
        if let ::core::option::Option::Some(v) = $value {
            $o.insert($key, $crate::ToJson::to_json(v));
        }
    };
}

/// Internal: reads one `json_struct!` field.
#[doc(hidden)]
#[macro_export]
macro_rules! __json_get {
    (required $o:ident, $key:expr) => {
        $crate::typed::required_field($o, $key)?
    };
    (optional $o:ident, $key:expr) => {
        $crate::typed::optional_field($o, $key)?
    };
}
