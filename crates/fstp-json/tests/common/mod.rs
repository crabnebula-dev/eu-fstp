//! Helpers shared by the integration tests.

use fstp_json::Value;

/// The memory estimate that `ParseLimits::max_memory_bytes` documents.
pub(crate) fn documented_estimate(v: &Value) -> usize {
    let mut total = 0;
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        total += 64;
        match v {
            Value::String(s) => total += s.len(),
            Value::Number(n) => total += n.as_str().len(),
            Value::Array(a) => stack.extend(a.iter()),
            Value::Object(o) => {
                if o.len() > 8 {
                    total += 128 + 80 * o.len();
                }
                for (k, v) in o.iter() {
                    total += 64 + k.len();
                    stack.push(v);
                }
            }
            Value::Null | Value::Bool(_) => {}
        }
    }
    total
}
