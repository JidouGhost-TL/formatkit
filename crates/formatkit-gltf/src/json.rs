//! A tiny, dependency-free JSON value and serializer.
//!
//! The exporter emits a small, fixed-shape document, so a hand-written value
//! tree plus a compact serializer is enough — no external JSON crate is pulled
//! in. Numbers keep their integer/float distinction (glTF cares: an accessor
//! `count` is an integer, a bounding-box coordinate is a float), and strings are
//! escaped for all JSON control characters and quotes.

/// A JSON value. `Int`/`UInt` serialize without a decimal point; `Num`
/// serializes as a float. A non-finite `Num` is written as `0` so a crafted or
/// degenerate input can never produce invalid JSON (`NaN`/`Infinity`).
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// JSON boolean (`true` or `false`).
    Bool(bool),
    /// Signed integer serialized without a decimal point.
    Int(i64),
    /// Unsigned integer serialized without a decimal point.
    UInt(u64),
    /// Finite floating-point number (non-finite values serialize as `0`).
    Num(f64),
    /// UTF-8 JSON string (escaped on serialization).
    Str(String),
    /// JSON array.
    Arr(Vec<Json>),
    /// JSON object with static field keys in insertion order.
    Obj(Vec<(&'static str, Json)>),
}

impl Json {
    /// Serialize to a compact (whitespace-free) JSON string.
    #[must_use]
    pub fn to_json_string(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => out.push_str(&i.to_string()),
            Json::UInt(u) => out.push_str(&u.to_string()),
            Json::Num(f) => write_num(*f, out),
            Json::Str(s) => write_str(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    it.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_num(f: f64, out: &mut String) {
    if !f.is_finite() {
        out.push('0');
        return;
    }
    out.push_str(&f.to_string());
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Convenience: build a [`Json::Obj`] from a list of fields.
#[must_use]
pub fn obj(fields: Vec<(&'static str, Json)>) -> Json {
    Json::Obj(fields)
}

/// Convenience: build a [`Json::Arr`].
#[must_use]
pub fn arr(items: Vec<Json>) -> Json {
    Json::Arr(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_have_no_decimal_point() {
        assert_eq!(Json::UInt(42).to_json_string(), "42");
        assert_eq!(Json::Int(-7).to_json_string(), "-7");
        assert_eq!(Json::Num(1.0).to_json_string(), "1");
        assert_eq!(Json::Num(0.5).to_json_string(), "0.5");
    }

    #[test]
    fn non_finite_num_is_zero() {
        assert_eq!(Json::Num(f64::NAN).to_json_string(), "0");
        assert_eq!(Json::Num(f64::INFINITY).to_json_string(), "0");
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(
            Json::Str("a\"b\\c".to_string()).to_json_string(),
            "\"a\\\"b\\\\c\""
        );
    }

    #[test]
    fn nested_object_and_array() {
        let v = obj(vec![
            ("a", Json::UInt(1)),
            ("b", arr(vec![Json::Bool(true), Json::Num(2.5)])),
        ]);
        assert_eq!(v.to_json_string(), "{\"a\":1,\"b\":[true,2.5]}");
    }
}
