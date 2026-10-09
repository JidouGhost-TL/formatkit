/// Decode parameters and selectors a sample file can't carry itself
/// (dimensions, an inner-artifact path, etc.), read from `spec.json`.
#[derive(Debug, Clone, Default)]
pub struct Args(pub serde_json::Map<String, serde_json::Value>);

impl Args {
    /// The raw JSON value for `k`, or `None` if it isn't present.
    pub fn get(&self, k: &str) -> Option<&serde_json::Value> {
        self.0.get(k)
    }

    /// `k` as a `u32` — the common decode-param case. `None` if absent or not
    /// representable as a `u32` (no silent truncation or type coercion).
    pub fn u32(&self, k: &str) -> Option<u32> {
        self.get(k)?.as_u64()?.try_into().ok()
    }

    /// `k` as a `&str` — the common selector case. `None` if absent or not a
    /// JSON string.
    pub fn str(&self, k: &str) -> Option<&str> {
        self.get(k)?.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::Args;
    use serde_json::json;

    fn args_from(pairs: &[(&str, serde_json::Value)]) -> Args {
        let mut map = serde_json::Map::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), v.clone());
        }
        Args(map)
    }

    #[test]
    fn get_returns_the_raw_value() {
        let a = args_from(&[("width", json!(640))]);
        assert_eq!(a.get("width"), Some(&json!(640)));
        assert_eq!(a.get("missing"), None);
    }

    #[test]
    fn u32_reads_a_json_number() {
        let a = args_from(&[("width", json!(640)), ("label", json!("x"))]);
        assert_eq!(a.u32("width"), Some(640));
        assert_eq!(a.u32("missing"), None);
        assert_eq!(a.u32("label"), None, "non-numeric value must not coerce");
    }

    #[test]
    fn str_reads_a_json_string() {
        let a = args_from(&[("inner", json!("selector")), ("width", json!(640))]);
        assert_eq!(a.str("inner"), Some("selector"));
        assert_eq!(a.str("missing"), None);
        assert_eq!(a.str("width"), None, "non-string value must not coerce");
    }

    #[test]
    fn default_is_empty() {
        let a = Args::default();
        assert_eq!(a.get("anything"), None);
    }
}
