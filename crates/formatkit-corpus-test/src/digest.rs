use crate::Args;

/// One format's canonical, deterministic, provenance-clean digest.
///
/// Captures salient parsed fields plus content hashes of decoded output —
/// everything a golden comparison needs, nothing source-identifying. Takes
/// `&self` so a handler can be a unit struct registered as `Box<dyn Digest>`
/// in a [`Registry`](crate::Registry).
pub trait Digest {
    fn digest(&self, bytes: &[u8], args: &Args) -> formatkit_core::Result<serde_json::Value>;
}

#[cfg(test)]
mod tests {
    use super::Digest;
    use crate::Args;
    use serde_json::json;

    struct Len;

    impl Digest for Len {
        fn digest(&self, bytes: &[u8], _args: &Args) -> formatkit_core::Result<serde_json::Value> {
            Ok(json!({ "len": bytes.len() }))
        }
    }

    #[test]
    fn a_unit_struct_can_implement_digest() {
        let d = Len;
        let got = d.digest(b"abcd", &Args::default()).unwrap();
        assert_eq!(got, json!({ "len": 4 }));
    }

    #[test]
    fn digest_can_be_boxed_as_a_trait_object() {
        let boxed: Box<dyn Digest> = Box::new(Len);
        let got = boxed.digest(b"abc", &Args::default()).unwrap();
        assert_eq!(got, json!({ "len": 3 }));
    }
}
