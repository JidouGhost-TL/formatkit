use formatkit_patch::ips::{create, ApplyOptions, GrowthPolicy, Patch};
#[test]
fn ips_growth_emits_zero_padding_records_without_eof_size() {
    let base = [0x11; 16];
    let mut target = base.to_vec();
    target[3] = 0x22;
    target.resize(32, 0);
    let encoded = create(&base, &target).unwrap();
    let patch = Patch::parse(&encoded).unwrap();
    assert_eq!(patch.truncate_to, None, "EOF size is truncate-only");
    assert_eq!(
        patch
            .apply(
                &base,
                ApplyOptions {
                    growth: GrowthPolicy::ZeroFill,
                    ..ApplyOptions::default()
                }
            )
            .unwrap(),
        target
    );
}
