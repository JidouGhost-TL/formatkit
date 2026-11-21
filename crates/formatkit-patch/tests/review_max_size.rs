use formatkit_patch::ips::{create, ApplyOptions, Patch};
#[test]
fn creation_accepts_a_full_twenty_four_bit_address_space() {
    let base = vec![0; 0x1000000];
    let mut target = base.clone();
    target[0x100] = 7;
    let encoded =
        create(&base, &target).expect("16 MiB equal-size image has representable IPS records");
    let patch = Patch::parse(&encoded).unwrap();
    assert_eq!(patch.truncate_to, None);
    assert_eq!(patch.apply(&base, ApplyOptions::default()).unwrap(), target);
}
