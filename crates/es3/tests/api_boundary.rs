#[test]
fn transform_public_type_is_reexported_from_crate_root() {
    let parsed = "base64"
        .parse::<es3::Transform>()
        .expect("public Transform re-export works");

    assert_eq!(parsed.as_str(), "base64");
}
