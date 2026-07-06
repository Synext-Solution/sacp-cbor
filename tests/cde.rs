#![cfg(feature = "cde")]

use sacp_cbor::cde::{from_cde, to_cde};
use sacp_cbor::{validate_canonical, DecodeLimits, ErrorCode};

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "odd hex length: {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn limits() -> DecodeLimits {
    DecodeLimits::for_bytes(1 << 16)
}

fn vectors() -> Vec<(char, Vec<u8>, Vec<u8>)> {
    include_str!("fixtures/cde_vectors.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut parts = line.split_whitespace();
            let flag = parts.next().expect("flag").chars().next().expect("flag");
            let sacp = hex_to_bytes(parts.next().expect("sacp column"));
            let cde = hex_to_bytes(parts.next().expect("cde column"));
            assert!(parts.next().is_none(), "extra column: {line}");
            (flag, sacp, cde)
        })
        .collect()
}

#[test]
fn to_cde_matches_frozen_vectors() {
    for (_, sacp, cde) in vectors() {
        let item = validate_canonical(&sacp, limits()).expect("sacp column is canonical");
        assert_eq!(to_cde(item).expect("to_cde is total"), cde);
    }
}

#[test]
fn from_cde_matches_frozen_vectors() {
    for (_, sacp, cde) in vectors() {
        let converted = from_cde(&cde, limits()).expect("cde column is accepted");
        assert_eq!(converted.as_bytes(), sacp.as_slice());
    }
}

#[test]
fn bridge_directions_are_mutually_inverse_on_vectors() {
    for (_, sacp, cde) in vectors() {
        let item = validate_canonical(&sacp, limits()).expect("canonical");
        let image = to_cde(item).expect("total");
        assert_eq!(
            from_cde(&image, limits()).expect("inverse").as_bytes(),
            sacp
        );
        let back = from_cde(&cde, limits()).expect("accepted");
        assert_eq!(to_cde(back.as_canonical_ref()).expect("total"), cde);
    }
}

#[test]
fn to_cde_never_grows_the_item() {
    for (_, sacp, cde) in vectors() {
        assert!(cde.len() <= sacp.len(), "cde image longer than sacp item");
    }
}

fn from_cde_err(hex: &str) -> ErrorCode {
    from_cde(&hex_to_bytes(hex), limits())
        .expect_err("must reject")
        .code
}

#[test]
fn from_cde_rejects_band_integers_spelled_as_bignums() {
    // 1, 2^53, and 2^64 - 1 as tag-2 bignums: all fit a 64-bit head, so CDE
    // requires head form regardless of the SACP safe bound.
    assert_eq!(from_cde_err("c24101"), ErrorCode::NonCanonicalEncoding);
    assert_eq!(
        from_cde_err("c24820000000000000ff"),
        ErrorCode::NonCanonicalEncoding
    );
    assert_eq!(
        from_cde_err("c348ffffffffffffffff"),
        ErrorCode::NonCanonicalEncoding
    );
}

#[test]
fn from_cde_rejects_malformed_bignums() {
    // Leading zero in a nine-byte magnitude, and an empty magnitude.
    assert_eq!(
        from_cde_err("c24900010000000000000000"),
        ErrorCode::BignumNotCanonical
    );
    assert_eq!(from_cde_err("c240"), ErrorCode::BignumNotCanonical);
    // A tag payload that is not a byte string.
    assert_eq!(from_cde_err("c26161"), ErrorCode::ForbiddenOrMalformedTag);
}

#[test]
fn from_cde_rejects_foreign_tags_and_simples() {
    assert_eq!(from_cde_err("c001"), ErrorCode::ForbiddenOrMalformedTag);
    assert_eq!(
        from_cde_err("d81843010203"),
        ErrorCode::ForbiddenOrMalformedTag
    );
    assert_eq!(from_cde_err("f7"), ErrorCode::UnsupportedSimpleValue);
    assert_eq!(from_cde_err("f820"), ErrorCode::UnsupportedSimpleValue);
}

#[test]
fn from_cde_rejects_non_preferred_floats() {
    // Any NaN spelling other than 0xf97e00.
    assert_eq!(from_cde_err("f97e01"), ErrorCode::NonCanonicalNaN);
    assert_eq!(from_cde_err("fa7fc00000"), ErrorCode::NonCanonicalNaN);
    assert_eq!(
        from_cde_err("fb7ff8000000000000"),
        ErrorCode::NonCanonicalNaN
    );
    // Negative zero at every width.
    assert_eq!(from_cde_err("f98000"), ErrorCode::NegativeZeroForbidden);
    assert_eq!(from_cde_err("fa80000000"), ErrorCode::NegativeZeroForbidden);
    assert_eq!(
        from_cde_err("fb8000000000000000"),
        ErrorCode::NegativeZeroForbidden
    );
    // Wider spellings of float16/float32-exact values.
    assert_eq!(from_cde_err("fa3fc00000"), ErrorCode::NonCanonicalEncoding);
    assert_eq!(
        from_cde_err("fb3ff8000000000000"),
        ErrorCode::NonCanonicalEncoding
    );
    assert_eq!(
        from_cde_err("fb40f86a0000000000"),
        ErrorCode::NonCanonicalEncoding
    );
}

#[test]
fn from_cde_rejects_structural_defects() {
    assert_eq!(from_cde_err("1800"), ErrorCode::NonCanonicalEncoding);
    assert_eq!(from_cde_err("9f01ff"), ErrorCode::IndefiniteLengthForbidden);
    assert_eq!(from_cde_err("0001"), ErrorCode::TrailingBytes);
    assert_eq!(from_cde_err("82"), ErrorCode::UnexpectedEof);
    assert_eq!(from_cde_err(""), ErrorCode::UnexpectedEof);
    assert_eq!(from_cde_err("1c"), ErrorCode::ReservedAdditionalInfo);
    assert_eq!(from_cde_err("ff"), ErrorCode::ReservedAdditionalInfo);
}

#[test]
fn from_cde_defers_map_rules_to_the_canonical_pass() {
    // Non-text keys and unordered keys are CDE-legal shapes SACP-CBOR/1
    // rejects; the second pass reports them (offsets in the converted image).
    assert_eq!(from_cde_err("a10102"), ErrorCode::MapKeyMustBeText);
    assert_eq!(
        from_cde_err("a2616201616102"),
        ErrorCode::NonCanonicalMapOrder
    );
    assert_eq!(from_cde_err("a26161016161f4"), ErrorCode::DuplicateMapKey);
}

#[test]
fn from_cde_enforces_depth_and_size_limits() {
    let mut deep = vec![0x81u8; 200];
    deep.push(0x01);
    let mut small = DecodeLimits::for_bytes(1 << 16);
    small.max_depth = 8;
    assert_eq!(
        from_cde(&deep, small).expect_err("too deep").code,
        ErrorCode::DepthLimitExceeded
    );
    let tiny = DecodeLimits::for_bytes(4);
    assert_eq!(
        from_cde(&[0x45, 1, 2, 3, 4, 5], tiny)
            .expect_err("too large")
            .code,
        ErrorCode::MessageLenLimitExceeded
    );
}

#[test]
fn band_integers_reorder_inside_a_transcoded_container() {
    // The array [2^53, -5] keeps its order across the bridge (arrays are
    // semantic order); a sorted-set convention over encoded bytes would order
    // the two elements differently per profile, which is exactly why set
    // re-canonicalization is a schema-layer duty, not a bridge duty.
    let sacp = hex_to_bytes("82c2472000000000000024");
    let cde = hex_to_bytes("821b002000000000000024");
    let item = validate_canonical(&sacp, limits()).expect("canonical");
    assert_eq!(to_cde(item).expect("total"), cde);
    // Under SACP octet order the tagged 2^53 (0xc2...) sorts after -5 (0x24);
    // under CDE octet order the head form (0x1b...) sorts before it.
    assert!(sacp[1] > sacp[10], "sacp order: band integer sorts last");
    assert!(cde[1] < cde[10], "cde order: band integer sorts first");
}
