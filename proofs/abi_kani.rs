use crate::runtime::{
    validate_sorted_schema_ids, RequiredSeen, RuntimeAbiError, RuntimeInline,
    RuntimeNamedResolution, RuntimeRejectNamed, RuntimeTypeMode,
};
use crate::view::{validate_abi_id_value, validate_sorted_query_ids};
use sacp_cbor::{CborError, ErrorCode};

fn assert_err<T>(actual: Result<T, CborError>, expected: ErrorCode) {
    match actual {
        Err(err) => assert!(err.code == expected),
        Ok(_) => unreachable!(),
    }
}

#[kani::proof]
fn abi_id_validator_accepts_exact_nonzero_u32_range() {
    let id: i64 = kani::any();
    let offset: usize = kani::any();
    let actual = validate_abi_id_value(id, offset);

    if id > 0 && id <= u32::MAX as i64 {
        let decoded = actual.unwrap();
        assert!(decoded != 0);
        assert!(i64::from(decoded) == id);
    } else {
        assert_err(actual, ErrorCode::InvalidAbiValue);
    }
}

#[kani::proof]
fn sorted_query_ids_accepts_exact_nonzero_singleton() {
    let id: u32 = kani::any();
    let offset: usize = kani::any();
    let ids = [id];
    let actual = validate_sorted_query_ids(&ids, offset);

    if id == 0 {
        assert_err(actual, ErrorCode::InvalidQuery);
    } else {
        assert!(actual.is_ok());
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn sorted_query_ids_accepts_exact_strict_nonzero_order_for_len3() {
    let ids = [kani::any::<u32>(), kani::any::<u32>(), kani::any::<u32>()];
    let offset: usize = kani::any();
    let actual = validate_sorted_query_ids(&ids, offset);
    let valid = ids[0] != 0 && ids[1] != 0 && ids[2] != 0 && ids[0] < ids[1] && ids[1] < ids[2];

    if valid {
        assert!(actual.is_ok());
    } else {
        assert_err(actual, ErrorCode::InvalidQuery);
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn runtime_schema_ids_accept_exact_strict_nonzero_order_for_len3() {
    let ids = [kani::any::<u32>(), kani::any::<u32>(), kani::any::<u32>()];
    let actual = validate_sorted_schema_ids(&ids);
    let valid = ids[0] != 0 && ids[1] != 0 && ids[2] != 0 && ids[0] < ids[1] && ids[1] < ids[2];

    if valid {
        assert!(actual.is_ok());
    } else {
        assert!(actual.is_err());
    }
}

#[kani::proof]
fn runtime_required_seen_small_bitset_tracks_len3_exactly() {
    let mark0: bool = kani::any();
    let mark1: bool = kani::any();
    let mark2: bool = kani::any();
    let mut seen = RequiredSeen::new(3).unwrap();

    if mark0 {
        seen.mark(0);
    }
    if mark1 {
        seen.mark(1);
    }
    if mark2 {
        seen.mark(2);
    }

    assert!(seen.all_seen(3) == (mark0 && mark1 && mark2));
}

#[kani::proof]
fn runtime_inline_named_policy_is_always_opaque() {
    let has_version: bool = kani::any();
    let version_value: u32 = kani::any();
    let version = has_version.then_some(version_value);

    let actual = RuntimeInline.resolve_named("runtime.Named", version);
    assert!(matches!(actual, Ok(RuntimeNamedResolution::Opaque)));
}

#[kani::proof]
fn runtime_reject_named_policy_always_rejects_named() {
    let has_version: bool = kani::any();
    let version_value: u32 = kani::any();
    let version = has_version.then_some(version_value);

    let actual = RuntimeRejectNamed.resolve_named("runtime.Named", version);
    assert!(matches!(actual, Err(RuntimeAbiError::UnresolvedNamedType)));
}
