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
