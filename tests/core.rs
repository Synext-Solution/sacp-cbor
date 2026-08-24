#![cfg(all(feature = "alloc", feature = "collections"))]

use sacp_cbor::bytes::{Bytes, BytesRef};
use sacp_cbor::value::BigInt;
use sacp_cbor::{
    decode, decode_canonical, encode_to_canonical, encode_to_vec, DecodeLimits, ErrorCode,
};

#[test]
fn empty_array_counts_depth() {
    let bytes = [0x80u8];
    let mut limits = DecodeLimits::for_bytes(bytes.len());
    limits.max_depth = 0;
    let err = decode::<Vec<bool>>(&bytes, limits).unwrap_err();
    assert_eq!(err.code, ErrorCode::DepthLimitExceeded);
}

#[test]
fn u64_outside_safe_range_roundtrips_as_bignum() {
    let bytes = encode_to_vec(&u64::MAX).unwrap();
    assert_eq!(bytes[0], 0xc2);
    let decoded: u64 = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded, u64::MAX);
}

#[test]
fn bigint_roundtrip() {
    let big = BigInt::new(false, vec![0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
    let canon = encode_to_canonical(&big).unwrap();
    let decoded: BigInt = decode_canonical(
        canon.as_canonical_ref(),
        DecodeLimits::for_bytes(canon.as_bytes().len()),
    )
    .unwrap();
    assert_eq!(decoded, big);
}

#[test]
fn bytes_wrapper_is_byte_string_and_vec_u8_is_array() {
    let bytes = encode_to_vec(&BytesRef::new(&[1, 2])).unwrap();
    assert_eq!(bytes, [0x42, 1, 2]);

    let vec_bytes = encode_to_vec(&vec![1u8, 2]).unwrap();
    assert_eq!(vec_bytes, [0x82, 1, 2]);

    let decoded_vec: Vec<u8> =
        decode(&vec_bytes, DecodeLimits::for_bytes(vec_bytes.len())).unwrap();
    assert_eq!(decoded_vec, vec![1, 2]);

    let decoded_bytes: Bytes = decode(&bytes, DecodeLimits::for_bytes(bytes.len())).unwrap();
    assert_eq!(decoded_bytes.as_slice(), &[1, 2]);
}

#[test]
fn integer_ref_decodes_zero_copy_in_both_modes() {
    use sacp_cbor::query::IntegerRef;
    use sacp_cbor::{Decoder, ValidationOptions};

    let mut enc = sacp_cbor::Encoder::new();
    enc.array(4, |a| {
        a.int(42)?;
        a.int(-7)?;
        a.bignum(false, &[0x20, 0, 0, 0, 0, 0, 0])?; // 2^53
        a.bignum(true, &[0x20, 0, 0, 0, 0, 0, 0]) // -(2^53 + 1)
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish");
    let limits = DecodeLimits::for_bytes(bytes.len());
    let canon = sacp_cbor::CanonicalCbor::from_vec(bytes, limits).expect("canonical");
    let bytes = canon.as_bytes();

    let mut checked =
        Decoder::<true>::new_checked_with(bytes, limits, ValidationOptions::new()).expect("new");
    {
        let mut arr = checked.array().expect("array");
        assert_eq!(
            arr.next_value::<IntegerRef<'_>>()
                .expect("ok")
                .expect("some"),
            IntegerRef::Safe(42)
        );
        assert_eq!(
            arr.next_value::<IntegerRef<'_>>()
                .expect("ok")
                .expect("some"),
            IntegerRef::Safe(-7)
        );
        let big = arr
            .next_value::<IntegerRef<'_>>()
            .expect("ok")
            .expect("some")
            .as_bigint()
            .expect("bignum");
        assert!(!big.is_negative());
        assert_eq!(big.magnitude(), &[0x20, 0, 0, 0, 0, 0, 0]);
        let neg = arr
            .next_value::<IntegerRef<'_>>()
            .expect("ok")
            .expect("some")
            .as_bigint()
            .expect("bignum");
        assert!(neg.is_negative());
    }
    checked.finish().expect("witness");

    let mut trusted = Decoder::<false>::new_trusted(canon.as_canonical_ref(), limits).expect("new");
    let mut arr = trusted.array().expect("array");
    for _ in 0..4 {
        arr.next_value::<IntegerRef<'_>>()
            .expect("ok")
            .expect("some");
    }
}

#[test]
fn integer_ref_decode_rejects_non_integer() {
    use sacp_cbor::query::IntegerRef;
    use sacp_cbor::{CborDecode, Decoder, ValidationOptions};

    let mut enc = sacp_cbor::Encoder::new();
    enc.text("nope").expect("encode");
    let bytes = enc.finish().expect("finish");
    let limits = DecodeLimits::for_bytes(bytes.len());
    let canon = sacp_cbor::CanonicalCbor::from_vec(bytes, limits).expect("canonical");
    let bytes = canon.as_bytes();

    let mut checked =
        Decoder::<true>::new_checked_with(bytes, limits, ValidationOptions::new()).expect("new");
    let err = IntegerRef::decode(&mut checked).expect_err("not an integer");
    assert_eq!(err.code, ErrorCode::ExpectedInteger);
}

#[test]
fn scalar_funnels_consume_kind_checked_batches() {
    use sacp_cbor::{Decoder, ScalarKind, ValidationOptions};

    let mut enc = sacp_cbor::Encoder::new();
    enc.map(1, |m| {
        m.entry("v", |e| {
            e.array(3, |a| {
                a.int(1)?;
                a.int(-2)?;
                a.bignum(false, &[0x20, 0, 0, 0, 0, 0, 0])
            })
        })
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish");
    let limits = DecodeLimits::for_bytes(bytes.len());
    let canon = sacp_cbor::CanonicalCbor::from_vec(bytes, limits).expect("canonical");
    let bytes = canon.as_bytes();

    // Checked batch consume, then a full witness.
    let mut d =
        Decoder::<true>::new_checked_with(bytes, limits, ValidationOptions::new()).expect("new");
    {
        let mut m = d.map().expect("map");
        m.next_key_ref().expect("key").expect("some");
        m.decode_value_with(|d| {
            let mut a = d.array()?;
            a.skip_scalars(ScalarKind::Integer)
        })
        .expect("batch");
    }
    d.finish().expect("witness");

    // Trusted spans: each range is the element's complete encoding.
    let mut d = Decoder::<false>::new_trusted(canon.as_canonical_ref(), limits).expect("new");
    let mut m = d.map().expect("map");
    m.next_key_ref().expect("key").expect("some");
    m.decode_value_with(|d| {
        let mut a = d.array()?;
        let mut prev_end = 0usize;
        while let Some(span) = a.next_scalar_span(ScalarKind::Integer)? {
            assert!(span.start < span.end);
            assert!(span.start >= prev_end);
            prev_end = span.end;
        }
        Ok::<(), sacp_cbor::CborError>(())
    })
    .expect("spans");
}

#[test]
fn scalar_funnels_reject_kind_mismatch_and_restrictions() {
    use sacp_cbor::{Decoder, ScalarKind, ValidationOptions};

    // ["x"] consumed as integers must fail with ExpectedInteger and poison.
    let mut enc = sacp_cbor::Encoder::new();
    enc.array(1, |a| a.text("x")).expect("encode");
    let bytes = enc.finish().expect("finish");
    let bytes = bytes.as_slice();
    let limits = DecodeLimits::for_bytes(bytes.len());
    let mut d =
        Decoder::<true>::new_checked_with(bytes, limits, ValidationOptions::new()).expect("new");
    {
        let mut a = d.array().expect("array");
        let err = a.skip_scalars(ScalarKind::Integer).expect_err("mismatch");
        assert_eq!(err.code, ErrorCode::ExpectedInteger);
    }
    assert!(d.finish().is_err(), "mismatch poisons the pass");

    // [true] under no-simple mode fails inside the batch.
    let mut enc = sacp_cbor::Encoder::new();
    enc.array(1, |a| a.bool(true)).expect("encode");
    let bytes = enc.finish().expect("finish");
    let bytes = bytes.as_slice();
    let limits = DecodeLimits::for_bytes(bytes.len());
    let mut d =
        Decoder::<true>::new_checked_with(bytes, limits, ValidationOptions::new().no_simple())
            .expect("new");
    let mut a = d.array().expect("array");
    let err = a.skip_scalars(ScalarKind::Bool).expect_err("restricted");
    assert_eq!(err.code, ErrorCode::SimpleForbidden);
}

#[test]
fn scalar_funnel_rejects_non_canonical_element() {
    use sacp_cbor::{Decoder, ScalarKind, ValidationOptions};

    // 0x81 0x18 0x05: [5] with a non-minimal uint encoding.
    let bytes = [0x81, 0x18, 0x05];
    let limits = DecodeLimits::for_bytes(bytes.len());
    let mut d =
        Decoder::<true>::new_checked_with(&bytes, limits, ValidationOptions::new()).expect("new");
    let mut a = d.array().expect("array");
    let err = a
        .skip_scalars(ScalarKind::Integer)
        .expect_err("non-canonical");
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
}

#[test]
fn sorted_scalar_batches_enforce_memcmp_order() {
    use sacp_cbor::{Decoder, ScalarKind, ValidationOptions};

    let encode_bytes_array = |elems: &[&[u8]]| {
        let mut enc = sacp_cbor::Encoder::new();
        enc.array(elems.len(), |a| {
            for e in elems {
                a.bytes(e)?;
            }
            Ok(())
        })
        .expect("encode");
        enc.finish().expect("finish")
    };
    let run = |bytes: &[u8]| {
        let limits = DecodeLimits::for_bytes(bytes.len());
        let mut d = Decoder::<true>::new_checked_with(bytes, limits, ValidationOptions::new())
            .expect("new");
        let result = {
            let mut a = d.array().expect("array");
            a.skip_sorted_scalars(ScalarKind::Bytes)
        };
        result.map(|()| d.finish().map(|_| ()).expect("witness"))
    };

    run(&encode_bytes_array(&[b"a", b"b", b"cd"])).expect("ascending");

    let err = run(&encode_bytes_array(&[b"a", b"a"])).expect_err("duplicate");
    assert_eq!(err.code, ErrorCode::DuplicateElement);

    let err = run(&encode_bytes_array(&[b"b", b"a"])).expect_err("descending");
    assert_eq!(err.code, ErrorCode::NonAscendingElement);

    // Kind mismatch inside the sorted batch still reports Expected*.
    let mut enc = sacp_cbor::Encoder::new();
    enc.array(2, |a| {
        a.bytes(b"a")?;
        a.int(1)
    })
    .expect("encode");
    let bytes = enc.finish().expect("finish");
    let err = run(&bytes).expect_err("mismatch");
    assert_eq!(err.code, ErrorCode::ExpectedBytes);
}
