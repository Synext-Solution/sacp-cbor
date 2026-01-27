#![cfg(feature = "alloc")]

use sacp_cbor::{cbor_bytes, path, ErrorCode};

#[test]
fn edit_noop_preserves_bytes() {
    let bytes = cbor_bytes!({ a: 1, b: [true, null] }).unwrap();
    let out = bytes.edit(|_e| Ok(())).unwrap();
    assert_eq!(out.as_bytes(), bytes.as_bytes());
}

#[test]
fn edit_inserts_respect_canonical_order() {
    let bytes = cbor_bytes!({ b: 1 }).unwrap();
    let out = bytes
        .edit(|e| {
            e.insert(path!["a"], 0i64)?;
            e.insert(path!["c"], 2i64)?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!({ a: 0, b: 1, c: 2 }).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_nested_update_and_delete() {
    let bytes = cbor_bytes!({ sig: b"sig", meta: { ts: 1, kid: "old" } }).unwrap();
    let out = bytes
        .edit(|e| {
            e.delete(path!["sig"])?;
            e.set(path!["meta", "ts"], 42i64)?;
            e.replace(path!["meta", "kid"], "new")?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!({ meta: { ts: 42, kid: "new" } }).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_conflicts_are_rejected() {
    let bytes = cbor_bytes!({ a: 1 }).unwrap();
    let err = bytes
        .edit(|e| {
            e.set(path!["a"], 2i64)?;
            e.delete(path!["a"])?;
            Ok(())
        })
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::PatchConflict);
}

#[test]
fn edit_array_index_replacement() {
    let bytes = cbor_bytes!([1, 2, 3]).unwrap();
    let out = bytes
        .edit(|e| {
            e.set(path![1], 10i64)?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!([1, 10, 3]).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_array_index_out_of_bounds() {
    let bytes = cbor_bytes!([1, 2, 3]).unwrap();
    let err = bytes
        .edit(|e| {
            e.set(path![3], 0i64)?;
            Ok(())
        })
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::IndexOutOfBounds);
}

#[test]
fn edit_array_delete_removes_element() {
    let bytes = cbor_bytes!([1, 2, 3]).unwrap();
    let out = bytes
        .edit(|e| {
            e.delete(path![1])?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!([1, 3]).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_array_insert_before_index() {
    let bytes = cbor_bytes!([1, 2, 3]).unwrap();
    let out = bytes
        .edit(|e| {
            e.insert(path![1], 9i64)?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!([1, 9, 2, 3]).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_set_raw_reuses_value_bytes() {
    let bytes = cbor_bytes!({ a: [1, 2], b: 0 }).unwrap();
    let raw = bytes.at(path!["a"]).unwrap().unwrap();
    let out = bytes
        .edit(|e| {
            e.set_raw(path!["b"], raw)?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!({ a: [1, 2], b: [1, 2] }).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_can_create_missing_maps_when_enabled() {
    let bytes = cbor_bytes!({}).unwrap();
    let out = bytes
        .edit(|e| {
            e.options_mut().create_missing_maps = true;
            e.set(path!["a", "b"], 1i64)?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!({ a: { b: 1 } }).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}
