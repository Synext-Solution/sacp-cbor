#![cfg(all(feature = "derive", feature = "edit"))]

use sacp_cbor::edit::{ArrayPos, DeleteMode, PatchValue, SetMode, Splice};
use sacp_cbor::query::PathElem;
use sacp_cbor::{cbor_bytes, encode_to_canonical, CborEncode, ErrorCode};

fn encoded<'a, T: CborEncode>(value: &T) -> PatchValue<'a> {
    PatchValue::Encoded(encode_to_canonical(value).unwrap())
}

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
            e.set(&[PathElem::Key("a")], SetMode::InsertOnly, encoded(&0i64))?;
            e.set(&[PathElem::Key("c")], SetMode::InsertOnly, encoded(&2i64))?;
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
            e.delete(&[PathElem::Key("sig")], DeleteMode::Require)?;
            e.set(
                &[PathElem::Key("meta"), PathElem::Key("ts")],
                SetMode::Upsert,
                encoded(&42i64),
            )?;
            e.set(
                &[PathElem::Key("meta"), PathElem::Key("kid")],
                SetMode::ReplaceOnly,
                encoded(&"new"),
            )?;
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
            e.set(&[PathElem::Key("a")], SetMode::Upsert, encoded(&2i64))?;
            e.delete(&[PathElem::Key("a")], DeleteMode::Require)?;
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
            e.set(&[PathElem::Index(1)], SetMode::ReplaceOnly, encoded(&10i64))?;
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
            e.set(&[PathElem::Index(3)], SetMode::ReplaceOnly, encoded(&0i64))?;
            Ok(())
        })
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::IndexOutOfBounds);
}

#[test]
fn edit_delete_removes_array_element() {
    let bytes = cbor_bytes!([1, 2, 3]).unwrap();
    let out = bytes
        .edit(|e| {
            e.delete(&[PathElem::Index(1)], DeleteMode::Require)?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!([1, 3]).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_splice_inserts_before_array_index() {
    let bytes = cbor_bytes!([1, 2, 3]).unwrap();
    let out = bytes
        .edit(|e| {
            e.splice(
                &[],
                Splice {
                    pos: ArrayPos::At(1),
                    delete: 0,
                    insert: vec![encoded(&9i64)],
                },
            )?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!([1, 9, 2, 3]).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_set_raw_reuses_value_bytes() {
    let bytes = cbor_bytes!({ a: [1, 2], b: 0 }).unwrap();
    let raw = bytes.at(&[PathElem::Key("a")]).unwrap().unwrap();
    let out = bytes
        .edit(|e| {
            e.set(&[PathElem::Key("b")], SetMode::Upsert, PatchValue::Raw(raw))?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!({ a: [1, 2], b: [1, 2] }).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_rejects_missing_nested_maps() {
    let bytes = cbor_bytes!({}).unwrap();
    let err = bytes
        .edit(|e| {
            e.set(
                &[PathElem::Key("a"), PathElem::Key("b")],
                SetMode::Upsert,
                encoded(&1i64),
            )?;
            Ok(())
        })
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::MissingKey);
}

#[test]
fn edit_encoded_builders_and_delete_if_present() {
    let bytes = cbor_bytes!({ arr: [], obj: { a: 1 } }).unwrap();
    let out = bytes
        .edit(|e| {
            e.splice(
                &[PathElem::Key("arr")],
                Splice {
                    pos: ArrayPos::End,
                    delete: 0,
                    insert: vec![PatchValue::Encoded(cbor_bytes!("x").unwrap())],
                },
            )?;
            e.set(
                &[PathElem::Key("obj"), PathElem::Key("b")],
                SetMode::Upsert,
                PatchValue::Encoded(cbor_bytes!([2]).unwrap()),
            )?;
            e.delete(
                &[PathElem::Key("obj"), PathElem::Key("missing")],
                DeleteMode::IfPresent,
            )?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!({ arr: ["x"], obj: { a: 1, b: [2] } }).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}

#[test]
fn edit_map_modes_report_missing_or_existing_keys() {
    let bytes = cbor_bytes!({ a: 1 }).unwrap();

    let err = bytes
        .edit(|e| {
            e.set(&[PathElem::Key("a")], SetMode::InsertOnly, encoded(&2i64))?;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidQuery);

    let err = bytes
        .edit(|e| {
            e.set(&[PathElem::Key("b")], SetMode::ReplaceOnly, encoded(&2i64))?;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MissingKey);

    let err = bytes
        .edit(|e| {
            e.delete(&[PathElem::Key("b")], DeleteMode::Require)?;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MissingKey);

    let out = bytes
        .edit(|e| {
            e.delete(&[PathElem::Key("b")], DeleteMode::IfPresent)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(out.as_bytes(), bytes.as_bytes());
}

#[test]
fn edit_splice_inserts_raw_and_encoded_values() {
    let bytes = cbor_bytes!([[1], 3]).unwrap();
    let raw = bytes.at(&[PathElem::Index(0)]).unwrap().unwrap();
    let out = bytes
        .edit(|e| {
            e.splice(
                &[],
                Splice {
                    pos: ArrayPos::At(1),
                    delete: 0,
                    insert: vec![
                        PatchValue::Raw(raw),
                        PatchValue::Encoded(cbor_bytes!("x").unwrap()),
                    ],
                },
            )?;
            Ok(())
        })
        .unwrap();

    let expected = cbor_bytes!([[1], [1], "x", 3]).unwrap();
    assert_eq!(out.as_bytes(), expected.as_bytes());
}
