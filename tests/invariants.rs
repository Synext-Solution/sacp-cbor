#![cfg(all(feature = "derive", feature = "edit"))]

use sacp_cbor::edit::{ArrayPos, PatchValue, Splice};
use sacp_cbor::{cbor_bytes, ErrorCode};

#[test]
fn splice_insert_inside_delete_conflicts() {
    let bytes = sacp_cbor::cbor_bytes!([0, 1, 2, 3]).unwrap();
    let mut editor = bytes.editor();
    editor
        .splice(
            &[],
            Splice {
                pos: ArrayPos::At(1),
                delete: 2,
                insert: Vec::new(),
            },
        )
        .unwrap();

    let err = editor
        .splice(
            &[],
            Splice {
                pos: ArrayPos::At(2),
                delete: 0,
                insert: vec![PatchValue::Encoded(cbor_bytes!(9).unwrap())],
            },
        )
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::PatchConflict);
}

#[test]
fn splice_end_and_at_len_conflict_on_apply() {
    let bytes = sacp_cbor::cbor_bytes!([0, 1]).unwrap();
    let mut editor = bytes.editor();
    editor
        .splice(
            &[],
            Splice {
                pos: ArrayPos::At(2),
                delete: 0,
                insert: vec![PatchValue::Encoded(cbor_bytes!(9).unwrap())],
            },
        )
        .unwrap();
    editor
        .splice(
            &[],
            Splice {
                pos: ArrayPos::End,
                delete: 0,
                insert: vec![PatchValue::Encoded(cbor_bytes!(8).unwrap())],
            },
        )
        .unwrap();

    let err = editor.apply().unwrap_err();
    assert_eq!(err.code, ErrorCode::PatchConflict);
}

#[test]
fn duplicate_end_splices_are_rejected() {
    let bytes = sacp_cbor::cbor_bytes!([0, 1]).unwrap();
    let mut editor = bytes.editor();
    editor
        .splice(
            &[],
            Splice {
                pos: ArrayPos::End,
                delete: 0,
                insert: vec![PatchValue::Encoded(cbor_bytes!(9).unwrap())],
            },
        )
        .unwrap();

    let err = editor
        .splice(
            &[],
            Splice {
                pos: ArrayPos::End,
                delete: 0,
                insert: vec![PatchValue::Encoded(cbor_bytes!(8).unwrap())],
            },
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::PatchConflict);
}
