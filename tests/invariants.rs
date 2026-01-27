#![cfg(feature = "alloc")]

use sacp_cbor::{ArrayPos, EncodedTextKey, Encoder, ErrorCode};

#[test]
fn encoded_text_key_parse_rejects_non_text() {
    let err = EncodedTextKey::parse(&[0x01]).unwrap_err();
    assert_eq!(err.code, ErrorCode::MapKeyMustBeText);
}

#[test]
fn encoded_text_key_parse_rejects_noncanonical() {
    let err = EncodedTextKey::parse(&[0x78, 0x01, b'a']).unwrap_err();
    assert_eq!(err.code, ErrorCode::NonCanonicalEncoding);
}

#[test]
fn map_encoder_entry_raw_key_accepts_valid_key() {
    let key = EncodedTextKey::parse(&[0x61, b'a']).unwrap();
    let mut enc = Encoder::new();
    enc.map(1, |m| m.entry_raw_key(key, |e| e.null())).unwrap();
    let bytes = enc.into_canonical().unwrap();
    assert_eq!(bytes.as_bytes(), &[0xa1, 0x61, b'a', 0xf6]);
}

#[test]
fn splice_insert_inside_delete_conflicts() {
    let bytes = sacp_cbor::cbor_bytes!([0, 1, 2, 3]).unwrap();
    let mut editor = bytes.editor();
    editor
        .splice(&[], ArrayPos::At(1), 2)
        .unwrap()
        .finish()
        .unwrap();

    let err = editor
        .splice(&[], ArrayPos::At(2), 0)
        .unwrap()
        .insert(9i64)
        .unwrap()
        .finish()
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::PatchConflict);
}

#[test]
fn splice_end_and_at_len_conflict_on_apply() {
    let bytes = sacp_cbor::cbor_bytes!([0, 1]).unwrap();
    let mut editor = bytes.editor();
    editor
        .splice(&[], ArrayPos::At(2), 0)
        .unwrap()
        .insert(9i64)
        .unwrap()
        .finish()
        .unwrap();
    editor
        .splice(&[], ArrayPos::End, 0)
        .unwrap()
        .insert(8i64)
        .unwrap()
        .finish()
        .unwrap();

    let err = editor.apply().unwrap_err();
    assert_eq!(err.code, ErrorCode::PatchConflict);
}
