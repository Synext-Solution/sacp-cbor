use sacp_cbor::{CanonicalCbor, DecodeLimits, Encoder, ErrorCode};
use sacp_cbor_abi::{
    compile_runtime_schema, encode_to_vec, AbiSchemaRegistry, AbiType, CborAbi, FieldDef,
    FieldPresence, FieldSetDef, RuntimeAbiError, RuntimeAbiOptions, RuntimeFieldSetSchema,
    RuntimeSchema, RuntimeTypeValidation, Schema, TypeDef, TypeRef, UnknownFieldPolicy,
};

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "runtime.Transfer", version = 1, unknown_fields = "preserve")]
struct Transfer {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
    #[abi(unknown_fields)]
    unknown: sacp_cbor_abi::UnknownFields,
}

fn field(id: u32, ty: TypeRef, presence: FieldPresence) -> FieldDef {
    FieldDef {
        id,
        name: format!("f{id}"),
        ty,
        presence,
    }
}

fn field_set(fields: Vec<FieldDef>, unknown_fields: UnknownFieldPolicy) -> FieldSetDef {
    FieldSetDef {
        fields,
        unknown_fields,
    }
}

fn compiled(
    fields: Vec<FieldDef>,
    unknown_fields: UnknownFieldPolicy,
) -> RuntimeFieldSetSchema<'static> {
    let def = Box::leak(Box::new(field_set(fields, unknown_fields)));
    RuntimeFieldSetSchema::compile(def).unwrap()
}

fn canon(bytes: &[u8]) -> CanonicalCbor {
    CanonicalCbor::from_slice(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap()
}

fn view_result(schema: &RuntimeFieldSetSchema<'_>, bytes: &[u8]) -> Result<(), RuntimeAbiError> {
    let canon = canon(bytes);
    schema
        .view_value(canon.as_canonical_ref().root())
        .map(|_| ())
}

fn validate_result(
    schema: &RuntimeFieldSetSchema<'_>,
    bytes: &[u8],
    options: &RuntimeAbiOptions<'_>,
) -> Result<(), RuntimeAbiError> {
    let canon = canon(bytes);
    schema
        .validate_value(canon.as_canonical_ref().root(), options)
        .map(|_| ())
}

fn assert_cbor_code(err: RuntimeAbiError, code: ErrorCode) {
    match err {
        RuntimeAbiError::Cbor(err) => assert_eq!(err.code, code),
        other => panic!("expected CBOR error {code:?}, got {other:?}"),
    }
}

fn inline_options() -> RuntimeAbiOptions<'static> {
    RuntimeAbiOptions {
        type_validation: RuntimeTypeValidation::InlineOnly,
        max_recursion_depth: 32,
    }
}

#[test]
fn compile_rejects_invalid_runtime_schema_ids() {
    let zero = field_set(
        vec![field(0, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    assert!(matches!(
        RuntimeFieldSetSchema::compile(&zero),
        Err(RuntimeAbiError::InvalidSchema { .. })
    ));

    let duplicate = field_set(
        vec![
            field(2, TypeRef::U64, FieldPresence::Required),
            field(1, TypeRef::Bool, FieldPresence::Optional),
            field(1, TypeRef::Text, FieldPresence::Required),
        ],
        UnknownFieldPolicy::Reject,
    );
    assert!(matches!(
        RuntimeFieldSetSchema::compile(&duplicate),
        Err(RuntimeAbiError::InvalidSchema { .. })
    ));
}

#[test]
fn view_rejects_invalid_wire_field_set_shell() {
    let schema = compiled(
        vec![
            field(1, TypeRef::U64, FieldPresence::Required),
            field(2, TypeRef::U64, FieldPresence::Optional),
        ],
        UnknownFieldPolicy::Reject,
    );

    assert_cbor_code(
        view_result(&schema, &[0x82, 0x00, 0x01]).unwrap_err(),
        ErrorCode::InvalidAbiValue,
    );
    assert_cbor_code(
        view_result(&schema, &[0x84, 0x01, 0x01, 0x01, 0x02]).unwrap_err(),
        ErrorCode::DuplicateMapKey,
    );
    assert_cbor_code(
        view_result(&schema, &[0x84, 0x02, 0x01, 0x01, 0x02]).unwrap_err(),
        ErrorCode::NonCanonicalMapOrder,
    );
    assert_cbor_code(
        view_result(&schema, &[0x81, 0x01]).unwrap_err(),
        ErrorCode::ArrayLenMismatch,
    );
}

#[test]
fn required_optional_and_unknown_policy_match_abi_rules() {
    let reject = compiled(
        vec![
            field(1, TypeRef::U64, FieldPresence::Required),
            field(3, TypeRef::Text, FieldPresence::Optional),
        ],
        UnknownFieldPolicy::Reject,
    );
    assert_cbor_code(
        view_result(&reject, &[0x80]).unwrap_err(),
        ErrorCode::MissingKey,
    );
    assert!(view_result(&reject, &[0x82, 0x01, 0x05]).is_ok());
    assert_cbor_code(
        view_result(&reject, &[0x84, 0x01, 0x05, 0x02, 0xf5]).unwrap_err(),
        ErrorCode::UnknownField,
    );

    let ignore = compiled(
        vec![field(1, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Ignore,
    );
    let ignored_cbor = canon(&[0x84, 0x01, 0x05, 0x02, 0xf5]);
    let ignored = ignore
        .view_value(ignored_cbor.as_canonical_ref().root())
        .unwrap();
    assert_eq!(ignored.unknown_fields().unwrap().count(), 0);

    let preserve = compiled(
        vec![field(1, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Preserve,
    );
    let preserve_cbor = canon(&[0x84, 0x01, 0x05, 0x02, 0xf5]);
    let view = preserve
        .view_value(preserve_cbor.as_canonical_ref().root())
        .unwrap();
    let unknown: Vec<_> = view.unknown_fields().unwrap().map(Result::unwrap).collect();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].id, 2);
    assert_eq!(unknown[0].value.as_bytes(), &[0xf5]);
}

#[test]
fn primitive_and_fixed_bytes_validation_is_exact() {
    let u8_schema = compiled(
        vec![field(1, TypeRef::U8, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    assert!(u8_schema
        .validate_value(
            canon(&[0x82, 0x01, 0x18, 0xff]).as_canonical_ref().root(),
            &inline_options(),
        )
        .is_ok());
    assert_cbor_code(
        validate_result(
            &u8_schema,
            &[0x82, 0x01, 0x19, 0x01, 0x00],
            &inline_options(),
        )
        .unwrap_err(),
        ErrorCode::ExpectedInteger,
    );

    let fixed = compiled(
        vec![field(
            1,
            TypeRef::FixedBytes { len: 2 },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    assert!(fixed
        .validate_value(
            canon(&[0x82, 0x01, 0x42, 0xaa, 0xbb])
                .as_canonical_ref()
                .root(),
            &inline_options(),
        )
        .is_ok());
    assert_cbor_code(
        validate_result(&fixed, &[0x82, 0x01, 0x41, 0xaa], &inline_options()).unwrap_err(),
        ErrorCode::ExpectedBytes,
    );
}

#[test]
fn vector_items_are_validated_only_when_deep_validation_is_requested() {
    let schema = compiled(
        vec![field(
            1,
            TypeRef::Vec {
                item: Box::new(TypeRef::U8),
            },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    let bytes = [0x82, 0x01, 0x82, 0x01, 0x19, 0x01, 0x00];

    assert!(view_result(&schema, &bytes).is_ok());
    assert_cbor_code(
        validate_result(&schema, &bytes, &inline_options()).unwrap_err(),
        ErrorCode::ExpectedInteger,
    );
}

#[test]
fn get_checked_validates_one_selected_field() {
    let schema = compiled(
        vec![
            field(1, TypeRef::U8, FieldPresence::Required),
            field(2, TypeRef::Text, FieldPresence::Required),
        ],
        UnknownFieldPolicy::Reject,
    );
    let cbor = canon(&[0x84, 0x01, 0x19, 0x01, 0x00, 0x02, 0x62, b'o', b'k']);
    let view = schema.view_value(cbor.as_canonical_ref().root()).unwrap();

    assert_eq!(
        view.get_checked(2, &inline_options())
            .unwrap()
            .unwrap()
            .text()
            .unwrap(),
        "ok"
    );
    assert_cbor_code(
        view.get_checked(1, &inline_options()).unwrap_err(),
        ErrorCode::ExpectedInteger,
    );
}

#[test]
fn get_many_raw_sorted_into_reads_selected_fields_in_one_query() {
    let schema = compiled(
        vec![
            field(1, TypeRef::U8, FieldPresence::Required),
            field(2, TypeRef::Text, FieldPresence::Required),
            field(3, TypeRef::Bool, FieldPresence::Optional),
        ],
        UnknownFieldPolicy::Reject,
    );
    let cbor = canon(&[0x86, 0x01, 0x05, 0x02, 0x62, b'o', b'k', 0x03, 0xf5]);
    let view = schema.view_value(cbor.as_canonical_ref().root()).unwrap();
    let mut out = [None; 3];

    view.get_many_raw_sorted_into(&[1, 2, 3], &mut out).unwrap();

    assert_eq!(out[0].unwrap().integer().unwrap().as_u128(), Some(5));
    assert_eq!(out[1].unwrap().text().unwrap(), "ok");
    assert!(out[2].unwrap().bool().unwrap());

    let err = view
        .get_many_raw_sorted_into(&[2, 1], &mut out[..2])
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidQuery);
}

struct Registry {
    child: Schema,
}

impl AbiSchemaRegistry for Registry {
    fn resolve(&self, type_id: &str, version: Option<u32>) -> Option<&Schema> {
        if type_id == self.child.type_id && version == Some(self.child.version) {
            Some(&self.child)
        } else {
            None
        }
    }
}

#[test]
fn named_types_are_opaque_rejected_or_resolved_by_policy() {
    let root_schema = compiled(
        vec![field(
            1,
            TypeRef::Named {
                type_id: "runtime.Child".to_string(),
                version: Some(1),
            },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    let child = Schema::new(
        "runtime.Child",
        1,
        TypeDef::Struct(field_set(
            vec![field(1, TypeRef::U8, FieldPresence::Required)],
            UnknownFieldPolicy::Reject,
        )),
    );
    let registry = Registry { child };
    let bad_child = [0x82, 0x01, 0x82, 0x01, 0x19, 0x01, 0x00];

    assert!(root_schema
        .validate_value(
            canon(&bad_child).as_canonical_ref().root(),
            &inline_options()
        )
        .is_ok());

    let reject_options = RuntimeAbiOptions {
        type_validation: RuntimeTypeValidation::RejectNamed,
        max_recursion_depth: 32,
    };
    assert_eq!(
        validate_result(&root_schema, &bad_child, &reject_options).unwrap_err(),
        RuntimeAbiError::UnresolvedNamedType
    );

    let resolve_options = RuntimeAbiOptions {
        type_validation: RuntimeTypeValidation::ResolveNamed(&registry),
        max_recursion_depth: 32,
    };
    assert_cbor_code(
        validate_result(&root_schema, &bad_child, &resolve_options).unwrap_err(),
        ErrorCode::ExpectedInteger,
    );

    let good_child = [0x82, 0x01, 0x82, 0x01, 0x05];
    assert!(validate_result(&root_schema, &good_child, &resolve_options).is_ok());
}

#[test]
fn named_recursion_honors_depth_limit() {
    let root_schema = compiled(
        vec![field(
            1,
            TypeRef::Named {
                type_id: "runtime.Child".to_string(),
                version: Some(1),
            },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    let child = Schema::new(
        "runtime.Child",
        1,
        TypeDef::Struct(field_set(
            vec![field(1, TypeRef::U8, FieldPresence::Required)],
            UnknownFieldPolicy::Reject,
        )),
    );
    let registry = Registry { child };
    let options = RuntimeAbiOptions {
        type_validation: RuntimeTypeValidation::ResolveNamed(&registry),
        max_recursion_depth: 0,
    };

    assert_eq!(
        validate_result(&root_schema, &[0x82, 0x01, 0x82, 0x01, 0x05], &options).unwrap_err(),
        RuntimeAbiError::RecursionLimit
    );
}

#[test]
fn runtime_accepts_derived_abi_and_raw_reencode_is_identical() {
    let value = Transfer {
        from: 1,
        to: 2,
        amount: 50,
        memo: None,
        unknown: sacp_cbor_abi::UnknownFields::empty(),
    };
    let bytes = encode_to_vec(&value).unwrap();
    let schema = Transfer::schema();
    let RuntimeSchema::Struct(compiled) = compile_runtime_schema(&schema).unwrap();
    let canon = canon(&bytes);
    let view = compiled
        .validate_value(canon.as_canonical_ref().root(), &inline_options())
        .unwrap();

    assert_eq!(
        view.require_raw(3).unwrap().integer().unwrap().as_u128(),
        Some(50)
    );

    let mut enc = Encoder::new();
    enc.raw_value_ref(view.raw_value()).unwrap();
    let encoded = enc.finish().unwrap();
    assert_eq!(encoded.as_bytes(), bytes.as_slice());
}

#[test]
fn compile_runtime_schema_rejects_non_struct_roots_in_v1() {
    let schema = Schema::new(
        "runtime.Primitive",
        1,
        TypeDef::Primitive { ty: TypeRef::U64 },
    );
    assert_eq!(
        compile_runtime_schema(&schema).unwrap_err(),
        RuntimeAbiError::UnsupportedRoot
    );
}
