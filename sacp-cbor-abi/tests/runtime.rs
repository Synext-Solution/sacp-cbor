use core::alloc::{GlobalAlloc, Layout};
use sacp_cbor::{CanonicalCbor, CountingSink, DecodeLimits, Encoder, ErrorCode};
use sacp_cbor_abi::{
    compile_runtime_schema, encode_to_vec, AbiEncode, AbiSchemaRegistry, CborAbi, EnumDef,
    FieldDef, FieldPresence, FieldSetDef, NoNamedSchemas, RuntimeAbiError, RuntimeFieldSetSchema,
    RuntimeSchema, RuntimeValidationLimits, RuntimeValidationWorkspace, Schema, TypeDef, TypeRef,
    UnknownFieldPolicy, UnknownVariantPolicy, VariantDef,
};
use std::alloc::System;
use std::cell::Cell;

thread_local! {
    static FAIL_NEXT_ALLOCATION: Cell<bool> = const { Cell::new(false) };
}

struct TestAllocator;

// SAFETY: every operation delegates to `System`; `alloc` and `realloc` may additionally
// return null, which is permitted by the `GlobalAlloc` contract and is consumed exactly
// once per thread.
unsafe impl GlobalAlloc for TestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false)) {
            core::ptr::null_mut()
        } else {
            // SAFETY: the layout is forwarded unchanged to the system allocator.
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout came from the system allocator.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false)) {
            core::ptr::null_mut()
        } else {
            // SAFETY: the pointer and layout came from the system allocator.
            unsafe { System.realloc(pointer, layout, new_size) }
        }
    }
}

#[global_allocator]
static ALLOCATOR: TestAllocator = TestAllocator;

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "runtime.Transfer", version = 1, unknown_fields = "preserve")]
struct Transfer {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
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
    RuntimeFieldSetSchema::compile(Box::leak(Box::new(field_set(fields, unknown_fields)))).unwrap()
}

fn canon(bytes: &[u8]) -> CanonicalCbor {
    CanonicalCbor::from_slice(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap()
}

fn assert_cbor_code(err: RuntimeAbiError, rule: ErrorCode) {
    match err {
        RuntimeAbiError::Cbor(err) => assert_eq!(err.code, rule, "rejection rule {rule:?}"),
        other => panic!("expected rejection rule {rule:?}, got {other:?}"),
    }
}

fn runtime_limits() -> RuntimeValidationLimits {
    RuntimeValidationLimits::new(64, 100_000, 100_000, 100_000)
}

#[test]
fn prepared_runtime_validation_does_not_allocate_to_find_deep_value_boundaries() {
    let schema = compiled(
        vec![field(1, TypeRef::CanonicalCbor, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    let mut bytes = vec![0x82, 0x01];
    bytes.extend(core::iter::repeat_n(0x81, 40));
    bytes.push(0xf6);
    let canonical = canon(&bytes);
    let limits = runtime_limits();
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();

    FAIL_NEXT_ALLOCATION.with(|flag| flag.set(true));
    let result = schema.validate_value(canonical.root(), &NoNamedSchemas, limits, &mut workspace);
    FAIL_NEXT_ALLOCATION.with(|flag| flag.set(false));

    result.expect("prepared runtime validation must not allocate while locating values");
}

fn validate_fields<'a, 's, R: AbiSchemaRegistry<'s>>(
    schema: &'s RuntimeFieldSetSchema<'s>,
    value: sacp_cbor::query::CborValueRef<'a>,
    registry: &'s R,
) -> Result<sacp_cbor_abi::RuntimeFieldSetView<'a, 's>, RuntimeAbiError> {
    let limits = runtime_limits();
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits)?;
    schema.validate_value(value, registry, limits, &mut workspace)
}

fn validate_enum<'a, 's, R: AbiSchemaRegistry<'s>>(
    schema: &'s sacp_cbor_abi::RuntimeEnumSchema<'s>,
    value: sacp_cbor::query::CborValueRef<'a>,
    registry: &'s R,
) -> Result<sacp_cbor_abi::RuntimeEnumView<'a, 's>, RuntimeAbiError> {
    let limits = runtime_limits();
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits)?;
    schema.validate_value(value, registry, limits, &mut workspace)
}

#[test]
fn derived_abi_encodes_directly_to_a_generic_counting_sink() {
    let value = Transfer {
        from: 1,
        to: 2,
        amount: 3,
        unknown: Default::default(),
    };
    let expected = encode_to_vec(&value).unwrap();
    let mut encoder = Encoder::with_sink(CountingSink::new());
    encoder
        .encode_with(|enc| AbiEncode::abi_encode(&value, enc))
        .unwrap();
    assert_eq!(encoder.finish().unwrap(), expected.len());
}

#[test]
fn runtime_field_schema_rejects_zero_and_duplicate_id_rules() {
    let zero = field_set(
        vec![field(0, TypeRef::U64, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    assert!(matches!(
        RuntimeFieldSetSchema::compile(&zero),
        Err(RuntimeAbiError::InvalidSchema {
            reason: "field ID must be nonzero"
        })
    ));
    let duplicate = field_set(
        vec![
            field(1, TypeRef::Bool, FieldPresence::Optional),
            field(1, TypeRef::Text, FieldPresence::Required),
        ],
        UnknownFieldPolicy::Reject,
    );
    assert!(matches!(
        RuntimeFieldSetSchema::compile(&duplicate),
        Err(RuntimeAbiError::InvalidSchema {
            reason: "duplicate field ID"
        })
    ));
}

#[test]
fn runtime_field_shell_enforces_order_required_and_unknown_rules() {
    let schema = compiled(
        vec![
            field(1, TypeRef::U64, FieldPresence::Required),
            field(2, TypeRef::Bool, FieldPresence::Optional),
        ],
        UnknownFieldPolicy::Reject,
    );
    for (bytes, rule) in [
        (&[0x82, 0x00, 0x01][..], ErrorCode::InvalidAbiValue),
        (&[0x82, 0x02, 0xf5][..], ErrorCode::MissingKey),
        (&[0x84, 0x01, 0x01, 0x03, 0xf5][..], ErrorCode::UnknownField),
    ] {
        assert_cbor_code(
            schema
                .view_value(canon(bytes).as_canonical_ref().root())
                .unwrap_err(),
            rule,
        );
    }
}

#[test]
fn deep_runtime_validation_covers_primitives_vectors_and_fixed_bytes() {
    let schema = compiled(
        vec![
            field(1, TypeRef::U8, FieldPresence::Required),
            field(
                2,
                TypeRef::Vec {
                    item: Box::new(TypeRef::Bool),
                },
                FieldPresence::Required,
            ),
            field(3, TypeRef::FixedBytes { len: 2 }, FieldPresence::Required),
        ],
        UnknownFieldPolicy::Reject,
    );
    let valid = canon(&[
        0x86, 0x01, 0x18, 0xff, 0x02, 0x82, 0xf4, 0xf5, 0x03, 0x42, 1, 2,
    ]);
    validate_fields(&schema, valid.as_canonical_ref().root(), &NoNamedSchemas).unwrap();
    let wrong_item = canon(&[0x86, 0x01, 1, 0x02, 0x81, 1, 0x03, 0x42, 1, 2]);
    assert_cbor_code(
        validate_fields(
            &schema,
            wrong_item.as_canonical_ref().root(),
            &NoNamedSchemas,
        )
        .unwrap_err(),
        ErrorCode::ExpectedBool,
    );
    let wrong_len = canon(&[0x86, 0x01, 1, 0x02, 0x80, 0x03, 0x41, 1]);
    assert_cbor_code(
        validate_fields(
            &schema,
            wrong_len.as_canonical_ref().root(),
            &NoNamedSchemas,
        )
        .unwrap_err(),
        ErrorCode::ExpectedBytes,
    );
}

struct Registry {
    type_id: &'static str,
    version: Option<u32>,
    schema: RuntimeSchema<'static>,
}
impl<'s> AbiSchemaRegistry<'s> for Registry {
    fn resolve(&'s self, type_id: &str, version: Option<u32>) -> Option<&'s RuntimeSchema<'s>> {
        (type_id == self.type_id && version == self.version).then_some(&self.schema)
    }
}

#[test]
fn named_runtime_types_require_and_use_compiled_registry_schemas() {
    let child_source = Box::leak(Box::new(Schema::new(
        "runtime.Child",
        1,
        TypeDef::Struct(field_set(
            vec![field(1, TypeRef::Bool, FieldPresence::Required)],
            UnknownFieldPolicy::Reject,
        )),
    )));
    let registry = Registry {
        type_id: "runtime.Child",
        version: Some(1),
        schema: compile_runtime_schema(child_source).unwrap(),
    };
    let parent = compiled(
        vec![field(
            1,
            TypeRef::Named {
                type_id: "runtime.Child".into(),
                version: Some(1),
            },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    let invalid_child = canon(&[0x82, 0x01, 0x82, 0x01, 0x01]);
    assert_eq!(
        validate_fields(
            &parent,
            invalid_child.as_canonical_ref().root(),
            &NoNamedSchemas,
        )
        .unwrap_err(),
        RuntimeAbiError::UnresolvedNamedType,
        "unresolved named type rejection rule"
    );
    assert_cbor_code(
        validate_fields(&parent, invalid_child.as_canonical_ref().root(), &registry).unwrap_err(),
        ErrorCode::ExpectedBool,
    );
}

fn enum_schema(unknown_variants: UnknownVariantPolicy) -> Schema {
    Schema::new(
        "runtime.Decision",
        1,
        TypeDef::Enum(EnumDef {
            variants: vec![
                VariantDef {
                    id: 1,
                    name: "Unit".into(),
                    fields: vec![],
                },
                VariantDef {
                    id: 2,
                    name: "Value".into(),
                    fields: vec![field(1, TypeRef::U8, FieldPresence::Required)],
                },
            ],
            unknown_fields: UnknownFieldPolicy::Reject,
            unknown_variants,
        }),
    )
}

#[test]
fn runtime_enum_enforces_unit_struct_and_unknown_variant_rules() {
    let source = enum_schema(UnknownVariantPolicy::Reject);
    let RuntimeSchema::Enum(runtime) = compile_runtime_schema(&source).unwrap() else {
        panic!("enum runtime root must compile")
    };
    let unit = canon(&[0x82, 0x01, 0xf6]);
    let unit_view =
        validate_enum(&runtime, unit.as_canonical_ref().root(), &NoNamedSchemas).unwrap();
    assert_eq!(unit_view.variant_id(), 1);
    assert_eq!(unit_view.variant().unwrap().name, "Unit");
    let named = canon(&[0x82, 0x02, 0x82, 0x01, 0x18, 0xff]);
    validate_enum(&runtime, named.as_canonical_ref().root(), &NoNamedSchemas).unwrap();
    let wrong_unit = canon(&[0x82, 0x01, 0x80]);
    assert_cbor_code(
        validate_enum(
            &runtime,
            wrong_unit.as_canonical_ref().root(),
            &NoNamedSchemas,
        )
        .unwrap_err(),
        ErrorCode::ExpectedNull,
    );
    let wrong_payload = canon(&[0x82, 0x02, 0x82, 0x01, 0x19, 0x01, 0x00]);
    assert_cbor_code(
        validate_enum(
            &runtime,
            wrong_payload.as_canonical_ref().root(),
            &NoNamedSchemas,
        )
        .unwrap_err(),
        ErrorCode::ExpectedInteger,
    );
    let unknown = canon(&[0x82, 0x09, 0x61, b'x']);
    assert_cbor_code(
        validate_enum(&runtime, unknown.as_canonical_ref().root(), &NoNamedSchemas).unwrap_err(),
        ErrorCode::InvalidAbiValue,
    );
    let preserving_source = enum_schema(UnknownVariantPolicy::Preserve);
    let RuntimeSchema::Enum(preserving) = compile_runtime_schema(&preserving_source).unwrap()
    else {
        unreachable!()
    };
    let view = validate_enum(
        &preserving,
        unknown.as_canonical_ref().root(),
        &NoNamedSchemas,
    )
    .unwrap();
    assert_eq!(view.variant_id(), 9);
    assert!(view.variant().is_none());
    assert_eq!(view.payload().text().unwrap(), "x");
}

#[test]
fn runtime_enum_schema_rejects_zero_and_duplicate_variant_id_rules() {
    for variants in [
        vec![VariantDef {
            id: 0,
            name: "Zero".into(),
            fields: vec![],
        }],
        vec![
            VariantDef {
                id: 1,
                name: "A".into(),
                fields: vec![],
            },
            VariantDef {
                id: 1,
                name: "B".into(),
                fields: vec![],
            },
        ],
    ] {
        let source = Schema::new(
            "runtime.Bad",
            1,
            TypeDef::Enum(EnumDef {
                variants,
                unknown_fields: UnknownFieldPolicy::Reject,
                unknown_variants: UnknownVariantPolicy::Reject,
            }),
        );
        assert!(matches!(
            compile_runtime_schema(&source),
            Err(RuntimeAbiError::InvalidSchema { .. })
        ));
    }
}

#[test]
fn unified_runtime_root_admission_covers_transparent_and_primitive_roots() {
    let transparent_source = Schema::new(
        "runtime.Flags",
        1,
        TypeDef::Transparent {
            inner: TypeRef::Vec {
                item: Box::new(TypeRef::Bool),
            },
        },
    );
    let transparent = compile_runtime_schema(&transparent_source).unwrap();
    let primitive_source =
        Schema::new("runtime.Label", 1, TypeDef::Primitive { ty: TypeRef::Text });
    let primitive = compile_runtime_schema(&primitive_source).unwrap();
    let flags = canon(&[0x82, 0xf4, 0xf5]);
    let label = canon(&[0x62, b'o', b'k']);
    let invalid = canon(&[0x01]);
    let limits = RuntimeValidationLimits::new(1, 16, 2, 3);

    let mut transparent_workspace = RuntimeValidationWorkspace::new();
    transparent_workspace.prepare(limits).unwrap();
    transparent
        .validate_value(
            flags.as_canonical_ref().root(),
            &NoNamedSchemas,
            limits,
            &mut transparent_workspace,
        )
        .unwrap();

    let mut primitive_workspace = RuntimeValidationWorkspace::new();
    primitive_workspace.prepare(limits).unwrap();
    primitive
        .validate_value(
            label.as_canonical_ref().root(),
            &NoNamedSchemas,
            limits,
            &mut primitive_workspace,
        )
        .unwrap();
    assert_cbor_code(
        primitive
            .validate_value(
                invalid.as_canonical_ref().root(),
                &NoNamedSchemas,
                limits,
                &mut primitive_workspace,
            )
            .unwrap_err(),
        ErrorCode::ExpectedText,
    );
}

#[test]
fn named_recursion_obeys_the_explicit_depth_rule() {
    let source = Box::leak(Box::new(Schema::new(
        "runtime.Node",
        1,
        TypeDef::Struct(field_set(
            vec![field(
                1,
                TypeRef::Named {
                    type_id: "runtime.Node".into(),
                    version: Some(1),
                },
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Reject,
        )),
    )));
    let registry = Registry {
        type_id: "runtime.Node",
        version: Some(1),
        schema: compile_runtime_schema(source).unwrap(),
    };
    let RuntimeSchema::Struct(root) = &registry.schema else {
        unreachable!()
    };
    let nested = canon(&[0x82, 0x01, 0x82, 0x01, 0x82, 0x01, 0x82, 0x01, 0xf6]);
    let limits = RuntimeValidationLimits::new(2, 100, 100, 100);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();
    assert_eq!(
        root.validate_value(
            nested.as_canonical_ref().root(),
            &registry,
            limits,
            &mut workspace,
        )
        .unwrap_err(),
        RuntimeAbiError::DepthLimit,
        "runtime recursion depth rejection rule"
    );
}

#[test]
fn wide_required_field_sets_use_constant_live_frames_after_prepare() {
    const FIELD_COUNT: usize = 257;
    let schema = compiled(
        (1..=FIELD_COUNT)
            .map(|id| field(id as u32, TypeRef::Bool, FieldPresence::Required))
            .collect(),
        UnknownFieldPolicy::Reject,
    );
    let mut encoder = Encoder::new();
    encoder
        .array(FIELD_COUNT * 2, |array| {
            for id in 1..=FIELD_COUNT {
                array.value(&(id as u32))?;
                array.bool(true)?;
            }
            Ok(())
        })
        .unwrap();
    let bytes = encoder.finish().unwrap();
    let value = canon(&bytes);
    let limits = RuntimeValidationLimits::new(0, FIELD_COUNT * 2 + 2, FIELD_COUNT, 2);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();
    schema
        .validate_value(
            value.as_canonical_ref().root(),
            &NoNamedSchemas,
            limits,
            &mut workspace,
        )
        .unwrap();
    assert_eq!(workspace.prepared_frames(), 2);

    let too_narrow = RuntimeValidationLimits::new(0, FIELD_COUNT * 2 + 2, FIELD_COUNT, 1);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(too_narrow).unwrap();
    assert_eq!(
        schema
            .validate_value(
                value.as_canonical_ref().root(),
                &NoNamedSchemas,
                too_narrow,
                &mut workspace,
            )
            .unwrap_err(),
        RuntimeAbiError::FrameLimit,
    );
    assert_eq!(
        schema
            .validate_value(
                value.as_canonical_ref().root(),
                &NoNamedSchemas,
                limits,
                &mut workspace,
            )
            .unwrap_err(),
        RuntimeAbiError::WorkspaceTooSmall,
    );
}

#[test]
fn named_validation_is_machine_stack_safe_at_large_explicit_depth() {
    const DEPTH: usize = 4_096;
    let source = Box::leak(Box::new(Schema::new(
        "runtime.DeepNode",
        1,
        TypeDef::Struct(field_set(
            vec![field(
                1,
                TypeRef::Named {
                    type_id: "runtime.DeepNode".into(),
                    version: Some(1),
                },
                FieldPresence::Required,
            )],
            UnknownFieldPolicy::Reject,
        )),
    )));
    let registry = Registry {
        type_id: "runtime.DeepNode",
        version: Some(1),
        schema: compile_runtime_schema(source).unwrap(),
    };
    let RuntimeSchema::Struct(root) = &registry.schema else {
        unreachable!()
    };

    let mut bytes = Vec::with_capacity(DEPTH * 2 + 1);
    for _ in 0..DEPTH {
        bytes.extend_from_slice(&[0x82, 0x01]);
    }
    bytes.push(0xf6);
    let mut decode_limits = DecodeLimits::for_bytes(bytes.len());
    decode_limits.max_depth = DEPTH + 1;
    let value = CanonicalCbor::from_vec(bytes, decode_limits).unwrap();
    let limits = RuntimeValidationLimits::new(DEPTH, DEPTH * 5, DEPTH, DEPTH + 2);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();
    assert_cbor_code(
        root.validate_value(
            value.as_canonical_ref().root(),
            &registry,
            limits,
            &mut workspace,
        )
        .unwrap_err(),
        ErrorCode::ExpectedArray,
    );
}

#[test]
fn runtime_limits_reject_before_exceeding_declared_work() {
    let schema = compiled(
        vec![field(
            1,
            TypeRef::Vec {
                item: Box::new(TypeRef::Bool),
            },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    let value = canon(&[0x82, 0x01, 0x83, 0xf4, 0xf5, 0xf4]);
    let limits = RuntimeValidationLimits::new(1, 100, 3, 4);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();
    assert_eq!(
        schema
            .validate_value(
                value.as_canonical_ref().root(),
                &NoNamedSchemas,
                limits,
                &mut workspace,
            )
            .unwrap_err(),
        RuntimeAbiError::ItemLimit,
    );

    let limits = RuntimeValidationLimits::new(1, 1, 4, 4);
    workspace.prepare(limits).unwrap();
    assert_eq!(
        schema
            .validate_value(
                value.as_canonical_ref().root(),
                &NoNamedSchemas,
                limits,
                &mut workspace,
            )
            .unwrap_err(),
        RuntimeAbiError::StepLimit,
    );
}

#[test]
fn prepared_workspace_reuses_storage_across_short_lived_messages() {
    let schema = compiled(
        vec![field(1, TypeRef::Bool, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    let limits = RuntimeValidationLimits::new(0, 4, 1, 2);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();

    for bytes in [&[0x82, 0x01, 0xf4][..], &[0x82, 0x01, 0xf5][..]] {
        let message = canon(bytes);
        schema
            .validate_value(
                message.as_canonical_ref().root(),
                &NoNamedSchemas,
                limits,
                &mut workspace,
            )
            .unwrap();
    }
    assert_eq!(workspace.prepared_frames(), 2);
}

struct PanicOnceRegistry {
    should_panic: Cell<bool>,
    schema: RuntimeSchema<'static>,
}

impl<'s> AbiSchemaRegistry<'s> for PanicOnceRegistry {
    fn resolve(&'s self, _type_id: &str, _version: Option<u32>) -> Option<&'s RuntimeSchema<'s>> {
        assert!(!self.should_panic.replace(false), "injected registry panic");
        Some(&self.schema)
    }
}

#[test]
fn workspace_drops_live_continuations_on_unwind_before_reuse() {
    let root = compiled(
        vec![field(
            1,
            TypeRef::Named {
                type_id: "runtime.Bool".into(),
                version: Some(1),
            },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    let primitive = Box::leak(Box::new(Schema::new(
        "runtime.Bool",
        1,
        TypeDef::Primitive { ty: TypeRef::Bool },
    )));
    let registry = PanicOnceRegistry {
        should_panic: Cell::new(true),
        schema: compile_runtime_schema(primitive).unwrap(),
    };
    let message = canon(&[0x82, 0x01, 0xf5]);
    let limits = RuntimeValidationLimits::new(1, 16, 1, 3);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = root.validate_value(
            message.as_canonical_ref().root(),
            &registry,
            limits,
            &mut workspace,
        );
    }));
    assert!(panic.is_err());
    root.validate_value(
        message.as_canonical_ref().root(),
        &registry,
        limits,
        &mut workspace,
    )
    .unwrap();
}
