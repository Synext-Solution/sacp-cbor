use core::alloc::{GlobalAlloc, Layout};

use sacp_cbor::{CanonicalCbor, CountingSink, DecodeLimits, EncodeLimits, ErrorCode};
use sacp_cbor_abi::{
    encode_to_sink, AbiSchemaRegistry, EnumDef, FieldDef, FieldPresence, FieldSetDef,
    NoNamedSchemas, RuntimeAbiError, RuntimeSchema, RuntimeValidationLimits,
    RuntimeValidationWorkspace, Schema, TypeDef, TypeRef, UnknownFieldPolicy, UnknownVariantPolicy,
    VariantDef,
};
use std::alloc::System;
use std::cell::Cell;

thread_local! {
    static FAIL_NEXT_ALLOCATION: Cell<bool> = const { Cell::new(false) };
}

struct TestAllocator;

// SAFETY: every operation delegates to `System`; `alloc` and `realloc` may additionally return
// null, which is permitted by `GlobalAlloc` and is consumed at most once on the current thread.
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
            // SAFETY: the pointer and layout are forwarded unchanged to the system allocator.
            unsafe { System.realloc(pointer, layout, new_size) }
        }
    }
}

#[global_allocator]
static ALLOCATOR: TestAllocator = TestAllocator;

static LABEL_SCHEMA: Schema =
    Schema::new("runtime.Label", 1, TypeDef::Primitive { ty: TypeRef::TEXT });

static RECORD_SCHEMA: Schema = Schema::new(
    "runtime.Record",
    1,
    TypeDef::Struct(FieldSetDef::new(
        &[
            FieldDef::new(
                1,
                "label",
                TypeRef::named("runtime.Label", Some(1)),
                FieldPresence::Required,
            ),
            FieldDef::new(
                2,
                "values",
                TypeRef::sequence(TypeRef::U8),
                FieldPresence::Required,
            ),
        ],
        UnknownFieldPolicy::Preserve,
    )),
);

static CHOICE_SCHEMA: Schema = Schema::new(
    "runtime.Choice",
    1,
    TypeDef::Enum(EnumDef::new(
        &[
            VariantDef::unit(1, "Unit"),
            VariantDef::fields(
                2,
                "EmptyFields",
                FieldSetDef::new(&[], UnknownFieldPolicy::Reject),
            ),
        ],
        UnknownVariantPolicy::Preserve,
    )),
);

static CANONICAL_SCHEMA: Schema = Schema::new(
    "runtime.CanonicalEnvelope",
    1,
    TypeDef::Struct(FieldSetDef::new(
        &[FieldDef::new(
            1,
            "payload",
            TypeRef::CANONICAL_CBOR,
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    )),
);

#[derive(Clone, Copy)]
struct Registry;

impl AbiSchemaRegistry for Registry {
    fn resolve(&self, type_id: &str, version: Option<u32>) -> Option<RuntimeSchema> {
        match (type_id, version) {
            ("runtime.Label", Some(1)) => Some(RuntimeSchema::new(&LABEL_SCHEMA)),
            _ => None,
        }
    }
}

fn canon(bytes: &[u8]) -> CanonicalCbor {
    CanonicalCbor::from_slice(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap()
}

fn limits() -> RuntimeValidationLimits {
    RuntimeValidationLimits::new(64, 10_000, 10_000, 128)
}

fn assert_cbor_code(error: RuntimeAbiError, expected: ErrorCode) {
    match error {
        RuntimeAbiError::Cbor(error) => assert_eq!(error.code, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

fn validate(
    schema: RuntimeSchema,
    value: &CanonicalCbor,
    registry: &impl AbiSchemaRegistry,
    validation_limits: RuntimeValidationLimits,
) -> Result<(), RuntimeAbiError> {
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(validation_limits)?;
    schema.validate_value(value.root(), registry, validation_limits, &mut workspace)
}

#[test]
fn static_runtime_schema_validates_named_and_sequence_fields_without_compilation() {
    const RUNTIME: RuntimeSchema = RuntimeSchema::new(&RECORD_SCHEMA);
    let value = canon(&[
        0x86, 0x01, 0x62, b'o', b'k', 0x02, 0x83, 0x01, 0x02, 0x18, 0xff, 0x09, 0xf5,
    ]);
    validate(RUNTIME, &value, &Registry, limits()).unwrap();

    let RuntimeSchema::Struct(fields) = RUNTIME else {
        unreachable!()
    };
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits()).unwrap();
    let view = fields
        .validate_value(value.root(), &Registry, limits(), &mut workspace)
        .unwrap();
    assert_eq!(view.require_raw(1).unwrap().text().unwrap(), "ok",);
    let unknown: Vec<_> = view.unknown_fields().unwrap().map(Result::unwrap).collect();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].id, 9);
}

#[test]
fn runtime_validation_rejects_unresolved_names_and_bad_sequence_items() {
    let valid_shape = canon(&[0x84, 0x01, 0x62, b'o', b'k', 0x02, 0x81, 0x01]);
    assert_eq!(
        validate(
            RuntimeSchema::new(&RECORD_SCHEMA),
            &valid_shape,
            &NoNamedSchemas,
            limits(),
        ),
        Err(RuntimeAbiError::UnresolvedNamedType)
    );

    let bad_item = canon(&[0x84, 0x01, 0x62, b'o', b'k', 0x02, 0x81, 0x19, 0x01, 0x00]);
    let error = validate(
        RuntimeSchema::new(&RECORD_SCHEMA),
        &bad_item,
        &Registry,
        limits(),
    )
    .unwrap_err();
    assert_cbor_code(error, ErrorCode::ExpectedInteger);
}

#[test]
fn enum_runtime_distinguishes_unit_from_an_empty_field_set() {
    let RuntimeSchema::Enum(schema) = RuntimeSchema::new(&CHOICE_SCHEMA) else {
        unreachable!()
    };
    for bytes in [&[0x82, 0x01, 0xf6][..], &[0x82, 0x02, 0x80][..]] {
        let value = canon(bytes);
        let mut workspace = RuntimeValidationWorkspace::new();
        workspace.prepare(limits()).unwrap();
        schema
            .validate_value(value.root(), &NoNamedSchemas, limits(), &mut workspace)
            .unwrap();
    }

    let unit_with_fields = canon(&[0x82, 0x01, 0x80]);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits()).unwrap();
    let error = schema
        .validate_value(
            unit_with_fields.root(),
            &NoNamedSchemas,
            limits(),
            &mut workspace,
        )
        .unwrap_err();
    assert_cbor_code(error, ErrorCode::ExpectedNull);

    let fields_with_null = canon(&[0x82, 0x02, 0xf6]);
    let error = schema
        .validate_value(
            fields_with_null.root(),
            &NoNamedSchemas,
            limits(),
            &mut workspace,
        )
        .unwrap_err();
    assert_cbor_code(error, ErrorCode::ExpectedArray);

    let unknown = canon(&[0x82, 0x09, 0xf5]);
    let view = schema
        .validate_value(unknown.root(), &NoNamedSchemas, limits(), &mut workspace)
        .unwrap();
    assert_eq!(view.variant_id(), 9);
    assert!(view.variant().is_none());
}

#[test]
fn explicit_runtime_budgets_fail_at_their_typed_boundaries() {
    let value = canon(&[0x84, 0x01, 0x61, b'x', 0x02, 0x81, 0x01]);
    let schema = RuntimeSchema::new(&RECORD_SCHEMA);

    let declared = RuntimeValidationLimits::new(8, 32, 32, 2);
    let mut workspace = RuntimeValidationWorkspace::new();
    assert_eq!(
        schema.validate_value(value.root(), &Registry, declared, &mut workspace),
        Err(RuntimeAbiError::WorkspaceTooSmall)
    );

    let step_limited = RuntimeValidationLimits::new(8, 0, 32, 8);
    workspace.prepare(step_limited).unwrap();
    assert_eq!(
        schema.validate_value(value.root(), &Registry, step_limited, &mut workspace),
        Err(RuntimeAbiError::StepLimit)
    );

    let item_limited = RuntimeValidationLimits::new(8, 32, 1, 8);
    workspace.prepare(item_limited).unwrap();
    assert_eq!(
        schema.validate_value(value.root(), &Registry, item_limited, &mut workspace),
        Err(RuntimeAbiError::ItemLimit)
    );

    let frame_limited = RuntimeValidationLimits::new(8, 32, 32, 1);
    workspace.prepare(frame_limited).unwrap();
    assert_eq!(
        schema.validate_value(value.root(), &Registry, frame_limited, &mut workspace),
        Err(RuntimeAbiError::FrameLimit)
    );

    let depth_limited = RuntimeValidationLimits::new(0, 32, 32, 8);
    workspace.prepare(depth_limited).unwrap();
    assert_eq!(
        schema.validate_value(value.root(), &Registry, depth_limited, &mut workspace),
        Err(RuntimeAbiError::DepthLimit)
    );
}

#[test]
fn prepared_runtime_validation_and_direct_schema_hashing_do_not_allocate() {
    let mut bytes = vec![0x82, 0x01];
    bytes.extend(core::iter::repeat_n(0x81, 40));
    bytes.push(0xf6);
    let value = canon(&bytes);
    let validation_limits = limits();
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(validation_limits).unwrap();

    FAIL_NEXT_ALLOCATION.with(|flag| flag.set(false));
    FAIL_NEXT_ALLOCATION.with(|flag| flag.set(true));
    let result = RuntimeSchema::new(&CANONICAL_SCHEMA).validate_value(
        value.root(),
        &NoNamedSchemas,
        validation_limits,
        &mut workspace,
    );
    let allocation_was_not_attempted = FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false));
    assert!(result.is_ok());
    assert!(allocation_was_not_attempted);

    FAIL_NEXT_ALLOCATION.with(|flag| flag.set(true));
    let hash = RECORD_SCHEMA.wire_hash(EncodeLimits::for_bytes(4096));
    let allocation_was_not_attempted = FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false));
    assert!(hash.is_ok());
    assert!(allocation_was_not_attempted);

    let values = [u64::MAX, 0, 1];
    FAIL_NEXT_ALLOCATION.with(|flag| flag.set(true));
    let encoded = encode_to_sink(
        &values[..],
        CountingSink::new(),
        EncodeLimits::for_bytes(128),
    );
    let allocation_was_not_attempted = FAIL_NEXT_ALLOCATION.with(|flag| flag.replace(false));
    assert!(encoded.is_ok());
    assert!(allocation_was_not_attempted);
}

#[test]
fn workspace_is_reusable_after_validation_failure() {
    let schema = RuntimeSchema::new(&RECORD_SCHEMA);
    let validation_limits = limits();
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(validation_limits).unwrap();

    let invalid = canon(&[0x84, 0x01, 0x61, b'x', 0x02, 0x81, 0x19, 0x01, 0x00]);
    assert!(schema
        .validate_value(invalid.root(), &Registry, validation_limits, &mut workspace,)
        .is_err());

    let valid = canon(&[0x84, 0x01, 0x61, b'x', 0x02, 0x81, 0x01]);
    schema
        .validate_value(valid.root(), &Registry, validation_limits, &mut workspace)
        .unwrap();
}
