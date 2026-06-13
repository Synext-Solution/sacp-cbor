use std::cell::Cell;

use sacp_cbor::query::CborValueRef;
use sacp_cbor::{CanonicalCbor, DecodeLimits, Encoder, ErrorCode};
use sacp_cbor_abi::{
    compile_runtime_schema, encode_to_vec, AbiSchemaRegistry, AbiType, CborAbi, FieldDef,
    FieldPresence, FieldSetDef, RuntimeAbiError, RuntimeFieldContext, RuntimeFieldSetSchema,
    RuntimeHookOutcome, RuntimeInline, RuntimeNamedDecision, RuntimeRejectNamed,
    RuntimeResolveNamed, RuntimeSchema, RuntimeTypeContext, RuntimeTypeMode,
    RuntimeValidationConfig, RuntimeValidationHooks, RuntimeVecItemContext, Schema, TypeDef,
    TypeRef, UnknownFieldPolicy,
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

fn validate_result<M: RuntimeTypeMode>(
    schema: &RuntimeFieldSetSchema<'_>,
    bytes: &[u8],
    mode: M,
) -> Result<(), RuntimeAbiError> {
    let canon = canon(bytes);
    schema
        .validate_value(canon.as_canonical_ref().root(), mode)
        .map(|_| ())
}

fn validate_result_with_config<M: RuntimeTypeMode>(
    schema: &RuntimeFieldSetSchema<'_>,
    bytes: &[u8],
    mode: M,
    config: RuntimeValidationConfig,
) -> Result<(), RuntimeAbiError> {
    let canon = canon(bytes);
    schema
        .validate_value_with_config(canon.as_canonical_ref().root(), mode, config)
        .map(|_| ())
}

fn validate_hooks_result<M: RuntimeTypeMode, H: RuntimeValidationHooks>(
    schema: &RuntimeFieldSetSchema<'_>,
    bytes: &[u8],
    mode: M,
    hooks: &mut H,
) -> Result<(), RuntimeAbiError> {
    let canon = canon(bytes);
    schema
        .validate_value_with_hooks(
            canon.as_canonical_ref().root(),
            mode,
            RuntimeValidationConfig::default(),
            hooks,
        )
        .map(|_| ())
}

fn assert_cbor_code(err: RuntimeAbiError, code: ErrorCode) {
    match err {
        RuntimeAbiError::Cbor(err) => assert_eq!(err.code, code),
        other => panic!("expected CBOR error {code:?}, got {other:?}"),
    }
}

fn assert_hook_rejected(err: RuntimeAbiError, reason: &'static str, offset: usize) {
    assert_eq!(err, RuntimeAbiError::HookRejected { reason, offset });
}

fn inline_mode() -> RuntimeInline {
    RuntimeInline
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
            inline_mode(),
        )
        .is_ok());
    assert_cbor_code(
        validate_result(&u8_schema, &[0x82, 0x01, 0x19, 0x01, 0x00], inline_mode()).unwrap_err(),
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
            inline_mode(),
        )
        .is_ok());
    assert_cbor_code(
        validate_result(&fixed, &[0x82, 0x01, 0x41, 0xaa], inline_mode()).unwrap_err(),
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
        validate_result(&schema, &bytes, inline_mode()).unwrap_err(),
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
        view.get_checked(2, inline_mode())
            .unwrap()
            .unwrap()
            .text()
            .unwrap(),
        "ok"
    );
    assert_cbor_code(
        view.get_checked(1, inline_mode()).unwrap_err(),
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

#[derive(Default)]
struct CountingHooks {
    enter_fields: usize,
    enter_types: usize,
    named: usize,
}

impl RuntimeValidationHooks for CountingHooks {
    fn enter_field(
        &mut self,
        ctx: RuntimeFieldContext<'_>,
        field: &FieldDef,
        _value: CborValueRef<'_>,
    ) -> Result<(), RuntimeAbiError> {
        assert_eq!(ctx.field_id, field.id);
        self.enter_fields += 1;
        Ok(())
    }

    fn enter_type_ref(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _ty: &TypeRef,
        _value: CborValueRef<'_>,
    ) -> Result<(), RuntimeAbiError> {
        self.enter_types += 1;
        Ok(())
    }

    fn validate_named(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _type_id: &str,
        _version: Option<u32>,
        _value: CborValueRef<'_>,
    ) -> Result<RuntimeNamedDecision, RuntimeAbiError> {
        self.named += 1;
        Ok(RuntimeNamedDecision::Continue)
    }
}

#[test]
fn hooks_disabled_and_noop_hook_match_builtin_validation() {
    let schema = compiled(
        vec![field(1, TypeRef::U8, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    let valid = [0x82, 0x01, 0x05];
    let invalid = [0x82, 0x01, 0x19, 0x01, 0x00];

    assert!(validate_result(&schema, &valid, inline_mode()).is_ok());
    let mut hooks = CountingHooks::default();
    assert!(validate_hooks_result(&schema, &valid, inline_mode(), &mut hooks).is_ok());
    assert_eq!(hooks.enter_fields, 1);
    assert_eq!(hooks.enter_types, 1);

    let no_hook = validate_result(&schema, &invalid, inline_mode()).unwrap_err();
    let mut hooks = CountingHooks::default();
    let hooked = validate_hooks_result(&schema, &invalid, inline_mode(), &mut hooks).unwrap_err();
    assert_eq!(hooked, no_hook);
}

#[test]
fn shell_only_never_calls_hooks() {
    let schema = compiled(
        vec![field(1, TypeRef::U8, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    let hooks = CountingHooks::default();

    assert!(view_result(&schema, &[0x82, 0x01, 0x19, 0x01, 0x00]).is_ok());
    assert_eq!(hooks.enter_fields, 0);
    assert_eq!(hooks.enter_types, 0);
}

struct RejectFieldHook;

impl RuntimeValidationHooks for RejectFieldHook {
    fn enter_field(
        &mut self,
        _ctx: RuntimeFieldContext<'_>,
        field: &FieldDef,
        value: CborValueRef<'_>,
    ) -> Result<(), RuntimeAbiError> {
        if field.id == 1 {
            return Err(RuntimeAbiError::HookRejected {
                reason: "field-refinement",
                offset: value.offset(),
            });
        }
        Ok(())
    }
}

#[test]
fn field_hook_rejects_abi_valid_value() {
    let schema = compiled(
        vec![field(1, TypeRef::U8, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    let mut hook = RejectFieldHook;
    assert_hook_rejected(
        validate_hooks_result(&schema, &[0x82, 0x01, 0x05], inline_mode(), &mut hook).unwrap_err(),
        "field-refinement",
        2,
    );
}

struct TypeRefinementHook;

impl RuntimeValidationHooks for TypeRefinementHook {
    fn exit_type_ref(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        ty: &TypeRef,
        value: CborValueRef<'_>,
        outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        if outcome != RuntimeHookOutcome::Success {
            return Ok(());
        }

        let reason = match ty {
            TypeRef::Bytes if value.bytes()?.len() < 2 => Some("bytes-range"),
            TypeRef::FixedBytes { .. } if value.bytes()?.first() == Some(&0) => {
                Some("fixed-bytes-bits")
            }
            TypeRef::CanonicalCbor if value.is_null() => Some("canonical-profile"),
            TypeRef::Vec { .. } => {
                let mut prev = None;
                for item in value.array()?.iter() {
                    let item = item?;
                    let offset = item.offset();
                    let item = item.integer()?.as_u128().ok_or_else(|| {
                        sacp_cbor::CborError::new(ErrorCode::ExpectedInteger, offset)
                    })?;
                    if prev.is_some_and(|prev| item <= prev) {
                        return Err(RuntimeAbiError::HookRejected {
                            reason: "vec-sorted-unique",
                            offset: value.offset(),
                        });
                    }
                    prev = Some(item);
                }
                None
            }
            _ => None,
        };

        if let Some(reason) = reason {
            Err(RuntimeAbiError::HookRejected {
                reason,
                offset: value.offset(),
            })
        } else {
            Ok(())
        }
    }
}

#[test]
fn type_hooks_reject_semantic_refinements() {
    let mut hook = TypeRefinementHook;

    let bytes = compiled(
        vec![field(1, TypeRef::Bytes, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    assert_hook_rejected(
        validate_hooks_result(&bytes, &[0x82, 0x01, 0x41, 0xaa], inline_mode(), &mut hook)
            .unwrap_err(),
        "bytes-range",
        2,
    );

    let fixed = compiled(
        vec![field(
            1,
            TypeRef::FixedBytes { len: 2 },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    assert_hook_rejected(
        validate_hooks_result(
            &fixed,
            &[0x82, 0x01, 0x42, 0x00, 0xaa],
            inline_mode(),
            &mut hook,
        )
        .unwrap_err(),
        "fixed-bytes-bits",
        2,
    );

    let canonical = compiled(
        vec![field(1, TypeRef::CanonicalCbor, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    assert_hook_rejected(
        validate_hooks_result(&canonical, &[0x82, 0x01, 0xf6], inline_mode(), &mut hook)
            .unwrap_err(),
        "canonical-profile",
        2,
    );

    let vector = compiled(
        vec![field(
            1,
            TypeRef::Vec {
                item: Box::new(TypeRef::U8),
            },
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    );
    assert_hook_rejected(
        validate_hooks_result(
            &vector,
            &[0x82, 0x01, 0x82, 0x02, 0x02],
            inline_mode(),
            &mut hook,
        )
        .unwrap_err(),
        "vec-sorted-unique",
        2,
    );
}

struct AcceptNamedHook {
    calls: usize,
}

impl RuntimeValidationHooks for AcceptNamedHook {
    fn validate_named(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        type_id: &str,
        version: Option<u32>,
        _value: CborValueRef<'_>,
    ) -> Result<RuntimeNamedDecision, RuntimeAbiError> {
        assert_eq!(type_id, "runtime.Child");
        assert_eq!(version, Some(1));
        self.calls += 1;
        Ok(RuntimeNamedDecision::Accepted)
    }
}

#[test]
fn named_hook_accepted_is_the_only_validation_skip_path() {
    let primitive = compiled(
        vec![field(1, TypeRef::U8, FieldPresence::Required)],
        UnknownFieldPolicy::Reject,
    );
    let mut hook = AcceptNamedHook { calls: 0 };
    assert_cbor_code(
        validate_hooks_result(
            &primitive,
            &[0x82, 0x01, 0x19, 0x01, 0x00],
            inline_mode(),
            &mut hook,
        )
        .unwrap_err(),
        ErrorCode::ExpectedInteger,
    );
    assert_eq!(hook.calls, 0);
}

#[test]
fn named_hook_accepted_works_for_every_named_policy() {
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
    let child = Box::leak(Box::new(Schema::new(
        "runtime.Child",
        1,
        TypeDef::Struct(field_set(
            vec![field(1, TypeRef::U8, FieldPresence::Required)],
            UnknownFieldPolicy::Reject,
        )),
    )));
    let registry = Registry {
        type_id: "runtime.Child",
        version: Some(1),
        child: compile_runtime_schema(child).unwrap(),
        resolve_count: Cell::new(0),
    };
    let invalid_child = [0x82, 0x01, 0x82, 0x01, 0x19, 0x01, 0x00];

    let mut hook = AcceptNamedHook { calls: 0 };
    assert!(validate_hooks_result(&root_schema, &invalid_child, RuntimeInline, &mut hook).is_ok());
    assert_eq!(hook.calls, 1);

    let mut hook = AcceptNamedHook { calls: 0 };
    assert!(
        validate_hooks_result(&root_schema, &invalid_child, RuntimeRejectNamed, &mut hook).is_ok()
    );
    assert_eq!(hook.calls, 1);

    let mut hook = AcceptNamedHook { calls: 0 };
    assert!(validate_hooks_result(
        &root_schema,
        &invalid_child,
        RuntimeResolveNamed::new(&registry),
        &mut hook,
    )
    .is_ok());
    assert_eq!(hook.calls, 1);
    assert_eq!(registry.resolve_count.get(), 0);
}

#[test]
fn named_hook_continue_preserves_named_policy() {
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
    let invalid_child = [0x82, 0x01, 0x82, 0x01, 0x19, 0x01, 0x00];
    let mut hooks = CountingHooks::default();

    assert!(validate_hooks_result(&root_schema, &invalid_child, RuntimeInline, &mut hooks).is_ok());
    assert_eq!(hooks.named, 1);

    let mut hooks = CountingHooks::default();
    assert_eq!(
        validate_hooks_result(&root_schema, &invalid_child, RuntimeRejectNamed, &mut hooks,)
            .unwrap_err(),
        RuntimeAbiError::UnresolvedNamedType
    );
}

#[test]
fn unknown_fields_are_never_exposed_to_hooks() {
    let reject = compiled(vec![], UnknownFieldPolicy::Reject);
    let mut hooks = CountingHooks::default();
    assert_cbor_code(
        validate_hooks_result(&reject, &[0x82, 0x02, 0xf5], inline_mode(), &mut hooks).unwrap_err(),
        ErrorCode::UnknownField,
    );
    assert_eq!(hooks.enter_fields, 0);
    assert_eq!(hooks.enter_types, 0);

    for policy in [UnknownFieldPolicy::Ignore, UnknownFieldPolicy::Preserve] {
        let schema = compiled(vec![field(1, TypeRef::U8, FieldPresence::Required)], policy);
        let mut hooks = CountingHooks::default();
        assert!(validate_hooks_result(
            &schema,
            &[0x84, 0x01, 0x05, 0x02, 0xf5],
            inline_mode(),
            &mut hooks,
        )
        .is_ok());
        assert_eq!(hooks.enter_fields, 1);
        assert_eq!(hooks.enter_types, 1);
    }
}

#[derive(Default)]
struct VecTraceHook {
    len: Option<usize>,
    indexes: Vec<usize>,
    type_error_exits: usize,
    vec_error_exits: usize,
    item_error_exits: usize,
    field_error_exits: usize,
}

impl RuntimeValidationHooks for VecTraceHook {
    fn enter_vec(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _item: &TypeRef,
        _value: CborValueRef<'_>,
        len: usize,
    ) -> Result<(), RuntimeAbiError> {
        self.len = Some(len);
        Ok(())
    }

    fn exit_vec_item(
        &mut self,
        ctx: RuntimeVecItemContext<'_>,
        _item: &TypeRef,
        _value: CborValueRef<'_>,
        outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        if matches!(outcome, RuntimeHookOutcome::Error(_)) {
            self.item_error_exits += 1;
        }
        self.indexes.push(ctx.index);
        Ok(())
    }

    fn exit_vec(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _item: &TypeRef,
        _value: CborValueRef<'_>,
        outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        if matches!(outcome, RuntimeHookOutcome::Error(_)) {
            self.vec_error_exits += 1;
        }
        Ok(())
    }

    fn exit_type_ref(
        &mut self,
        _ctx: RuntimeTypeContext<'_>,
        _ty: &TypeRef,
        _value: CborValueRef<'_>,
        outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        if matches!(outcome, RuntimeHookOutcome::Error(_)) {
            self.type_error_exits += 1;
        }
        Ok(())
    }

    fn exit_field(
        &mut self,
        _ctx: RuntimeFieldContext<'_>,
        _field: &FieldDef,
        _value: CborValueRef<'_>,
        outcome: RuntimeHookOutcome,
    ) -> Result<(), RuntimeAbiError> {
        if matches!(outcome, RuntimeHookOutcome::Error(_)) {
            self.field_error_exits += 1;
        }
        Ok(())
    }
}

#[test]
fn vec_item_callbacks_receive_indexes_in_order() {
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
    let mut hook = VecTraceHook::default();

    assert!(validate_hooks_result(
        &schema,
        &[0x82, 0x01, 0x83, 0x01, 0x02, 0x03],
        inline_mode(),
        &mut hook,
    )
    .is_ok());
    assert_eq!(hook.len, Some(3));
    assert_eq!(hook.indexes, [0, 1, 2]);
    assert_eq!(hook.type_error_exits, 0);
}

#[test]
fn exit_hooks_observe_nested_validation_errors() {
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
    let mut hook = VecTraceHook::default();

    assert_cbor_code(
        validate_hooks_result(
            &schema,
            &[0x82, 0x01, 0x82, 0x01, 0x19, 0x01, 0x00],
            inline_mode(),
            &mut hook,
        )
        .unwrap_err(),
        ErrorCode::ExpectedInteger,
    );
    assert_eq!(hook.indexes, [0, 1]);
    assert_eq!(hook.item_error_exits, 1);
    assert_eq!(hook.vec_error_exits, 1);
    assert_eq!(hook.field_error_exits, 1);
    assert_eq!(hook.type_error_exits, 2);
}

struct Registry {
    type_id: &'static str,
    version: Option<u32>,
    child: RuntimeSchema<'static>,
    resolve_count: Cell<usize>,
}

impl AbiSchemaRegistry for Registry {
    fn resolve<'r>(&'r self, type_id: &str, version: Option<u32>) -> Option<&'r RuntimeSchema<'r>> {
        if type_id == self.type_id && version == self.version {
            self.resolve_count.set(self.resolve_count.get() + 1);
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
    let child = Box::leak(Box::new(Schema::new(
        "runtime.Child",
        1,
        TypeDef::Struct(field_set(
            vec![field(1, TypeRef::U8, FieldPresence::Required)],
            UnknownFieldPolicy::Reject,
        )),
    )));
    let registry = Registry {
        type_id: "runtime.Child",
        version: Some(1),
        child: compile_runtime_schema(child).unwrap(),
        resolve_count: Cell::new(0),
    };
    let bad_child = [0x82, 0x01, 0x82, 0x01, 0x19, 0x01, 0x00];

    assert!(root_schema
        .validate_value(canon(&bad_child).as_canonical_ref().root(), inline_mode())
        .is_ok());

    assert_eq!(
        validate_result(&root_schema, &bad_child, RuntimeRejectNamed).unwrap_err(),
        RuntimeAbiError::UnresolvedNamedType
    );

    let resolve_mode = RuntimeResolveNamed::new(&registry);
    assert_cbor_code(
        validate_result(&root_schema, &bad_child, resolve_mode).unwrap_err(),
        ErrorCode::ExpectedInteger,
    );

    let good_child = [0x82, 0x01, 0x82, 0x01, 0x05];
    assert!(validate_result(&root_schema, &good_child, resolve_mode).is_ok());
    assert_eq!(registry.resolve_count.get(), 2);
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
    let child = Box::leak(Box::new(Schema::new(
        "runtime.Child",
        1,
        TypeDef::Struct(field_set(
            vec![field(1, TypeRef::U8, FieldPresence::Required)],
            UnknownFieldPolicy::Reject,
        )),
    )));
    let registry = Registry {
        type_id: "runtime.Child",
        version: Some(1),
        child: compile_runtime_schema(child).unwrap(),
        resolve_count: Cell::new(0),
    };
    let config = RuntimeValidationConfig::default().with_max_recursion_depth(0);

    assert_eq!(
        validate_result_with_config(
            &root_schema,
            &[0x82, 0x01, 0x82, 0x01, 0x05],
            RuntimeResolveNamed::new(&registry),
            config,
        )
        .unwrap_err(),
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
    let RuntimeSchema::Struct(compiled) = compile_runtime_schema(&schema).unwrap() else {
        unreachable!("Transfer schema is a struct")
    };
    let canon = canon(&bytes);
    let view = compiled
        .validate_value(canon.as_canonical_ref().root(), inline_mode())
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
fn compile_runtime_schema_accepts_non_enum_roots() {
    let primitive = Schema::new(
        "runtime.Primitive",
        1,
        TypeDef::Primitive { ty: TypeRef::U64 },
    );
    assert!(matches!(
        compile_runtime_schema(&primitive).unwrap(),
        RuntimeSchema::Primitive { .. }
    ));

    let transparent = Schema::new(
        "runtime.Transparent",
        1,
        TypeDef::Transparent {
            inner: TypeRef::U64,
        },
    );
    assert!(matches!(
        compile_runtime_schema(&transparent).unwrap(),
        RuntimeSchema::Transparent { .. }
    ));

    let enum_schema = Schema::new(
        "runtime.Enum",
        1,
        TypeDef::Enum(sacp_cbor_abi::EnumDef {
            variants: Vec::new(),
            unknown_fields: UnknownFieldPolicy::Reject,
            unknown_variants: sacp_cbor_abi::UnknownVariantPolicy::Reject,
        }),
    );
    assert_eq!(
        compile_runtime_schema(&enum_schema).unwrap_err(),
        RuntimeAbiError::UnsupportedRoot
    );
}
