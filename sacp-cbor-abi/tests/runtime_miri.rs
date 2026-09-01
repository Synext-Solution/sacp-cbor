use sacp_cbor::{CanonicalCbor, DecodeLimits};
use sacp_cbor_abi::{
    AbiSchemaRegistry, FieldDef, FieldPresence, FieldSetDef, RuntimeSchema,
    RuntimeValidationLimits, RuntimeValidationWorkspace, Schema, TypeDef, TypeRef,
    UnknownFieldPolicy,
};

static CHILD: Schema = Schema::new("miri.Child", 1, TypeDef::Primitive { ty: TypeRef::U64 });

static ROOT: Schema = Schema::new(
    "miri.Root",
    1,
    TypeDef::Struct(FieldSetDef::new(
        &[FieldDef::new(
            1,
            "children",
            TypeRef::sequence(TypeRef::named("miri.Child", Some(1))),
            FieldPresence::Required,
        )],
        UnknownFieldPolicy::Reject,
    )),
);

struct Registry;

impl AbiSchemaRegistry for Registry {
    fn resolve(&self, type_id: &str, version: Option<u32>) -> Option<RuntimeSchema> {
        (type_id == "miri.Child" && version == Some(1)).then(|| RuntimeSchema::new(&CHILD))
    }
}

fn canonical(bytes: &[u8]) -> CanonicalCbor {
    CanonicalCbor::from_slice(bytes, DecodeLimits::for_bytes(bytes.len())).unwrap()
}

#[test]
fn runtime_workspace_frames_remain_valid_across_failure_and_reuse() {
    let runtime = RuntimeSchema::new(&ROOT);
    let limits = RuntimeValidationLimits::new(16, 256, 256, 32);
    let mut workspace = RuntimeValidationWorkspace::new();
    workspace.prepare(limits).unwrap();
    let invalid = canonical(&[0x82, 0x01, 0x82, 0x01, 0x61, b'x']);
    let valid = canonical(&[0x82, 0x01, 0x83, 0x01, 0x02, 0x03]);

    for _ in 0..4 {
        assert!(runtime
            .validate_value(invalid.root(), &Registry, limits, &mut workspace)
            .is_err());
        runtime
            .validate_value(valid.root(), &Registry, limits, &mut workspace)
            .unwrap();
    }
}
