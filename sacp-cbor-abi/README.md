# sacp-cbor-abi

Stable public ABI schemas and codecs for [`sacp-cbor`](https://crates.io/crates/sacp-cbor).

Use this crate when bytes are part of a public protocol, durable storage format, or compatibility
contract. It gives the wire format stable numeric field and variant IDs instead of deriving identity
from Rust field names or module paths.

The examples below are mirrored by `tests/readme_examples.rs` in the repository.

## Install

```toml
[dependencies]
sacp-cbor = "0.18"
sacp-cbor-abi = "0.8"
```

The default `derive` feature exports `#[derive(CborAbi)]`. Disable default features only when using
the runtime schema/diff APIs without macro generation:

```toml
[dependencies]
sacp-cbor-abi = { version = "0.8", default-features = false }
```

## Struct ABI

```rust
use sacp_cbor::{CanonicalCbor, DecodeLimits, EncodeLimits};
use sacp_cbor_abi::{decode, encode_to_vec, AbiType, CborAbi};

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 1)]
struct Transfer {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
}

let value = Transfer {
    from: 1001,
    to: 2002,
    amount: 5000,
    memo: None,
};

let encode_limits = EncodeLimits::for_bytes(4096);
let bytes = encode_to_vec(&value, encode_limits)?;
let mut context = ();
let decoded: Transfer = decode(
    &bytes,
    DecodeLimits::for_bytes(bytes.len()),
    &mut context,
)?;
assert_eq!(decoded, value);

let wire_hash = Transfer::schema().wire_hash(encode_limits)?;
let full_hash = Transfer::schema().full_hash(encode_limits)?;
assert_ne!(wire_hash, full_hash);
```

Structs encode as canonical field-set arrays:

```text
[field_id, value, field_id, value, ...]
```

For the `Transfer` value above, `memo: None` is omitted and the wire bytes represent:

```text
[1, 1001, 2, 2002, 3, 5000]
```

Field IDs and variant IDs are nonzero `u32` values. Field-set IDs must be strictly increasing on the
wire; zero, duplicate, decreasing, and odd-length field-set arrays are rejected.

## Storage-independent encoding and exact sequences

The derived declaration owns numeric IDs, presence rules, unknown-value policy, and the static wire
schema. Rust storage does not. Alongside ordinary owned encoding, a struct derive generates
`TypeAbiProjection` and `TypeAbiProjected`; an enum derive additionally generates a consuming
`TypeAbiVariantVisitor`. Business adapters implement semantic field or variant methods and never
receive numeric IDs.

For a `Vec<T>` field, the protocol type is `wire::Sequence<T::Wire>`. The same field can therefore
be supplied by an owned `Vec<T>`, a borrowed slice, an engine-driven `ExactIndexProjection`, or a
source-driven `SequenceProjection`. There is deliberately no `Iterator` or `ExactSizeIterator`
blanket implementation: definite-length correctness cannot depend on advisory iterator metadata.

```rust
struct BorrowedTransfer<'a> {
    from: u64,
    to: u64,
    amount: u64,
    memo: Option<&'a str>,
}

impl TransferAbiProjection for BorrowedTransfer<'_> {
    type Error = core::convert::Infallible;
    type FieldFrom<'a> = u64 where Self: 'a;
    type FieldTo<'a> = u64 where Self: 'a;
    type FieldAmount<'a> = u64 where Self: 'a;
    type FieldMemo<'a> = &'a str where Self: 'a;

    fn from(&self) -> Result<Self::FieldFrom<'_>, Self::Error> { Ok(self.from) }
    fn to(&self) -> Result<Self::FieldTo<'_>, Self::Error> { Ok(self.to) }
    fn amount(&self) -> Result<Self::FieldAmount<'_>, Self::Error> { Ok(self.amount) }
    fn memo(&self) -> Result<Option<Self::FieldMemo<'_>>, Self::Error> { Ok(self.memo) }
}

let source = BorrowedTransfer { from: 1, to: 2, amount: 3, memo: None };
let bytes = encode_to_vec(&TransferAbiProjected::new(&source), encode_limits)?;
```

Every sequence length is checked transactionally. Underfill, overfill, projection failures, core
limit failures, and sink failures remain typed in `AbiEncodeError` and poison the encoder. All ABI
entry points require explicit `EncodeLimits`; `encode_to_sink` can target `CountingSink`,
`DigestSink`, `FanoutSink`, or an application sink without staging canonical bytes in a `Vec`.

## Context-aware owned admission

`decode` and `decode_canonical` require one explicit `AbiDecodeContext`, threaded through every
recursive field and element. `admit` receives a stable type/variant/field location and a typed value
event after canonical headers, lengths, and core limits succeed but before the first owned
reservation or payload copy. This lets a protocol enforce aggregate record and byte budgets in the
same decode pass without a preflight traversal or a temporary ABI object tree.

Use `&mut ()` when the core `DecodeLimits` are the complete policy. A custom context chooses which
semantic locations to charge and returns its own typed error through `type Error: From<CborError>`.
Borrowed `&str`, `BytesRef`, and `CanonicalCborRef` fields are zero-copy and do not emit owned
admission events. Truncated or invalid payloads can fail after an admission event, so a stateful
context is transaction state and must be discarded or rolled back when decoding returns an error.

## Zero-copy views

`#[derive(CborAbi)]` also generates a borrowed `TypeView<'a>` for read-heavy paths:

```rust
let canon = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
let view = TransferView::from_canonical(canon.as_canonical_ref())?;

assert_eq!(view.amount()?, 5000);
assert_eq!(view.memo()?, None);

let raw_amount = view.amount_raw()?;
assert_eq!(raw_amount.as_bytes(), &[0x19, 0x13, 0x88]); // 5000

let owned_again = view.to_owned(&mut context)?;
assert_eq!(owned_again, value);
```

View construction validates the ABI shell, required fields, ID order, and unknown-field policy.
Accessors decode only the selected payload. Raw accessors return borrowed canonical sub-values for
forwarding, routing, and patching.

Borrowed accessor mapping:

- `String` and `&str` fields return `&'a str`.
- `Bytes` and `BytesRef` fields return `BytesRef<'a>`.
- `CanonicalCbor` and `CanonicalCborRef` fields return `CanonicalCborRef<'a>`.
- `Vec<T>` fields return `AbiArrayView<'a, T>`.
- Nested ABI types return their generated nested views.
- `Option<T>` is represented by field presence and returns `Option<T::View>`.

## Runtime field-set views

Runtime systems can validate and inspect field-set values from a `Schema` without a generated Rust
type. `RuntimeSchema::new` is a constant-time, allocation-free view over the derive-owned static
descriptor; there is no sorting or runtime schema compilation phase:

```rust
use sacp_cbor_abi::{
    NoNamedSchemas, RuntimeSchema, RuntimeValidationLimits, RuntimeValidationWorkspace,
};

let runtime = match RuntimeSchema::new(Transfer::schema()) {
    RuntimeSchema::Struct(runtime) => runtime,
    _ => unreachable!("Transfer is a struct schema"),
};

let canon = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len()))?;

// Shell-only validation checks field-set shape, required fields, ordering, duplicates,
// and unknown-field policy.
let view = runtime.view_value(canon.as_canonical_ref().root())?;

let raw_amount = view.require_raw(3)?;
assert_eq!(raw_amount.integer()?.as_u128(), Some(5000));

// Deep validation checks every known TypeRef with explicit work bounds. Prepare once and reuse
// the workspace; the runtime validation machine does not grow the machine stack or allocate
// validation frames while checking a value.
let limits = RuntimeValidationLimits::new(
    16,    // nested named/vector/enum-payload depth
    1_024, // validation-machine steps
    1_024, // visited container items
    32,    // simultaneously live continuation frames
);
let mut workspace = RuntimeValidationWorkspace::new();
workspace.prepare(limits)?;
let checked = runtime.validate_value(
    canon.as_canonical_ref().root(),
    &NoNamedSchemas,
    limits,
    &mut workspace,
)?;
assert_eq!(checked.require_raw(3)?.integer()?.as_u128(), Some(5000));
```

## Enums

Enums encode as `[variant_id, payload]`. Unit variants use `null`; named variants use field-set
payloads:

```rust
use sacp_cbor_abi::{CborAbi, UnknownVariant};

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(type_id = "ledger.Command", version = 1)]
enum Command {
    #[abi(id = 1)]
    Route {
        #[abi(id = 1)]
        transfer_id: String,
        #[abi(id = 2)]
        priority: u64,
    },
    #[abi(id = 2)]
    Ping,
    #[abi(unknown)]
    Unknown(UnknownVariant),
}
```

Unknown enum variants are rejected unless the enum has one `#[abi(unknown)]` variant. Preserved
unknown variants retain the numeric variant ID and canonical payload.

## Unknown fields

Unknown fields can be rejected, ignored, or preserved:

```rust
use sacp_cbor_abi::{CborAbi, UnknownFields};

#[derive(Debug, PartialEq, Eq, CborAbi)]
#[abi(
    type_id = "ledger.TransferEnvelope",
    version = 1,
    unknown_fields = "preserve"
)]
struct TransferEnvelope {
    #[abi(id = 1)]
    transfer: Transfer,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}
```

Owned decode stores preserved unknown fields as owned canonical values. Generated views expose
borrowed `UnknownFieldRef<'a>` values, so forwarding and patching do not need to copy unknown
payloads.

## Schema compatibility

Rust names are diagnostic metadata. Wire identity comes from `type_id`, numeric IDs, field presence,
and stable `TypeRef` values.

```rust
use sacp_cbor_abi::{AbiType, CborAbi, CompatibilityClass, UnknownFields};

#[derive(CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 1, unknown_fields = "preserve")]
struct TransferV1 {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

#[derive(CborAbi)]
#[abi(type_id = "ledger.Transfer", version = 2, unknown_fields = "preserve")]
struct TransferV2 {
    #[abi(id = 1)]
    from: u64,
    #[abi(id = 2)]
    to: u64,
    #[abi(id = 3)]
    amount: u64,
    #[abi(id = 4, optional)]
    memo: Option<String>,
    #[abi(unknown_fields)]
    unknown: UnknownFields,
}

let report = sacp_cbor_abi::diff(TransferV1::schema(), TransferV2::schema());
assert_eq!(report.new_reads_old, CompatibilityClass::Compatible);
assert_eq!(report.old_reads_new, CompatibilityClass::Compatible);
assert_eq!(report.old_preserves_new, CompatibilityClass::Compatible);
```

## Facade crates

Generated code can be routed through facade modules:

```rust
pub mod wire {
    pub mod abi {
        pub use sacp_cbor_abi::*;
    }
    pub mod cbor {
        pub use sacp_cbor::{
            ByteSink, CanonicalCbor, CborDecode, CborError, Decoder, ErrorCode, ValueEncoder,
        };
    }
}

use crate::wire::abi::CborAbi;

#[derive(CborAbi)]
#[abi(
    crate = crate::wire::abi,
    cbor = crate::wire::cbor,
    type_id = "facade.Transfer",
    version = 1
)]
struct FacadeTransfer {
    #[abi(id = 1)]
    amount: u64,
}
```

## API choice

Use owned `encode_to_vec`, `decode`, and `decode_canonical` when business logic already owns the
declared Rust value. Use generated projections when data lives in another business model, a slice,
an indexed source, or a source-driven stream and must not be copied into an ABI DTO. Use generated
views for routing, filtering, forwarding, patching, and other hot paths that read only a subset of
fields. With default features disabled, the runtime remains `no_std` with `alloc` for owned values,
diff reports, and caller-prepared validation workspaces; static schemas and their runtime views use
only `&'static` descriptors.
