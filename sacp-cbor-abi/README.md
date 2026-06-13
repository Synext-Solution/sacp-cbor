# sacp-cbor-abi

Stable public ABI schemas and codecs for [`sacp-cbor`](https://crates.io/crates/sacp-cbor).

Use this crate when bytes are part of a public protocol, durable storage format, or compatibility
contract. It gives the wire format stable numeric field and variant IDs instead of deriving identity
from Rust field names or module paths.

The examples below are mirrored by `tests/readme_examples.rs` in the repository.

## Install

```toml
[dependencies]
sacp-cbor = "0.17"
sacp-cbor-abi = "0.4"
```

The default `derive` feature exports `#[derive(CborAbi)]`. Disable default features only when using
the runtime schema/diff APIs without macro generation:

```toml
[dependencies]
sacp-cbor-abi = { version = "0.4", default-features = false }
```

## Struct ABI

```rust
use sacp_cbor::{CanonicalCbor, DecodeLimits};
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

let bytes = encode_to_vec(&value)?;
let decoded: Transfer = decode(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
assert_eq!(decoded, value);

let wire_hash = Transfer::schema().wire_hash()?;
let full_hash = Transfer::schema().full_hash()?;
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

## Zero-copy views

`#[derive(CborAbi)]` also generates a borrowed `TypeView<'a>` for read-heavy paths:

```rust
let canon = CanonicalCbor::from_slice(&bytes, DecodeLimits::for_bytes(bytes.len()))?;
let view = TransferView::from_canonical(canon.as_canonical_ref())?;

assert_eq!(view.amount()?, 5000);
assert_eq!(view.memo()?, None);

let raw_amount = view.amount_raw()?;
assert_eq!(raw_amount.as_bytes(), &[0x19, 0x13, 0x88]); // 5000

let owned_again = view.to_owned()?;
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

let report = sacp_cbor_abi::diff(&TransferV1::schema(), &TransferV2::schema());
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
            CanonicalCbor, CborDecode, CborError, Decoder, Encoder, ErrorCode,
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

Use owned `encode_to_vec`, `decode`, and `decode_canonical` when business logic needs an owned Rust
value or will re-encode the whole object. Use generated views for routing, filtering, forwarding,
patching, and other hot paths that read only a subset of fields.
