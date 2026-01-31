//! Procedural macro derives for `sacp-cbor`.

#![deny(clippy::all)]
#![deny(missing_docs)]

extern crate proc_macro;

mod attrs;
mod cbor_bytes;
mod decode;
mod encode;
mod types;
mod util;

use proc_macro::TokenStream;
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput};

use crate::attrs::{parse_cbor_enum_attrs, EnumTagging};
use crate::cbor_bytes::expand as expand_cbor_bytes;
use crate::decode::{decode_enum, decode_enum_untagged, decode_struct};
use crate::encode::{encode_enum, encode_enum_untagged, encode_struct};

#[proc_macro_derive(CborEncode, attributes(cbor))]
/// Derive canonical CBOR encoding for structs and enums.
pub fn derive_cbor_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let out = (|| -> syn::Result<proc_macro2::TokenStream> {
        match &input.data {
            Data::Struct(data) => encode_struct(&input.ident, &input.generics, data),
            Data::Enum(data) => {
                let tagging = parse_cbor_enum_attrs(&input.attrs)?;
                match tagging {
                    EnumTagging::Untagged => {
                        encode_enum_untagged(&input.ident, &input.generics, data)
                    }
                    EnumTagging::Tagged => encode_enum(&input.ident, &input.generics, data),
                }
            }
            Data::Union(u) => Err(syn::Error::new(
                u.union_token.span(),
                "CborEncode not supported for unions",
            )),
        }
    })();

    match out {
        Ok(ts) => TokenStream::from(ts),
        Err(e) => TokenStream::from(e.to_compile_error()),
    }
}

#[proc_macro_derive(CborDecode, attributes(cbor))]
/// Derive canonical CBOR decoding for structs and enums.
pub fn derive_cbor_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let out = (|| -> syn::Result<proc_macro2::TokenStream> {
        match &input.data {
            Data::Struct(data) => decode_struct(&input.ident, &input.generics, data),
            Data::Enum(data) => {
                let tagging = parse_cbor_enum_attrs(&input.attrs)?;
                match tagging {
                    EnumTagging::Untagged => {
                        decode_enum_untagged(&input.ident, &input.generics, data)
                    }
                    EnumTagging::Tagged => decode_enum(&input.ident, &input.generics, data),
                }
            }
            Data::Union(u) => Err(syn::Error::new(
                u.union_token.span(),
                "CborDecode not supported for unions",
            )),
        }
    })();

    match out {
        Ok(ts) => TokenStream::from(ts),
        Err(e) => TokenStream::from(e.to_compile_error()),
    }
}

/// Construct canonical CBOR bytes with a JSON-like literal syntax.
#[proc_macro]
pub fn cbor_bytes(input: TokenStream) -> TokenStream {
    expand_cbor_bytes(input)
}
