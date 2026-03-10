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
use syn::{parse_macro_input, spanned::Spanned, Data, DataEnum, DeriveInput, Ident};

use crate::attrs::parse_cbor_enum_attrs;
use crate::cbor_bytes::expand as expand_cbor_bytes;
use crate::decode::{decode_enum, decode_struct};
use crate::encode::{encode_enum, encode_struct};

fn ensure_non_empty_enum(name: &Ident, data: &DataEnum, derive_name: &str) -> syn::Result<()> {
    if data.variants.is_empty() {
        return Err(syn::Error::new(
            name.span(),
            format!("{derive_name} does not support empty enums"),
        ));
    }

    Ok(())
}

#[proc_macro_derive(CborEncode, attributes(cbor))]
/// Derive canonical CBOR encoding for structs and enums.
pub fn derive_cbor_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let out = (|| -> syn::Result<proc_macro2::TokenStream> {
        match &input.data {
            Data::Struct(data) => encode_struct(&input.ident, &input.generics, data),
            Data::Enum(data) => {
                ensure_non_empty_enum(&input.ident, data, "CborEncode")?;
                let attrs = parse_cbor_enum_attrs(&input.attrs)?;
                encode_enum(&input.ident, &input.generics, data, &attrs)
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
                ensure_non_empty_enum(&input.ident, data, "CborDecode")?;
                let attrs = parse_cbor_enum_attrs(&input.attrs)?;
                decode_enum(&input.ident, &input.generics, data, &attrs)
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
