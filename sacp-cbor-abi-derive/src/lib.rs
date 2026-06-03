//! Derive macros for `sacp-cbor-abi`.

#![deny(clippy::all)]
#![deny(missing_docs)]

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DataStruct, DeriveInput, Field,
    Fields, GenericArgument, Ident, LitInt, LitStr, PathArguments, Type,
};

#[derive(Clone, Copy)]
enum UnknownPolicy {
    Reject,
    Ignore,
}

impl UnknownPolicy {
    fn tokens(self) -> proc_macro2::TokenStream {
        match self {
            Self::Reject => quote!(::sacp_cbor_abi::UnknownFieldPolicy::Reject),
            Self::Ignore => quote!(::sacp_cbor_abi::UnknownFieldPolicy::Ignore),
        }
    }
}

struct ContainerAttr {
    type_id: LitStr,
    version: u32,
    unknown_fields: UnknownPolicy,
}

struct FieldAttr {
    id: Option<u32>,
    optional: bool,
}

struct VariantAttr {
    id: Option<u32>,
}

struct FieldSpec<'a> {
    ident: &'a Ident,
    id: u32,
    ty: &'a Type,
    wire_ty: &'a Type,
    ty_name: String,
    optional: bool,
}

struct VariantSpec<'a> {
    ident: &'a Ident,
    id: u32,
    fields: Vec<FieldSpec<'a>>,
    unit: bool,
}

#[proc_macro_derive(CborAbi, attributes(abi))]
/// Derive stable ABI encode, decode, and schema metadata.
pub fn derive_cbor_abi(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let out = (|| -> syn::Result<proc_macro2::TokenStream> {
        if !input.generics.params.is_empty() || input.generics.where_clause.is_some() {
            return Err(syn::Error::new(
                input.generics.span(),
                "CborAbi does not support generic public ABI types",
            ));
        }
        let attrs = parse_container_attrs(&input.attrs)?;
        match &input.data {
            Data::Struct(data) => derive_struct(&input.ident, data, &attrs),
            Data::Enum(data) => derive_enum(&input.ident, data, &attrs),
            Data::Union(u) => Err(syn::Error::new(
                u.union_token.span(),
                "CborAbi does not support unions",
            )),
        }
    })();

    match out {
        Ok(ts) => ts.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn parse_container_attrs(attrs: &[Attribute]) -> syn::Result<ContainerAttr> {
    let mut type_id = None;
    let mut version = None;
    let mut unknown_fields = UnknownPolicy::Reject;
    let mut transparent = false;

    for attr in attrs {
        if !attr.path().is_ident("abi") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("type_id") {
                if type_id.is_some() {
                    return Err(meta.error("duplicate `abi(type_id=...)`"));
                }
                type_id = Some(meta.value()?.parse::<LitStr>()?);
                return Ok(());
            }
            if meta.path.is_ident("version") {
                if version.is_some() {
                    return Err(meta.error("duplicate `abi(version=...)`"));
                }
                version = Some(parse_u32_lit(&meta.value()?.parse::<LitInt>()?)?);
                return Ok(());
            }
            if meta.path.is_ident("unknown_fields") {
                let lit = meta.value()?.parse::<LitStr>()?;
                unknown_fields = match lit.value().as_str() {
                    "reject" => UnknownPolicy::Reject,
                    "ignore" => UnknownPolicy::Ignore,
                    _ => {
                        return Err(syn::Error::new(
                            lit.span(),
                            "unknown_fields must be `reject` or `ignore`",
                        ))
                    }
                };
                return Ok(());
            }
            if meta.path.is_ident("transparent") {
                transparent = true;
                return Ok(());
            }
            Err(meta.error("unsupported `abi(...)` container attribute"))
        })?;
    }

    if transparent {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "`abi(transparent)` is reserved and is not implemented yet",
        ));
    }

    let type_id = type_id.ok_or_else(|| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            "missing `abi(type_id = \"...\")`",
        )
    })?;
    let version = version.ok_or_else(|| {
        syn::Error::new(proc_macro2::Span::call_site(), "missing `abi(version = N)`")
    })?;

    Ok(ContainerAttr {
        type_id,
        version,
        unknown_fields,
    })
}

fn parse_field_attrs(field: &Field) -> syn::Result<FieldAttr> {
    let mut id = None;
    let mut optional = false;
    for attr in &field.attrs {
        if !attr.path().is_ident("abi") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("id") {
                if id.is_some() {
                    return Err(meta.error("duplicate `abi(id=...)`"));
                }
                id = Some(parse_u32_lit(&meta.value()?.parse::<LitInt>()?)?);
                return Ok(());
            }
            if meta.path.is_ident("optional") {
                if optional {
                    return Err(meta.error("duplicate `abi(optional)`"));
                }
                optional = true;
                return Ok(());
            }
            Err(meta.error("unsupported `abi(...)` field attribute"))
        })?;
    }
    Ok(FieldAttr { id, optional })
}

fn parse_variant_attrs(variant: &syn::Variant) -> syn::Result<VariantAttr> {
    let mut id = None;
    for attr in &variant.attrs {
        if !attr.path().is_ident("abi") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("id") {
                if id.is_some() {
                    return Err(meta.error("duplicate `abi(id=...)`"));
                }
                id = Some(parse_u32_lit(&meta.value()?.parse::<LitInt>()?)?);
                return Ok(());
            }
            Err(meta.error("unsupported `abi(...)` variant attribute"))
        })?;
    }
    Ok(VariantAttr { id })
}

fn parse_u32_lit(lit: &LitInt) -> syn::Result<u32> {
    let value = lit.base10_parse::<u32>()?;
    if value == 0 {
        return Err(syn::Error::new(lit.span(), "ABI IDs must be nonzero"));
    }
    Ok(value)
}

fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let last = path.path.segments.last()?;
    if last.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    match args.args.first()? {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

fn named_field_specs(fields: &syn::FieldsNamed) -> syn::Result<Vec<FieldSpec<'_>>> {
    let mut out = Vec::new();
    let mut seen = Vec::<u32>::new();
    for field in &fields.named {
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new(field.span(), "expected named field"))?;
        let attr = parse_field_attrs(field)?;
        let id = attr
            .id
            .ok_or_else(|| syn::Error::new(field.span(), "missing `abi(id = N)`"))?;
        if seen.contains(&id) {
            return Err(syn::Error::new(
                field.span(),
                format!("duplicate ABI field ID `{id}`"),
            ));
        }
        seen.push(id);

        let inner = option_inner(&field.ty);
        if attr.optional && inner.is_none() {
            return Err(syn::Error::new(
                field.ty.span(),
                "`abi(optional)` requires `Option<T>`",
            ));
        }
        if !attr.optional && inner.is_some() {
            return Err(syn::Error::new(
                field.ty.span(),
                "required `Option<T>` fields are not allowed; add `abi(optional)` or use a non-Option type",
            ));
        }
        let wire_ty = inner.unwrap_or(&field.ty);
        out.push(FieldSpec {
            ident,
            id,
            ty: &field.ty,
            wire_ty,
            ty_name: wire_ty.to_token_stream().to_string(),
            optional: attr.optional,
        });
    }
    out.sort_by_key(|field| field.id);
    Ok(out)
}

fn derive_struct(
    name: &Ident,
    data: &DataStruct,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "public ABI structs must use named fields; tuple structs require an explicit transparent ABI design",
        ));
    };
    let fields = named_field_specs(fields)?;
    let encode = encode_struct_body(&fields, quote!(self));
    let decode = decode_field_set_body(&fields, attrs.unknown_fields, quote!(Self));
    let schema = schema_struct_tokens(attrs, &fields);

    Ok(quote! {
        impl ::sacp_cbor_abi::AbiEncode for #name {
            fn abi_encode(
                &self,
                enc: &mut ::sacp_cbor_abi::__private::sacp_cbor::Encoder,
            ) -> ::core::result::Result<(), ::sacp_cbor_abi::__private::sacp_cbor::CborError> {
                #encode
            }
        }

        impl<'__abi> ::sacp_cbor_abi::AbiDecode<'__abi> for #name {
            fn abi_decode<const CHECKED: bool>(
                decoder: &mut ::sacp_cbor_abi::__private::sacp_cbor::Decoder<'__abi, CHECKED>,
            ) -> ::core::result::Result<Self, ::sacp_cbor_abi::__private::sacp_cbor::CborError> {
                #decode
            }
        }

        impl ::sacp_cbor_abi::AbiType for #name {
            fn schema() -> ::sacp_cbor_abi::Schema {
                #schema
            }
        }
    })
}

fn derive_enum(
    name: &Ident,
    data: &DataEnum,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    if data.variants.is_empty() {
        return Err(syn::Error::new(
            name.span(),
            "CborAbi does not support empty enums",
        ));
    }

    let variants = enum_variant_specs(data)?;
    let encode = encode_enum_body(&variants);
    let decode = decode_enum_body(&variants, attrs.unknown_fields);
    let schema = schema_enum_tokens(attrs, &variants);

    Ok(quote! {
        impl ::sacp_cbor_abi::AbiEncode for #name {
            fn abi_encode(
                &self,
                enc: &mut ::sacp_cbor_abi::__private::sacp_cbor::Encoder,
            ) -> ::core::result::Result<(), ::sacp_cbor_abi::__private::sacp_cbor::CborError> {
                #encode
            }
        }

        impl<'__abi> ::sacp_cbor_abi::AbiDecode<'__abi> for #name {
            fn abi_decode<const CHECKED: bool>(
                decoder: &mut ::sacp_cbor_abi::__private::sacp_cbor::Decoder<'__abi, CHECKED>,
            ) -> ::core::result::Result<Self, ::sacp_cbor_abi::__private::sacp_cbor::CborError> {
                #decode
            }
        }

        impl ::sacp_cbor_abi::AbiType for #name {
            fn schema() -> ::sacp_cbor_abi::Schema {
                #schema
            }
        }
    })
}

fn enum_variant_specs(data: &DataEnum) -> syn::Result<Vec<VariantSpec<'_>>> {
    let mut out = Vec::new();
    let mut seen = Vec::<u32>::new();
    for variant in &data.variants {
        let attr = parse_variant_attrs(variant)?;
        let id = attr
            .id
            .ok_or_else(|| syn::Error::new(variant.span(), "missing `abi(id = N)` on variant"))?;
        if seen.contains(&id) {
            return Err(syn::Error::new(
                variant.span(),
                format!("duplicate ABI variant ID `{id}`"),
            ));
        }
        seen.push(id);

        match &variant.fields {
            Fields::Unit => out.push(VariantSpec {
                ident: &variant.ident,
                id,
                fields: Vec::new(),
                unit: true,
            }),
            Fields::Named(fields) => out.push(VariantSpec {
                ident: &variant.ident,
                id,
                fields: named_field_specs(fields)?,
                unit: false,
            }),
            Fields::Unnamed(fields) => {
                return Err(syn::Error::new(
                    fields.span(),
                    "public ABI enum variants must be unit or named-field variants",
                ))
            }
        }
    }
    out.sort_by_key(|variant| variant.id);
    Ok(out)
}

fn encode_struct_body(
    fields: &[FieldSpec<'_>],
    self_expr: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let len_terms = fields.iter().map(|field| {
        let ident = field.ident;
        if field.optional {
            quote! { + if #self_expr.#ident.is_some() { 2 } else { 0 } }
        } else {
            quote! { + 2 }
        }
    });
    let writes = fields.iter().map(|field| {
        let ident = field.ident;
        let id = field.id;
        if field.optional {
            quote! {
                if let ::core::option::Option::Some(__abi_value) = &#self_expr.#ident {
                    __abi_encode_id(__abi_array, #id)?;
                    __abi_array.value_with(|enc| {
                        ::sacp_cbor_abi::AbiEncode::abi_encode(__abi_value, enc)
                    })?;
                }
            }
        } else {
            quote! {
                __abi_encode_id(__abi_array, #id)?;
                __abi_array.value_with(|enc| {
                    ::sacp_cbor_abi::AbiEncode::abi_encode(&#self_expr.#ident, enc)
                })?;
            }
        }
    });
    quote! {
        fn __abi_encode_id(
            array: &mut ::sacp_cbor_abi::__private::sacp_cbor::encode::ArrayEncoder<'_>,
            id: u32,
        ) -> ::core::result::Result<(), ::sacp_cbor_abi::__private::sacp_cbor::CborError> {
            array.value_with(|enc| {
                ::sacp_cbor_abi::__private::sacp_cbor::CborEncode::encode(&id, enc)
            })
        }

        let __abi_len = 0usize #(#len_terms)*;
        enc.array(__abi_len, |__abi_array| {
            #(#writes)*
            ::core::result::Result::Ok(())
        })
    }
}

fn decode_field_set_body(
    fields: &[FieldSpec<'_>],
    unknown: UnknownPolicy,
    target: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let storage_decls = fields.iter().map(|field| {
        let ident = storage_ident(field.ident);
        let ty = field.ty;
        quote! { let mut #ident: ::core::option::Option<#ty> = ::core::option::Option::None; }
    });
    let match_arms = fields.iter().map(|field| {
        let id = field.id;
        let storage = storage_ident(field.ident);
        let decode_ty = field.wire_ty;
        if field.optional {
            quote! {
                #id => {
                    if #storage.is_some() {
                        return Err(::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                            ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::DuplicateMapKey,
                            __abi_id_off,
                        ));
                    }
                    let __abi_value: #decode_ty = __abi_next_value(&mut __abi_array, __abi_arr_off)?;
                    #storage = ::core::option::Option::Some(::core::option::Option::Some(__abi_value));
                }
            }
        } else {
            quote! {
                #id => {
                    if #storage.is_some() {
                        return Err(::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                            ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::DuplicateMapKey,
                            __abi_id_off,
                        ));
                    }
                    #storage = ::core::option::Option::Some(
                        __abi_next_value(&mut __abi_array, __abi_arr_off)?
                    );
                }
            }
        }
    });
    let unknown_arm = match unknown {
        UnknownPolicy::Reject => quote! {
            _ => {
                return Err(::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                    ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::UnknownField,
                    __abi_id_off,
                ));
            }
        },
        UnknownPolicy::Ignore => quote! {
            _ => {
                let _: () = __abi_array.decode_next(|decoder| {
                    decoder.skip_value()?;
                    ::core::result::Result::Ok(())
                })?.ok_or_else(|| {
                    ::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                        ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::ArrayLenMismatch,
                        __abi_arr_off,
                    )
                })?;
            }
        },
    };
    let finals = fields.iter().map(|field| {
        let ident = field.ident;
        let storage = storage_ident(field.ident);
        if field.optional {
            quote! { #ident: #storage.unwrap_or(::core::option::Option::None), }
        } else {
            quote! {
                #ident: #storage.ok_or_else(|| {
                    ::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                        ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::MissingKey,
                        __abi_arr_off,
                    )
                })?,
            }
        }
    });

    quote! {
        fn __abi_next_value<'__abi, T, const CHECKED: bool>(
            array: &mut ::sacp_cbor_abi::__private::sacp_cbor::decode::ArrayDecoder<'_, '__abi, CHECKED>,
            arr_off: usize,
        ) -> ::core::result::Result<T, ::sacp_cbor_abi::__private::sacp_cbor::CborError>
        where
            T: ::sacp_cbor_abi::AbiDecode<'__abi>,
        {
            array.decode_next(::sacp_cbor_abi::AbiDecode::abi_decode)?.ok_or_else(|| {
                ::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                    ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::ArrayLenMismatch,
                    arr_off,
                )
            })
        }

        let __abi_arr_off = decoder.position();
        let mut __abi_array = decoder.array()?;
        if __abi_array.remaining() % 2 != 0 {
            return Err(::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::ArrayLenMismatch,
                __abi_arr_off,
            ));
        }
        #(#storage_decls)*
        let mut __abi_prev_id: ::core::option::Option<u32> = ::core::option::Option::None;
        while __abi_array.remaining() > 0 {
            let (__abi_id_off, __abi_id): (usize, u32) = __abi_array.decode_next(|decoder| {
                let off = decoder.position();
                let id = ::sacp_cbor_abi::__private::sacp_cbor::CborDecode::decode(decoder)?;
                ::core::result::Result::Ok((off, id))
            })?.ok_or_else(|| {
                ::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                    ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::ArrayLenMismatch,
                    __abi_arr_off,
                )
            })?;
            if let ::core::option::Option::Some(prev) = __abi_prev_id {
                if __abi_id == prev {
                    return Err(::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                        ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::DuplicateMapKey,
                        __abi_id_off,
                    ));
                }
                if __abi_id < prev {
                    return Err(::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                        ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::NonCanonicalMapOrder,
                        __abi_id_off,
                    ));
                }
            }
            __abi_prev_id = ::core::option::Option::Some(__abi_id);
            match __abi_id {
                #(#match_arms)*
                #unknown_arm
            }
        }
        ::core::result::Result::Ok(#target { #(#finals)* })
    }
}

fn encode_enum_body(variants: &[VariantSpec<'_>]) -> proc_macro2::TokenStream {
    let arms = variants.iter().map(|variant| {
        let ident = variant.ident;
        let id = variant.id;
        if variant.unit {
            quote! {
                Self::#ident => enc.array(2, |__abi_array| {
                    __abi_encode_id(__abi_array, #id)?;
                    __abi_array.null()?;
                    ::core::result::Result::Ok(())
                })
            }
        } else {
            let pats = variant.fields.iter().map(|field| field.ident);
            let body = encode_variant_payload(&variant.fields);
            quote! {
                Self::#ident { #(#pats),* } => enc.array(2, |__abi_array| {
                    __abi_encode_id(__abi_array, #id)?;
                    __abi_array.value_with(|enc| {
                        #body
                    })?;
                    ::core::result::Result::Ok(())
                })
            }
        }
    });
    quote! {
        fn __abi_encode_id(
            array: &mut ::sacp_cbor_abi::__private::sacp_cbor::encode::ArrayEncoder<'_>,
            id: u32,
        ) -> ::core::result::Result<(), ::sacp_cbor_abi::__private::sacp_cbor::CborError> {
            array.value_with(|enc| {
                ::sacp_cbor_abi::__private::sacp_cbor::CborEncode::encode(&id, enc)
            })
        }
        match self {
            #(#arms),*
        }
    }
}

fn encode_variant_payload(fields: &[FieldSpec<'_>]) -> proc_macro2::TokenStream {
    let len_terms = fields.iter().map(|field| {
        let ident = field.ident;
        if field.optional {
            quote! { + if #ident.is_some() { 2 } else { 0 } }
        } else {
            quote! { + 2 }
        }
    });
    let writes = fields.iter().map(|field| {
        let ident = field.ident;
        let id = field.id;
        if field.optional {
            quote! {
                if let ::core::option::Option::Some(__abi_value) = #ident {
                    __abi_encode_id(__abi_array, #id)?;
                    __abi_array.value_with(|enc| {
                        ::sacp_cbor_abi::AbiEncode::abi_encode(__abi_value, enc)
                    })?;
                }
            }
        } else {
            quote! {
                __abi_encode_id(__abi_array, #id)?;
                __abi_array.value_with(|enc| {
                    ::sacp_cbor_abi::AbiEncode::abi_encode(#ident, enc)
                })?;
            }
        }
    });
    quote! {
        let __abi_len = 0usize #(#len_terms)*;
        enc.array(__abi_len, |__abi_array| {
            #(#writes)*
            ::core::result::Result::Ok(())
        })
    }
}

fn decode_enum_body(
    variants: &[VariantSpec<'_>],
    unknown: UnknownPolicy,
) -> proc_macro2::TokenStream {
    let arms = variants.iter().map(|variant| {
        let ident = variant.ident;
        let id = variant.id;
        if variant.unit {
            quote! {
                #id => {
                    let _: () = __abi_array.decode_next(|decoder| {
                        ::sacp_cbor_abi::__private::sacp_cbor::CborDecode::decode(decoder)
                    })?.ok_or_else(|| {
                        ::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                            ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::ArrayLenMismatch,
                            __abi_arr_off,
                        )
                    })?;
                    ::core::result::Result::Ok(Self::#ident)
                }
            }
        } else {
            let body = decode_field_set_body(&variant.fields, unknown, quote!(Self::#ident));
            quote! {
                #id => {
                    let __abi_payload = __abi_array.decode_next(|decoder| {
                        #body
                    })?.ok_or_else(|| {
                        ::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                            ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::ArrayLenMismatch,
                            __abi_arr_off,
                        )
                    })?;
                    ::core::result::Result::Ok(__abi_payload)
                }
            }
        }
    });
    quote! {
        let __abi_arr_off = decoder.position();
        let mut __abi_array = decoder.array()?;
        if __abi_array.remaining() != 2 {
            return Err(::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::ArrayLenMismatch,
                __abi_arr_off,
            ));
        }
        let (__abi_id_off, __abi_id): (usize, u32) = __abi_array.decode_next(|decoder| {
            let off = decoder.position();
            let id = ::sacp_cbor_abi::__private::sacp_cbor::CborDecode::decode(decoder)?;
            ::core::result::Result::Ok((off, id))
        })?.ok_or_else(|| {
            ::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::ArrayLenMismatch,
                __abi_arr_off,
            )
        })?;
        match __abi_id {
            #(#arms,)*
            _ => Err(::sacp_cbor_abi::__private::sacp_cbor::CborError::new(
                ::sacp_cbor_abi::__private::sacp_cbor::ErrorCode::UnknownEnumVariant,
                __abi_id_off,
            )),
        }
    }
}

fn schema_struct_tokens(
    attrs: &ContainerAttr,
    fields: &[FieldSpec<'_>],
) -> proc_macro2::TokenStream {
    let type_id = &attrs.type_id;
    let version = attrs.version;
    let unknown = attrs.unknown_fields.tokens();
    let fields = field_defs_tokens(fields);
    quote! {
        ::sacp_cbor_abi::Schema::new(
            #type_id,
            #version,
            ::sacp_cbor_abi::TypeDef::Struct {
                fields: #fields,
                unknown_fields: #unknown,
            },
        )
    }
}

fn schema_enum_tokens(
    attrs: &ContainerAttr,
    variants: &[VariantSpec<'_>],
) -> proc_macro2::TokenStream {
    let type_id = &attrs.type_id;
    let version = attrs.version;
    let unknown = attrs.unknown_fields.tokens();
    let variants = variants.iter().map(|variant| {
        let id = variant.id;
        let name = variant.ident.to_string();
        let fields = field_defs_tokens(&variant.fields);
        quote! {
            ::sacp_cbor_abi::VariantDef {
                id: #id,
                name: ::sacp_cbor_abi::__private::String::from(#name),
                fields: #fields,
            }
        }
    });
    quote! {
        ::sacp_cbor_abi::Schema::new(
            #type_id,
            #version,
            ::sacp_cbor_abi::TypeDef::Enum {
                variants: ::sacp_cbor_abi::__private::vec![#(#variants),*],
                unknown_fields: #unknown,
            },
        )
    }
}

fn field_defs_tokens(fields: &[FieldSpec<'_>]) -> proc_macro2::TokenStream {
    let defs = fields.iter().map(|field| {
        let id = field.id;
        let name = field.ident.to_string();
        let ty = &field.ty_name;
        let optional = field.optional;
        quote! {
            ::sacp_cbor_abi::FieldDef {
                id: #id,
                name: ::sacp_cbor_abi::__private::String::from(#name),
                ty: ::sacp_cbor_abi::__private::String::from(#ty),
                optional: #optional,
            }
        }
    });
    quote! { ::sacp_cbor_abi::__private::vec![#(#defs),*] }
}

fn storage_ident(ident: &Ident) -> Ident {
    format_ident!("__abi_field_{ident}")
}
