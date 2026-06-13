//! Derive macros for `sacp-cbor-abi`.

#![deny(clippy::all)]
#![deny(missing_docs)]

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::fold::{self, Fold};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DataStruct, DeriveInput, Field,
    Fields, GenericArgument, GenericParam, Generics, Ident, Lifetime, LitInt, LitStr, Path,
    PathArguments, Type,
};

mod view;

use view::{derive_enum_view, derive_struct_view};

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnknownFieldMode {
    Reject,
    Ignore,
    Preserve,
}

impl UnknownFieldMode {
    fn tokens(self, abi_path: &Path) -> proc_macro2::TokenStream {
        match self {
            Self::Reject => quote!(#abi_path::UnknownFieldPolicy::Reject),
            Self::Ignore => quote!(#abi_path::UnknownFieldPolicy::Ignore),
            Self::Preserve => quote!(#abi_path::UnknownFieldPolicy::Preserve),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnknownVariantMode {
    Reject,
    Preserve,
}

impl UnknownVariantMode {
    fn tokens(self, abi_path: &Path) -> proc_macro2::TokenStream {
        match self {
            Self::Reject => quote!(#abi_path::UnknownVariantPolicy::Reject),
            Self::Preserve => quote!(#abi_path::UnknownVariantPolicy::Preserve),
        }
    }
}

struct ContainerAttr {
    abi_path: Path,
    cbor_path: Path,
    type_id: LitStr,
    version: u32,
    unknown_fields: UnknownFieldMode,
    unknown_variants: Option<UnknownVariantMode>,
    transparent: bool,
    try_from: Option<Path>,
}

struct FieldAttr {
    id: Option<u32>,
    optional: bool,
    ty: Option<LitStr>,
    ty_version: Option<u32>,
    unknown_fields: bool,
}

struct VariantAttr {
    id: Option<u32>,
    unknown: bool,
}

struct FieldSpec<'a> {
    ident: &'a Ident,
    id: u32,
    wire_ty: &'a Type,
    decode_ty: Type,
    decode_wire_ty: Type,
    optional: bool,
    ty_override: Option<LitStr>,
    ty_version: Option<u32>,
}

struct FieldSetSpec<'a> {
    fields: Vec<FieldSpec<'a>>,
    unknown_field: Option<&'a Ident>,
}

struct VariantSpec<'a> {
    ident: &'a Ident,
    id: u32,
    fields: FieldSetSpec<'a>,
    unit: bool,
}

struct UnknownVariantSpec<'a> {
    ident: &'a Ident,
}

#[proc_macro_derive(CborAbi, attributes(abi))]
/// Derive stable ABI encode, decode, and schema metadata.
pub fn derive_cbor_abi(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let out = (|| -> syn::Result<proc_macro2::TokenStream> {
        validate_generics(&input.generics)?;
        let attrs = parse_container_attrs(&input.attrs)?;
        let codec = match &input.data {
            Data::Struct(data) => derive_struct(&input.ident, &input.generics, data, &attrs),
            Data::Enum(data) => derive_enum(&input.ident, &input.generics, data, &attrs),
            Data::Union(u) => Err(syn::Error::new(
                u.union_token.span(),
                "CborAbi does not support unions",
            )),
        }?;
        let view = match &input.data {
            Data::Struct(data) => {
                derive_struct_view(&input.vis, &input.ident, &input.generics, data, &attrs)
            }
            Data::Enum(data) => {
                derive_enum_view(&input.vis, &input.ident, &input.generics, data, &attrs)
            }
            Data::Union(u) => Err(syn::Error::new(
                u.union_token.span(),
                "CborAbi does not support unions",
            )),
        }?;
        Ok(quote! {
            #codec
            #view
        })
    })();

    match out {
        Ok(ts) => ts.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn validate_generics(generics: &Generics) -> syn::Result<()> {
    if generics.where_clause.is_some()
        || generics
            .params
            .iter()
            .any(|param| !matches!(param, GenericParam::Lifetime(_)))
    {
        return Err(syn::Error::new(
            generics.span(),
            "CborAbi supports lifetimes but not type parameters, const parameters, or where clauses",
        ));
    }
    Ok(())
}

fn decode_ty_generics(generics: &Generics) -> proc_macro2::TokenStream {
    let count = generics.lifetimes().count();
    if count == 0 {
        quote! {}
    } else {
        let lifetimes = (0..count).map(|_| quote!('__sacp_abi));
        quote!(<#(#lifetimes),*>)
    }
}

fn ty_generics_with_lifetime(generics: &Generics, lifetime: &Lifetime) -> proc_macro2::TokenStream {
    let count = generics.lifetimes().count();
    if count == 0 {
        quote! {}
    } else {
        let lifetimes = (0..count).map(|_| quote!(#lifetime));
        quote!(<#(#lifetimes),*>)
    }
}

fn decode_type(ty: &Type) -> Type {
    struct DecodeLifetime;

    impl Fold for DecodeLifetime {
        fn fold_lifetime(&mut self, _: Lifetime) -> Lifetime {
            syn::parse_quote!('__sacp_abi)
        }

        fn fold_type_reference(&mut self, mut node: syn::TypeReference) -> syn::TypeReference {
            if node.lifetime.is_none() {
                node.lifetime = Some(syn::parse_quote!('__sacp_abi));
            }
            fold::fold_type_reference(self, node)
        }
    }

    DecodeLifetime.fold_type(ty.clone())
}

fn view_type(ty: &Type, lifetime: &Lifetime) -> Type {
    struct ViewLifetime {
        lifetime: Lifetime,
    }

    impl Fold for ViewLifetime {
        fn fold_lifetime(&mut self, _: Lifetime) -> Lifetime {
            self.lifetime.clone()
        }

        fn fold_type_reference(&mut self, mut node: syn::TypeReference) -> syn::TypeReference {
            node.lifetime = Some(self.lifetime.clone());
            fold::fold_type_reference(self, node)
        }
    }

    ViewLifetime {
        lifetime: lifetime.clone(),
    }
    .fold_type(ty.clone())
}

fn parse_container_attrs(attrs: &[Attribute]) -> syn::Result<ContainerAttr> {
    let mut abi_path = None;
    let mut cbor_path = None;
    let mut type_id = None;
    let mut version = None;
    let mut unknown_fields = UnknownFieldMode::Reject;
    let mut unknown_variants = None;
    let mut transparent = false;
    let mut try_from = None;

    for attr in attrs {
        if !attr.path().is_ident("abi") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("crate") {
                if abi_path.is_some() {
                    return Err(meta.error("duplicate `abi(crate=...)`"));
                }
                abi_path = Some(meta.value()?.parse::<Path>()?);
                return Ok(());
            }
            if meta.path.is_ident("cbor") {
                if cbor_path.is_some() {
                    return Err(meta.error("duplicate `abi(cbor=...)`"));
                }
                cbor_path = Some(meta.value()?.parse::<Path>()?);
                return Ok(());
            }
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
                    "reject" => UnknownFieldMode::Reject,
                    "ignore" => UnknownFieldMode::Ignore,
                    "preserve" => UnknownFieldMode::Preserve,
                    _ => {
                        return Err(syn::Error::new(
                            lit.span(),
                            "unknown_fields must be `reject`, `ignore`, or `preserve`",
                        ))
                    }
                };
                return Ok(());
            }
            if meta.path.is_ident("unknown_variants") {
                if unknown_variants.is_some() {
                    return Err(meta.error("duplicate `abi(unknown_variants=...)`"));
                }
                let lit = meta.value()?.parse::<LitStr>()?;
                unknown_variants = Some(match lit.value().as_str() {
                    "reject" => UnknownVariantMode::Reject,
                    "preserve" => UnknownVariantMode::Preserve,
                    _ => {
                        return Err(syn::Error::new(
                            lit.span(),
                            "unknown_variants must be `reject` or `preserve`",
                        ))
                    }
                });
                return Ok(());
            }
            if meta.path.is_ident("transparent") {
                if transparent {
                    return Err(meta.error("duplicate `abi(transparent)`"));
                }
                transparent = true;
                return Ok(());
            }
            if meta.path.is_ident("try_from") {
                if try_from.is_some() {
                    return Err(meta.error("duplicate `abi(try_from=...)`"));
                }
                let lit = meta.value()?.parse::<LitStr>()?;
                try_from = Some(lit.parse::<Path>()?);
                return Ok(());
            }
            Err(meta.error("unsupported `abi(...)` container attribute"))
        })?;
    }

    if try_from.is_some() && !transparent {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "`abi(try_from=...)` requires `abi(transparent)`",
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
        abi_path: abi_path.unwrap_or_else(|| syn::parse_quote!(::sacp_cbor_abi)),
        cbor_path: cbor_path
            .unwrap_or_else(|| syn::parse_quote!(::sacp_cbor_abi::__private::sacp_cbor)),
        type_id,
        version,
        unknown_fields,
        unknown_variants,
        transparent,
        try_from,
    })
}

fn parse_field_attrs(field: &Field) -> syn::Result<FieldAttr> {
    let mut id = None;
    let mut optional = false;
    let mut ty = None;
    let mut ty_version = None;
    let mut unknown_fields = false;

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
            if meta.path.is_ident("ty") {
                if ty.is_some() {
                    return Err(meta.error("duplicate `abi(ty=...)`"));
                }
                ty = Some(meta.value()?.parse::<LitStr>()?);
                return Ok(());
            }
            if meta.path.is_ident("ty_version") {
                if ty_version.is_some() {
                    return Err(meta.error("duplicate `abi(ty_version=...)`"));
                }
                ty_version = Some(parse_u32_lit(&meta.value()?.parse::<LitInt>()?)?);
                return Ok(());
            }
            if meta.path.is_ident("unknown_fields") {
                if unknown_fields {
                    return Err(meta.error("duplicate `abi(unknown_fields)`"));
                }
                unknown_fields = true;
                return Ok(());
            }
            Err(meta.error("unsupported `abi(...)` field attribute"))
        })?;
    }

    if ty_version.is_some() && ty.is_none() {
        return Err(syn::Error::new(
            field.span(),
            "`abi(ty_version=...)` requires `abi(ty=...)`",
        ));
    }

    Ok(FieldAttr {
        id,
        optional,
        ty,
        ty_version,
        unknown_fields,
    })
}

fn parse_variant_attrs(variant: &syn::Variant) -> syn::Result<VariantAttr> {
    let mut id = None;
    let mut unknown = false;

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
            if meta.path.is_ident("unknown") {
                if unknown {
                    return Err(meta.error("duplicate `abi(unknown)`"));
                }
                unknown = true;
                return Ok(());
            }
            Err(meta.error("unsupported `abi(...)` variant attribute"))
        })?;
    }

    Ok(VariantAttr { id, unknown })
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

fn named_field_specs(fields: &syn::FieldsNamed) -> syn::Result<FieldSetSpec<'_>> {
    let mut out = Vec::new();
    let mut unknown_field = None;
    let mut seen = Vec::<u32>::new();

    for field in &fields.named {
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| syn::Error::new(field.span(), "expected named field"))?;
        let attr = parse_field_attrs(field)?;

        if attr.unknown_fields {
            if attr.id.is_some() || attr.optional || attr.ty.is_some() || attr.ty_version.is_some()
            {
                return Err(syn::Error::new(
                    field.span(),
                    "`abi(unknown_fields)` cannot be combined with field ID, optionality, or type override",
                ));
            }
            if unknown_field.is_some() {
                return Err(syn::Error::new(
                    field.span(),
                    "duplicate `abi(unknown_fields)` storage field",
                ));
            }
            unknown_field = Some(ident);
            continue;
        }

        let id = attr
            .id
            .ok_or_else(|| syn::Error::new(field.span(), "missing `abi(id = N)`"))?;
        if id == 0 {
            return Err(syn::Error::new(
                field.span(),
                "ABI field ID must be nonzero",
            ));
        }
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
                "required `Option<T>` fields are not valid ABI fields",
            ));
        }
        let wire_ty = inner.unwrap_or(&field.ty);
        out.push(FieldSpec {
            ident,
            id,
            wire_ty,
            decode_ty: decode_type(&field.ty),
            decode_wire_ty: decode_type(wire_ty),
            optional: attr.optional,
            ty_override: attr.ty,
            ty_version: attr.ty_version,
        });
    }

    out.sort_by_key(|field| field.id);
    Ok(FieldSetSpec {
        fields: out,
        unknown_field,
    })
}

fn validate_unknown_field_storage(
    field_set: &FieldSetSpec<'_>,
    mode: UnknownFieldMode,
    span: proc_macro2::Span,
) -> syn::Result<()> {
    match (mode, field_set.unknown_field) {
        (UnknownFieldMode::Preserve, None) => Err(syn::Error::new(
            span,
            "`abi(unknown_fields = \"preserve\")` requires one `#[abi(unknown_fields)]` storage field",
        )),
        (UnknownFieldMode::Reject | UnknownFieldMode::Ignore, Some(ident)) => Err(syn::Error::new(
            ident.span(),
            "`abi(unknown_fields)` requires `abi(unknown_fields = \"preserve\")`",
        )),
        _ => Ok(()),
    }
}

fn derive_struct(
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    if attrs.transparent {
        return derive_transparent_struct(name, generics, data, attrs);
    }

    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "field-set ABI structs must use named fields",
        ));
    };
    let field_set = named_field_specs(fields)?;
    validate_unknown_field_storage(&field_set, attrs.unknown_fields, data.fields.span())?;

    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let encode = encode_field_set_body(
        &field_set,
        attrs.unknown_fields,
        EncodeContext::Struct,
        abi_path,
    );
    let decode = decode_field_set_body(
        &field_set,
        attrs.unknown_fields,
        quote!(Self),
        abi_path,
        cbor_path,
    );
    let schema = schema_struct_tokens(attrs, &field_set);
    let type_ref = type_ref_impl_tokens(name, generics, attrs);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let decode_ty_generics = decode_ty_generics(generics);

    Ok(quote! {
        impl #impl_generics #abi_path::AbiEncode for #name #ty_generics #where_clause {
            fn abi_encode(
                &self,
                enc: &mut #cbor_path::Encoder,
            ) -> ::core::result::Result<(), #cbor_path::CborError> {
                #encode
            }
        }

        impl<'__sacp_abi> #abi_path::AbiDecode<'__sacp_abi> for #name #decode_ty_generics {
            fn abi_decode<const CHECKED: bool>(
                decoder: &mut #cbor_path::Decoder<'__sacp_abi, CHECKED>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                #decode
            }
        }

        impl #impl_generics #abi_path::AbiType for #name #ty_generics #where_clause {
            fn schema() -> #abi_path::Schema {
                #schema
            }
        }

        #type_ref
    })
}

fn derive_transparent_struct(
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let inner = transparent_inner(data)?;
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let inner_ty = inner.ty;
    let decode_inner_ty = &inner.decode_ty;
    let schema = schema_transparent_tokens(attrs, inner_ty);
    let type_ref = type_ref_impl_tokens(name, generics, attrs);
    let access = inner.access;
    let construct = inner.construct;
    let try_from = attrs.try_from.as_ref();
    let decode_construct = if let Some(try_from) = try_from {
        quote! {
            #try_from(__abi_inner).map_err(|_| {
                #cbor_path::CborError::new(#cbor_path::ErrorCode::InvalidAbiValue, __abi_off)
            })
        }
    } else {
        quote! { ::core::result::Result::Ok(#construct) }
    };
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let decode_ty_generics = decode_ty_generics(generics);

    Ok(quote! {
        impl #impl_generics #abi_path::AbiEncode for #name #ty_generics #where_clause {
            fn abi_encode(
                &self,
                enc: &mut #cbor_path::Encoder,
            ) -> ::core::result::Result<(), #cbor_path::CborError> {
                #abi_path::AbiEncode::abi_encode(#access, enc)
            }
        }

        impl<'__sacp_abi> #abi_path::AbiDecode<'__sacp_abi> for #name #decode_ty_generics {
            fn abi_decode<const CHECKED: bool>(
                decoder: &mut #cbor_path::Decoder<'__sacp_abi, CHECKED>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                let __abi_off = decoder.position();
                let __abi_inner: #decode_inner_ty = #abi_path::AbiDecode::abi_decode(decoder)?;
                #decode_construct
            }
        }

        impl #impl_generics #abi_path::AbiType for #name #ty_generics #where_clause {
            fn schema() -> #abi_path::Schema {
                #schema
            }
        }

        #type_ref
    })
}

struct TransparentInner<'a> {
    ty: &'a Type,
    decode_ty: Type,
    access: proc_macro2::TokenStream,
    construct: proc_macro2::TokenStream,
}

fn transparent_inner(data: &DataStruct) -> syn::Result<TransparentInner<'_>> {
    match &data.fields {
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            let field = fields.unnamed.first().expect("len checked");
            ensure_no_abi_field_attrs(field)?;
            let index = syn::Index::from(0);
            Ok(TransparentInner {
                ty: &field.ty,
                decode_ty: decode_type(&field.ty),
                access: quote!(&self.#index),
                construct: quote!(Self(__abi_inner)),
            })
        }
        Fields::Named(fields) if fields.named.len() == 1 => {
            let field = fields.named.first().expect("len checked");
            ensure_no_abi_field_attrs(field)?;
            let ident = field.ident.as_ref().expect("named field");
            Ok(TransparentInner {
                ty: &field.ty,
                decode_ty: decode_type(&field.ty),
                access: quote!(&self.#ident),
                construct: quote!(Self { #ident: __abi_inner }),
            })
        }
        _ => Err(syn::Error::new(
            data.fields.span(),
            "`abi(transparent)` requires exactly one field",
        )),
    }
}

fn ensure_no_abi_field_attrs(field: &Field) -> syn::Result<()> {
    for attr in &field.attrs {
        if attr.path().is_ident("abi") {
            return Err(syn::Error::new(
                attr.span(),
                "`abi(...)` field attributes are not valid inside transparent structs",
            ));
        }
    }
    Ok(())
}

fn derive_enum(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    if attrs.transparent {
        return Err(syn::Error::new(
            name.span(),
            "`abi(transparent)` is only valid on structs",
        ));
    }
    if data.variants.is_empty() {
        return Err(syn::Error::new(
            name.span(),
            "CborAbi does not support empty enums",
        ));
    }

    let (variants, unknown_variant) = enum_variant_specs(data, attrs.unknown_fields)?;
    let unknown_mode = resolve_unknown_variant_mode(attrs, unknown_variant.as_ref())?;
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let encode = encode_enum_body(&variants, unknown_variant.as_ref(), attrs, unknown_mode);
    let decode = decode_enum_body(&variants, unknown_variant.as_ref(), attrs, unknown_mode);
    let schema = schema_enum_tokens(attrs, &variants, unknown_mode);
    let type_ref = type_ref_impl_tokens(name, generics, attrs);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let decode_ty_generics = decode_ty_generics(generics);

    Ok(quote! {
        impl #impl_generics #abi_path::AbiEncode for #name #ty_generics #where_clause {
            fn abi_encode(
                &self,
                enc: &mut #cbor_path::Encoder,
            ) -> ::core::result::Result<(), #cbor_path::CborError> {
                #encode
            }
        }

        impl<'__sacp_abi> #abi_path::AbiDecode<'__sacp_abi> for #name #decode_ty_generics {
            fn abi_decode<const CHECKED: bool>(
                decoder: &mut #cbor_path::Decoder<'__sacp_abi, CHECKED>,
            ) -> ::core::result::Result<Self, #cbor_path::CborError> {
                #decode
            }
        }

        impl #impl_generics #abi_path::AbiType for #name #ty_generics #where_clause {
            fn schema() -> #abi_path::Schema {
                #schema
            }
        }

        #type_ref
    })
}

fn enum_variant_specs<'a>(
    data: &'a DataEnum,
    unknown_fields: UnknownFieldMode,
) -> syn::Result<(Vec<VariantSpec<'a>>, Option<UnknownVariantSpec<'a>>)> {
    let mut out = Vec::new();
    let mut unknown_variant = None;
    let mut seen = Vec::<u32>::new();

    for variant in &data.variants {
        let attr = parse_variant_attrs(variant)?;
        if attr.unknown {
            if attr.id.is_some() {
                return Err(syn::Error::new(
                    variant.span(),
                    "`abi(unknown)` variants do not have ABI IDs",
                ));
            }
            validate_unknown_variant_shape(variant)?;
            if unknown_variant.is_some() {
                return Err(syn::Error::new(
                    variant.span(),
                    "duplicate `abi(unknown)` variant",
                ));
            }
            unknown_variant = Some(UnknownVariantSpec {
                ident: &variant.ident,
            });
            continue;
        }

        let id = attr
            .id
            .ok_or_else(|| syn::Error::new(variant.span(), "missing `abi(id = N)` on variant"))?;
        if id == 0 {
            return Err(syn::Error::new(
                variant.span(),
                "ABI variant ID must be nonzero",
            ));
        }
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
                fields: FieldSetSpec {
                    fields: Vec::new(),
                    unknown_field: None,
                },
                unit: true,
            }),
            Fields::Named(fields) => {
                let field_set = named_field_specs(fields)?;
                validate_unknown_field_storage(&field_set, unknown_fields, fields.span())?;
                out.push(VariantSpec {
                    ident: &variant.ident,
                    id,
                    fields: field_set,
                    unit: false,
                });
            }
            Fields::Unnamed(fields) => {
                return Err(syn::Error::new(
                    fields.span(),
                    "ABI enum variants must be unit, named-field, or `abi(unknown)` variants",
                ))
            }
        }
    }

    out.sort_by_key(|variant| variant.id);
    Ok((out, unknown_variant))
}

fn validate_unknown_variant_shape(variant: &syn::Variant) -> syn::Result<()> {
    match &variant.fields {
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Ok(()),
        _ => Err(syn::Error::new(
            variant.fields.span(),
            "`abi(unknown)` variant must be a one-field tuple variant",
        )),
    }
}

fn resolve_unknown_variant_mode(
    attrs: &ContainerAttr,
    unknown_variant: Option<&UnknownVariantSpec<'_>>,
) -> syn::Result<UnknownVariantMode> {
    match (attrs.unknown_variants, unknown_variant) {
        (Some(UnknownVariantMode::Reject), Some(variant)) => Err(syn::Error::new(
            variant.ident.span(),
            "`abi(unknown)` requires `abi(unknown_variants = \"preserve\")` or no explicit unknown-variant policy",
        )),
        (Some(UnknownVariantMode::Preserve), None) => Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "`abi(unknown_variants = \"preserve\")` requires one `#[abi(unknown)]` variant",
        )),
        (Some(mode), _) => Ok(mode),
        (None, Some(_)) => Ok(UnknownVariantMode::Preserve),
        (None, None) => Ok(UnknownVariantMode::Reject),
    }
}

#[derive(Clone, Copy)]
enum EncodeContext {
    Struct,
    Variant,
}

fn encode_field_set_body(
    field_set: &FieldSetSpec<'_>,
    unknown_mode: UnknownFieldMode,
    context: EncodeContext,
    abi_path: &Path,
) -> proc_macro2::TokenStream {
    let len_terms = field_set.fields.iter().map(|field| {
        let ident = field.ident;
        let access = match context {
            EncodeContext::Struct => quote!(&self.#ident),
            EncodeContext::Variant => quote!(#ident),
        };
        if field.optional {
            quote! { + if (#access).is_some() { 2 } else { 0 } }
        } else {
            quote! { + 2 }
        }
    });

    let unknown_len = if matches!(unknown_mode, UnknownFieldMode::Preserve) {
        let unknown = field_set.unknown_field.expect("validated unknown storage");
        let access = match context {
            EncodeContext::Struct => quote!(&self.#unknown),
            EncodeContext::Variant => quote!(#unknown),
        };
        quote! { + ((#access).len() * 2) }
    } else {
        quote! {}
    };

    let unknown_setup = if matches!(unknown_mode, UnknownFieldMode::Preserve) {
        let unknown = field_set.unknown_field.expect("validated unknown storage");
        let access = match context {
            EncodeContext::Struct => quote!(&self.#unknown),
            EncodeContext::Variant => quote!(#unknown),
        };
        quote! {
            let __abi_unknown_fields = #access;
            let mut __abi_unknown_cursor = 0usize;
        }
    } else {
        quote! {}
    };

    let writes = field_set.fields.iter().map(|field| {
        let ident = field.ident;
        let id = field.id;
        let before_unknown = if matches!(unknown_mode, UnknownFieldMode::Preserve) {
            quote! {
                #abi_path::__private::encode_unknown_fields_before(
                    __abi_array,
                    __abi_unknown_fields,
                    &mut __abi_unknown_cursor,
                    #id,
                )?;
            }
        } else {
            quote! {}
        };
        let value_access = match context {
            EncodeContext::Struct => quote!(&self.#ident),
            EncodeContext::Variant => quote!(#ident),
        };
        let write_value = if field.optional {
            quote! {
                if let ::core::option::Option::Some(__abi_value) = #value_access {
                #abi_path::__private::encode_field_id(__abi_array, #id)?;
                __abi_array.value_with(|enc| {
                    #abi_path::AbiEncode::abi_encode(__abi_value, enc)
                })?;
                }
            }
        } else {
            quote! {
                #abi_path::__private::encode_field_id(__abi_array, #id)?;
                __abi_array.value_with(|enc| {
                    #abi_path::AbiEncode::abi_encode(#value_access, enc)
                })?;
            }
        };
        quote! {
            #before_unknown
            #write_value
        }
    });

    let remaining_unknown = if matches!(unknown_mode, UnknownFieldMode::Preserve) {
        quote! {
            #abi_path::__private::encode_remaining_unknown_fields(
                __abi_array,
                __abi_unknown_fields,
                &mut __abi_unknown_cursor,
            )?;
        }
    } else {
        quote! {}
    };

    quote! {
        let __abi_len = 0usize #(#len_terms)* #unknown_len;
        enc.array(__abi_len, |__abi_array| {
            #unknown_setup
            #(#writes)*
            #remaining_unknown
            ::core::result::Result::Ok(())
        })
    }
}

fn decode_field_set_body(
    field_set: &FieldSetSpec<'_>,
    unknown_mode: UnknownFieldMode,
    target: proc_macro2::TokenStream,
    abi_path: &Path,
    cbor_path: &Path,
) -> proc_macro2::TokenStream {
    let storage_decls = field_set.fields.iter().map(|field| {
        let ident = storage_ident(field.ident);
        let ty = &field.decode_ty;
        quote! { let mut #ident: ::core::option::Option<#ty> = ::core::option::Option::None; }
    });
    let unknown_decl = if matches!(unknown_mode, UnknownFieldMode::Preserve) {
        quote! {
            let mut __abi_unknown_fields = #abi_path::__private::Vec::<#abi_path::UnknownField>::new();
        }
    } else {
        quote! {}
    };

    let match_arms = field_set.fields.iter().map(|field| {
        let id = field.id;
        let storage = storage_ident(field.ident);
        let decode_ty = &field.decode_wire_ty;
        if field.optional {
            quote! {
                #id => {
                    if #storage.is_some() {
                        return Err(#cbor_path::CborError::new(
                            #cbor_path::ErrorCode::DuplicateMapKey,
                            __abi_id_off,
                        ));
                    }
                    let __abi_value: #decode_ty = __abi_array
                        .decode_next(#abi_path::AbiDecode::abi_decode)?
                        .ok_or_else(|| #cbor_path::CborError::new(
                            #cbor_path::ErrorCode::ArrayLenMismatch,
                            __abi_arr_off,
                        ))?;
                    #storage = ::core::option::Option::Some(::core::option::Option::Some(__abi_value));
                }
            }
        } else {
            quote! {
                #id => {
                    if #storage.is_some() {
                        return Err(#cbor_path::CborError::new(
                            #cbor_path::ErrorCode::DuplicateMapKey,
                            __abi_id_off,
                        ));
                    }
                    let __abi_value: #decode_ty = __abi_array
                        .decode_next(#abi_path::AbiDecode::abi_decode)?
                        .ok_or_else(|| #cbor_path::CborError::new(
                            #cbor_path::ErrorCode::ArrayLenMismatch,
                            __abi_arr_off,
                        ))?;
                    #storage = ::core::option::Option::Some(__abi_value);
                }
            }
        }
    });

    let unknown_arm = match unknown_mode {
        UnknownFieldMode::Reject => quote! {
            _ => {
                return Err(#cbor_path::CborError::new(
                    #cbor_path::ErrorCode::UnknownField,
                    __abi_id_off,
                ));
            }
        },
        UnknownFieldMode::Ignore => quote! {
            _ => {
                let _: () = __abi_array.decode_next(|decoder| {
                    decoder.skip_value()?;
                    ::core::result::Result::Ok(())
                })?.ok_or_else(|| #cbor_path::CborError::new(
                    #cbor_path::ErrorCode::ArrayLenMismatch,
                    __abi_arr_off,
                ))?;
            }
        },
        UnknownFieldMode::Preserve => quote! {
            _ => {
                let __abi_value: #cbor_path::CanonicalCbor = __abi_array
                    .decode_next(#cbor_path::CborDecode::decode)?
                    .ok_or_else(|| #cbor_path::CborError::new(
                        #cbor_path::ErrorCode::ArrayLenMismatch,
                        __abi_arr_off,
                    ))?;
                __abi_unknown_fields.push(#abi_path::UnknownField {
                    id: __abi_id,
                    value: __abi_value,
                });
            }
        },
    };

    let finals = field_set.fields.iter().map(|field| {
        let ident = field.ident;
        let storage = storage_ident(field.ident);
        if field.optional {
            quote! { #ident: #storage.unwrap_or(::core::option::Option::None), }
        } else {
            quote! {
                #ident: #storage.ok_or_else(|| #cbor_path::CborError::new(
                    #cbor_path::ErrorCode::MissingKey,
                    __abi_arr_off,
                ))?,
            }
        }
    });
    let unknown_final = if let Some(unknown) = field_set.unknown_field {
        quote! {
            #unknown: #abi_path::UnknownFields::try_from_vec(__abi_unknown_fields)?,
        }
    } else {
        quote! {}
    };

    quote! {
        let __abi_arr_off = decoder.position();
        let mut __abi_array = decoder.array()?;
        if __abi_array.remaining() % 2 != 0 {
            return Err(#cbor_path::CborError::new(
                #cbor_path::ErrorCode::ArrayLenMismatch,
                __abi_arr_off,
            ));
        }
        #(#storage_decls)*
        #unknown_decl
        let mut __abi_prev_id: ::core::option::Option<u32> = ::core::option::Option::None;
        while __abi_array.remaining() > 0 {
            let (__abi_id_off, __abi_id): (usize, u32) = __abi_array.decode_next(|decoder| {
                let off = decoder.position();
                let id = #cbor_path::CborDecode::decode(decoder)?;
                ::core::result::Result::Ok((off, id))
            })?.ok_or_else(|| #cbor_path::CborError::new(
                #cbor_path::ErrorCode::ArrayLenMismatch,
                __abi_arr_off,
            ))?;
            if __abi_id == 0 {
                return Err(#cbor_path::CborError::new(
                    #cbor_path::ErrorCode::InvalidAbiValue,
                    __abi_id_off,
                ));
            }
            if let ::core::option::Option::Some(prev) = __abi_prev_id {
                if __abi_id == prev {
                    return Err(#cbor_path::CborError::new(
                        #cbor_path::ErrorCode::DuplicateMapKey,
                        __abi_id_off,
                    ));
                }
                if __abi_id < prev {
                    return Err(#cbor_path::CborError::new(
                        #cbor_path::ErrorCode::NonCanonicalMapOrder,
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
        ::core::result::Result::Ok(#target { #(#finals)* #unknown_final })
    }
}

fn encode_enum_body(
    variants: &[VariantSpec<'_>],
    unknown_variant: Option<&UnknownVariantSpec<'_>>,
    attrs: &ContainerAttr,
    unknown_mode: UnknownVariantMode,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let arms = variants.iter().map(|variant| {
        let ident = variant.ident;
        let id = variant.id;
        if variant.unit {
            quote! {
                Self::#ident => enc.array(2, |__abi_array| {
                    #abi_path::__private::encode_field_id(__abi_array, #id)?;
                    __abi_array.null()?;
                    ::core::result::Result::Ok(())
                })
            }
        } else {
            let pats = variant.fields.fields.iter().map(|field| field.ident);
            let unknown_pat = variant.fields.unknown_field;
            let body = encode_field_set_body(
                &variant.fields,
                attrs.unknown_fields,
                EncodeContext::Variant,
                abi_path,
            );
            quote! {
                Self::#ident { #(#pats,)* #unknown_pat } => enc.array(2, |__abi_array| {
                    #abi_path::__private::encode_field_id(__abi_array, #id)?;
                    __abi_array.value_with(|enc| {
                        #body
                    })?;
                    ::core::result::Result::Ok(())
                })
            }
        }
    });

    let unknown_arm = if matches!(unknown_mode, UnknownVariantMode::Preserve) {
        let unknown = unknown_variant.expect("validated unknown variant");
        let ident = unknown.ident;
        let reserved_ids = variants.iter().map(|variant| {
            let id = variant.id;
            quote!(#id)
        });
        quote! {
            Self::#ident(__abi_unknown) => {
                const __ABI_RESERVED_VARIANTS: &[u32] = &[#(#reserved_ids),*];
                #abi_path::__private::validate_unknown_variant(
                    __abi_unknown,
                    __ABI_RESERVED_VARIANTS,
                )?;
                enc.array(2, |__abi_array| {
                    #abi_path::__private::encode_field_id(__abi_array, __abi_unknown.id)?;
                    __abi_array.raw_cbor(__abi_unknown.payload.as_canonical_ref())?;
                    ::core::result::Result::Ok(())
                })
            }
        }
    } else {
        quote! {}
    };

    quote! {
        match self {
            #(#arms,)*
            #unknown_arm
        }
    }
}

fn decode_enum_body(
    variants: &[VariantSpec<'_>],
    unknown_variant: Option<&UnknownVariantSpec<'_>>,
    attrs: &ContainerAttr,
    unknown_mode: UnknownVariantMode,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let arms = variants.iter().map(|variant| {
        let ident = variant.ident;
        let id = variant.id;
        if variant.unit {
            quote! {
                #id => {
                    let _: () = __abi_array
                        .decode_next(#abi_path::AbiDecode::abi_decode)?
                        .ok_or_else(|| #cbor_path::CborError::new(
                            #cbor_path::ErrorCode::ArrayLenMismatch,
                            __abi_arr_off,
                        ))?;
                    ::core::result::Result::Ok(Self::#ident)
                }
            }
        } else {
            let body = decode_field_set_body(
                &variant.fields,
                attrs.unknown_fields,
                quote!(Self::#ident),
                abi_path,
                cbor_path,
            );
            quote! {
                #id => {
                    __abi_array.decode_next(|decoder| {
                        #body
                    })?.ok_or_else(|| #cbor_path::CborError::new(
                        #cbor_path::ErrorCode::ArrayLenMismatch,
                        __abi_arr_off,
                    ))
                }
            }
        }
    });

    let unknown_arm = if matches!(unknown_mode, UnknownVariantMode::Preserve) {
        let unknown = unknown_variant.expect("validated unknown variant");
        let ident = unknown.ident;
        quote! {
            _ => {
                let __abi_payload: #cbor_path::CanonicalCbor = __abi_array
                    .decode_next(#cbor_path::CborDecode::decode)?
                    .ok_or_else(|| #cbor_path::CborError::new(
                        #cbor_path::ErrorCode::ArrayLenMismatch,
                        __abi_arr_off,
                    ))?;
                ::core::result::Result::Ok(Self::#ident(#abi_path::UnknownVariant {
                    id: __abi_id,
                    payload: __abi_payload,
                }))
            }
        }
    } else {
        quote! {
            _ => Err(#cbor_path::CborError::new(
                #cbor_path::ErrorCode::UnknownEnumVariant,
                __abi_id_off,
            ))
        }
    };

    quote! {
        let __abi_arr_off = decoder.position();
        let mut __abi_array = decoder.array()?;
        if __abi_array.remaining() != 2 {
            return Err(#cbor_path::CborError::new(
                #cbor_path::ErrorCode::ArrayLenMismatch,
                __abi_arr_off,
            ));
        }
        let (__abi_id_off, __abi_id): (usize, u32) = __abi_array.decode_next(|decoder| {
            let off = decoder.position();
            let id = #cbor_path::CborDecode::decode(decoder)?;
            ::core::result::Result::Ok((off, id))
        })?.ok_or_else(|| #cbor_path::CborError::new(
            #cbor_path::ErrorCode::ArrayLenMismatch,
            __abi_arr_off,
        ))?;
        if __abi_id == 0 {
            return Err(#cbor_path::CborError::new(
                #cbor_path::ErrorCode::InvalidAbiValue,
                __abi_id_off,
            ));
        }
        match __abi_id {
            #(#arms,)*
            #unknown_arm
        }
    }
}

fn schema_struct_tokens(
    attrs: &ContainerAttr,
    field_set: &FieldSetSpec<'_>,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let type_id = &attrs.type_id;
    let version = attrs.version;
    let unknown = attrs.unknown_fields.tokens(abi_path);
    let fields = field_defs_tokens(field_set, abi_path);
    quote! {
        #abi_path::Schema::new(
            #type_id,
            #version,
            #abi_path::TypeDef::Struct(#abi_path::FieldSetDef {
                fields: #fields,
                unknown_fields: #unknown,
            }),
        )
    }
}

fn schema_transparent_tokens(attrs: &ContainerAttr, inner: &Type) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let type_id = &attrs.type_id;
    let version = attrs.version;
    quote! {
        #abi_path::Schema::new(
            #type_id,
            #version,
            #abi_path::TypeDef::Transparent {
                inner: <#inner as #abi_path::AbiTypeRef>::abi_type_ref(),
            },
        )
    }
}

fn schema_enum_tokens(
    attrs: &ContainerAttr,
    variants: &[VariantSpec<'_>],
    unknown_mode: UnknownVariantMode,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let type_id = &attrs.type_id;
    let version = attrs.version;
    let unknown_fields = attrs.unknown_fields.tokens(abi_path);
    let unknown_variants = unknown_mode.tokens(abi_path);
    let variants = variants.iter().map(|variant| {
        let id = variant.id;
        let name = variant.ident.to_string();
        let fields = field_defs_tokens(&variant.fields, abi_path);
        quote! {
            #abi_path::VariantDef {
                id: #id,
                name: #abi_path::__private::String::from(#name),
                fields: #fields,
            }
        }
    });
    quote! {
        #abi_path::Schema::new(
            #type_id,
            #version,
            #abi_path::TypeDef::Enum(#abi_path::EnumDef {
                variants: #abi_path::__private::vec![#(#variants),*],
                unknown_fields: #unknown_fields,
                unknown_variants: #unknown_variants,
            }),
        )
    }
}

fn field_defs_tokens(field_set: &FieldSetSpec<'_>, abi_path: &Path) -> proc_macro2::TokenStream {
    let defs = field_set.fields.iter().map(|field| {
        let id = field.id;
        let name = field.ident.to_string();
        let ty = field_type_ref_tokens(field, abi_path);
        let presence = if field.optional {
            quote!(#abi_path::FieldPresence::Optional)
        } else {
            quote!(#abi_path::FieldPresence::Required)
        };
        quote! {
            #abi_path::FieldDef {
                id: #id,
                name: #abi_path::__private::String::from(#name),
                ty: #ty,
                presence: #presence,
            }
        }
    });
    quote! { #abi_path::__private::vec![#(#defs),*] }
}

fn field_type_ref_tokens(field: &FieldSpec<'_>, abi_path: &Path) -> proc_macro2::TokenStream {
    if let Some(type_id) = &field.ty_override {
        let version = match field.ty_version {
            Some(version) => quote!(::core::option::Option::Some(#version)),
            None => quote!(::core::option::Option::None),
        };
        quote! {
            #abi_path::TypeRef::Named {
                type_id: #abi_path::__private::String::from(#type_id),
                version: #version,
            }
        }
    } else {
        let wire_ty = field.wire_ty;
        quote!(<#wire_ty as #abi_path::AbiTypeRef>::abi_type_ref())
    }
}

fn type_ref_impl_tokens(
    name: &Ident,
    generics: &Generics,
    attrs: &ContainerAttr,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let type_id = &attrs.type_id;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        impl #impl_generics #abi_path::AbiTypeRef for #name #ty_generics #where_clause {
            fn abi_type_ref() -> #abi_path::TypeRef {
                #abi_path::TypeRef::Named {
                    type_id: #abi_path::__private::String::from(#type_id),
                    version: ::core::option::Option::None,
                }
            }
        }
    }
}

fn storage_ident(ident: &Ident) -> Ident {
    format_ident!("__abi_field_{ident}")
}
