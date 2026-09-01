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

use view::{derive_enum_view, derive_struct_view, derive_transparent_struct_view};

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
        match &input.data {
            Data::Struct(data) => {
                derive_struct(&input.vis, &input.ident, &input.generics, data, &attrs)
            }
            Data::Enum(data) => {
                derive_enum(&input.vis, &input.ident, &input.generics, data, &attrs)
            }
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

fn encode_impl_generics(generics: &Generics) -> proc_macro2::TokenStream {
    let lifetimes = generics.lifetimes();
    quote!(<#(#lifetimes,)* __E>)
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
    let mut unknown_fields_set = false;
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
                if unknown_fields_set {
                    return Err(meta.error("duplicate `abi(unknown_fields=...)`"));
                }
                unknown_fields_set = true;
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

    Ok(FieldAttr {
        id,
        optional,
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
            if attr.id.is_some() || attr.optional {
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
    vis: &syn::Visibility,
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    if attrs.transparent {
        return derive_transparent_struct(vis, name, generics, data, attrs);
    }

    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "field-set ABI structs must use named fields",
        ));
    };
    let field_set = named_field_specs(fields)?;
    validate_unknown_field_storage(&field_set, attrs.unknown_fields, data.fields.span())?;
    let view = derive_struct_view(vis, name, generics, &field_set, attrs)?;

    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let projection = struct_projection_tokens(vis, name, generics, &field_set, attrs);
    let decode = decode_field_set_body(
        &field_set,
        attrs.unknown_fields,
        quote!(Self),
        &attrs.type_id,
        None,
        abi_path,
        cbor_path,
    );
    let schema = schema_struct_tokens(attrs, &field_set);
    let type_ref = wire_owner_impl_tokens(name, generics, attrs);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let decode_ty_generics = decode_ty_generics(generics);

    Ok(quote! {
        #projection

        impl<'__sacp_abi, __C> #abi_path::AbiDecode<'__sacp_abi, __C> for #name #decode_ty_generics
        where
            __C: #abi_path::AbiDecodeContext + ?Sized,
        {
            fn abi_decode<const CHECKED: bool>(
                decoder: &mut #cbor_path::Decoder<'__sacp_abi, CHECKED>,
                context: &mut __C,
                _location: #abi_path::AbiDecodeLocation,
            ) -> ::core::result::Result<Self, __C::Error> {
                #decode
            }
        }

        impl #impl_generics #abi_path::AbiType for #name #ty_generics #where_clause {
            const SCHEMA: &'static #abi_path::Schema = &(#schema);
        }

        #type_ref
        #view
    })
}

fn derive_transparent_struct(
    vis: &syn::Visibility,
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
    attrs: &ContainerAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let inner = transparent_inner(data)?;
    let view = derive_transparent_struct_view(vis, name, generics, &inner, attrs)?;
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let inner_ty = inner.ty;
    let decode_inner_ty = &inner.decode_ty;
    let schema = schema_transparent_tokens(attrs, inner_ty);
    let projection = transparent_projection_tokens(vis, name, generics, &inner, attrs);
    let type_ref = wire_owner_impl_tokens(name, generics, attrs);
    let construct = inner.construct;
    let try_from = attrs.try_from.as_ref();
    let decode_construct = if let Some(try_from) = try_from {
        quote! {
            #try_from(__abi_inner).map_err(|_| {
                #abi_path::__private::decode_error::<__C>(
                    #cbor_path::ErrorCode::InvalidAbiValue,
                    __abi_off,
                )
            })
        }
    } else {
        quote! { ::core::result::Result::Ok(#construct) }
    };
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let decode_ty_generics = decode_ty_generics(generics);

    Ok(quote! {
        #projection

        impl<'__sacp_abi, __C> #abi_path::AbiDecode<'__sacp_abi, __C> for #name #decode_ty_generics
        where
            __C: #abi_path::AbiDecodeContext + ?Sized,
        {
            fn abi_decode<const CHECKED: bool>(
                decoder: &mut #cbor_path::Decoder<'__sacp_abi, CHECKED>,
                context: &mut __C,
                location: #abi_path::AbiDecodeLocation,
            ) -> ::core::result::Result<Self, __C::Error> {
                let __abi_off = decoder.position();
                let __abi_inner: #decode_inner_ty =
                    #abi_path::AbiDecode::abi_decode(decoder, context, location)?;
                #decode_construct
            }
        }

        impl #impl_generics #abi_path::AbiType for #name #ty_generics #where_clause {
            const SCHEMA: &'static #abi_path::Schema = &(#schema);
        }

        #type_ref
        #view
    })
}

struct TransparentInner<'a> {
    ty: &'a Type,
    decode_ty: Type,
    semantic_ident: Ident,
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
                semantic_ident: format_ident!("inner"),
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
                semantic_ident: ident.clone(),
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
    vis: &syn::Visibility,
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
    let view = derive_enum_view(vis, name, generics, &variants, unknown_mode, attrs)?;
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let projection = enum_projection_tokens(
        vis,
        name,
        generics,
        &variants,
        unknown_variant.as_ref(),
        attrs,
        unknown_mode,
    );
    let decode = decode_enum_body(&variants, unknown_variant.as_ref(), attrs, unknown_mode);
    let schema = schema_enum_tokens(attrs, &variants, unknown_mode);
    let type_ref = wire_owner_impl_tokens(name, generics, attrs);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let decode_ty_generics = decode_ty_generics(generics);

    Ok(quote! {
        #projection

        impl<'__sacp_abi, __C> #abi_path::AbiDecode<'__sacp_abi, __C> for #name #decode_ty_generics
        where
            __C: #abi_path::AbiDecodeContext + ?Sized,
        {
            fn abi_decode<const CHECKED: bool>(
                decoder: &mut #cbor_path::Decoder<'__sacp_abi, CHECKED>,
                context: &mut __C,
                _location: #abi_path::AbiDecodeLocation,
            ) -> ::core::result::Result<Self, __C::Error> {
                #decode
            }
        }

        impl #impl_generics #abi_path::AbiType for #name #ty_generics #where_clause {
            const SCHEMA: &'static #abi_path::Schema = &(#schema);
        }

        #type_ref
        #view
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

fn decode_field_set_body(
    field_set: &FieldSetSpec<'_>,
    unknown_mode: UnknownFieldMode,
    target: proc_macro2::TokenStream,
    type_id: &LitStr,
    variant_id: Option<u32>,
    abi_path: &Path,
    cbor_path: &Path,
) -> proc_macro2::TokenStream {
    let variant_id = match variant_id {
        Some(id) => quote!(::core::option::Option::Some(#id)),
        None => quote!(::core::option::Option::None),
    };
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
        let location = quote! {
            #abi_path::AbiDecodeLocation::Field {
                type_id: #type_id,
                variant_id: #variant_id,
                field_id: #id,
            }
        };
        if field.optional {
            quote! {
                #id => {
                    if #storage.is_some() {
                        return Err(#abi_path::__private::decode_error::<__C>(
                            #cbor_path::ErrorCode::DuplicateMapKey,
                            __abi_id_off,
                        ));
                    }
                    let __abi_value: #decode_ty = __abi_array
                        .decode_next_with(|decoder| {
                            #abi_path::AbiDecode::abi_decode(decoder, context, #location)
                        })?
                        .ok_or_else(|| #abi_path::__private::decode_error::<__C>(
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
                        return Err(#abi_path::__private::decode_error::<__C>(
                            #cbor_path::ErrorCode::DuplicateMapKey,
                            __abi_id_off,
                        ));
                    }
                    let __abi_value: #decode_ty = __abi_array
                        .decode_next_with(|decoder| {
                            #abi_path::AbiDecode::abi_decode(decoder, context, #location)
                        })?
                        .ok_or_else(|| #abi_path::__private::decode_error::<__C>(
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
                return Err(#abi_path::__private::decode_error::<__C>(
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
                })?.ok_or_else(|| #abi_path::__private::decode_error::<__C>(
                    #cbor_path::ErrorCode::ArrayLenMismatch,
                    __abi_arr_off,
                ))?;
            }
        },
        UnknownFieldMode::Preserve => quote! {
            _ => {
                let __abi_location = #abi_path::AbiDecodeLocation::UnknownField {
                    type_id: #type_id,
                    variant_id: #variant_id,
                    field_id: __abi_id,
                };
                context.admit(
                    __abi_location,
                    #abi_path::AbiDecodeValue::UnknownField { offset: __abi_id_off },
                )?;
                __abi_unknown_fields.try_reserve(1).map_err(|_| {
                    #abi_path::__private::decode_error::<__C>(
                        #cbor_path::ErrorCode::AllocationFailed,
                        __abi_arr_off,
                    )
                })?;
                let __abi_value: #cbor_path::CanonicalCbor = __abi_array
                    .decode_next_with(|decoder| {
                        #abi_path::AbiDecode::abi_decode(
                            decoder,
                            context,
                            __abi_location,
                        )
                    })?
                    .ok_or_else(|| #abi_path::__private::decode_error::<__C>(
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
                #ident: #storage.ok_or_else(|| #abi_path::__private::decode_error::<__C>(
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
            return Err(#abi_path::__private::decode_error::<__C>(
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
            })?.ok_or_else(|| #abi_path::__private::decode_error::<__C>(
                #cbor_path::ErrorCode::ArrayLenMismatch,
                __abi_arr_off,
            ))?;
            if __abi_id == 0 {
                return Err(#abi_path::__private::decode_error::<__C>(
                    #cbor_path::ErrorCode::InvalidAbiValue,
                    __abi_id_off,
                ));
            }
            if let ::core::option::Option::Some(prev) = __abi_prev_id {
                if __abi_id == prev {
                    return Err(#abi_path::__private::decode_error::<__C>(
                        #cbor_path::ErrorCode::DuplicateMapKey,
                        __abi_id_off,
                    ));
                }
                if __abi_id < prev {
                    return Err(#abi_path::__private::decode_error::<__C>(
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

fn decode_enum_body(
    variants: &[VariantSpec<'_>],
    unknown_variant: Option<&UnknownVariantSpec<'_>>,
    attrs: &ContainerAttr,
    unknown_mode: UnknownVariantMode,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let type_id = &attrs.type_id;
    let arms = variants.iter().map(|variant| {
        let ident = variant.ident;
        let id = variant.id;
        if variant.unit {
            quote! {
                #id => {
                    let _: () = __abi_array
                        .decode_next_with(|decoder| {
                            #abi_path::AbiDecode::abi_decode(
                                decoder,
                                context,
                                #abi_path::AbiDecodeLocation::Root,
                            )
                        })?
                        .ok_or_else(|| #abi_path::__private::decode_error::<__C>(
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
                &attrs.type_id,
                Some(id),
                abi_path,
                cbor_path,
            );
            quote! {
                #id => {
                    __abi_array.decode_next_with(|decoder| {
                        #body
                    })?.ok_or_else(|| #abi_path::__private::decode_error::<__C>(
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
                let __abi_location = #abi_path::AbiDecodeLocation::UnknownVariant {
                    type_id: #type_id,
                    variant_id: __abi_id,
                };
                context.admit(
                    __abi_location,
                    #abi_path::AbiDecodeValue::UnknownVariant { offset: __abi_id_off },
                )?;
                let __abi_payload: #cbor_path::CanonicalCbor = __abi_array
                    .decode_next_with(|decoder| {
                        #abi_path::AbiDecode::abi_decode(
                            decoder,
                            context,
                            __abi_location,
                        )
                    })?
                    .ok_or_else(|| #abi_path::__private::decode_error::<__C>(
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
            _ => Err(#abi_path::__private::decode_error::<__C>(
                #cbor_path::ErrorCode::UnknownEnumVariant,
                __abi_id_off,
            ))
        }
    };

    quote! {
        let __abi_arr_off = decoder.position();
        let mut __abi_array = decoder.array()?;
        if __abi_array.remaining() != 2 {
            return Err(#abi_path::__private::decode_error::<__C>(
                #cbor_path::ErrorCode::ArrayLenMismatch,
                __abi_arr_off,
            ));
        }
        let (__abi_id_off, __abi_id): (usize, u32) = __abi_array.decode_next(|decoder| {
            let off = decoder.position();
            let id = #cbor_path::CborDecode::decode(decoder)?;
            ::core::result::Result::Ok((off, id))
        })?.ok_or_else(|| #abi_path::__private::decode_error::<__C>(
            #cbor_path::ErrorCode::ArrayLenMismatch,
            __abi_arr_off,
        ))?;
        if __abi_id == 0 {
            return Err(#abi_path::__private::decode_error::<__C>(
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
            #abi_path::TypeDef::Struct(#abi_path::FieldSetDef::new(#fields, #unknown)),
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
                inner: <<#inner as #abi_path::AbiRepresentation>::Wire as #abi_path::AbiWireType>::TYPE_REF,
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
    let unknown_variants = unknown_mode.tokens(abi_path);
    let variants = variants.iter().map(|variant| {
        let id = variant.id;
        let name = variant.ident.to_string();
        if variant.unit {
            quote!(#abi_path::VariantDef::unit(#id, #name))
        } else {
            let fields = field_defs_tokens(&variant.fields, abi_path);
            let unknown_fields = attrs.unknown_fields.tokens(abi_path);
            quote! {
                #abi_path::VariantDef::fields(
                    #id,
                    #name,
                    #abi_path::FieldSetDef::new(#fields, #unknown_fields),
                )
            }
        }
    });
    quote! {
        #abi_path::Schema::new(
            #type_id,
            #version,
            #abi_path::TypeDef::Enum(#abi_path::EnumDef::new(
                &[#(#variants),*],
                #unknown_variants,
            )),
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
            #abi_path::FieldDef::new(#id, #name, #ty, #presence)
        }
    });
    quote! { &[#(#defs),*] }
}

fn field_type_ref_tokens(field: &FieldSpec<'_>, abi_path: &Path) -> proc_macro2::TokenStream {
    let wire_ty = field.wire_ty;
    quote!(<<#wire_ty as #abi_path::AbiRepresentation>::Wire as #abi_path::AbiWireType>::TYPE_REF)
}

fn wire_owner_impl_tokens(
    name: &Ident,
    generics: &Generics,
    attrs: &ContainerAttr,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let type_id = &attrs.type_id;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        impl #impl_generics #abi_path::AbiWireType for #name #ty_generics #where_clause {
            const TYPE_REF: #abi_path::TypeRef = #abi_path::TypeRef::named(
                #type_id,
                ::core::option::Option::None,
            );
        }

        impl #impl_generics #abi_path::AbiRepresentation for #name #ty_generics #where_clause {
            type Wire = Self;
        }
    }
}

fn transparent_projection_tokens(
    vis: &syn::Visibility,
    name: &Ident,
    generics: &Generics,
    inner: &TransparentInner<'_>,
    attrs: &ContainerAttr,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let projection_trait = format_ident!("{name}AbiProjection");
    let projected = format_ident!("{name}AbiProjected");
    let driver = format_ident!("__sacp_cbor_abi_encode_{}", snake_case(&name.to_string()));
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let owned_encode_impl_generics = encode_impl_generics(generics);
    let lifetimes: Vec<Lifetime> = generics
        .lifetimes()
        .map(|param| param.lifetime.clone())
        .collect();
    let inner_ty = inner.ty;
    let semantic_ident = &inner.semantic_ident;
    let access = &inner.access;

    quote! {
        #[doc = "Semantic, fallible projection into this transparent declaration's inner wire value."]
        #vis trait #projection_trait #generics {
            #[doc = "Caller-owned business projection failure."]
            type Error;

            #[doc = "Carrier returned for the transparent inner wire value."]
            type Inner<'__abi_value>:
                #abi_path::AbiEncodeAs<
                    <#inner_ty as #abi_path::AbiRepresentation>::Wire,
                    Self::Error,
                >
            where
                Self: '__abi_value;

            #[doc = "Project the transparent semantic value exactly once."]
            fn #semantic_ident(
                &self,
            ) -> ::core::result::Result<Self::Inner<'_>, Self::Error>;
        }

        #[doc = "Allocation-free ABI encoding view over a transparent projection."]
        #vis struct #projected<'__abi_projection, #(#lifetimes,)* __P: ?Sized> {
            projection: &'__abi_projection __P,
            owner: ::core::marker::PhantomData<fn() -> #name #ty_generics>,
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #projected<'__abi_projection, #(#lifetimes,)* __P>
        {
            #[doc = "Borrow a projection without materializing the owning wrapper."]
            #vis const fn new(projection: &'__abi_projection __P) -> Self {
                Self {
                    projection,
                    owner: ::core::marker::PhantomData,
                }
            }
        }

        impl #impl_generics #projection_trait #ty_generics for #name #ty_generics #where_clause {
            type Error = ::core::convert::Infallible;
            type Inner<'__abi_value> = &'__abi_value #inner_ty
            where
                Self: '__abi_value;

            fn #semantic_ident(
                &self,
            ) -> ::core::result::Result<Self::Inner<'_>, Self::Error> {
                ::core::result::Result::Ok(#access)
            }
        }

        fn #driver<#(#lifetimes,)* __P: ?Sized, __S: #cbor_path::ByteSink>(
            projection: &__P,
            enc: &mut #cbor_path::ValueEncoder<'_, __S>,
        ) -> ::core::result::Result<
            (),
            #abi_path::AbiEncodeError<__S::Error, __P::Error>,
        >
        where
            __P: #projection_trait #ty_generics,
        {
            let __abi_inner = projection
                .#semantic_ident()
                .map_err(#abi_path::AbiEncodeError::Projection)?;
            #abi_path::AbiEncodeAs::<
                <#inner_ty as #abi_path::AbiRepresentation>::Wire,
                __P::Error,
            >::abi_encode_as(&__abi_inner, enc)
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #abi_path::AbiEncode for #projected<'__abi_projection, #(#lifetimes,)* __P>
        where
            __P: #projection_trait #ty_generics,
        {
            type Error = __P::Error;

            fn abi_encode<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, Self::Error>,
            > {
                #driver(self.projection, enc)
            }
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #abi_path::AbiEncodeAs<#name #ty_generics, __P::Error>
            for #projected<'__abi_projection, #(#lifetimes,)* __P>
        where
            __P: #projection_trait #ty_generics,
        {
            fn abi_encode_as<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, __P::Error>,
            > {
                #driver(self.projection, enc)
            }
        }

        impl #owned_encode_impl_generics
            #abi_path::AbiEncodeAs<#name #ty_generics, __E>
            for #name #ty_generics #where_clause
        {
            fn abi_encode_as<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, __E>,
            > {
                #driver(self, enc).map_err(#abi_path::__private::widen_infallible)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn enum_projection_tokens(
    vis: &syn::Visibility,
    name: &Ident,
    generics: &Generics,
    variants: &[VariantSpec<'_>],
    unknown_variant: Option<&UnknownVariantSpec<'_>>,
    attrs: &ContainerAttr,
    unknown_mode: UnknownVariantMode,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let projection_trait = format_ident!("{name}AbiProjection");
    let visitor_trait = format_ident!("{name}AbiVariantVisitor");
    let projected = format_ident!("{name}AbiProjected");
    let encoder_visitor = format_ident!("__{}AbiEncoder", name);
    let driver = format_ident!("__sacp_cbor_abi_encode_{}", snake_case(&name.to_string()));
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let owned_encode_impl_generics = encode_impl_generics(generics);
    let lifetimes: Vec<Lifetime> = generics
        .lifetimes()
        .map(|param| param.lifetime.clone())
        .collect();

    let mut visitor_methods = Vec::new();
    let mut encoder_methods = Vec::new();
    let mut owned_arms = Vec::new();

    for variant in variants {
        let variant_ident = variant.ident;
        let method = format_ident!("{}", snake_case(&variant.ident.to_string()));
        let id = variant.id;
        if variant.unit {
            visitor_methods.push(quote! {
                #[doc = "Select this semantic unit variant."]
                fn #method(self) -> Self::Output;
            });
            encoder_methods.push(quote! {
                fn #method(self) -> Self::Output {
                    self.enc.array_with_caller_error(2, |__abi_array| {
                        #abi_path::__private::encode_field_id(__abi_array, #id)?;
                        __abi_array.null()?;
                        ::core::result::Result::<
                            (),
                            #abi_path::AbiEncodeError<__S::Error, __E>,
                        >::Ok(())
                    })
                }
            });
            owned_arms.push(quote!(Self::#variant_ident => visitor.#method()));
            continue;
        }

        let carrier_types: Vec<Ident> = variant
            .fields
            .fields
            .iter()
            .map(|field| format_ident!("__AbiField{}", upper_camel(&field.ident.to_string())))
            .collect();
        let generic_decl = if carrier_types.is_empty() {
            quote! {}
        } else {
            quote!(<#(#carrier_types),*>)
        };
        let mut parameters: Vec<proc_macro2::TokenStream> = variant
            .fields
            .fields
            .iter()
            .zip(&carrier_types)
            .map(|(field, carrier)| {
                let ident = field.ident;
                if field.optional {
                    quote!(#ident: ::core::option::Option<#carrier>)
                } else {
                    quote!(#ident: #carrier)
                }
            })
            .collect();
        if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
            parameters.push(quote!(__abi_unknown_fields: &#abi_path::UnknownFields));
        }
        let carrier_bounds: Vec<proc_macro2::TokenStream> = variant
            .fields
            .fields
            .iter()
            .zip(&carrier_types)
            .map(|(field, carrier)| {
                let wire_ty = field.wire_ty;
                quote! {
                    #carrier: #abi_path::AbiEncodeAs<
                        <#wire_ty as #abi_path::AbiRepresentation>::Wire,
                        __E,
                    >
                }
            })
            .collect();
        let where_bounds = if carrier_bounds.is_empty() {
            quote! {}
        } else {
            quote!(where #(#carrier_bounds),*)
        };
        visitor_methods.push(quote! {
            #[doc = "Select this semantic field-set variant."]
            fn #method #generic_decl(
                self,
                #(#parameters),*
            ) -> Self::Output
            #where_bounds;
        });

        let length_steps = variant.fields.fields.iter().map(|field| {
            let ident = field.ident;
            if field.optional {
                quote! {
                    if #ident.is_some() {
                        __abi_len = __abi_len
                            .checked_add(2)
                            .ok_or_else(#abi_path::__private::length_overflow)?;
                    }
                }
            } else {
                quote! {
                    __abi_len = __abi_len
                        .checked_add(2)
                        .ok_or_else(#abi_path::__private::length_overflow)?;
                }
            }
        });
        let unknown_length = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
            quote! {
                let __abi_unknown_items = __abi_unknown_fields
                    .len()
                    .checked_mul(2)
                    .ok_or_else(#abi_path::__private::length_overflow)?;
                __abi_len = __abi_len
                    .checked_add(__abi_unknown_items)
                    .ok_or_else(#abi_path::__private::length_overflow)?;
            }
        } else {
            quote! {}
        };
        let unknown_cursor = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
            quote!(let mut __abi_unknown_cursor = 0usize;)
        } else {
            quote! {}
        };
        let writes = variant
            .fields
            .fields
            .iter()
            .zip(&carrier_types)
            .map(|(field, _carrier)| {
                let field_ident = field.ident;
                let field_id = field.id;
                let wire_ty = field.wire_ty;
                let wire = quote!(<#wire_ty as #abi_path::AbiRepresentation>::Wire);
                let before_unknown = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
                    quote! {
                        #abi_path::__private::encode_unknown_fields_before(
                            __abi_fields,
                            __abi_unknown_fields,
                            &mut __abi_unknown_cursor,
                            #field_id,
                        )?;
                    }
                } else {
                    quote! {}
                };
                let emit = if field.optional {
                    quote! {
                        if let ::core::option::Option::Some(__abi_value) = #field_ident {
                            #abi_path::__private::encode_field_id(__abi_fields, #field_id)?;
                            __abi_fields.encode_with_caller_error(|enc| {
                                #abi_path::AbiEncodeAs::<#wire, __E>::abi_encode_as(
                                    &__abi_value,
                                    enc,
                                )
                            })?;
                        }
                    }
                } else {
                    quote! {
                        #abi_path::__private::encode_field_id(__abi_fields, #field_id)?;
                        __abi_fields.encode_with_caller_error(|enc| {
                            #abi_path::AbiEncodeAs::<#wire, __E>::abi_encode_as(
                                &#field_ident,
                                enc,
                            )
                        })?;
                    }
                };
                quote! {
                    #before_unknown
                    #emit
                }
            });
        let remaining_unknown = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
            quote! {
                #abi_path::__private::encode_remaining_unknown_fields(
                    __abi_fields,
                    __abi_unknown_fields,
                    &mut __abi_unknown_cursor,
                )?;
            }
        } else {
            quote! {}
        };
        encoder_methods.push(quote! {
            fn #method #generic_decl(
                self,
                #(#parameters),*
            ) -> Self::Output
            #where_bounds
            {
                let mut __abi_len = 0usize;
                #(#length_steps)*
                #unknown_length
                self.enc.array_with_caller_error(2, |__abi_variant| {
                    #abi_path::__private::encode_field_id(__abi_variant, #id)?;
                    __abi_variant.encode_with_caller_error(|enc| {
                        enc.array_with_caller_error(__abi_len, |__abi_fields| {
                            #unknown_cursor
                            #(#writes)*
                            #remaining_unknown
                            ::core::result::Result::<
                                (),
                                #abi_path::AbiEncodeError<__S::Error, __E>,
                            >::Ok(())
                        })
                    })?;
                    ::core::result::Result::<
                        (),
                        #abi_path::AbiEncodeError<__S::Error, __E>,
                    >::Ok(())
                })
            }
        });

        let pattern_fields: Vec<&Ident> = variant
            .fields
            .fields
            .iter()
            .map(|field| field.ident)
            .collect();
        let mut owned_arguments: Vec<proc_macro2::TokenStream> = variant
            .fields
            .fields
            .iter()
            .map(|field| {
                let ident = field.ident;
                if field.optional {
                    quote!(#ident.as_ref())
                } else {
                    quote!(#ident)
                }
            })
            .collect();
        let unknown_pattern = variant.fields.unknown_field;
        if let Some(unknown) = unknown_pattern {
            owned_arguments.push(quote!(#unknown));
        }
        owned_arms.push(quote! {
            Self::#variant_ident { #(#pattern_fields,)* #unknown_pattern } => {
                visitor.#method(#(#owned_arguments),*)
            }
        });
    }

    let unknown_visitor_method = if matches!(unknown_mode, UnknownVariantMode::Preserve) {
        quote! {
            #[doc = "Select the schema-governed preserved unknown variant."]
            fn preserved_unknown_variant(
                self,
                value: &#abi_path::UnknownVariant,
            ) -> Self::Output;
        }
    } else {
        quote! {}
    };
    let unknown_encoder_method = if matches!(unknown_mode, UnknownVariantMode::Preserve) {
        let reserved_ids = variants.iter().map(|variant| variant.id);
        quote! {
            fn preserved_unknown_variant(
                self,
                value: &#abi_path::UnknownVariant,
            ) -> Self::Output {
                const __ABI_RESERVED_VARIANTS: &[u32] = &[#(#reserved_ids),*];
                #abi_path::__private::validate_unknown_variant(
                    value,
                    __ABI_RESERVED_VARIANTS,
                )?;
                self.enc.array_with_caller_error(2, |__abi_array| {
                    #abi_path::__private::encode_field_id(__abi_array, value.id)?;
                    __abi_array.raw_cbor(value.payload.as_canonical_ref())?;
                    ::core::result::Result::<
                        (),
                        #abi_path::AbiEncodeError<__S::Error, __E>,
                    >::Ok(())
                })
            }
        }
    } else {
        quote! {}
    };
    let unknown_owned_arm = if matches!(unknown_mode, UnknownVariantMode::Preserve) {
        let unknown = unknown_variant.expect("validated unknown variant").ident;
        quote!(Self::#unknown(value) => visitor.preserved_unknown_variant(value))
    } else {
        quote! {}
    };

    quote! {
        #[doc = "Semantic, fallible projection that selects exactly one declared enum variant."]
        #vis trait #projection_trait #generics {
            #[doc = "Caller-owned business projection failure."]
            type Error;

            #[doc = "Select one semantic variant through the generated consuming visitor."]
            fn project_variant<__V>(&self, visitor: __V) -> __V::Output
            where
                __V: #visitor_trait<#(#lifetimes,)* Self::Error>;
        }

        #[doc = "Consuming semantic variant selector; numeric ABI IDs are intentionally absent."]
        #vis trait #visitor_trait<#(#lifetimes,)* __E> {
            #[doc = "Result produced after selecting one variant."]
            type Output;

            #[doc = "Abort selection with a typed business projection error."]
            fn projection_error(self, error: __E) -> Self::Output;

            #(#visitor_methods)*
            #unknown_visitor_method
        }

        #[doc = "Allocation-free ABI encoding view over an enum projection."]
        #vis struct #projected<'__abi_projection, #(#lifetimes,)* __P: ?Sized> {
            projection: &'__abi_projection __P,
            owner: ::core::marker::PhantomData<fn() -> #name #ty_generics>,
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #projected<'__abi_projection, #(#lifetimes,)* __P>
        {
            #[doc = "Borrow a projection without materializing the owning wire enum."]
            #vis const fn new(projection: &'__abi_projection __P) -> Self {
                Self {
                    projection,
                    owner: ::core::marker::PhantomData,
                }
            }
        }

        impl #impl_generics #projection_trait #ty_generics for #name #ty_generics #where_clause {
            type Error = ::core::convert::Infallible;

            fn project_variant<__V>(&self, visitor: __V) -> __V::Output
            where
                __V: #visitor_trait<#(#lifetimes,)* Self::Error>,
            {
                match self {
                    #(#owned_arms,)*
                    #unknown_owned_arm
                }
            }
        }

        struct #encoder_visitor<'__abi_borrow, '__abi_encoder, __S, __E>
        where
            __S: #cbor_path::ByteSink,
        {
            enc: &'__abi_borrow mut #cbor_path::ValueEncoder<'__abi_encoder, __S>,
            error: ::core::marker::PhantomData<fn() -> __E>,
        }

        impl<'__abi_borrow, '__abi_encoder, #(#lifetimes,)* __S, __E>
            #visitor_trait<#(#lifetimes,)* __E>
            for #encoder_visitor<'__abi_borrow, '__abi_encoder, __S, __E>
        where
            __S: #cbor_path::ByteSink,
        {
            type Output = ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, __E>,
            >;

            fn projection_error(self, error: __E) -> Self::Output {
                ::core::result::Result::Err(#abi_path::AbiEncodeError::Projection(error))
            }

            #(#encoder_methods)*
            #unknown_encoder_method
        }

        fn #driver<#(#lifetimes,)* __P: ?Sized, __S: #cbor_path::ByteSink>(
            projection: &__P,
            enc: &mut #cbor_path::ValueEncoder<'_, __S>,
        ) -> ::core::result::Result<
            (),
            #abi_path::AbiEncodeError<__S::Error, __P::Error>,
        >
        where
            __P: #projection_trait #ty_generics,
        {
            projection.project_variant(#encoder_visitor {
                enc,
                error: ::core::marker::PhantomData,
            })
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #abi_path::AbiEncode for #projected<'__abi_projection, #(#lifetimes,)* __P>
        where
            __P: #projection_trait #ty_generics,
        {
            type Error = __P::Error;

            fn abi_encode<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, Self::Error>,
            > {
                #driver(self.projection, enc)
            }
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #abi_path::AbiEncodeAs<#name #ty_generics, __P::Error>
            for #projected<'__abi_projection, #(#lifetimes,)* __P>
        where
            __P: #projection_trait #ty_generics,
        {
            fn abi_encode_as<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, __P::Error>,
            > {
                #driver(self.projection, enc)
            }
        }

        impl #owned_encode_impl_generics
            #abi_path::AbiEncodeAs<#name #ty_generics, __E>
            for #name #ty_generics #where_clause
        {
            fn abi_encode_as<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, __E>,
            > {
                #driver(self, enc).map_err(#abi_path::__private::widen_infallible)
            }
        }
    }
}

fn struct_projection_tokens(
    vis: &syn::Visibility,
    name: &Ident,
    generics: &Generics,
    field_set: &FieldSetSpec<'_>,
    attrs: &ContainerAttr,
) -> proc_macro2::TokenStream {
    let abi_path = &attrs.abi_path;
    let cbor_path = &attrs.cbor_path;
    let projection_trait = format_ident!("{name}AbiProjection");
    let projected = format_ident!("{name}AbiProjected");
    let driver = format_ident!("__sacp_cbor_abi_encode_{}", snake_case(&name.to_string()));
    let (_, ty_generics, where_clause) = generics.split_for_impl();
    let impl_generics = generics.split_for_impl().0;
    let owned_encode_impl_generics = encode_impl_generics(generics);
    let lifetimes: Vec<Lifetime> = generics
        .lifetimes()
        .map(|param| param.lifetime.clone())
        .collect();

    let associated_types = field_set.fields.iter().map(|field| {
        let associated = format_ident!("Field{}", upper_camel(&field.ident.to_string()));
        let wire_ty = field.wire_ty;
        quote! {
            #[doc = "Carrier returned for this semantic ABI field."]
            type #associated<'__abi_value>:
                #abi_path::AbiEncodeAs<
                    <#wire_ty as #abi_path::AbiRepresentation>::Wire,
                    Self::Error,
                >
            where
                Self: '__abi_value;
        }
    });
    let accessors = field_set.fields.iter().map(|field| {
        let ident = field.ident;
        let associated = format_ident!("Field{}", upper_camel(&field.ident.to_string()));
        if field.optional {
            quote! {
                #[doc = "Project this optional semantic field exactly once."]
                fn #ident(
                    &self,
                ) -> ::core::result::Result<
                    ::core::option::Option<Self::#associated<'_>>,
                    Self::Error,
                >;
            }
        } else {
            quote! {
                #[doc = "Project this required semantic field exactly once."]
                fn #ident(
                    &self,
                ) -> ::core::result::Result<Self::#associated<'_>, Self::Error>;
            }
        }
    });
    let unknown_trait = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
        quote! {
            #[doc = "Return schema-governed preserved extension fields exactly once."]
            fn preserved_unknown_fields(
                &self,
            ) -> ::core::result::Result<&#abi_path::UnknownFields, Self::Error>;
        }
    } else {
        quote! {}
    };

    let owned_associated = field_set.fields.iter().map(|field| {
        let associated = format_ident!("Field{}", upper_camel(&field.ident.to_string()));
        let wire_ty = field.wire_ty;
        quote! {
            type #associated<'__abi_value> = &'__abi_value #wire_ty
            where
                Self: '__abi_value;
        }
    });
    let owned_accessors = field_set.fields.iter().map(|field| {
        let ident = field.ident;
        let associated = format_ident!("Field{}", upper_camel(&field.ident.to_string()));
        if field.optional {
            quote! {
                fn #ident(
                    &self,
                ) -> ::core::result::Result<
                    ::core::option::Option<Self::#associated<'_>>,
                    Self::Error,
                > {
                    ::core::result::Result::Ok(self.#ident.as_ref())
                }
            }
        } else {
            quote! {
                fn #ident(
                    &self,
                ) -> ::core::result::Result<Self::#associated<'_>, Self::Error> {
                    ::core::result::Result::Ok(&self.#ident)
                }
            }
        }
    });
    let owned_unknown = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
        let unknown = field_set.unknown_field.expect("validated unknown storage");
        quote! {
            fn preserved_unknown_fields(
                &self,
            ) -> ::core::result::Result<&#abi_path::UnknownFields, Self::Error> {
                ::core::result::Result::Ok(&self.#unknown)
            }
        }
    } else {
        quote! {}
    };

    let getter_bindings = field_set.fields.iter().map(|field| {
        let ident = field.ident;
        let binding = storage_ident(field.ident);
        quote! {
            let #binding = projection.#ident().map_err(#abi_path::AbiEncodeError::Projection)?;
        }
    });
    let unknown_binding = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
        quote! {
            let __abi_unknown_fields = projection
                .preserved_unknown_fields()
                .map_err(#abi_path::AbiEncodeError::Projection)?;
        }
    } else {
        quote! {}
    };
    let length_steps = field_set.fields.iter().map(|field| {
        let binding = storage_ident(field.ident);
        if field.optional {
            quote! {
                if #binding.is_some() {
                    __abi_len = __abi_len
                        .checked_add(2)
                        .ok_or_else(#abi_path::__private::length_overflow)?;
                }
            }
        } else {
            quote! {
                __abi_len = __abi_len
                    .checked_add(2)
                    .ok_or_else(#abi_path::__private::length_overflow)?;
            }
        }
    });
    let unknown_length = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
        quote! {
            let __abi_unknown_items = __abi_unknown_fields
                .len()
                .checked_mul(2)
                .ok_or_else(#abi_path::__private::length_overflow)?;
            __abi_len = __abi_len
                .checked_add(__abi_unknown_items)
                .ok_or_else(#abi_path::__private::length_overflow)?;
        }
    } else {
        quote! {}
    };
    let unknown_cursor = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
        quote!(let mut __abi_unknown_cursor = 0usize;)
    } else {
        quote! {}
    };
    let writes = field_set.fields.iter().map(|field| {
        let id = field.id;
        let binding = storage_ident(field.ident);
        let wire_ty = field.wire_ty;
        let wire = quote!(<#wire_ty as #abi_path::AbiRepresentation>::Wire);
        let before_unknown = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
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
        let emit = if field.optional {
            quote! {
                if let ::core::option::Option::Some(__abi_value) = #binding {
                    #abi_path::__private::encode_field_id(__abi_array, #id)?;
                    __abi_array.encode_with_caller_error(|enc| {
                        #abi_path::AbiEncodeAs::<#wire, __P::Error>::abi_encode_as(
                            &__abi_value,
                            enc,
                        )
                    })?;
                }
            }
        } else {
            quote! {
                #abi_path::__private::encode_field_id(__abi_array, #id)?;
                __abi_array.encode_with_caller_error(|enc| {
                    #abi_path::AbiEncodeAs::<#wire, __P::Error>::abi_encode_as(
                        &#binding,
                        enc,
                    )
                })?;
            }
        };
        quote! {
            #before_unknown
            #emit
        }
    });
    let remaining_unknown = if matches!(attrs.unknown_fields, UnknownFieldMode::Preserve) {
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
        #[doc = "Semantic, fallible projection into this declaration's schema-owned fields."]
        #vis trait #projection_trait #generics {
            #[doc = "Caller-owned business projection failure."]
            type Error;

            #(#associated_types)*
            #(#accessors)*
            #unknown_trait
        }

        #[doc = "Allocation-free ABI encoding view over a semantic projection."]
        #vis struct #projected<'__abi_projection, #(#lifetimes,)* __P: ?Sized> {
            projection: &'__abi_projection __P,
            owner: ::core::marker::PhantomData<fn() -> #name #ty_generics>,
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #projected<'__abi_projection, #(#lifetimes,)* __P>
        {
            #[doc = "Borrow a projection without materializing the owning wire DTO."]
            #vis const fn new(projection: &'__abi_projection __P) -> Self {
                Self {
                    projection,
                    owner: ::core::marker::PhantomData,
                }
            }
        }

        impl #impl_generics #projection_trait #ty_generics for #name #ty_generics #where_clause {
            type Error = ::core::convert::Infallible;
            #(#owned_associated)*
            #(#owned_accessors)*
            #owned_unknown
        }

        fn #driver<#(#lifetimes,)* __P: ?Sized, __S: #cbor_path::ByteSink>(
            projection: &__P,
            enc: &mut #cbor_path::ValueEncoder<'_, __S>,
        ) -> ::core::result::Result<
            (),
            #abi_path::AbiEncodeError<__S::Error, __P::Error>,
        >
        where
            __P: #projection_trait #ty_generics,
        {
            #(#getter_bindings)*
            #unknown_binding
            let mut __abi_len = 0usize;
            #(#length_steps)*
            #unknown_length
            enc.array_with_caller_error(__abi_len, |__abi_array| {
                #unknown_cursor
                #(#writes)*
                #remaining_unknown
                ::core::result::Result::<
                    (),
                    #abi_path::AbiEncodeError<__S::Error, __P::Error>,
                >::Ok(())
            })
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #abi_path::AbiEncode for #projected<'__abi_projection, #(#lifetimes,)* __P>
        where
            __P: #projection_trait #ty_generics,
        {
            type Error = __P::Error;

            fn abi_encode<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, Self::Error>,
            > {
                #driver(self.projection, enc)
            }
        }

        impl<'__abi_projection, #(#lifetimes,)* __P: ?Sized>
            #abi_path::AbiEncodeAs<#name #ty_generics, __P::Error>
            for #projected<'__abi_projection, #(#lifetimes,)* __P>
        where
            __P: #projection_trait #ty_generics,
        {
            fn abi_encode_as<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, __P::Error>,
            > {
                #driver(self.projection, enc)
            }
        }

        impl #owned_encode_impl_generics
            #abi_path::AbiEncodeAs<#name #ty_generics, __E>
            for #name #ty_generics #where_clause
        {
            fn abi_encode_as<__S: #cbor_path::ByteSink>(
                &self,
                enc: &mut #cbor_path::ValueEncoder<'_, __S>,
            ) -> ::core::result::Result<
                (),
                #abi_path::AbiEncodeError<__S::Error, __E>,
            > {
                #driver(self, enc).map_err(#abi_path::__private::widen_infallible)
            }
        }
    }
}

fn storage_ident(ident: &Ident) -> Ident {
    format_ident!("__abi_field_{ident}")
}

fn upper_camel(value: &str) -> String {
    let value = value.strip_prefix("r#").unwrap_or(value);
    let mut out = String::new();
    let mut uppercase = true;
    for character in value.chars() {
        if character == '_' {
            uppercase = true;
        } else if uppercase {
            out.extend(character.to_uppercase());
            uppercase = false;
        } else {
            out.push(character);
        }
    }
    out
}

fn snake_case(value: &str) -> String {
    let value = value.strip_prefix("r#").unwrap_or(value);
    let mut out = String::new();
    for (index, character) in value.chars().enumerate() {
        if character.is_uppercase() {
            if index != 0 {
                out.push('_');
            }
            out.extend(character.to_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}
