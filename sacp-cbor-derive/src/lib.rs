extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DataStruct, DeriveInput,
    Fields, GenericArgument, GenericParam, Generics, Ident, Lifetime, LifetimeParam, LitStr,
    PathArguments, Type,
};

#[derive(Default, Clone)]
struct CborFieldAttr {
    rename: Option<LitStr>,
    skip: bool,
    default: bool,
}

#[derive(Default, Clone)]
struct CborVariantAttr {
    rename: Option<LitStr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnumTagging {
    Tagged,
    Untagged,
}

impl Default for EnumTagging {
    fn default() -> Self {
        Self::Tagged
    }
}

fn ensure_no_cbor_attrs(attrs: &[Attribute], ctx: &str) -> syn::Result<()> {
    for a in attrs {
        if a.path().is_ident("cbor") {
            return Err(syn::Error::new(
                a.span(),
                format!("`#[cbor(...)]` is not supported on {ctx}"),
            ));
        }
    }
    Ok(())
}

fn parse_cbor_field_attrs(attrs: &[Attribute]) -> syn::Result<CborFieldAttr> {
    let mut out = CborFieldAttr::default();
    for attr in attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                if out.skip {
                    return Err(meta.error("duplicate `cbor(skip)`"));
                }
                out.skip = true;
                return Ok(());
            }
            if meta.path.is_ident("default") {
                if out.default {
                    return Err(meta.error("duplicate `cbor(default)`"));
                }
                out.default = true;
                return Ok(());
            }
            if meta.path.is_ident("rename") {
                if out.rename.is_some() {
                    return Err(meta.error("duplicate `cbor(rename=...)`"));
                }
                let lit: LitStr = meta.value()?.parse()?;
                out.rename = Some(lit);
                return Ok(());
            }
            Err(meta
                .error("unsupported `cbor(...)` field attribute (allowed: rename, skip, default)"))
        })?;
    }

    if out.skip && (out.rename.is_some() || out.default) {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "`cbor(skip)` cannot be combined with `rename` or `default`",
        ));
    }

    Ok(out)
}

fn parse_cbor_variant_attrs(attrs: &[Attribute]) -> syn::Result<CborVariantAttr> {
    let mut out = CborVariantAttr::default();
    for attr in attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                if out.rename.is_some() {
                    return Err(meta.error("duplicate `cbor(rename=...)` on variant"));
                }
                let lit: LitStr = meta.value()?.parse()?;
                out.rename = Some(lit);
                return Ok(());
            }
            if meta.path.is_ident("skip") || meta.path.is_ident("default") {
                return Err(
                    meta.error("`cbor(skip)` / `cbor(default)` are not valid on enum variants")
                );
            }
            Err(meta.error("unsupported `cbor(...)` variant attribute (allowed: rename)"))
        })?;
    }
    Ok(out)
}

fn parse_cbor_enum_attrs(attrs: &[Attribute]) -> syn::Result<EnumTagging> {
    let mut seen_tagged = false;
    let mut seen_untagged = false;

    for attr in attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("untagged") {
                if seen_untagged {
                    return Err(meta.error("duplicate `cbor(untagged)`"));
                }
                seen_untagged = true;
                return Ok(());
            }
            if meta.path.is_ident("tagged") {
                if seen_tagged {
                    return Err(meta.error("duplicate `cbor(tagged)`"));
                }
                seen_tagged = true;
                return Ok(());
            }
            Err(meta.error("unsupported `cbor(...)` enum attribute (allowed: tagged, untagged)"))
        })?;
    }

    if seen_tagged && seen_untagged {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "cbor enum cannot be both tagged and untagged",
        ));
    }

    Ok(if seen_untagged {
        EnumTagging::Untagged
    } else {
        EnumTagging::Tagged
    })
}

fn is_option_type(ty: &Type) -> bool {
    let Type::Path(tp) = ty else { return false };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    seg.ident == "Option"
}

fn vec_inner_type(ty: &Type) -> Option<&Type> {
    let Type::Path(tp) = ty else { return None };
    let seg = tp.path.segments.last()?;
    if seg.ident != "Vec" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    let mut iter = args.args.iter();
    let Some(GenericArgument::Type(inner)) = iter.next() else {
        return None;
    };
    if iter.next().is_some() {
        return None;
    }
    Some(inner)
}

fn type_is_ident(ty: &Type, name: &str) -> bool {
    let Type::Path(tp) = ty else { return false };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    seg.ident == name
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VariantKind {
    Null,
    Bool,
    Integer,
    Float,
    Bytes,
    Text,
    Array,
    Map,
}

impl VariantKind {
    const ORDER: [VariantKind; 8] = [
        VariantKind::Null,
        VariantKind::Bool,
        VariantKind::Integer,
        VariantKind::Float,
        VariantKind::Bytes,
        VariantKind::Text,
        VariantKind::Array,
        VariantKind::Map,
    ];

    fn idx(self) -> usize {
        match self {
            VariantKind::Null => 0,
            VariantKind::Bool => 1,
            VariantKind::Integer => 2,
            VariantKind::Float => 3,
            VariantKind::Bytes => 4,
            VariantKind::Text => 5,
            VariantKind::Array => 6,
            VariantKind::Map => 7,
        }
    }

    fn to_cbor_kind_ts(self) -> proc_macro2::TokenStream {
        match self {
            VariantKind::Null => quote!(::sacp_cbor::CborKind::Null),
            VariantKind::Bool => quote!(::sacp_cbor::CborKind::Bool),
            VariantKind::Integer => quote!(::sacp_cbor::CborKind::Integer),
            VariantKind::Float => quote!(::sacp_cbor::CborKind::Float),
            VariantKind::Bytes => quote!(::sacp_cbor::CborKind::Bytes),
            VariantKind::Text => quote!(::sacp_cbor::CborKind::Text),
            VariantKind::Array => quote!(::sacp_cbor::CborKind::Array),
            VariantKind::Map => quote!(::sacp_cbor::CborKind::Map),
        }
    }
}

fn path_might_be_self(path: &syn::Path, self_ident: &Ident) -> bool {
    let Some(last) = path.segments.last() else {
        return false;
    };
    if last.ident != *self_ident {
        return false;
    }
    if path.segments.len() == 1 {
        return true;
    }
    path.segments
        .iter()
        .take(path.segments.len() - 1)
        .all(|seg| matches!(seg.ident.to_string().as_str(), "crate" | "self" | "super"))
}

fn type_mentions_self(ty: &Type, self_ident: &Ident) -> bool {
    match ty {
        Type::Path(tp) => {
            if tp.qself.is_none() && path_might_be_self(&tp.path, self_ident) {
                return true;
            }
            if let Some(q) = &tp.qself {
                if type_mentions_self(&q.ty, self_ident) {
                    return true;
                }
            }
            tp.path.segments.iter().any(|seg| match &seg.arguments {
                PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| match arg {
                    GenericArgument::Type(inner) => type_mentions_self(inner, self_ident),
                    _ => false,
                }),
                _ => false,
            })
        }
        Type::Reference(tr) => type_mentions_self(&tr.elem, self_ident),
        Type::Tuple(tt) => tt.elems.iter().any(|t| type_mentions_self(t, self_ident)),
        Type::Array(ta) => type_mentions_self(&ta.elem, self_ident),
        Type::Slice(ts) => type_mentions_self(&ts.elem, self_ident),
        Type::Group(tg) => type_mentions_self(&tg.elem, self_ident),
        Type::Paren(tp) => type_mentions_self(&tp.elem, self_ident),
        _ => false,
    }
}

fn type_kind(ty: &Type) -> Option<VariantKind> {
    match ty {
        Type::Reference(tr) => type_kind(&tr.elem),
        Type::Group(tg) => type_kind(&tg.elem),
        Type::Paren(tp) => type_kind(&tp.elem),
        Type::Slice(ts) => {
            if type_is_ident(&ts.elem, "u8") {
                Some(VariantKind::Bytes)
            } else {
                None
            }
        }
        Type::Path(tp) => {
            let seg = tp.path.segments.last()?;
            let ident = seg.ident.to_string();
            match ident.as_str() {
                "bool" => Some(VariantKind::Bool),
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64"
                | "u128" | "usize" => Some(VariantKind::Integer),
                "f32" | "f64" => Some(VariantKind::Float),
                "String" | "str" => Some(VariantKind::Text),
                "CborBytesRef" => Some(VariantKind::Bytes),
                "MapEntries" => Some(VariantKind::Map),
                "Vec" => {
                    let inner = vec_inner_type(ty)?;
                    if type_is_ident(inner, "u8") {
                        Some(VariantKind::Bytes)
                    } else {
                        Some(VariantKind::Array)
                    }
                }
                "Option" | "CborValueRef" => None,
                _ => None,
            }
        }
        _ => None,
    }
}

fn decode_lifetime(generics: &Generics) -> (Generics, Lifetime) {
    let mut out = generics.clone();
    let mut name = "__cbor".to_string();
    let mut counter = 0usize;
    loop {
        let probe = Ident::new(&name, proc_macro2::Span::call_site());
        let exists = out.lifetimes().any(|lt| lt.lifetime.ident == probe);
        if !exists {
            break;
        }
        counter += 1;
        name = format!("__cbor{counter}");
    }
    let lt = Lifetime::new(&format!("'{name}"), proc_macro2::Span::call_site());
    out.params
        .insert(0, GenericParam::Lifetime(LifetimeParam::new(lt.clone())));

    let wc = out.make_where_clause();
    for lifetime in generics.lifetimes() {
        let lt_ident = &lifetime.lifetime;
        wc.predicates.push(syn::parse_quote!(#lt: #lt_ident));
    }

    (out, lt)
}

fn add_where_bound(wc: &mut syn::WhereClause, ty: &Type, bound: proc_macro2::TokenStream) {
    let pred: syn::WherePredicate = syn::parse_quote!(#ty: #bound);
    wc.predicates.push(pred);
}

fn decode_named_fields(
    fields: &syn::FieldsNamed,
    target: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    let mut inits = Vec::new();
    let mut matches = Vec::new();
    let mut finals = Vec::new();

    for field in &fields.named {
        let attr = parse_cbor_field_attrs(&field.attrs)?;
        let ident = field.ident.as_ref().unwrap();
        let ty = &field.ty;

        if attr.skip {
            finals.push(quote! { #ident: ::core::default::Default::default(), });
            continue;
        }

        let key = attr
            .rename
            .unwrap_or_else(|| LitStr::new(&ident.to_string(), ident.span()));
        let var = format_ident!("__{ident}");

        inits.push(
            quote! { let mut #var: ::core::option::Option<#ty> = ::core::option::Option::None; },
        );

        matches.push(quote! {
            #key => {
                if #var.is_some() {
                    return Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::DuplicateMapKey,
                        key_off,
                    ));
                }
                #var = ::core::option::Option::Some(::sacp_cbor::CborDecode::decode(decoder)?);
            }
        });

        let is_option = is_option_type(ty);
        if is_option || attr.default {
            finals.push(quote! { #ident: #var.unwrap_or_default(), });
        } else {
            finals.push(quote! {
                #ident: #var.ok_or_else(|| {
                    ::sacp_cbor::CborError::new(::sacp_cbor::ErrorCode::MissingKey, map_off)
                })?,
            });
        }
    }

    Ok(quote! {
        let map_off = decoder.position();
        let (map_len, entered) = decoder.parse_map_len()?;
        #(#inits)*
        for _ in 0..map_len {
            let key_off = decoder.position();
            let k = decoder.parse_text_key()?;
            match k {
                #(#matches)*
                _ => decoder.skip_value()?,
            }
        }
        if entered {
            decoder.exit_container();
        }
        Ok(#target { #(#finals)* })
    })
}

fn encode_struct(
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let base_where_clause = where_clause;

    match &data.fields {
        Fields::Named(fields) => {
            let mut entries = Vec::new();
            let mut bounds = Vec::new();

            for field in &fields.named {
                let attr = parse_cbor_field_attrs(&field.attrs)?;
                if attr.skip {
                    continue;
                }
                let ident = field.ident.as_ref().unwrap();
                let key = attr
                    .rename
                    .unwrap_or_else(|| LitStr::new(&ident.to_string(), ident.span()));

                if !type_mentions_self(&field.ty, name) {
                    bounds.push(&field.ty);
                }

                entries.push(quote! {
                    m.entry(#key, |enc| ::sacp_cbor::CborEncode::encode(&self.#ident, enc))?;
                });
            }

            let len = entries.len();
            let mut encode_where_clause = base_where_clause.cloned();
            if !bounds.is_empty() {
                let wc = encode_where_clause.get_or_insert_with(|| syn::WhereClause {
                    where_token: Default::default(),
                    predicates: Default::default(),
                });
                for ty in bounds {
                    add_where_bound(wc, ty, quote!(::sacp_cbor::CborEncode));
                }
            }

            Ok(quote! {
                impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #encode_where_clause {
                    fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                        enc.map(#len, |m| {
                            #(#entries)*
                            Ok(())
                        })
                    }
                }

                impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #encode_where_clause {}
            })
        }

        Fields::Unnamed(fields) => {
            let mut items = Vec::new();
            let mut bounds = Vec::new();

            for (idx, field) in fields.unnamed.iter().enumerate() {
                ensure_no_cbor_attrs(&field.attrs, "tuple struct fields")?;
                let index = syn::Index::from(idx);

                if !type_mentions_self(&field.ty, name) {
                    bounds.push(&field.ty);
                }

                items.push(quote! { a.value(&self.#index)?; });
            }

            let len = items.len();
            let mut encode_where_clause = base_where_clause.cloned();
            if !bounds.is_empty() {
                let wc = encode_where_clause.get_or_insert_with(|| syn::WhereClause {
                    where_token: Default::default(),
                    predicates: Default::default(),
                });
                for ty in bounds {
                    add_where_bound(wc, ty, quote!(::sacp_cbor::CborEncode));
                }
            }

            Ok(quote! {
                impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #encode_where_clause {
                    fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                        enc.array(#len, |a| {
                            #(#items)*
                            Ok(())
                        })
                    }
                }

                impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #encode_where_clause {}
            })
        }

        Fields::Unit => Ok(quote! {
            impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #base_where_clause {
                fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                    enc.null()
                }
            }

            impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #base_where_clause {}
        }),
    }
}

fn encode_enum(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let base_where_clause = where_clause;

    let mut arms = Vec::new();
    let mut bounds = Vec::new();

    for variant in &data.variants {
        let v_attr = parse_cbor_variant_attrs(&variant.attrs)?;
        let vname = v_attr
            .rename
            .unwrap_or_else(|| LitStr::new(&variant.ident.to_string(), variant.ident.span()));
        let ident = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    Self::#ident => enc.map(1, |m| {
                        m.entry(#vname, |enc| enc.null())?;
                        Ok(())
                    })
                });
            }

            Fields::Unnamed(fields) => {
                let mut pats = Vec::new();
                let mut items = Vec::new();

                for (idx, field) in fields.unnamed.iter().enumerate() {
                    ensure_no_cbor_attrs(&field.attrs, "tuple enum variant fields")?;
                    let var = format_ident!("v{idx}");
                    pats.push(var.clone());

                    if !type_mentions_self(&field.ty, name) {
                        bounds.push(&field.ty);
                    }

                    items.push(quote! { a.value(#var)?; });
                }

                let len = items.len();
                arms.push(quote! {
                    Self::#ident( #(#pats),* ) => enc.map(1, |m| {
                        m.entry(#vname, |enc| {
                            enc.array(#len, |a| {
                                #(#items)*
                                Ok(())
                            })
                        })?;
                        Ok(())
                    })
                });
            }

            Fields::Named(fields) => {
                let mut pats = Vec::new();
                let mut entries = Vec::new();

                for field in &fields.named {
                    let attr = parse_cbor_field_attrs(&field.attrs)?;
                    let f_ident = field.ident.as_ref().unwrap();
                    pats.push(quote!(#f_ident));

                    if attr.skip {
                        continue;
                    }

                    let key = attr
                        .rename
                        .unwrap_or_else(|| LitStr::new(&f_ident.to_string(), f_ident.span()));

                    if !type_mentions_self(&field.ty, name) {
                        bounds.push(&field.ty);
                    }

                    entries.push(quote! {
                        m.entry(#key, |enc| ::sacp_cbor::CborEncode::encode(#f_ident, enc))?;
                    });
                }

                let len = entries.len();
                arms.push(quote! {
                    Self::#ident { #(#pats),* } => enc.map(1, |m| {
                        m.entry(#vname, |enc| {
                            enc.map(#len, |m| {
                                #(#entries)*
                                Ok(())
                            })
                        })?;
                        Ok(())
                    })
                });
            }
        }
    }

    let mut encode_where_clause = base_where_clause.cloned();
    if !bounds.is_empty() {
        let wc = encode_where_clause.get_or_insert_with(|| syn::WhereClause {
            where_token: Default::default(),
            predicates: Default::default(),
        });
        for ty in bounds {
            add_where_bound(wc, ty, quote!(::sacp_cbor::CborEncode));
        }
    }

    Ok(quote! {
        impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #encode_where_clause {
            fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                match self { #(#arms),* }
            }
        }

        impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #encode_where_clause {}
    })
}

fn encode_enum_untagged(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let base_where_clause = where_clause;

    let mut arms = Vec::new();
    let mut bounds = Vec::new();

    for variant in &data.variants {
        let v_attr = parse_cbor_variant_attrs(&variant.attrs)?;
        if v_attr.rename.is_some() {
            return Err(syn::Error::new(
                variant.span(),
                "variant `cbor(rename=...)` is meaningless for `#[cbor(untagged)]` enums",
            ));
        }

        let ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! { Self::#ident => enc.null() });
            }

            Fields::Unnamed(fields) => {
                let n = fields.unnamed.len();
                if n == 1 {
                    let field = fields.unnamed.first().unwrap();
                    ensure_no_cbor_attrs(&field.attrs, "tuple enum variant fields")?;
                    if !type_mentions_self(&field.ty, name) {
                        bounds.push(&field.ty);
                    }
                    let v0 = format_ident!("v0");
                    arms.push(quote! {
                        Self::#ident(#v0) => ::sacp_cbor::CborEncode::encode(#v0, enc)
                    });
                } else {
                    let mut pats = Vec::new();
                    let mut items = Vec::new();

                    for (idx, field) in fields.unnamed.iter().enumerate() {
                        ensure_no_cbor_attrs(&field.attrs, "tuple enum variant fields")?;
                        let var = format_ident!("v{idx}");
                        pats.push(var.clone());

                        if !type_mentions_self(&field.ty, name) {
                            bounds.push(&field.ty);
                        }
                        items.push(quote! { a.value(#var)?; });
                    }

                    arms.push(quote! {
                        Self::#ident( #(#pats),* ) => enc.array(#n, |a| {
                            #(#items)*
                            Ok(())
                        })
                    });
                }
            }

            Fields::Named(fields) => {
                let mut pats = Vec::new();
                let mut entries = Vec::new();

                for field in &fields.named {
                    let attr = parse_cbor_field_attrs(&field.attrs)?;
                    let f_ident = field.ident.as_ref().unwrap();
                    pats.push(quote!(#f_ident));

                    if attr.skip {
                        continue;
                    }
                    let key = attr
                        .rename
                        .unwrap_or_else(|| LitStr::new(&f_ident.to_string(), f_ident.span()));

                    if !type_mentions_self(&field.ty, name) {
                        bounds.push(&field.ty);
                    }

                    entries.push(quote! {
                        m.entry(#key, |enc| ::sacp_cbor::CborEncode::encode(#f_ident, enc))?;
                    });
                }

                let len = entries.len();
                arms.push(quote! {
                    Self::#ident { #(#pats),* } => enc.map(#len, |m| {
                        #(#entries)*
                        Ok(())
                    })
                });
            }
        }
    }

    let mut encode_where_clause = base_where_clause.cloned();
    if !bounds.is_empty() {
        let wc = encode_where_clause.get_or_insert_with(|| syn::WhereClause {
            where_token: Default::default(),
            predicates: Default::default(),
        });
        for ty in bounds {
            add_where_bound(wc, ty, quote!(::sacp_cbor::CborEncode));
        }
    }

    Ok(quote! {
        impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #encode_where_clause {
            fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                match self { #(#arms),* }
            }
        }

        impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #encode_where_clause {}
    })
}

fn decode_struct(
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics2, decode_lt) = decode_lifetime(generics);
    let (impl_generics, _, where_clause) = impl_generics2.split_for_impl();
    let (_, ty_generics, _) = generics.split_for_impl();

    let mut where_clause = where_clause.cloned();
    let wc = where_clause.get_or_insert_with(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    match &data.fields {
        Fields::Named(fields) => {
            for field in &fields.named {
                let attr = parse_cbor_field_attrs(&field.attrs)?;
                if attr.skip {
                    add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                    continue;
                }
                if is_option_type(&field.ty) || attr.default {
                    add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                }
                if !type_mentions_self(&field.ty, name) {
                    add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                }
            }

            let body = decode_named_fields(fields, quote!(Self))?;
            Ok(quote! {
                impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
                    fn decode(decoder: &mut ::sacp_cbor::Decoder<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                        #body
                    }
                }
            })
        }

        Fields::Unnamed(fields) => {
            let mut vars = Vec::new();
            let mut decodes = Vec::new();

            for (idx, field) in fields.unnamed.iter().enumerate() {
                ensure_no_cbor_attrs(&field.attrs, "tuple struct fields")?;

                let var = format_ident!("v{idx}");
                vars.push(var.clone());

                if !type_mentions_self(&field.ty, name) {
                    add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                }
                decodes.push(quote! { let #var = ::sacp_cbor::CborDecode::decode(decoder)?; });
            }

            let expected = vars.len();
            Ok(quote! {
                impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
                    fn decode(decoder: &mut ::sacp_cbor::Decoder<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                        let arr_off = decoder.position();
                        let (arr_len, entered) = decoder.parse_array_len()?;
                        if arr_len != #expected {
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::ArrayLenMismatch,
                                arr_off,
                            ));
                        }
                        #(#decodes)*
                        if entered {
                            decoder.exit_container();
                        }
                        Ok(Self(#(#vars),*))
                    }
                }
            })
        }

        Fields::Unit => Ok(quote! {
            impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
                fn decode(decoder: &mut ::sacp_cbor::Decoder<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                    let _unit: () = ::sacp_cbor::CborDecode::decode(decoder)?;
                    Ok(Self)
                }
            }
        }),
    }
}

fn decode_enum(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics2, decode_lt) = decode_lifetime(generics);
    let (impl_generics, _, where_clause) = impl_generics2.split_for_impl();
    let (_, ty_generics, _) = generics.split_for_impl();

    let mut where_clause = where_clause.cloned();
    let wc = where_clause.get_or_insert_with(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    let mut arms = Vec::new();

    for variant in &data.variants {
        let v_attr = parse_cbor_variant_attrs(&variant.attrs)?;
        let vname = v_attr
            .rename
            .unwrap_or_else(|| LitStr::new(&variant.ident.to_string(), variant.ident.span()));
        let ident = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    #vname => {
                        let _unit: () = ::sacp_cbor::CborDecode::decode(decoder)?;
                        Ok(Self::#ident)
                    }
                });
            }

            Fields::Unnamed(fields) => {
                let mut vars = Vec::new();
                let mut decodes = Vec::new();

                for (idx, field) in fields.unnamed.iter().enumerate() {
                    ensure_no_cbor_attrs(&field.attrs, "tuple enum variant fields")?;

                    if !type_mentions_self(&field.ty, name) {
                        add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }

                    let var = format_ident!("v{idx}");
                    vars.push(var.clone());
                    decodes.push(quote! { let #var = ::sacp_cbor::CborDecode::decode(decoder)?; });
                }

                let expected = vars.len();
                arms.push(quote! {
                    #vname => {
                        let arr_off = decoder.position();
                        let (arr_len, entered) = decoder.parse_array_len()?;
                        if arr_len != #expected {
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::ArrayLenMismatch,
                                arr_off,
                            ));
                        }
                        #(#decodes)*
                        if entered {
                            decoder.exit_container();
                        }
                        Ok(Self::#ident(#(#vars),*))
                    }
                });
            }

            Fields::Named(fields) => {
                for field in &fields.named {
                    let attr = parse_cbor_field_attrs(&field.attrs)?;
                    if attr.skip {
                        add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                        continue;
                    }
                    if is_option_type(&field.ty) || attr.default {
                        add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                    }
                    if !type_mentions_self(&field.ty, name) {
                        add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                }

                let body = decode_named_fields(fields, quote!(Self::#ident))?;
                arms.push(quote! { #vname => { #body } });
            }
        }
    }

    Ok(quote! {
        impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
            fn decode(decoder: &mut ::sacp_cbor::Decoder<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                let map_off = decoder.position();
                let (map_len, entered) = decoder.parse_map_len()?;
                if map_len != 1 {
                    return Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::MapLenMismatch,
                        map_off,
                    ));
                }
                let _key_off = decoder.position();
                let k = decoder.parse_text_key()?;
                let result = match k {
                    #(#arms),*,
                    _ => Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::MissingKey,
                        map_off,
                    )),
                };
                if entered {
                    decoder.exit_container();
                }
                result
            }
        }
    })
}

fn decode_enum_untagged(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics2, decode_lt) = decode_lifetime(generics);
    let (impl_generics, _, where_clause) = impl_generics2.split_for_impl();
    let (_, ty_generics, _) = generics.split_for_impl();

    let mut where_clause = where_clause.cloned();
    let wc = where_clause.get_or_insert_with(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    let mut bodies: Vec<Option<proc_macro2::TokenStream>> = vec![None; 8];

    for variant in &data.variants {
        let v_attr = parse_cbor_variant_attrs(&variant.attrs)?;
        if v_attr.rename.is_some() {
            return Err(syn::Error::new(
                variant.span(),
                "variant `cbor(rename=...)` is meaningless for `#[cbor(untagged)]` enums",
            ));
        }

        let ident = &variant.ident;
        let kind = match &variant.fields {
            Fields::Unit => VariantKind::Null,

            Fields::Unnamed(fields) => {
                if fields.unnamed.len() == 1 {
                    let field = fields.unnamed.first().unwrap();
                    ensure_no_cbor_attrs(&field.attrs, "tuple enum variant fields")?;
                    type_kind(&field.ty).ok_or_else(|| {
                        syn::Error::new(
                            field.span(),
                            "untagged enum single-field variants must map to a concrete CBOR kind",
                        )
                    })?
                } else {
                    VariantKind::Array
                }
            }

            Fields::Named(_) => VariantKind::Map,
        };

        let idx = kind.idx();
        if bodies[idx].is_some() {
            return Err(syn::Error::new(
                variant.span(),
                "untagged enum variants must have distinct CBOR kinds",
            ));
        }

        let body = match &variant.fields {
            Fields::Unit => quote! {
                let _unit: () = ::sacp_cbor::CborDecode::decode(decoder)?;
                Ok(Self::#ident)
            },

            Fields::Unnamed(fields) => {
                if fields.unnamed.len() == 1 {
                    let field = fields.unnamed.first().unwrap();
                    if !type_mentions_self(&field.ty, name) {
                        add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                    quote! {
                        Ok(Self::#ident(::sacp_cbor::CborDecode::decode(decoder)?))
                    }
                } else {
                    let mut vars = Vec::new();
                    let mut decodes = Vec::new();
                    for (i, field) in fields.unnamed.iter().enumerate() {
                        ensure_no_cbor_attrs(&field.attrs, "tuple enum variant fields")?;

                        if !type_mentions_self(&field.ty, name) {
                            add_where_bound(
                                wc,
                                &field.ty,
                                quote!(::sacp_cbor::CborDecode<#decode_lt>),
                            );
                        }
                        let v = format_ident!("v{i}");
                        vars.push(v.clone());
                        decodes
                            .push(quote! { let #v = ::sacp_cbor::CborDecode::decode(decoder)?; });
                    }
                    let expected = vars.len();
                    quote! {
                        let arr_off = decoder.position();
                        let (arr_len, entered) = decoder.parse_array_len()?;
                        if arr_len != #expected {
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::ArrayLenMismatch,
                                arr_off,
                            ));
                        }
                        #(#decodes)*
                        if entered {
                            decoder.exit_container();
                        }
                        Ok(Self::#ident(#(#vars),*))
                    }
                }
            }

            Fields::Named(fields) => {
                for field in &fields.named {
                    let attr = parse_cbor_field_attrs(&field.attrs)?;
                    if attr.skip {
                        add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                        continue;
                    }
                    if is_option_type(&field.ty) || attr.default {
                        add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                    }
                    if !type_mentions_self(&field.ty, name) {
                        add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                }
                decode_named_fields(fields, quote!(Self::#ident))?
            }
        };

        bodies[idx] = Some(body);
    }

    let mut arms = Vec::new();
    for kind in VariantKind::ORDER {
        if let Some(body) = bodies[kind.idx()].take() {
            let kind_ts = kind.to_cbor_kind_ts();
            arms.push(quote! { #kind_ts => { #body } });
        }
    }

    Ok(quote! {
        impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
            fn decode(decoder: &mut ::sacp_cbor::Decoder<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                match decoder.peek_kind()? {
                    #(#arms),*,
                    _ => Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::ExpectedEnum,
                        decoder.position(),
                    )),
                }
            }
        }
    })
}

#[proc_macro_derive(CborEncode, attributes(cbor))]
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
