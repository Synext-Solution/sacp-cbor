extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, spanned::Spanned, Attribute, Data, DataEnum, DataStruct, DeriveInput,
    Fields, GenericArgument, GenericParam, Generics, Ident, Lifetime, LifetimeParam, LitStr,
    PathArguments, Type,
};

#[derive(Default)]
struct CborAttr {
    rename: Option<String>,
    skip: bool,
    default: bool,
}

fn parse_cbor_attrs(attrs: &[Attribute]) -> syn::Result<CborAttr> {
    let mut out = CborAttr::default();
    for attr in attrs {
        if !attr.path().is_ident("cbor") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                out.skip = true;
                return Ok(());
            }
            if meta.path.is_ident("default") {
                out.default = true;
                return Ok(());
            }
            if meta.path.is_ident("rename") {
                let lit: LitStr = meta.value()?.parse()?;
                out.rename = Some(lit.value());
                return Ok(());
            }
            Err(meta.error("unsupported cbor attribute"))
        })?;
    }
    Ok(out)
}

fn is_option_type(ty: &Type) -> bool {
    let Type::Path(tp) = ty else { return false };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    seg.ident == "Option"
}

fn type_mentions_ident(ty: &Type, ident: &Ident) -> bool {
    match ty {
        Type::Path(tp) => tp.path.segments.iter().any(|seg| {
            if seg.ident == *ident {
                return true;
            }
            match &seg.arguments {
                PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| match arg {
                    GenericArgument::Type(inner) => type_mentions_ident(inner, ident),
                    _ => false,
                }),
                _ => false,
            }
        }),
        Type::Reference(tr) => type_mentions_ident(&tr.elem, ident),
        Type::Tuple(tt) => tt.elems.iter().any(|elem| type_mentions_ident(elem, ident)),
        Type::Array(ta) => type_mentions_ident(&ta.elem, ident),
        Type::Group(tg) => type_mentions_ident(&tg.elem, ident),
        Type::Paren(tp) => type_mentions_ident(&tp.elem, ident),
        _ => false,
    }
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
    let where_clause = out.make_where_clause();
    for lifetime in generics.lifetimes() {
        let lt_ident = &lifetime.lifetime;
        where_clause
            .predicates
            .push(syn::parse_quote!(#lt: #lt_ident));
    }
    (out, lt)
}

fn add_where_bound(
    where_clause: &mut syn::WhereClause,
    ty: &Type,
    bound: proc_macro2::TokenStream,
) {
    let pred: syn::WherePredicate = syn::parse_quote!(#ty: #bound);
    where_clause.predicates.push(pred);
}

fn encode_struct(name: &Ident, generics: &Generics, data: &DataStruct) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let base_where_clause = where_clause;

    match &data.fields {
        Fields::Named(fields) => {
            let mut entries = Vec::new();
            let mut bounds = Vec::new();
            for field in &fields.named {
                let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
                if attr.skip {
                    continue;
                }
                let key = attr
                    .rename
                    .unwrap_or_else(|| field.ident.as_ref().unwrap().to_string());
                let ident = field.ident.as_ref().unwrap();
                let is_recursive = type_mentions_ident(&field.ty, name);
                if !is_recursive {
                    bounds.push(&field.ty);
                }
                let recursive_vec =
                    vec_inner_type(&field.ty).is_some_and(|inner| type_mentions_ident(inner, name));
                if recursive_vec {
                    entries.push(quote! {
                        m.entry(#key, |enc| {
                            enc.array(self.#ident.len(), |a| {
                                for item in &self.#ident {
                                    a.value(item)?;
                                }
                                Ok(())
                            })
                        })?;
                    });
                } else {
                    entries.push(quote! {
                        m.entry(#key, |enc| ::sacp_cbor::CborEncode::encode(&self.#ident, enc))?;
                    });
                }
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
            quote! {
                impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #encode_where_clause {
                    fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                        enc.map(#len, |m| {
                            #(#entries)*
                            Ok(())
                        })
                    }
                }
                impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #base_where_clause {}
            }
        }
        Fields::Unnamed(fields) => {
            let mut items = Vec::new();
            let mut bounds = Vec::new();
            for (idx, field) in fields.unnamed.iter().enumerate() {
                let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
                if attr.skip || attr.default {
                    return syn::Error::new(
                        field.span(),
                        "cbor skip/default not supported on tuple fields",
                    )
                    .to_compile_error();
                }
                let index = syn::Index::from(idx);
                let is_recursive = type_mentions_ident(&field.ty, name);
                if !is_recursive {
                    bounds.push(&field.ty);
                }
                let recursive_vec =
                    vec_inner_type(&field.ty).is_some_and(|inner| type_mentions_ident(inner, name));
                if recursive_vec {
                    items.push(quote! {
                        a.array(self.#index.len(), |a| {
                            for item in &self.#index {
                                a.value(item)?;
                            }
                            Ok(())
                        })?;
                    });
                } else {
                    items.push(quote! { a.value(&self.#index)?; });
                }
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
            quote! {
                impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #encode_where_clause {
                    fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                        enc.array(#len, |a| {
                            #(#items)*
                            Ok(())
                        })
                    }
                }
                impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #base_where_clause {}
            }
        }
        Fields::Unit => quote! {
            impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #base_where_clause {
                fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                    enc.null()
                }
            }
            impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #base_where_clause {}
        },
    }
}

fn encode_enum(name: &Ident, generics: &Generics, data: &DataEnum) -> proc_macro2::TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let base_where_clause = where_clause;
    let mut arms = Vec::new();
    let mut bounds = Vec::new();

    for variant in &data.variants {
        let v_attr = parse_cbor_attrs(&variant.attrs).unwrap_or_default();
        let vname = v_attr.rename.unwrap_or_else(|| variant.ident.to_string());
        let ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    Self::#ident => {
                        enc.map(1, |m| {
                            m.entry(#vname, |enc| enc.null())?;
                            Ok(())
                        })
                    }
                });
            }
            Fields::Unnamed(fields) => {
                let mut pats = Vec::new();
                let mut items = Vec::new();
                for (idx, field) in fields.unnamed.iter().enumerate() {
                    let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
                    if attr.skip || attr.default {
                        return syn::Error::new(
                            field.span(),
                            "cbor skip/default not supported on tuple variants",
                        )
                        .to_compile_error();
                    }
                    let var = format_ident!("v{idx}");
                    pats.push(var.clone());
                    let is_recursive = type_mentions_ident(&field.ty, name);
                    if !is_recursive {
                        bounds.push(&field.ty);
                    }
                    let recursive_vec = vec_inner_type(&field.ty)
                        .is_some_and(|inner| type_mentions_ident(inner, name));
                    if recursive_vec {
                        items.push(quote! {
                            a.array(#var.len(), |a| {
                                for item in #var.iter() {
                                    a.value(item)?;
                                }
                                Ok(())
                            })?;
                        });
                    } else {
                        items.push(quote! { a.value(#var)?; });
                    }
                }
                let len = items.len();
                arms.push(quote! {
                    Self::#ident( #(#pats),* ) => {
                        enc.map(1, |m| {
                            m.entry(#vname, |enc| {
                                enc.array(#len, |a| {
                                    #(#items)*
                                    Ok(())
                                })
                            })?;
                            Ok(())
                        })
                    }
                });
            }
            Fields::Named(fields) => {
                let mut pats = Vec::new();
                let mut entries = Vec::new();
                for field in &fields.named {
                    let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
                    if attr.skip {
                        continue;
                    }
                    let key = attr
                        .rename
                        .unwrap_or_else(|| field.ident.as_ref().unwrap().to_string());
                    let ident = field.ident.as_ref().unwrap();
                    pats.push(quote!(#ident));
                    let is_recursive = type_mentions_ident(&field.ty, name);
                    if !is_recursive {
                        bounds.push(&field.ty);
                    }
                    let recursive_vec = vec_inner_type(&field.ty)
                        .is_some_and(|inner| type_mentions_ident(inner, name));
                    if recursive_vec {
                        entries.push(quote! {
                            m.entry(#key, |enc| {
                                enc.array(#ident.len(), |a| {
                                    for item in #ident.iter() {
                                        a.value(item)?;
                                    }
                                    Ok(())
                                })
                            })?;
                        });
                    } else {
                        entries.push(quote! {
                            m.entry(#key, |enc| ::sacp_cbor::CborEncode::encode(#ident, enc))?;
                        });
                    }
                }
                let len = entries.len();
                arms.push(quote! {
                    Self::#ident { #(#pats),* } => {
                        enc.map(1, |m| {
                            m.entry(#vname, |enc| {
                                enc.map(#len, |m| {
                                    #(#entries)*
                                    Ok(())
                                })
                            })?;
                            Ok(())
                        })
                    }
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

    quote! {
        impl #impl_generics ::sacp_cbor::CborEncode for #name #ty_generics #encode_where_clause {
            fn encode(&self, enc: &mut ::sacp_cbor::Encoder) -> Result<(), ::sacp_cbor::CborError> {
                match self {
                    #(#arms),*
                }
            }
        }
        impl #impl_generics ::sacp_cbor::CborArrayElem for #name #ty_generics #base_where_clause {}
    }
}

fn decode_named_fields(
    value: &proc_macro2::TokenStream,
    fields: &syn::FieldsNamed,
    target: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let mut inits = Vec::new();
    let mut matches = Vec::new();
    let mut finals = Vec::new();

    for field in &fields.named {
        let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
        let ident = field.ident.as_ref().unwrap();
        let ty = &field.ty;
        let key = attr.rename.unwrap_or_else(|| ident.to_string());
        let var = format_ident!("__{ident}");

        if attr.skip {
            finals.push(quote! { #ident: ::core::default::Default::default(), });
            continue;
        }

        inits.push(quote! { let mut #var: Option<#ty> = None; });

        matches.push(quote! {
            #key => {
                if #var.is_some() {
                    return Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::DuplicateMapKey,
                        v.offset(),
                    ));
                }
                #var = Some(::sacp_cbor::CborDecode::decode(v)?);
            }
        });

        let is_option = is_option_type(ty);
        if is_option || attr.default {
            finals.push(quote! {
                #ident: #var.unwrap_or_default(),
            });
        } else {
            finals.push(quote! {
                #ident: #var.ok_or_else(|| {
                    ::sacp_cbor::CborError::new(::sacp_cbor::ErrorCode::MissingKey, #value.offset())
                })?,
            });
        }
    }

    quote! {
        let map = #value.map()?;
        #(#inits)*
        for entry in map.iter() {
            let (k, v) = entry?;
            match k {
                #(#matches)*
                _ => {}
            }
        }
        Ok(#target { #(#finals)* })
    }
}

fn decode_struct(name: &Ident, generics: &Generics, data: &DataStruct) -> proc_macro2::TokenStream {
    let (impl_generics, decode_lt) = decode_lifetime(generics);
    let (impl_generics, _, where_clause) = impl_generics.split_for_impl();
    let (_, ty_generics, _) = generics.split_for_impl();

    let mut where_clause = where_clause.cloned();
    let wc = where_clause.get_or_insert_with(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    match &data.fields {
        Fields::Named(fields) => {
            for field in &fields.named {
                let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
                if attr.skip {
                    add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                    continue;
                }
                if is_option_type(&field.ty) || attr.default {
                    add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                }
                if !type_mentions_ident(&field.ty, name) {
                    add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                }
            }
            let value = quote!(value);
            let body = decode_named_fields(&value, fields, quote!(Self));
            quote! {
                impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
                    fn decode(value: ::sacp_cbor::CborValueRef<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                        #body
                    }
                }
            }
        }
        Fields::Unnamed(fields) => {
            let mut vars = Vec::new();
            let mut decodes = Vec::new();
            for (idx, field) in fields.unnamed.iter().enumerate() {
                let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
                if attr.skip || attr.default {
                    return syn::Error::new(
                        field.span(),
                        "cbor skip/default not supported on tuple fields",
                    )
                    .to_compile_error();
                }
                let var = format_ident!("v{idx}");
                vars.push(var.clone());
                if !type_mentions_ident(&field.ty, name) {
                    add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                }
                decodes.push(quote! {
                    let #var = {
                        let item = iter.next().ok_or_else(|| {
                            ::sacp_cbor::CborError::new(::sacp_cbor::ErrorCode::ArrayLenMismatch, value.offset())
                        })??;
                        ::sacp_cbor::CborDecode::decode(item)?
                    };
                });
            }
            let len = vars.len();
            quote! {
                impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
                    fn decode(value: ::sacp_cbor::CborValueRef<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                        let arr = value.array()?;
                        if arr.len() != #len {
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::ArrayLenMismatch,
                                value.offset(),
                            ));
                        }
                        let mut iter = arr.iter();
                        #(#decodes)*
                        Ok(Self(#(#vars),*))
                    }
                }
            }
        }
        Fields::Unit => quote! {
            impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
                fn decode(value: ::sacp_cbor::CborValueRef<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                    let _unit: () = ::sacp_cbor::CborDecode::decode(value)?;
                    Ok(Self)
                }
            }
        },
    }
}

fn decode_enum(name: &Ident, generics: &Generics, data: &DataEnum) -> proc_macro2::TokenStream {
    let (impl_generics, decode_lt) = decode_lifetime(generics);
    let (impl_generics, _, where_clause) = impl_generics.split_for_impl();
    let (_, ty_generics, _) = generics.split_for_impl();

    let mut where_clause = where_clause.cloned();
    let wc = where_clause.get_or_insert_with(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    let mut arms = Vec::new();

    for variant in &data.variants {
        let v_attr = parse_cbor_attrs(&variant.attrs).unwrap_or_default();
        let vname = v_attr.rename.unwrap_or_else(|| variant.ident.to_string());
        let ident = &variant.ident;
        match &variant.fields {
            Fields::Unit => {
                arms.push(quote! {
                    #vname => {
                        if !v.is_null() {
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::ExpectedNull,
                                v.offset(),
                            ));
                        }
                        Ok(Self::#ident)
                    }
                });
            }
            Fields::Unnamed(fields) => {
                let mut vars = Vec::new();
                let mut decodes = Vec::new();
                for (idx, field) in fields.unnamed.iter().enumerate() {
                    let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
                    if attr.skip || attr.default {
                        return syn::Error::new(
                            field.span(),
                            "cbor skip/default not supported on tuple variants",
                        )
                        .to_compile_error();
                    }
                    if !type_mentions_ident(&field.ty, name) {
                        add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                    let var = format_ident!("v{idx}");
                    vars.push(var.clone());
                    decodes.push(quote! {
                        let #var = {
                            let item = iter.next().ok_or_else(|| {
                                ::sacp_cbor::CborError::new(::sacp_cbor::ErrorCode::ArrayLenMismatch, v.offset())
                            })??;
                            ::sacp_cbor::CborDecode::decode(item)?
                        };
                    });
                }
                let len = vars.len();
                arms.push(quote! {
                    #vname => {
                        let arr = v.array()?;
                        if arr.len() != #len {
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::ArrayLenMismatch,
                                v.offset(),
                            ));
                        }
                        let mut iter = arr.iter();
                        #(#decodes)*
                        Ok(Self::#ident(#(#vars),*))
                    }
                });
            }
            Fields::Named(fields) => {
                for field in &fields.named {
                    let attr = parse_cbor_attrs(&field.attrs).unwrap_or_default();
                    if attr.skip {
                        add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                        continue;
                    }
                    if is_option_type(&field.ty) || attr.default {
                        add_where_bound(wc, &field.ty, quote!(::core::default::Default));
                    }
                    if !type_mentions_ident(&field.ty, name) {
                        add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                }
                let value = quote!(v);
                let body = decode_named_fields(&value, fields, quote!(Self::#ident));
                arms.push(quote! { #vname => { #body } });
            }
        }
    }

    quote! {
        impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
            fn decode(value: ::sacp_cbor::CborValueRef<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                let map = value.map()?;
                if map.len() != 1 {
                    return Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::MapLenMismatch,
                        value.offset(),
                    ));
                }
                let mut iter = map.iter();
                let (k, v) = iter
                    .next()
                    .ok_or_else(|| ::sacp_cbor::CborError::new(::sacp_cbor::ErrorCode::MapLenMismatch, value.offset()))??;
                match k {
                    #(#arms),*
                    _ => Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::MissingKey,
                        value.offset(),
                    )),
                }
            }
        }
    }
}

#[proc_macro_derive(CborEncode, attributes(cbor))]
pub fn derive_cbor_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let out = match &input.data {
        Data::Struct(data) => encode_struct(&input.ident, &input.generics, data),
        Data::Enum(data) => encode_enum(&input.ident, &input.generics, data),
        Data::Union(u) => {
            syn::Error::new(u.union_token.span(), "CborEncode not supported for unions")
                .to_compile_error()
        }
    };
    TokenStream::from(out)
}

#[proc_macro_derive(CborDecode, attributes(cbor))]
pub fn derive_cbor_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let out = match &input.data {
        Data::Struct(data) => decode_struct(&input.ident, &input.generics, data),
        Data::Enum(data) => decode_enum(&input.ident, &input.generics, data),
        Data::Union(u) => {
            syn::Error::new(u.union_token.span(), "CborDecode not supported for unions")
                .to_compile_error()
        }
    };
    TokenStream::from(out)
}
