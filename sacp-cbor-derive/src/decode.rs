use quote::{format_ident, quote};
use syn::{
    spanned::Spanned, DataEnum, DataStruct, Fields, GenericParam, Generics, Ident, Lifetime,
    LifetimeParam, LitStr,
};

use crate::attrs::{ensure_no_cbor_attrs, parse_cbor_field_attrs, parse_cbor_variant_attrs};
use crate::types::{is_option_type, type_kind, type_mentions_self, VariantKind};
use crate::util::add_where_bound;

fn tuple_decode_parts(
    name: &Ident,
    fields: &syn::FieldsUnnamed,
    wc: &mut syn::WhereClause,
    decode_lt: &Lifetime,
    ctx: &str,
) -> syn::Result<(Vec<Ident>, Vec<proc_macro2::TokenStream>)> {
    let mut vars = Vec::new();
    let mut decodes = Vec::new();

    for (idx, field) in fields.unnamed.iter().enumerate() {
        ensure_no_cbor_attrs(&field.attrs, ctx)?;

        let var = format_ident!("v{idx}");
        vars.push(var.clone());

        if !type_mentions_self(&field.ty, name) {
            add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
        }
        decodes.push(quote! { let #var = ::sacp_cbor::CborDecode::decode(decoder)?; });
    }

    Ok((vars, decodes))
}

fn add_decode_bounds_for_named_fields(
    name: &Ident,
    fields: &syn::FieldsNamed,
    wc: &mut syn::WhereClause,
    decode_lt: &Lifetime,
) -> syn::Result<()> {
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
    Ok(())
}

fn array_decode_block(
    expected: usize,
    decodes: &[proc_macro2::TokenStream],
    result: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
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
        #result
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

pub(crate) fn decode_struct(
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
            add_decode_bounds_for_named_fields(name, fields, wc, &decode_lt)?;
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
            let (vars, decodes) =
                tuple_decode_parts(name, fields, wc, &decode_lt, "tuple struct fields")?;
            let expected = vars.len();
            let body = array_decode_block(expected, &decodes, quote!(Ok(Self(#(#vars),*))));
            Ok(quote! {
                impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
                    fn decode(decoder: &mut ::sacp_cbor::Decoder<#decode_lt>) -> Result<Self, ::sacp_cbor::CborError> {
                        #body
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

pub(crate) fn decode_enum(
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
                let (vars, decodes) =
                    tuple_decode_parts(name, fields, wc, &decode_lt, "tuple enum variant fields")?;
                let expected = vars.len();
                let body =
                    array_decode_block(expected, &decodes, quote!(Ok(Self::#ident(#(#vars),*))));
                arms.push(quote! {
                    #vname => {
                        #body
                    }
                });
            }

            Fields::Named(fields) => {
                add_decode_bounds_for_named_fields(name, fields, wc, &decode_lt)?;
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

pub(crate) fn decode_enum_untagged(
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
                    let (vars, decodes) = tuple_decode_parts(
                        name,
                        fields,
                        wc,
                        &decode_lt,
                        "tuple enum variant fields",
                    )?;
                    let expected = vars.len();
                    array_decode_block(expected, &decodes, quote!(Ok(Self::#ident(#(#vars),*))))
                }
            }

            Fields::Named(fields) => {
                add_decode_bounds_for_named_fields(name, fields, wc, &decode_lt)?;
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
