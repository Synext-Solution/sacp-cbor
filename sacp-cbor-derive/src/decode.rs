use quote::{format_ident, quote};
use syn::{
    spanned::Spanned, DataEnum, DataStruct, Fields, GenericParam, Generics, Ident, Lifetime,
    LifetimeParam, LitStr, Type,
};

use crate::attrs::{
    ensure_no_cbor_attrs, field_key, parse_cbor_field_attrs, validate_internal_tagging,
    variant_has_rename, variant_name, CborEnumAttr, EnumTagging,
};
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
        decodes.push(quote! {
            let #var = match array.next_value()? {
                ::core::option::Option::Some(value) => value,
                ::core::option::Option::None => {
                    return Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::ArrayLenMismatch,
                        arr_off,
                    ));
                }
            };
        });
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
        let mut array = decoder.array()?;
        let arr_len = array.remaining();
        if arr_len != #expected {
            return Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::ArrayLenMismatch,
                arr_off,
            ));
        }
        #(#decodes)*
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
                #var = ::core::option::Option::Some(map.next_value()?);
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
        let mut map = decoder.map()?;
        #(#inits)*
        while let ::core::option::Option::Some(k) = map.next_key()? {
            match k {
                #(#matches)*
                _ => {
                    let _unused: ::sacp_cbor::CborValueRef = map.next_value()?;
                }
            }
        }
        Ok(#target { #(#finals)* })
    })
}

#[derive(Clone)]
struct InternalFieldSlot {
    key: LitStr,
    storage: Ident,
}

#[derive(Clone)]
struct InternalVariantField {
    ident: Ident,
    ty: Type,
    storage: Option<Ident>,
    skip: bool,
    default: bool,
    option: bool,
}

#[derive(Clone)]
struct InternalVariantDecode {
    ident: Ident,
    name: LitStr,
    fields: Vec<InternalVariantField>,
    unit: bool,
}

fn decode_raw_value(ty: &Type, raw: &Ident) -> proc_macro2::TokenStream {
    quote! {
        ::sacp_cbor::decode::<#ty>(
            #raw.as_bytes(),
            ::sacp_cbor::DecodeLimits::for_bytes(#raw.as_bytes().len()),
        )
        .map_err(|err| ::sacp_cbor::CborError::new(err.code, #raw.offset() + err.offset))
    }
}

fn decode_body_from_raw(raw: &Ident, body: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
    quote! {
        {
            let __result: ::core::result::Result<Self, ::sacp_cbor::CborError> = (|| {
                let mut decoder = ::sacp_cbor::Decoder::<true>::new_checked(
                    #raw.as_bytes(),
                    ::sacp_cbor::DecodeLimits::for_bytes(#raw.as_bytes().len()),
                )?;
                #body
            })();
            __result
        }
        .map_err(|err| ::sacp_cbor::CborError::new(err.code, #raw.offset() + err.offset))
    }
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
                    fn decode<const CHECKED: bool>(decoder: &mut ::sacp_cbor::Decoder<#decode_lt, CHECKED>) -> ::core::result::Result<Self, ::sacp_cbor::CborError> {
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
                    fn decode<const CHECKED: bool>(decoder: &mut ::sacp_cbor::Decoder<#decode_lt, CHECKED>) -> ::core::result::Result<Self, ::sacp_cbor::CborError> {
                        #body
                    }
                }
            })
        }

        Fields::Unit => Ok(quote! {
            impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
                fn decode<const CHECKED: bool>(decoder: &mut ::sacp_cbor::Decoder<#decode_lt, CHECKED>) -> ::core::result::Result<Self, ::sacp_cbor::CborError> {
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
    attrs: &CborEnumAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    match &attrs.tagging {
        EnumTagging::External => decode_enum_external(name, generics, data, attrs),
        EnumTagging::Untagged => decode_enum_untagged(name, generics, data),
        EnumTagging::Internal { tag } => decode_enum_internal(name, generics, data, attrs, tag),
        EnumTagging::Adjacent { tag, content } => {
            decode_enum_adjacent(name, generics, data, attrs, tag, content)
        }
    }
}

fn decode_enum_external(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
    attrs: &CborEnumAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics2, decode_lt) = decode_lifetime(generics);
    let (impl_generics, _, where_clause) = impl_generics2.split_for_impl();
    let (_, ty_generics, _) = generics.split_for_impl();

    let mut where_clause = where_clause.cloned();
    let wc = where_clause.get_or_insert_with(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    let mut map_arms = Vec::new();
    let mut text_arms = Vec::new();

    for variant in &data.variants {
        let vname = variant_name(variant, attrs.rename_all)?;
        let ident = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                map_arms.push(quote! {
                    #vname => Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::ExpectedEnum,
                        map_off,
                    ))
                });
                text_arms.push(quote! {
                    #vname => Ok(Self::#ident)
                });
            }

            Fields::Unnamed(fields) => {
                if fields.unnamed.len() == 1 {
                    let field = fields.unnamed.first().unwrap();
                    ensure_no_cbor_attrs(&field.attrs, "tuple enum variant fields")?;
                    if !type_mentions_self(&field.ty, name) {
                        add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                    map_arms.push(quote! {
                        #vname => map.decode_value(|decoder| {
                            Ok(Self::#ident(::sacp_cbor::CborDecode::decode(decoder)?))
                        })
                    });
                } else {
                    let (vars, decodes) = tuple_decode_parts(
                        name,
                        fields,
                        wc,
                        &decode_lt,
                        "tuple enum variant fields",
                    )?;
                    let expected = vars.len();
                    let body = array_decode_block(
                        expected,
                        &decodes,
                        quote!(Ok(Self::#ident(#(#vars),*))),
                    );
                    map_arms.push(quote! {
                        #vname => map.decode_value(|decoder| {
                            #body
                        })
                    });
                }
            }

            Fields::Named(fields) => {
                add_decode_bounds_for_named_fields(name, fields, wc, &decode_lt)?;
                let body = decode_named_fields(fields, quote!(Self::#ident))?;
                map_arms.push(quote! { #vname => map.decode_value(|decoder| { #body }) });
            }
        }
    }

    let map_body = quote! {
        let map_off = decoder.position();
        let mut map = decoder.map()?;
        if map.remaining() != 1 {
            return Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::MapLenMismatch,
                map_off,
            ));
        }
        let k = match map.next_key()? {
            ::core::option::Option::Some(key) => key,
            ::core::option::Option::None => {
                return Err(::sacp_cbor::CborError::new(
                    ::sacp_cbor::ErrorCode::MapLenMismatch,
                    map_off,
                ));
            }
        };
        match k {
            #(#map_arms),*,
            _ => Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::UnknownEnumVariant,
                map_off,
            )),
        }
    };

    let text_body = if text_arms.is_empty() {
        quote! {
            Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::ExpectedEnum,
                decoder.position(),
            ))
        }
    } else {
        quote! {
            let text_off = decoder.position();
            let key: &#decode_lt str = ::sacp_cbor::CborDecode::decode(decoder)?;
            match key {
                #(#text_arms),*,
                _ => Err(::sacp_cbor::CborError::new(
                    ::sacp_cbor::ErrorCode::UnknownEnumVariant,
                    text_off,
                )),
            }
        }
    };

    let body = quote! {
        match decoder.peek_kind()? {
            ::sacp_cbor::CborKind::Text => {
                #text_body
            }
            ::sacp_cbor::CborKind::Map => {
                #map_body
            }
            _ => Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::ExpectedEnum,
                decoder.position(),
            )),
        }
    };

    Ok(quote! {
        impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
            fn decode<const CHECKED: bool>(decoder: &mut ::sacp_cbor::Decoder<#decode_lt, CHECKED>) -> ::core::result::Result<Self, ::sacp_cbor::CborError> {
                #body
            }
        }
    })
}

fn decode_enum_internal(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
    attrs: &CborEnumAttr,
    tag: &LitStr,
) -> syn::Result<proc_macro2::TokenStream> {
    validate_internal_tagging(data, tag)?;

    let (impl_generics2, decode_lt) = decode_lifetime(generics);
    let (impl_generics, _, where_clause) = impl_generics2.split_for_impl();
    let (_, ty_generics, _) = generics.split_for_impl();

    let mut where_clause = where_clause.cloned();
    let wc = where_clause.get_or_insert_with(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    let mut slots = Vec::<InternalFieldSlot>::new();
    let mut variants = Vec::<InternalVariantDecode>::new();

    for variant in &data.variants {
        let vname = variant_name(variant, attrs.rename_all)?;
        match &variant.fields {
            Fields::Unit => variants.push(InternalVariantDecode {
                ident: variant.ident.clone(),
                name: vname,
                fields: Vec::new(),
                unit: true,
            }),
            Fields::Named(fields) => {
                add_decode_bounds_for_named_fields(name, fields, wc, &decode_lt)?;

                let mut variant_fields = Vec::new();
                for field in &fields.named {
                    let attr = parse_cbor_field_attrs(&field.attrs)?;
                    let ident = field.ident.clone().unwrap();
                    let ty = field.ty.clone();

                    if attr.skip {
                        variant_fields.push(InternalVariantField {
                            ident,
                            ty,
                            storage: None,
                            skip: true,
                            default: false,
                            option: false,
                        });
                        continue;
                    }

                    let key = field_key(field)?;
                    let storage = if let Some(existing) =
                        slots.iter().find(|slot| slot.key.value() == key.value())
                    {
                        existing.storage.clone()
                    } else {
                        let storage = format_ident!("__raw_field_{}", slots.len());
                        slots.push(InternalFieldSlot {
                            key: key.clone(),
                            storage: storage.clone(),
                        });
                        storage
                    };

                    variant_fields.push(InternalVariantField {
                        ident,
                        ty,
                        storage: Some(storage),
                        skip: false,
                        default: attr.default,
                        option: is_option_type(&field.ty),
                    });
                }

                variants.push(InternalVariantDecode {
                    ident: variant.ident.clone(),
                    name: vname,
                    fields: variant_fields,
                    unit: false,
                });
            }
            Fields::Unnamed(_) => unreachable!(),
        }
    }

    let slot_inits = slots.iter().map(|slot| {
        let storage = &slot.storage;
        quote! {
            let mut #storage: ::core::option::Option<::sacp_cbor::CborValueRef<#decode_lt>> =
                ::core::option::Option::None;
        }
    });
    let slot_matches = slots.iter().map(|slot| {
        let key = &slot.key;
        let storage = &slot.storage;
        quote! {
            #key => {
                #storage = ::core::option::Option::Some(map.next_value()?);
            }
        }
    });

    let variant_arms = variants.iter().map(|variant| {
        let vname = &variant.name;
        let ident = &variant.ident;

        if variant.unit {
            quote! {
                #vname => Ok(Self::#ident)
            }
        } else {
            let finals = variant.fields.iter().map(|field| {
                let ident = &field.ident;
                if field.skip {
                    return quote! {
                        #ident: ::core::default::Default::default(),
                    };
                }

                let storage = field.storage.as_ref().unwrap();
                let raw = format_ident!("__raw_{}", ident);
                let decode_expr = decode_raw_value(&field.ty, &raw);

                if field.option || field.default {
                    quote! {
                        #ident: match #storage {
                            ::core::option::Option::Some(#raw) => #decode_expr?,
                            ::core::option::Option::None => ::core::default::Default::default(),
                        },
                    }
                } else {
                    quote! {
                        #ident: match #storage {
                            ::core::option::Option::Some(#raw) => #decode_expr?,
                            ::core::option::Option::None => {
                                return Err(::sacp_cbor::CborError::new(
                                    ::sacp_cbor::ErrorCode::MissingKey,
                                    map_off,
                                ));
                            }
                        },
                    }
                }
            });

            quote! {
                #vname => Ok(Self::#ident { #(#finals)* })
            }
        }
    });

    Ok(quote! {
        impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
            fn decode<const CHECKED: bool>(decoder: &mut ::sacp_cbor::Decoder<#decode_lt, CHECKED>) -> ::core::result::Result<Self, ::sacp_cbor::CborError> {
                let map_off = decoder.position();
                let mut map = decoder.map()?;
                let mut __tag: ::core::option::Option<&#decode_lt str> =
                    ::core::option::Option::None;
                #(#slot_inits)*
                while let ::core::option::Option::Some(k) = map.next_key()? {
                    match k {
                        #tag => {
                            __tag = ::core::option::Option::Some(map.next_value()?);
                        }
                        #(#slot_matches)*
                        _ => {
                            let _unused: ::sacp_cbor::CborValueRef = map.next_value()?;
                        }
                    }
                }
                let __tag = __tag.ok_or_else(|| {
                    ::sacp_cbor::CborError::new(::sacp_cbor::ErrorCode::MissingKey, map_off)
                })?;
                match __tag {
                    #(#variant_arms),*,
                    _ => Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::UnknownEnumVariant,
                        map_off,
                    )),
                }
            }
        }
    })
}

fn decode_enum_adjacent(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
    attrs: &CborEnumAttr,
    tag: &LitStr,
    content: &LitStr,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics2, decode_lt) = decode_lifetime(generics);
    let (impl_generics, _, where_clause) = impl_generics2.split_for_impl();
    let (_, ty_generics, _) = generics.split_for_impl();

    let mut where_clause = where_clause.cloned();
    let wc = where_clause.get_or_insert_with(|| syn::WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    });

    let mut variant_arms = Vec::new();

    for variant in &data.variants {
        let vname = variant_name(variant, attrs.rename_all)?;
        let ident = &variant.ident;

        match &variant.fields {
            Fields::Unit => {
                variant_arms.push(quote! {
                    #vname => Ok(Self::#ident)
                });
            }
            Fields::Unnamed(fields) => {
                if fields.unnamed.len() == 1 {
                    let field = fields.unnamed.first().unwrap();
                    if !type_mentions_self(&field.ty, name) {
                        add_where_bound(wc, &field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                    let raw = format_ident!("__content_raw");
                    let decode_expr = decode_raw_value(&field.ty, &raw);
                    variant_arms.push(quote! {
                        #vname => {
                            let #raw = __content.ok_or_else(|| {
                                ::sacp_cbor::CborError::new(
                                    ::sacp_cbor::ErrorCode::MissingKey,
                                    map_off,
                                )
                            })?;
                            Ok(Self::#ident(#decode_expr?))
                        }
                    });
                } else {
                    let (vars, decodes) = tuple_decode_parts(
                        name,
                        fields,
                        wc,
                        &decode_lt,
                        "tuple enum variant fields",
                    )?;
                    let expected = vars.len();
                    let body = array_decode_block(
                        expected,
                        &decodes,
                        quote!(Ok(Self::#ident(#(#vars),*))),
                    );
                    let raw = format_ident!("__content_raw");
                    let decode_expr = decode_body_from_raw(&raw, body);
                    variant_arms.push(quote! {
                        #vname => {
                            let #raw = __content.ok_or_else(|| {
                                ::sacp_cbor::CborError::new(
                                    ::sacp_cbor::ErrorCode::MissingKey,
                                    map_off,
                                )
                            })?;
                            #decode_expr
                        }
                    });
                }
            }
            Fields::Named(fields) => {
                add_decode_bounds_for_named_fields(name, fields, wc, &decode_lt)?;
                let body = decode_named_fields(fields, quote!(Self::#ident))?;
                let raw = format_ident!("__content_raw");
                let decode_expr = decode_body_from_raw(&raw, body);
                variant_arms.push(quote! {
                    #vname => {
                        let #raw = __content.ok_or_else(|| {
                            ::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::MissingKey,
                                map_off,
                            )
                        })?;
                        #decode_expr
                    }
                });
            }
        }
    }

    Ok(quote! {
        impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
            fn decode<const CHECKED: bool>(decoder: &mut ::sacp_cbor::Decoder<#decode_lt, CHECKED>) -> ::core::result::Result<Self, ::sacp_cbor::CborError> {
                let map_off = decoder.position();
                let mut map = decoder.map()?;
                let mut __tag: ::core::option::Option<&#decode_lt str> =
                    ::core::option::Option::None;
                let mut __content: ::core::option::Option<::sacp_cbor::CborValueRef<#decode_lt>> =
                    ::core::option::Option::None;
                while let ::core::option::Option::Some(k) = map.next_key()? {
                    match k {
                        #tag => {
                            __tag = ::core::option::Option::Some(map.next_value()?);
                        }
                        #content => {
                            __content = ::core::option::Option::Some(map.next_value()?);
                        }
                        _ => {
                            let _unused: ::sacp_cbor::CborValueRef = map.next_value()?;
                        }
                    }
                }
                let __tag = __tag.ok_or_else(|| {
                    ::sacp_cbor::CborError::new(::sacp_cbor::ErrorCode::MissingKey, map_off)
                })?;
                match __tag {
                    #(#variant_arms),*,
                    _ => Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::UnknownEnumVariant,
                        map_off,
                    )),
                }
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
        if variant_has_rename(variant)? {
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
            fn decode<const CHECKED: bool>(decoder: &mut ::sacp_cbor::Decoder<#decode_lt, CHECKED>) -> ::core::result::Result<Self, ::sacp_cbor::CborError> {
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
