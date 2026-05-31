use quote::{format_ident, quote, ToTokens};
use syn::{
    spanned::Spanned, DataEnum, DataStruct, Fields, GenericParam, Generics, Ident, Lifetime,
    LifetimeParam, LitStr, Type,
};

use crate::schema::{
    enum_variants, internal_tagged_tuple_variant_error, named_fields, tuple_fields,
    type_needs_trait_bound, validate_internal_tagging, CborEnumAttr, EnumTagging, NamedFieldSpec,
    TupleFieldSpec, VariantSpec,
};
use crate::util::{add_where_bound, ensure_where_clause};

fn decode_impl(
    name: &Ident,
    impl_generics: impl ToTokens,
    ty_generics: impl ToTokens,
    where_clause: impl ToTokens,
    decode_lt: &Lifetime,
    body: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        impl #impl_generics ::sacp_cbor::CborDecode<#decode_lt> for #name #ty_generics #where_clause {
            fn decode<const CHECKED: bool>(decoder: &mut ::sacp_cbor::Decoder<#decode_lt, CHECKED>) -> ::core::result::Result<Self, ::sacp_cbor::CborError> {
                #body
            }
        }
    }
}

fn tuple_decode_parts(
    name: &Ident,
    fields: &[TupleFieldSpec<'_>],
    wc: &mut syn::WhereClause,
    decode_lt: &Lifetime,
) -> syn::Result<(Vec<Ident>, Vec<proc_macro2::TokenStream>)> {
    let mut vars = Vec::new();
    let mut decodes = Vec::new();

    for field in fields {
        let idx = field.index;
        let var = format_ident!("v{idx}");
        vars.push(var.clone());

        if type_needs_trait_bound(field.ty, name) {
            add_where_bound(wc, field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
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
    fields: &[NamedFieldSpec<'_>],
    wc: &mut syn::WhereClause,
    decode_lt: &Lifetime,
) {
    for field in fields {
        if field.wire_key.is_none() {
            add_where_bound(wc, field.ty, quote!(::core::default::Default));
            continue;
        }
        if type_needs_trait_bound(field.ty, name) {
            add_where_bound(wc, field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
        }
    }
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

struct DecodeImplParts {
    generics: Generics,
    decode_lt: Lifetime,
    where_clause: Option<syn::WhereClause>,
}

impl DecodeImplParts {
    fn new(generics: &Generics) -> Self {
        let (impl_generics, decode_lt) = decode_lifetime(generics);
        let where_clause = impl_generics.split_for_impl().2.cloned();
        Self {
            generics: impl_generics,
            decode_lt,
            where_clause,
        }
    }

    fn where_clause_mut(&mut self) -> &mut syn::WhereClause {
        ensure_where_clause(&mut self.where_clause)
    }

    fn finish(
        &self,
        name: &Ident,
        source_generics: &Generics,
        body: proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        let (impl_generics, _, _) = self.generics.split_for_impl();
        let (_, ty_generics, _) = source_generics.split_for_impl();
        decode_impl(
            name,
            impl_generics,
            ty_generics,
            &self.where_clause,
            &self.decode_lt,
            body,
        )
    }
}

fn decode_named_fields(
    fields: &[NamedFieldSpec<'_>],
    target: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    let mut decodes = Vec::new();
    let mut finals = Vec::new();
    let mut entries = Vec::new();

    for field in fields {
        let ident = field.ident;
        let Some(key) = field.wire_key.clone() else {
            finals.push(quote! { #ident: ::core::default::Default::default(), });
            continue;
        };

        entries.push((key, ident.clone(), field.ty.clone()));
    }

    let expected_len = entries.len();
    for (key, ident, ty) in entries {
        let var = format_ident!("__{ident}");
        decodes.push(quote! {
            let #var: #ty = {
                let __key = match map.next_key_ref()? {
                    ::core::option::Option::Some(key) => key,
                    ::core::option::Option::None => {
                        return Err(::sacp_cbor::CborError::new(
                            ::sacp_cbor::ErrorCode::MapLenMismatch,
                            map_off,
                        ));
                    }
                };
                if __key.text != #key {
                    map.skip_value()?;
                    return Err(::sacp_cbor::CborError::new(
                        ::sacp_cbor::ErrorCode::UnknownField,
                        __key.offset,
                    ));
                }
                map.next_value()?
            };
        });
        finals.push(quote! { #ident: #var, });
    }

    Ok(quote! {
        let map_off = decoder.position();
        let mut map = decoder.map()?;
        if map.remaining() < #expected_len {
            return Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::MapLenMismatch,
                map_off,
            ));
        }
        #(#decodes)*
        if let ::core::option::Option::Some(__key) = map.next_key_ref()? {
            map.skip_value()?;
            return Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::UnknownField,
                __key.offset,
            ));
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

fn required_adjacent_content(
    raw: &Ident,
    decode_expr: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    quote! {
        let #raw = __content.ok_or_else(|| {
            ::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::MissingKey,
                map_off,
            )
        })?;
        #decode_expr
    }
}

pub(crate) fn decode_struct(
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
) -> syn::Result<proc_macro2::TokenStream> {
    let mut impl_parts = DecodeImplParts::new(generics);

    match &data.fields {
        Fields::Named(fields) => {
            let decode_lt = impl_parts.decode_lt.clone();
            let wc = impl_parts.where_clause_mut();
            let field_specs = named_fields(fields)?;
            add_decode_bounds_for_named_fields(name, &field_specs, wc, &decode_lt);
            let body = decode_named_fields(&field_specs, quote!(Self))?;
            Ok(impl_parts.finish(name, generics, body))
        }

        Fields::Unnamed(fields) => {
            let decode_lt = impl_parts.decode_lt.clone();
            let wc = impl_parts.where_clause_mut();
            let field_specs = tuple_fields(fields, "tuple struct fields")?;
            let (vars, decodes) = tuple_decode_parts(name, &field_specs, wc, &decode_lt)?;
            let expected = vars.len();
            let body = array_decode_block(expected, &decodes, quote!(Ok(Self(#(#vars),*))));
            Ok(impl_parts.finish(name, generics, body))
        }

        Fields::Unit => Ok(impl_parts.finish(
            name,
            generics,
            quote! {
                let _unit: () = ::sacp_cbor::CborDecode::decode(decoder)?;
                Ok(Self)
            },
        )),
    }
}

pub(crate) fn decode_enum(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
    attrs: &CborEnumAttr,
) -> syn::Result<proc_macro2::TokenStream> {
    let variants = enum_variants(data, attrs.rename_all)?;
    match &attrs.tagging {
        EnumTagging::External => decode_enum_external(name, generics, &variants),
        EnumTagging::Internal { tag } => decode_enum_internal(name, generics, data, &variants, tag),
        EnumTagging::Adjacent { tag, content } => {
            decode_enum_adjacent(name, generics, &variants, tag, content)
        }
    }
}

fn decode_enum_external(
    name: &Ident,
    generics: &Generics,
    variants: &[VariantSpec<'_>],
) -> syn::Result<proc_macro2::TokenStream> {
    let mut impl_parts = DecodeImplParts::new(generics);
    let decode_lt = impl_parts.decode_lt.clone();
    let wc = impl_parts.where_clause_mut();

    let mut map_arms = Vec::new();

    for variant in variants {
        let vname = &variant.name;
        let ident = variant.ident;

        match variant.fields {
            Fields::Unit => {
                map_arms.push(quote! {
                    #vname => map.decode_value(|decoder| {
                        let _unit: () = ::sacp_cbor::CborDecode::decode(decoder)?;
                        Ok(Self::#ident)
                    })
                });
            }

            Fields::Unnamed(fields) => {
                let field_specs = tuple_fields(fields, "tuple enum variant fields")?;
                if field_specs.len() == 1 {
                    let field = &field_specs[0];
                    if type_needs_trait_bound(field.ty, name) {
                        add_where_bound(wc, field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                    map_arms.push(quote! {
                        #vname => map.decode_value(|decoder| {
                            Ok(Self::#ident(::sacp_cbor::CborDecode::decode(decoder)?))
                        })
                    });
                } else {
                    let (vars, decodes) = tuple_decode_parts(name, &field_specs, wc, &decode_lt)?;
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
                let field_specs = named_fields(fields)?;
                add_decode_bounds_for_named_fields(name, &field_specs, wc, &decode_lt);
                let body = decode_named_fields(&field_specs, quote!(Self::#ident))?;
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
        let k = match map.next_key_ref()? {
            ::core::option::Option::Some(key) => key,
            ::core::option::Option::None => {
                return Err(::sacp_cbor::CborError::new(
                    ::sacp_cbor::ErrorCode::MapLenMismatch,
                    map_off,
                ));
            }
        };
        match k.text {
            #(#map_arms),*,
            _ => Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::UnknownEnumVariant,
                k.offset,
            )),
        }
    };

    let body = quote! {
        if !matches!(decoder.peek_kind()?, ::sacp_cbor::query::CborKind::Map) {
            return Err(::sacp_cbor::CborError::new(
                ::sacp_cbor::ErrorCode::ExpectedEnum,
                decoder.position(),
            ));
        }
        #map_body
    };

    Ok(impl_parts.finish(name, generics, body))
}

fn decode_enum_internal(
    name: &Ident,
    generics: &Generics,
    data: &DataEnum,
    variants: &[VariantSpec<'_>],
    tag: &LitStr,
) -> syn::Result<proc_macro2::TokenStream> {
    validate_internal_tagging(data, tag)?;

    let mut impl_parts = DecodeImplParts::new(generics);
    let decode_lt = impl_parts.decode_lt.clone();
    let wc = impl_parts.where_clause_mut();

    let mut slots = Vec::<InternalFieldSlot>::new();
    let mut variant_decodes = Vec::<InternalVariantDecode>::new();

    for variant in variants {
        let vname = &variant.name;
        match variant.fields {
            Fields::Unit => variant_decodes.push(InternalVariantDecode {
                ident: variant.ident.clone(),
                name: vname.clone(),
                fields: Vec::new(),
                unit: true,
            }),
            Fields::Named(fields) => {
                let field_specs = named_fields(fields)?;
                add_decode_bounds_for_named_fields(name, &field_specs, wc, &decode_lt);

                let mut variant_fields = Vec::new();
                for field in &field_specs {
                    let ident = field.ident.clone();
                    let ty = field.ty.clone();

                    let Some(key) = field.wire_key.clone() else {
                        variant_fields.push(InternalVariantField {
                            ident,
                            ty,
                            storage: None,
                            skip: true,
                        });
                        continue;
                    };

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
                    });
                }

                variant_decodes.push(InternalVariantDecode {
                    ident: variant.ident.clone(),
                    name: vname.clone(),
                    fields: variant_fields,
                    unit: false,
                });
            }
            Fields::Unnamed(fields) => {
                return Err(internal_tagged_tuple_variant_error(fields.span()))
            }
        }
    }

    let slot_inits = slots.iter().map(|slot| {
        let storage = &slot.storage;
        quote! {
            let mut #storage: ::core::option::Option<::sacp_cbor::query::CborValueRef<#decode_lt>> =
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

    let mut variant_arms = Vec::new();
    for variant in &variant_decodes {
        let vname = &variant.name;
        let ident = &variant.ident;
        let allowed_slots = variant
            .fields
            .iter()
            .filter_map(|field| field.storage.as_ref().map(ToString::to_string))
            .collect::<Vec<_>>();
        let extra_checks = slots
            .iter()
            .filter(|slot| {
                !allowed_slots
                    .iter()
                    .any(|allowed| allowed == &slot.storage.to_string())
            })
            .map(|slot| {
                let storage = &slot.storage;
                quote! {
                    if let ::core::option::Option::Some(__extra) = #storage {
                        return Err(::sacp_cbor::CborError::new(
                            ::sacp_cbor::ErrorCode::UnknownField,
                            __extra.offset(),
                        ));
                    }
                }
            })
            .collect::<Vec<_>>();

        if variant.unit {
            variant_arms.push(quote! {
                #vname => {
                    #(#extra_checks)*
                    Ok(Self::#ident)
                }
            });
        } else {
            let mut finals = Vec::new();
            for field in &variant.fields {
                let ident = &field.ident;
                if field.skip {
                    finals.push(quote! {
                        #ident: ::core::default::Default::default(),
                    });
                    continue;
                }

                let storage = field.storage.as_ref().ok_or_else(|| {
                    syn::Error::new(field.ident.span(), "missing internal field storage")
                })?;
                let raw = format_ident!("__raw_{}", ident);
                let decode_expr = decode_raw_value(&field.ty, &raw);

                finals.push(quote! {
                    #ident: match #storage {
                        ::core::option::Option::Some(#raw) => #decode_expr?,
                        ::core::option::Option::None => {
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::MissingKey,
                                map_off,
                            ));
                        }
                    },
                });
            }

            variant_arms.push(quote! {
                #vname => {
                    #(#extra_checks)*
                    Ok(Self::#ident { #(#finals)* })
                }
            });
        }
    }

    Ok(impl_parts.finish(
        name,
        generics,
        quote! {
                let map_off = decoder.position();
                let mut map = decoder.map()?;
                let mut __tag: ::core::option::Option<&#decode_lt str> =
                    ::core::option::Option::None;
                #(#slot_inits)*
                while let ::core::option::Option::Some(k) = map.next_key_ref()? {
                    match k.text {
                        #tag => {
                            __tag = ::core::option::Option::Some(map.next_value()?);
                        }
                        #(#slot_matches)*
                        _ => {
                            map.skip_value()?;
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::UnknownField,
                                k.offset,
                            ));
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
        },
    ))
}

fn decode_enum_adjacent(
    name: &Ident,
    generics: &Generics,
    variants: &[VariantSpec<'_>],
    tag: &LitStr,
    content: &LitStr,
) -> syn::Result<proc_macro2::TokenStream> {
    let mut impl_parts = DecodeImplParts::new(generics);
    let decode_lt = impl_parts.decode_lt.clone();
    let wc = impl_parts.where_clause_mut();

    let mut variant_arms = Vec::new();

    for variant in variants {
        let vname = &variant.name;
        let ident = variant.ident;

        match variant.fields {
            Fields::Unit => {
                let raw = format_ident!("__content_raw");
                let content = required_adjacent_content(
                    &raw,
                    quote! {
                        {
                            let _unit: () = ::sacp_cbor::decode(
                                #raw.as_bytes(),
                                ::sacp_cbor::DecodeLimits::for_bytes(#raw.as_bytes().len()),
                            )
                            .map_err(|err| ::sacp_cbor::CborError::new(
                                err.code,
                                #raw.offset() + err.offset,
                            ))?;
                            Ok(Self::#ident)
                        }
                    },
                );
                variant_arms.push(quote! {
                    #vname => {
                        #content
                    }
                });
            }
            Fields::Unnamed(fields) => {
                let field_specs = tuple_fields(fields, "tuple enum variant fields")?;
                if field_specs.len() == 1 {
                    let field = &field_specs[0];
                    if type_needs_trait_bound(field.ty, name) {
                        add_where_bound(wc, field.ty, quote!(::sacp_cbor::CborDecode<#decode_lt>));
                    }
                    let raw = format_ident!("__content_raw");
                    let decode_expr = decode_raw_value(field.ty, &raw);
                    let content =
                        required_adjacent_content(&raw, quote! { Ok(Self::#ident(#decode_expr?)) });
                    variant_arms.push(quote! {
                        #vname => {
                            #content
                        }
                    });
                } else {
                    let (vars, decodes) = tuple_decode_parts(name, &field_specs, wc, &decode_lt)?;
                    let expected = vars.len();
                    let body = array_decode_block(
                        expected,
                        &decodes,
                        quote!(Ok(Self::#ident(#(#vars),*))),
                    );
                    let raw = format_ident!("__content_raw");
                    let decode_expr = decode_body_from_raw(&raw, body);
                    let content = required_adjacent_content(&raw, decode_expr);
                    variant_arms.push(quote! {
                        #vname => {
                            #content
                        }
                    });
                }
            }
            Fields::Named(fields) => {
                let field_specs = named_fields(fields)?;
                add_decode_bounds_for_named_fields(name, &field_specs, wc, &decode_lt);
                let body = decode_named_fields(&field_specs, quote!(Self::#ident))?;
                let raw = format_ident!("__content_raw");
                let decode_expr = decode_body_from_raw(&raw, body);
                let content = required_adjacent_content(&raw, decode_expr);
                variant_arms.push(quote! {
                    #vname => {
                        #content
                    }
                });
            }
        }
    }

    Ok(impl_parts.finish(
        name,
        generics,
        quote! {
                let map_off = decoder.position();
                let mut map = decoder.map()?;
                let mut __tag: ::core::option::Option<&#decode_lt str> =
                    ::core::option::Option::None;
                let mut __content: ::core::option::Option<::sacp_cbor::query::CborValueRef<#decode_lt>> =
                    ::core::option::Option::None;
                while let ::core::option::Option::Some(k) = map.next_key_ref()? {
                    match k.text {
                        #tag => {
                            __tag = ::core::option::Option::Some(map.next_value()?);
                        }
                        #content => {
                            __content = ::core::option::Option::Some(map.next_value()?);
                        }
                        _ => {
                            map.skip_value()?;
                            return Err(::sacp_cbor::CborError::new(
                                ::sacp_cbor::ErrorCode::UnknownField,
                                k.offset,
                            ));
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
        },
    ))
}
