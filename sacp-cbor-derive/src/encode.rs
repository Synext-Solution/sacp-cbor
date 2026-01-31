use quote::{format_ident, quote};
use syn::{spanned::Spanned, DataEnum, DataStruct, Fields, Generics, Ident, LitStr, Type};

use crate::attrs::{ensure_no_cbor_attrs, parse_cbor_field_attrs, parse_cbor_variant_attrs};
use crate::types::type_mentions_self;
use crate::util::add_where_bound;

fn named_entries_with_pats<'a, F>(
    name: &Ident,
    fields: &'a syn::FieldsNamed,
    bounds: &mut Vec<&'a Type>,
    value: F,
) -> syn::Result<(Vec<Ident>, Vec<proc_macro2::TokenStream>)>
where
    F: Fn(&Ident) -> proc_macro2::TokenStream,
{
    let mut pats = Vec::new();
    let mut entries = Vec::new();

    struct NamedEntry {
        key_bytes: Vec<u8>,
        entry: proc_macro2::TokenStream,
    }

    for field in &fields.named {
        let attr = parse_cbor_field_attrs(&field.attrs)?;
        let f_ident = field.ident.as_ref().unwrap();
        pats.push(f_ident.clone());

        if attr.skip {
            continue;
        }

        let key = attr
            .rename
            .unwrap_or_else(|| LitStr::new(&f_ident.to_string(), f_ident.span()));

        if !type_mentions_self(&field.ty, name) {
            bounds.push(&field.ty);
        }

        let value_ts = value(f_ident);
        let key_bytes = key.value().into_bytes();
        entries.push(NamedEntry {
            key_bytes,
            entry: quote! {
                m.entry(#key, |enc| ::sacp_cbor::CborEncode::encode(#value_ts, enc))?;
            },
        });
    }

    entries.sort_by(|a, b| {
        a.key_bytes
            .len()
            .cmp(&b.key_bytes.len())
            .then_with(|| a.key_bytes.cmp(&b.key_bytes))
    });

    let entries = entries.into_iter().map(|entry| entry.entry).collect();

    Ok((pats, entries))
}

fn tuple_variant_parts<'a>(
    name: &Ident,
    fields: &'a syn::FieldsUnnamed,
    bounds: &mut Vec<&'a Type>,
) -> syn::Result<(Vec<Ident>, Vec<proc_macro2::TokenStream>)> {
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

    Ok((pats, items))
}

pub(crate) fn encode_struct(
    name: &Ident,
    generics: &Generics,
    data: &DataStruct,
) -> syn::Result<proc_macro2::TokenStream> {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let base_where_clause = where_clause;

    match &data.fields {
        Fields::Named(fields) => {
            let mut bounds = Vec::new();

            let (_, entries) =
                named_entries_with_pats(name, fields, &mut bounds, |ident| quote!(&self.#ident))?;

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

pub(crate) fn encode_enum(
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
                let (pats, items) = tuple_variant_parts(name, fields, &mut bounds)?;

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
                let (pats, entries) =
                    named_entries_with_pats(name, fields, &mut bounds, |ident| quote!(#ident))?;

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

pub(crate) fn encode_enum_untagged(
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
                    let (pats, items) = tuple_variant_parts(name, fields, &mut bounds)?;

                    arms.push(quote! {
                        Self::#ident( #(#pats),* ) => enc.array(#n, |a| {
                            #(#items)*
                            Ok(())
                        })
                    });
                }
            }

            Fields::Named(fields) => {
                let (pats, entries) =
                    named_entries_with_pats(name, fields, &mut bounds, |ident| quote!(#ident))?;

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
