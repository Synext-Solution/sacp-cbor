use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    braced, bracketed,
    parse::{Parse, ParseStream},
    parse_quote, Expr, Ident, LitStr, Path, Result, Token,
};

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as MacroInput);
    if let Err(err) = validate_value(&input.value) {
        return err.to_compile_error().into();
    }

    let crate_path = &input.crate_path;
    let mut emitter = Emitter::new(crate_path);
    let enc = format_ident!("__cbor_enc");
    let enc_ref = format_ident!("__cbor_enc_ref");
    let body = emitter.emit_value(&input.value, &enc_ref, Target::Encoder);

    let out = quote! {
        {
            (|| -> ::core::result::Result<#crate_path::CanonicalCbor, #crate_path::CborError> {
                let mut #enc = #crate_path::Encoder::new();
                {
                    let #enc_ref = &mut #enc;
                    #body?;
                }
                #enc.finish()
            })()
        }
    };

    TokenStream::from(out)
}

struct MacroInput {
    crate_path: Path,
    value: Value,
}

impl Parse for MacroInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let crate_path = if input.peek(Token![crate]) {
            input.parse::<Token![crate]>()?;
            input.parse::<Token![=]>()?;
            let path = input.parse::<Path>()?;
            input.parse::<Token![;]>()?;
            path
        } else {
            parse_quote!(::sacp_cbor)
        };
        let value = input.parse::<Value>()?;
        if !input.is_empty() {
            return Err(input.error("unexpected tokens after cbor_bytes! value"));
        }
        Ok(Self { crate_path, value })
    }
}

fn validate_value(value: &Value) -> Result<()> {
    match value {
        Value::Null | Value::Expr(_) => Ok(()),
        Value::Array(values) => {
            for value in values {
                validate_value(value)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            let mut entries_sorted = entries.iter().collect::<Vec<_>>();
            entries_sorted.sort_by(|a, b| {
                a.key_bytes
                    .len()
                    .cmp(&b.key_bytes.len())
                    .then_with(|| a.key_bytes.cmp(&b.key_bytes))
            });

            for pair in entries_sorted.windows(2) {
                if pair[0].key_bytes == pair[1].key_bytes {
                    return Err(syn::Error::new(
                        pair[1].key.span(),
                        "duplicate CBOR map key",
                    ));
                }
            }

            for entry in entries {
                validate_value(&entry.value)?;
            }
            Ok(())
        }
    }
}

#[derive(Clone)]
enum Value {
    Null,
    Array(Vec<Value>),
    Map(Vec<MapEntry>),
    Expr(Expr),
}

#[derive(Clone)]
struct MapEntry {
    key: LitStr,
    key_bytes: Vec<u8>,
    value: Value,
}

impl Parse for Value {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.peek(syn::token::Bracket) {
            let content;
            bracketed!(content in input);
            let elems = content.parse_terminated(Value::parse, Token![,])?;
            return Ok(Value::Array(elems.into_iter().collect()));
        }

        if input.peek(syn::token::Brace) {
            let content;
            braced!(content in input);
            let entries = content.parse_terminated(MapEntry::parse, Token![,])?;
            return Ok(Value::Map(entries.into_iter().collect()));
        }

        let fork = input.fork();
        if fork.peek(Ident) {
            let ident: Ident = fork.parse()?;
            if ident == "null" && fork.is_empty() {
                let _: Ident = input.parse()?;
                return Ok(Value::Null);
            }
        }

        let expr: Expr = input.parse()?;
        Ok(Value::Expr(expr))
    }
}

impl Parse for MapEntry {
    fn parse(input: ParseStream) -> Result<Self> {
        let key = if input.peek(Ident) {
            let ident: Ident = input.parse()?;
            LitStr::new(&ident.to_string(), ident.span())
        } else if input.peek(LitStr) {
            input.parse()?
        } else {
            return Err(input.error("map keys must be identifiers or string literals"));
        };

        input.parse::<Token![:]>()?;
        let value: Value = input.parse()?;
        let key_bytes = key.value().into_bytes();

        Ok(Self {
            key,
            key_bytes,
            value,
        })
    }
}

struct Emitter<'a> {
    counter: usize,
    crate_path: &'a Path,
}

#[derive(Clone, Copy)]
enum Target {
    Encoder,
    Array,
}

impl<'a> Emitter<'a> {
    fn new(crate_path: &'a Path) -> Self {
        Self {
            counter: 0,
            crate_path,
        }
    }

    fn fresh(&mut self, prefix: &str) -> Ident {
        let id = format_ident!("__cbor_{prefix}{}", self.counter);
        self.counter += 1;
        id
    }

    fn emit_value(&mut self, value: &Value, enc: &Ident, target: Target) -> TokenStream2 {
        let crate_path = &self.crate_path;
        match value {
            Value::Null => quote! { #enc.null() },
            Value::Expr(expr) => match target {
                Target::Encoder => quote! { #crate_path::CborEncode::encode(&#expr, #enc) },
                Target::Array => {
                    quote! { #crate_path::CborEncode::encode_array_item(&#expr, #enc) }
                }
            },
            Value::Array(elems) => {
                let len = elems.len();
                let arr = self.fresh("arr");
                let mut elem_stmts = Vec::with_capacity(len);
                for elem in elems {
                    let expr = self.emit_value(elem, &arr, Target::Array);
                    elem_stmts.push(quote! { #expr?; });
                }
                quote! {
                    #enc.array(#len, |#arr| {
                        #(#elem_stmts)*
                        ::core::result::Result::Ok(())
                    })
                }
            }
            Value::Map(entries) => {
                let len = entries.len();
                let map = self.fresh("map");
                let mut entries_sorted: Vec<&MapEntry> = entries.iter().collect();
                entries_sorted.sort_by(|a, b| {
                    a.key_bytes
                        .len()
                        .cmp(&b.key_bytes.len())
                        .then_with(|| a.key_bytes.cmp(&b.key_bytes))
                });
                let mut entry_stmts = Vec::with_capacity(len);
                for entry in entries_sorted {
                    let key = &entry.key;
                    let enc_inner = self.fresh("enc");
                    let expr = self.emit_value(&entry.value, &enc_inner, Target::Encoder);
                    entry_stmts.push(quote! {
                        #map.entry(#key, |#enc_inner| #expr)?;
                    });
                }
                quote! {
                    #enc.map(#len, |#map| {
                        #(#entry_stmts)*
                        ::core::result::Result::Ok(())
                    })
                }
            }
        }
    }
}
