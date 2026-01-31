use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    braced, bracketed,
    parse::{Parse, ParseStream},
    Expr, Ident, LitStr, Result, Token,
};

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let value = syn::parse_macro_input!(input as Value);
    let mut emitter = Emitter::new();
    let enc = format_ident!("__cbor_enc");
    let body = emitter.emit_value(&value, &enc);

    let out = quote! {
        {
            (|| -> ::core::result::Result<::sacp_cbor::CborBytes, ::sacp_cbor::CborError> {
                let mut #enc = ::sacp_cbor::Encoder::new();
                #body?;
                #enc.into_canonical()
            })()
        }
    };

    TokenStream::from(out)
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

struct Emitter {
    counter: usize,
}

impl Emitter {
    fn new() -> Self {
        Self { counter: 0 }
    }

    fn fresh(&mut self, prefix: &str) -> Ident {
        let id = format_ident!("__cbor_{prefix}{}", self.counter);
        self.counter += 1;
        id
    }

    fn emit_value(&mut self, value: &Value, enc: &Ident) -> TokenStream2 {
        match value {
            Value::Null => quote! { #enc.null() },
            Value::Expr(expr) => quote! { #enc.__encode_any(#expr) },
            Value::Array(elems) => {
                let len = elems.len();
                let arr = self.fresh("arr");
                let mut elem_stmts = Vec::with_capacity(len);
                for elem in elems {
                    let expr = self.emit_value(elem, &arr);
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
                let mut entries_sorted = entries.clone();
                entries_sorted.sort_by(|a, b| {
                    a.key_bytes
                        .len()
                        .cmp(&b.key_bytes.len())
                        .then_with(|| a.key_bytes.cmp(&b.key_bytes))
                });
                let mut entry_stmts = Vec::with_capacity(len);
                for entry in &entries_sorted {
                    let key = &entry.key;
                    let enc_inner = self.fresh("enc");
                    let expr = self.emit_value(&entry.value, &enc_inner);
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
