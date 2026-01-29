use proc_macro2::TokenStream;
use syn::{parse_quote, Type, WhereClause, WherePredicate};

pub(crate) fn add_where_bound(wc: &mut WhereClause, ty: &Type, bound: TokenStream) {
    let pred: WherePredicate = parse_quote!(#ty: #bound);
    wc.predicates.push(pred);
}
