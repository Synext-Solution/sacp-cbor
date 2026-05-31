use proc_macro2::TokenStream;
use syn::{parse_quote, Type, WhereClause, WherePredicate};

pub(crate) fn empty_where_clause() -> WhereClause {
    WhereClause {
        where_token: Default::default(),
        predicates: Default::default(),
    }
}

pub(crate) fn ensure_where_clause(where_clause: &mut Option<WhereClause>) -> &mut WhereClause {
    where_clause.get_or_insert_with(empty_where_clause)
}

pub(crate) fn add_where_bound(wc: &mut WhereClause, ty: &Type, bound: TokenStream) {
    let pred: WherePredicate = parse_quote!(#ty: #bound);
    wc.predicates.push(pred);
}

pub(crate) fn add_where_bounds<'a>(
    base: Option<&WhereClause>,
    bounds: impl IntoIterator<Item = &'a Type>,
    bound: TokenStream,
) -> Option<WhereClause> {
    let mut where_clause = base.cloned();
    for ty in bounds {
        add_where_bound(ensure_where_clause(&mut where_clause), ty, bound.clone());
    }
    where_clause
}
