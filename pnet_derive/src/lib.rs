#![crate_type = "proc-macro"]
#![recursion_limit = "256"]

#[macro_use]
extern crate failure;
extern crate proc_macro;
extern crate proc_macro2;
#[macro_use]
extern crate quote;
extern crate byteorder;
extern crate itertools;
extern crate regex;
#[macro_use]
extern crate syn;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

mod field;
mod packet;
mod types;

/// Derives `Packet` with internal attributes.
#[proc_macro_derive(Packet, attributes(payload, construct_with, length, length_fn))]
pub fn packet(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    syn::parse(input)
        .map_err(|err| err.into())
        .and_then(packet::parse)
        .map(|packets| {
            quote! {
                #(#packets)*
            }
        })
        .unwrap_or_else(|err| {
            let message = format!("err {}\n{}", err, err.backtrace());

            quote! {
                compile_error!(#message);
            }
        })
        .into()
}
