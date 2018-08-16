use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn;

use field::Field;
use types::{parse_primitive, Result};

pub fn parse(input: syn::DeriveInput) -> Result<Vec<Packet>> {
    let name = input.ident;

    match input.vis {
        syn::Visibility::Public(_) => {}
        _ => bail!("#[packet] structs/enums {} must be public", name),
    }

    match input.data {
        syn::Data::Struct(s) => Packet::parse(name, s.fields).map(|packet| vec![packet]),
        syn::Data::Enum(e) => e
            .variants
            .into_iter()
            .map(|v| Packet::parse(v.ident, v.fields))
            .collect(),
        syn::Data::Union(_) => unimplemented!(),
    }
}

pub struct Packet {
    ident: syn::Ident,
    fields: Vec<Field>,
}

impl Packet {
    fn base_name(&self) -> &syn::Ident {
        &self.ident
    }

    fn immutable_packet_name(&self) -> syn::Ident {
        syn::Ident::new(&format!("{}Packet", self.base_name()), Span::call_site())
    }

    fn mutable_packet_name(&self) -> syn::Ident {
        syn::Ident::new(
            &format!("Mutable{}Packet", self.base_name()),
            Span::call_site(),
        )
    }

    fn packet_name(&self, mutable: bool) -> syn::Ident {
        if mutable {
            self.mutable_packet_name()
        } else {
            self.immutable_packet_name()
        }
    }

    fn packet_data(&self, mutable: bool) -> syn::Ident {
        syn::Ident::new(
            if mutable {
                "MutPacketData"
            } else {
                "PacketData"
            },
            Span::call_site(),
        )
    }

    fn parse(ident: syn::Ident, fields: syn::Fields) -> Result<Packet> {
        let packet_fields = match fields {
            syn::Fields::Named(fields) => fields,
            _ => bail!("{} all fields in a packet must be named", ident),
        };

        let mut fields = vec![];
        let mut has_payload = false;

        for field in packet_fields.named {
            let mut is_payload = false;
            let mut packet_length = None;
            let mut construct_with = vec![];

            for attr in field.attrs {
                match attr.interpret_meta() {
                    Some(syn::Meta::Word(ref ident)) if ident == "payload" => {
                        if has_payload {
                            bail!("packet may not have multiple payloads")
                        }

                        has_payload = true;
                        is_payload = true;
                    }
                    Some(syn::Meta::List(syn::MetaList {
                        ref ident,
                        ref nested,
                        ..
                    })) if ident == "construct_with" =>
                    {
                        if nested.is_empty() {
                            bail!("#[construct_with] must have at least one argument")
                        }

                        for meta in nested {
                            if let syn::NestedMeta::Meta(syn::Meta::Word(ident)) = meta {
                                if parse_primitive(&ident.to_string()).is_none() {
                                    bail!("arguments to #[construct_with] must be primitives")
                                }

                                construct_with.push(ident.clone())
                            } else {
                                bail!("#[construct_with] should be of the form #[construct_with(<types>)]")
                            }
                        }
                    }
                    Some(syn::Meta::NameValue(syn::MetaNameValue {
                        ref ident, ref lit, ..
                    })) if ident == "length" =>
                    {
                        let n = match lit {
                            syn::Lit::Str(lit) => lit.value().parse()?,
                            syn::Lit::Int(lit) => lit.value(),
                            _ => bail!("expected attribute to be a string `{} = \"...\"`", ident),
                        };

                        packet_length = Some(quote!{ #n });
                    }
                    Some(syn::Meta::NameValue(syn::MetaNameValue {
                        ref ident, ref lit, ..
                    })) if ident == "length_fn" =>
                    {
                        let length_fn = match lit {
                            syn::Lit::Str(lit) => syn::Ident::new(&lit.value(), Span::call_site()),
                            _ => bail!("expected attribute to be a string `{} = \"...\"`", ident),
                        };

                        packet_length = Some(quote! {
                            #length_fn(&self.to_immutable())
                        });
                    }
                    _ => bail!("unknown attribute {}", attr.into_token_stream()),
                }
            }

            let field = Field::new(
                field.ident.unwrap(),
                field.ty,
                is_payload,
                packet_length,
                if construct_with.is_empty() {
                    None
                } else {
                    Some(construct_with)
                },
            );

            if let Some((inner_ty, item_size, _)) = field.as_vec() {
                if !field.is_payload && field.packet_length.is_none() {
                    bail!("variable length field must have #[length_fn] attribute")
                }

                if inner_ty == "Vec" {
                    bail!("variable length fields may not contain vectors")
                } else if inner_ty != "u8" || item_size % 8 != 0 {
                    bail!("unimplemented variable length field")
                }
            } else if field.as_primitive().is_none() && field.construct_with.is_none() {
                bail!("non-primitive field types must specify #[construct_with]")
            }

            fields.push(field)
        }

        if !has_payload {
            bail!("#[packet]'s must contain a payload")
        }

        Ok(Packet { ident, fields })
    }

    fn generate_packet(&self, mutable: bool) -> TokenStream {
        let packet_name = self.packet_name(mutable);
        let packet_struct = self.generate_packet_struct(mutable);

        let (accessors, bits_offset) = self.fields.iter().fold(
            (vec![], 0),
            |(mut accessors, mut bits_offset), field| {
                accessors.push(field.generate_accessor(mutable, &mut bits_offset));

                (accessors, bits_offset)
            },
        );
        let mutators = if mutable {
            let (mutators, _) = self.fields.iter().fold(
                (vec![], 0),
                |(mut mutators, mut bits_offset), field| {
                    mutators.push(field.generate_mutator(&mut bits_offset));

                    (mutators, bits_offset)
                },
            );

            mutators
        } else {
            vec![]
        };

        let new = self.generate_constructor_new(mutable);
        let owned = self.generate_constructor_owned(mutable);
        let to_immutable = if mutable {
            Some(self.generate_to_immutable())
        } else {
            None
        };
        let consume_to_immutable = if mutable {
            Some(self.generate_consume_to_immutable())
        } else {
            None
        };
        let minimum_packet_size = self.generate_minimum_packet_size((bits_offset + 7) / 8);
        let packet_size = self.generate_packet_size(0);
        let populate = if mutable {
            Some(self.generate_populate())
        } else {
            None
        };

        quote! {
            #packet_struct

            impl<'a> #packet_name<'a> {
                #new

                #owned

                #to_immutable

                #consume_to_immutable

                #minimum_packet_size

                #packet_size

                #populate

                #(#accessors)*

                #(#mutators)*
            }
        }
    }

    fn generate_packet_struct(&self, mutable: bool) -> TokenStream {
        let packet_name = self.packet_name(mutable);
        let packet_data = self.packet_data(mutable);

        quote! {
            /// A structure enabling manipulation of on the wire packets
            #[derive(PartialEq)]
            pub struct #packet_name<'p> {
                packet: ::pnet_macros_support::packet:: #packet_data<'p>,
            }
        }
    }

    fn generate_constructor_new(&self, mutable: bool) -> TokenStream {
        let packet_name = self.packet_name(mutable);
        let packet_data = self.packet_data(mutable);

        let comment = format!(
            "Constructs a new {}.
If the provided buffer is less than the minimum required packet size, this will return None.",
            packet_name
        );
        let mut_ = if mutable {
            Some(syn::Ident::new("mut", Span::call_site()))
        } else {
            None
        };

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn new<'p>(packet: &'p #mut_ [u8]) -> Option<#packet_name<'p>> {
                if packet.len() >= #packet_name::minimum_packet_size() {
                    use ::pnet_macros_support::packet:: #packet_data;
                    Some(#packet_name { packet: #packet_data::Borrowed(packet) })
                } else {
                    None
                }
            }
        }
    }

    fn generate_constructor_owned(&self, mutable: bool) -> TokenStream {
        let packet_name = self.packet_name(mutable);
        let packet_data = self.packet_data(mutable);

        let comment = format!(
            "Constructs a new {0}.
If the provided buffer is less than the minimum required packet size,
this will return None. With this constructor the {0} will own its own data
and the underlying buffer will be dropped when the {0} is.",
            packet_name
        );

        quote! {
            #[doc = #comment]
            pub fn owned(packet: Vec<u8>) -> Option<#packet_name<'static>> {
                if packet.len() >= #packet_name::minimum_packet_size() {
                    use ::pnet_macros_support::packet::#packet_data;
                    Some(#packet_name { packet: #packet_data::Owned(packet) })
                } else {
                    None
                }
            }
        }
    }

    fn generate_to_immutable(&self) -> TokenStream {
        let immutable_packet_name = self.immutable_packet_name();
        let mutable_packet_name = self.mutable_packet_name();

        let comment = format!(
            "Maps from a {} to a {}",
            mutable_packet_name, immutable_packet_name
        );

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn to_immutable<'p>(&'p self) -> #immutable_packet_name<'p> {
                use ::pnet_macros_support::packet::PacketData;
                #immutable_packet_name { packet: PacketData::Borrowed(self.packet.as_slice()) }
            }
        }
    }

    fn generate_consume_to_immutable(&self) -> TokenStream {
        let immutable_packet_name = self.immutable_packet_name();
        let mutable_packet_name = self.mutable_packet_name();

        let comment = format!(
            "Maps from a {} to a {} while consuming the source",
            mutable_packet_name, immutable_packet_name
        );

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn consume_to_immutable(self) -> #immutable_packet_name<'a> {
                #immutable_packet_name { packet: self.packet.to_immutable() }
            }
        }
    }

    fn generate_minimum_packet_size(&self, bytes_size: usize) -> TokenStream {
        quote! {
            /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
            /// of the fixed-size fields.
            #[inline]
            pub fn minimum_packet_size() -> usize {
                #bytes_size
            }
        }
    }

    fn generate_packet_size(&self, struct_size: usize) -> TokenStream {
        let base_name = self.base_name();

        let comment = format!(
            "The size (in bytes) of a {} instance when converted into a byte-array",
            base_name
        );

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn packet_size(_packet: &#base_name) -> usize {
                #struct_size
            }
        }
    }

    fn generate_populate(&self) -> TokenStream {
        let base_name = self.base_name();

        let comment = format!(
            "Populates a {} using a {} structure",
            self.mutable_packet_name(),
            base_name
        );

        let set_fields = self.fields.iter().map(|field| {
            let field_name = &field.field_name();
            let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());

            if field.as_vec().is_some() {
                quote! {
                    self.#set_field(&packet.#field_name);
                }
            } else {
                quote! {
                    self.#set_field(packet.#field_name);
                }
            }
        });

        quote! {
            #[doc = #comment]
            #[inline]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn populate(&mut self, packet: &#base_name) {
                #(#set_fields)*
            }
        }
    }
}

impl ToTokens for Packet {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(&[self.generate_packet(false), self.generate_packet(true)])
    }
}
