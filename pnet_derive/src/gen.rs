use std::cell::RefCell;
use std::iter::FromIterator;
use std::ops::Deref;

use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn;

use field::{Field, Kind};
use packet::Packet;
use types::{parse_primitive, Endianness, Length, ToBytesOffset};

pub trait Generator {
    fn tokens(&self) -> TokenStream;
}

pub struct PacketGenerator<'a> {
    packet: &'a Packet,
    mutable: bool,
}

impl<'a> Deref for PacketGenerator<'a> {
    type Target = Packet;

    fn deref(&self) -> &Self::Target {
        self.packet
    }
}

impl<'a> PacketGenerator<'a> {
    pub fn new(packet: &'a Packet, mutable: bool) -> Self {
        PacketGenerator { packet, mutable }
    }

    fn base_name(&self) -> &syn::Ident {
        &self.packet.ident
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

    fn packet_name(&self) -> syn::Ident {
        if self.mutable {
            self.mutable_packet_name()
        } else {
            self.immutable_packet_name()
        }
    }

    fn packet_data(&self) -> syn::Ident {
        syn::Ident::new(
            if self.mutable {
                "MutPacketData"
            } else {
                "PacketData"
            },
            Span::call_site(),
        )
    }
}

impl<'a> Generator for PacketGenerator<'a> {
    fn tokens(&self) -> TokenStream {
        let packet_name = self.packet_name();

        let (accessors, _) = self.packet.fields.iter().fold(
            (vec![], vec![]),
            |(mut accessors, mut length_funcs), field| {
                accessors.push(FieldAccessor::new(field, self.mutable, &length_funcs).tokens());
                if let Some(bits) = field.bits() {
                    length_funcs.push(bits)
                }
                (accessors, length_funcs)
            },
        );

        let (mutators, _) = self.packet.fields.iter().fold(
            (vec![], vec![]),
            |(mut mutators, mut length_funcs), field| {
                mutators.push(FieldMutator::new(field, &length_funcs).tokens());
                if let Some(bits) = field.bits() {
                    length_funcs.push(bits)
                }
                (mutators, length_funcs)
            },
        );

        let bits_length_funcs = self
            .packet
            .fields
            .iter()
            .flat_map(|field| field.bits())
            .collect::<Vec<_>>();
        let struct_length_funcs = self
            .packet
            .fields
            .iter()
            .flat_map(|field| field.len())
            .collect::<Vec<_>>();

        let new = New(self).tokens();
        let owned = Owned(self).tokens();
        let to_immutable = ToImmutable(self).tokens();
        let consume_to_immutable = ConsumeToImmutable(self).tokens();
        let minimum_packet_size = MinimumPacketSize(self, &bits_length_funcs).tokens();
        let packet_size = PacketSize(self, &struct_length_funcs).tokens();
        let populate = Populate(self).tokens();

        quote! {
            impl<'a> #packet_name<'a> {
                #(#accessors)*

                #(#mutators)*

                #new

                #owned

                #to_immutable

                #consume_to_immutable

                #minimum_packet_size

                #packet_size

                #populate
            }
        }
    }
}

struct New<'a>(&'a PacketGenerator<'a>);

impl<'a> Generator for New<'a> {
    fn tokens(&self) -> TokenStream {
        let packet_name = self.0.packet_name();
        let packet_data = self.0.packet_data();

        let comment = format!(
            "Constructs a new {}.
If the provided buffer is less than the minimum required packet size, this will return None.",
            packet_name
        );
        let mut_ = if self.0.mutable {
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
}

struct Owned<'a>(&'a PacketGenerator<'a>);

impl<'a> Generator for Owned<'a> {
    fn tokens(&self) -> TokenStream {
        let packet_name = self.0.packet_name();
        let packet_data = self.0.packet_data();

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
}

struct ToImmutable<'a>(&'a PacketGenerator<'a>);

impl<'a> Generator for ToImmutable<'a> {
    fn tokens(&self) -> TokenStream {
        let immutable_packet_name = self.0.immutable_packet_name();
        let mutable_packet_name = self.0.mutable_packet_name();

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
}

struct ConsumeToImmutable<'a>(&'a PacketGenerator<'a>);

impl<'a> Generator for ConsumeToImmutable<'a> {
    fn tokens(&self) -> TokenStream {
        let immutable_packet_name = self.0.immutable_packet_name();
        let mutable_packet_name = self.0.mutable_packet_name();

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
}

struct MinimumPacketSize<'a>(&'a PacketGenerator<'a>, &'a [Length]);

impl<'a> Generator for MinimumPacketSize<'a> {
    fn tokens(&self) -> TokenStream {
        let packet_size = self.1.bytes_offset();

        quote! {
            /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
            /// of the fixed-size fields.
            #[inline]
            pub fn minimum_packet_size() -> usize {
                #packet_size
            }
        }
    }
}

struct PacketSize<'a>(&'a PacketGenerator<'a>, &'a [Length]);

impl<'a> Generator for PacketSize<'a> {
    fn tokens(&self) -> TokenStream {
        let base_name = self.0.base_name();
        let comment = format!(
            "The size (in bytes) of a {} instance when converted into a byte-array",
            base_name
        );
        let packet_size = self.1.bytes_offset();

        quote! {
            #[doc = #comment]
            #[inline]
            pub fn packet_size(_packet: &#base_name) -> usize {
                #packet_size
            }
        }
    }
}

struct Populate<'a>(&'a PacketGenerator<'a>);

impl<'a> Generator for Populate<'a> {
    fn tokens(&self) -> TokenStream {
        let base_name = self.0.base_name();

        let comment = format!(
            "Populates a {} using a {} structure",
            self.0.mutable_packet_name(),
            base_name
        );

        let set_fields = self.0.packet.fields.iter().map(|field| {
            let field_name = &field.name();
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
            pub fn populate(&self, packet: &#base_name) {
                #(#set_fields)*
            }
        }
    }
}

struct FieldAccessor<'a> {
    field: &'a Field,
    mutable: bool,
    length_funcs: &'a [Length],
}

impl<'a> Deref for FieldAccessor<'a> {
    type Target = Field;

    fn deref(&self) -> &Self::Target {
        &self.field
    }
}

impl<'a> FieldAccessor<'a> {
    pub fn new(field: &'a Field, mutable: bool, length_funcs: &'a [Length]) -> Self {
        FieldAccessor {
            field,
            mutable,
            length_funcs,
        }
    }
}

impl<'a> Generator for FieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        match self.field.kind {
            Kind::Primitive { bits, endianness } => PrimitiveFieldAccessor {
                accessor: self,
                bits,
                endianness,
            }.tokens(),
            Kind::Vec {
                ref item_ty,
                item_bits,
                endianness,
                ref packet_length,
            } => VecFieldAccessor {
                accessor: self,
                item_ty,
                item_bits,
                endianness,
                packet_length: packet_length.as_ref(),
            }.tokens(),
            Kind::Custom { ref construct_with } => CustomFieldAccessor {
                accessor: self,
                arg_types: construct_with,
            }.tokens(),
        }
    }
}

struct PrimitiveFieldAccessor<'a> {
    accessor: &'a FieldAccessor<'a>,
    bits: usize,
    endianness: Option<Endianness>,
}

impl<'a> Deref for PrimitiveFieldAccessor<'a> {
    type Target = FieldAccessor<'a>;

    fn deref(&self) -> &Self::Target {
        &self.accessor
    }
}

impl<'a> Generator for PrimitiveFieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let comment = format!("Get the {} field.
This field is always stored in {} endianness within the struct, but this accessor returns host order.",
            field_name, self.endianness.map_or("host", |e| e.name())
        );
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());
        let read_ops = read_operations(
            self.length_funcs,
            self.bits,
            self.endianness,
            quote!{ self.packet },
        );

        quote_spanned! { self.span() =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #get_field(&self) -> #field_ty {
                #(#read_ops)*
            }
        }
    }
}

struct VecFieldAccessor<'a> {
    accessor: &'a FieldAccessor<'a>,
    item_ty: &'a syn::Ident,
    item_bits: usize,
    endianness: Option<Endianness>,
    packet_length: Option<&'a Length>,
}

impl<'a> Deref for VecFieldAccessor<'a> {
    type Target = FieldAccessor<'a>;

    fn deref(&self) -> &Self::Target {
        &self.accessor
    }
}

impl<'a> Generator for VecFieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        let raw_accessors = self
            .packet_length
            .map(|_| RawVecFieldAccessor(self).tokens());

        let vec_primitive_accessor = PrimitiveVecFieldAccessor(self).tokens();

        quote_spanned! { self.span() =>
            #raw_accessors

            #vec_primitive_accessor
        }
    }
}

struct RawVecFieldAccessor<'a>(&'a VecFieldAccessor<'a>);

impl<'a> Deref for RawVecFieldAccessor<'a> {
    type Target = VecFieldAccessor<'a>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> Generator for RawVecFieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        let field_name = &self.ident;
        let current_offset = self.length_funcs.bytes_offset();
        let packet_length = self.packet_length;

        let get_field_raw = {
            let comment = format!(
                "Get the raw &[u8] value of the {} field, without copying",
                field_name
            );
            let get_field_raw =
                syn::Ident::new(&format!("get_{}_raw", field_name), Span::call_site());

            quote_spanned! { self.span() =>
                #[doc = #comment]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn #get_field_raw(&self) -> &[u8] {
                    let off = #current_offset;
                    let packet_length = #packet_length;
                    let end = ::std::cmp::min(off + packet_length, self.packet.len());

                    &self.packet[off..end]
                }
            }
        };

        let get_field_raw_mut = if self.mutable {
            let comment = format!(
                "Get the raw &mut [u8] value of the {} field, without copying",
                field_name
            );
            let get_field_raw_mut =
                syn::Ident::new(&format!("get_{}_raw_mut", field_name), Span::call_site());

            Some(quote_spanned! { self.span() =>
                #[doc = #comment]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn #get_field_raw_mut(&mut self) -> &mut [u8] {
                    let off = #current_offset;
                    let packet_length = #packet_length;
                    let end = ::std::cmp::min(off + packet_length, self.packet.len());

                    &mut self.packet[off..end]
                }
            })
        } else {
            None
        };

        quote_spanned! { self.span() =>
            #get_field_raw

            #get_field_raw_mut
        }
    }
}

struct PrimitiveVecFieldAccessor<'a>(&'a VecFieldAccessor<'a>);

impl<'a> Deref for PrimitiveVecFieldAccessor<'a> {
    type Target = VecFieldAccessor<'a>;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> Generator for PrimitiveVecFieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        let field_name = &self.ident;
        let comment = format!(
            "Get the value of the {} field (copies contents)",
            field_name
        );
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());
        let current_offset = self.length_funcs.bytes_offset();
        let item_ty = &self.item_ty;

        let packet = if let Some(packet_length) = self.packet_length {
            quote! {
                let packet_length = #packet_length;
                let end = ::std::cmp::min(off + packet_length, self.packet.len());
                let packet = &self.packet[off..end];
            }
        } else {
            quote! {
                let packet = &self.packet[off..];
            }
        };
        let read_ops = if self.item_ty == "u8" {
            quote! {
                packet.to_vec()
            }
        } else {
            let item_size = self.item_bits / 8;
            let read_ops = read_operations(0, self.item_bits, self.endianness, quote! { chunk });

            quote! {
                packet.chunks(off).map(|chunk| { #read_ops }).collect()
            }
        };

        quote_spanned! { self.span() =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #get_field(&self) -> Vec<#item_ty> {
                let off = #current_offset;

                #packet

                #read_ops
            }
        }
    }
}

struct CustomFieldAccessor<'a> {
    accessor: &'a FieldAccessor<'a>,
    arg_types: &'a [syn::Ident],
}

impl<'a> Deref for CustomFieldAccessor<'a> {
    type Target = FieldAccessor<'a>;

    fn deref(&self) -> &Self::Target {
        &self.accessor
    }
}

impl<'a> Generator for CustomFieldAccessor<'a> {
    fn tokens(&self) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let get_field = syn::Ident::new(&format!("get_{}", field_name), Span::call_site());

        let ctor = if self.arg_types.is_empty() {
            let bytes_offset = self.length_funcs.bytes_offset();

            quote! {
                #field_ty ::new(&self.packet[#bytes_offset ..])
            }
        } else {
            let mut args = vec![];
            let mut length_funcs = Vec::from_iter(self.length_funcs.iter().cloned());

            for arg_ty in self.arg_types {
                let (bits, endianness) = parse_primitive(&arg_ty)
                    .expect("arguments to #[construct_with] must be primitives");

                let read_ops = read_operations(
                    length_funcs.as_slice(),
                    bits,
                    endianness,
                    quote! { self.packet },
                );

                args.push(quote! {
                    #(#read_ops)*
                });

                length_funcs.push(Length::Bits(bits));
            }

            quote! {
                #field_ty ::new( #(#args),* )
            }
        };

        let comment = format!("Get the value of the {} field", field_name);

        quote_spanned! { self.span() =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #get_field(&self) -> #field_ty {
                #ctor
            }
        }
    }
}

struct FieldMutator<'a> {
    field: &'a Field,
    length_funcs: &'a [Length],
}

impl<'a> Deref for FieldMutator<'a> {
    type Target = Field;

    fn deref(&self) -> &Self::Target {
        &self.field
    }
}

impl<'a> FieldMutator<'a> {
    pub fn new(field: &'a Field, length_funcs: &'a [Length]) -> Self {
        FieldMutator {
            field,
            length_funcs,
        }
    }
}

impl<'a> Generator for FieldMutator<'a> {
    fn tokens(&self) -> TokenStream {
        match self.field.kind {
            Kind::Primitive { bits, endianness } => PrimitiveFieldMutator {
                mutator: self,
                bits,
                endianness,
            }.tokens(),
            Kind::Vec {
                ref item_ty,
                item_bits,
                endianness,
                ref packet_length,
            } => VecFieldMutator {
                mutator: self,
                item_ty,
                item_bits,
                endianness,
                packet_length: packet_length.as_ref(),
            }.tokens(),
            Kind::Custom { ref construct_with } => CustomFieldMutator {
                mutator: self,
                arg_types: construct_with,
            }.tokens(),
        }
    }
}

struct PrimitiveFieldMutator<'a> {
    mutator: &'a FieldMutator<'a>,
    bits: usize,
    endianness: Option<Endianness>,
}

impl<'a> Deref for PrimitiveFieldMutator<'a> {
    type Target = FieldMutator<'a>;

    fn deref(&self) -> &Self::Target {
        &self.mutator
    }
}

impl<'a> Generator for PrimitiveFieldMutator<'a> {
    fn tokens(&self) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let comment = format!("Set the {} field.
This field is always stored in {} endianness within the struct, but this accessor returns host order.",
                            field_name, self.endianness.map_or("host", |e| e.name())
                        );
        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());
        let write_ops = write_operations(
            self.length_funcs,
            self.bits,
            self.endianness,
            quote! { self.packet },
            quote! { val },
        );

        quote_spanned! { self.span() =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #set_field(&mut self, val: #field_ty) {
                #(#write_ops)*
            }
        }
    }
}

struct VecFieldMutator<'a> {
    mutator: &'a FieldMutator<'a>,
    item_ty: &'a syn::Ident,
    item_bits: usize,
    endianness: Option<Endianness>,
    packet_length: Option<&'a Length>,
}

impl<'a> Deref for VecFieldMutator<'a> {
    type Target = FieldMutator<'a>;

    fn deref(&self) -> &Self::Target {
        &self.mutator
    }
}

impl<'a> Generator for VecFieldMutator<'a> {
    fn tokens(&self) -> TokenStream {
        let field_name = &self.ident;
        let comment = format!(
            "Set the value of the {} field (copies contents)",
            field_name
        );
        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());
        let item_ty = self.item_ty;
        let current_offset = self.length_funcs.bytes_offset();
        let packet = if let Some(packet_length) = self.packet_length {
            quote! {
                let packet_length = #packet_length;
                let end = ::std::cmp::min(off + packet_length, self.packet.len());
                let packet = &mut self.packet[off..end];
            }
        } else {
            quote! {
                let packet = &mut self.packet[off..];
            }
        };
        let write_ops = if self.item_ty == "u8" {
            quote! {
                packet.copy_from_slice(vals)
            }
        } else {
            let bytes_size = (self.item_bits + 7) / 8;
            let write_ops = write_operations(
                0,
                self.item_bits,
                self.endianness,
                quote! { buf },
                quote! { v },
            );

            quote!{
                let buf = vals.iter().flat_map(|&v| {
                    let mut buf = vec![0u8; #bytes_size];

                    #write_ops

                    buf.into_iter()
                }).collect::<Vec<_>>();

                packet.copy_from_slice(buf.as_slice())
            }
        };

        quote_spanned! { self.span() =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #set_field(&mut self, vals: &[#item_ty]) {
                let off = #current_offset;

                #packet

                #write_ops
            }
        }
    }
}

struct CustomFieldMutator<'a> {
    mutator: &'a FieldMutator<'a>,
    arg_types: &'a [syn::Ident],
}

impl<'a> Deref for CustomFieldMutator<'a> {
    type Target = FieldMutator<'a>;

    fn deref(&self) -> &Self::Target {
        &self.mutator
    }
}

impl<'a> Generator for CustomFieldMutator<'a> {
    fn tokens(&self) -> TokenStream {
        let field_name = &self.ident;
        let field_ty = &self.ty;
        let comment = format!("Set the value of the {} field", field_name);
        let set_field = syn::Ident::new(&format!("set_{}", field_name), Span::call_site());

        let setter = if self.arg_types.is_empty() {
            let bytes_offset = self.length_funcs.bytes_offset();

            quote_spanned! { self.span() =>
                self.packet[#bytes_offset .. #bytes_offset + ::std::mem::size_of_val(vals)].copy_from_slice(&vals[..]);
            }
        } else {
            let mut set_args = vec![];
            let mut length_funcs = Vec::from_iter(self.length_funcs.iter().cloned());

            for (idx, arg_ty) in self.arg_types.iter().enumerate() {
                let (bits, endianness) = parse_primitive(&arg_ty)
                    .expect("arguments to #[construct_with] must be primitives");

                let write_ops = write_operations(
                    length_funcs.as_slice(),
                    bits,
                    endianness,
                    quote! { self.packet },
                    quote!{ vals.#idx },
                );

                set_args.push(quote! {
                    #(#write_ops)*
                });

                length_funcs.push(Length::Bits(bits));
            }

            quote_spanned! { self.span() =>
                #(#set_args)*
            }
        };

        quote_spanned! { self.span() =>
            #[doc = #comment]
            #[inline]
            #[allow(trivial_numeric_casts)]
            #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
            pub fn #set_field(&mut self, val: #field_ty) {
                use pnet_macros_support::packet::PrimitiveValues;

                let vals = val.to_primitive_values();

                #setter
            }
        }
    }
}

pub fn read_operations<O: ToBytesOffset, T: ToTokens>(
    offset: O,
    bits: usize,
    endianness: Option<Endianness>,
    packet: T,
) -> TokenStream {
    if bits % 8 == 0 && bits <= 64 {
        let bytes_offset = offset.bytes_offset();
        let endianness_name = syn::Ident::new(
            match endianness {
                Some(Endianness::Little) => "LittenEndia",
                Some(Endianness::Big) => "BigEndian",
                None => "NativeEndian",
            },
            Span::call_site(),
        );

        match bits {
            8 => quote! {
                #packet[#bytes_offset]
            },
            16 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u16(&#packet[#bytes_offset..])
            },
            24 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u24(&#packet[#bytes_offset..])
            },
            32 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u32(&#packet[#bytes_offset..])
            },
            48 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u48(&#packet[#bytes_offset..])
            },
            64 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_u64(&#packet[#bytes_offset..])
            },
            _ => {
                let bytes = (bits + 7) / 8;

                quote!{
                    <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::read_uint(&#packet[#bytes_offset..], #bytes)
                }
            }
        }
    } else {
        unimplemented!()
    }
}

pub fn write_operations<O: ToBytesOffset, T: ToTokens, V: ToTokens>(
    offset: O,
    bits: usize,
    endianness: Option<Endianness>,
    packet: T,
    val: V,
) -> TokenStream {
    if bits % 8 == 0 && bits <= 64 {
        let bytes_offset = offset.bytes_offset();
        let endianness_name = syn::Ident::new(
            match endianness {
                Some(Endianness::Little) => "LittenEndian",
                Some(Endianness::Big) => "BigEndian",
                None => "NativeEndian",
            },
            Span::call_site(),
        );

        match bits {
            8 => quote! {
                #packet[#bytes_offset] = #val;
            },
            16 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u16(&mut #packet[#bytes_offset..], #val);
            },
            24 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u24(&mut #packet[#bytes_offset..], #val);
            },
            32 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u32(&mut #packet[#bytes_offset..], #val);
            },
            48 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u48(&mut #packet[#bytes_offset..], #val);
            },
            64 => quote! {
                <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_u64(&mut #packet[#bytes_offset..], #val);
            },
            _ => {
                let bytes = bits / 8;

                quote!{
                    <::byteorder:: #endianness_name as ::byteorder::ByteOrder>::write_uint(&mut #packet[#bytes_offset..], #bytes, #val);
                }
            }
        }
    } else {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! ident {
        ($name:expr) => {
            ident!($name, ::proc_macro2::Span::call_site())
        };
        ($name:expr, $span:expr) => {
            ::syn::Ident::new($name, $span)
        };
    }

    #[test]
    fn test_primitive_field() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                foo: u8,
            }
        };

        let field = Field::parse(fields.named.into_iter().next().unwrap()).unwrap();

        assert_eq!(field.name(), "foo");
        assert_eq!(field.as_primitive(), Some((8, Some(Endianness::Big))));

        let length_funcs = &[Length::Bits(32)][..];

        assert_eq!(
            FieldAccessor::new(&field, true, length_funcs)
                .tokens()
                .to_string(),
            quote! {
                #[doc = "Get the foo field.\nThis field is always stored in big endianness within the struct, but this accessor returns host order."]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn get_foo(&self) -> u8 {
                    self.packet[4usize]
                }
            }.to_string()
        );

        assert_eq!(
            FieldMutator::new(&field, length_funcs).tokens().to_string(),
            quote!{
                #[doc = "Set the foo field.\nThis field is always stored in big endianness within the struct, but this accessor returns host order."]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn set_foo(&mut self, val: u8 ) {
                    self.packet[4usize] = val;
                }
            }.to_string()
        );
    }

    #[test]
    fn test_vec_field_with_length() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[length = 8]
                body: Vec<u8>,

                #[length = "8"]
                body: Vec<u8>,

                #[length = "4+4"]
                body: Vec<u8>,

                #[length = "self.pkt_len/2"]
                body: Vec<u8>,
            }
        };

        let mut iter = fields.named.into_iter();

        let length_funcs = &[Length::Bits(16)][..];

        // #[length = 8]
        {
            let field = Field::parse(iter.next().unwrap()).unwrap();

            assert_eq!(
                field
                    .as_vec()
                    .map(|(_, _, _, packet_length)| packet_length.into_token_stream().to_string())
                    .unwrap(),
                "8usize"
            );

            assert_eq!(
                FieldAccessor::new(&field, true, length_funcs)
                    .tokens()
                    .to_string(),
                quote! {
                    #[doc = "Get the raw &[u8] value of the body field, without copying"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body_raw(&self) -> &[u8] {
                        let off = 2usize;
                        let packet_length = 8usize;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());

                        &self.packet[off..end]
                    }

                    #[doc = "Get the raw &mut [u8] value of the body field, without copying"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body_raw_mut(&mut self) -> &mut [u8] {
                        let off = 2usize;
                        let packet_length = 8usize;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());

                        &mut self.packet[off..end]
                    }

                    #[doc = "Get the value of the body field (copies contents)"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body(&self) -> Vec<u8> {
                        let off = 2usize;
                        let packet_length = 8usize;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());
                        let packet = &self.packet[off..end];

                        packet.to_vec()
                    }
                }.to_string()
            );

            assert_eq!(
                FieldMutator::new(&field, length_funcs).tokens().to_string(),
                quote! {
                   #[doc = "Set the value of the body field (copies contents)"]
                   #[inline]
                   #[allow(trivial_numeric_casts)]
                   #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                   pub fn set_body(&mut self, vals: &[u8]) {
                       let off = 2usize;
                       let packet_length = 8usize;
                       let end = ::std::cmp::min(off + packet_length, self.packet.len());
                       let packet = &mut self.packet[off..end];

                       packet.copy_from_slice(vals)
                   }
                }.to_string()
            );
        }
        // #[length = "8"]
        {
            let field = Field::parse(iter.next().unwrap()).unwrap();

            assert_eq!(
                field
                    .as_vec()
                    .map(|(_, _, _, packet_length)| packet_length.into_token_stream().to_string())
                    .unwrap(),
                "8"
            );

            assert_eq!(
                FieldAccessor::new(&field, true, length_funcs)
                    .tokens()
                    .to_string(),
                quote! {
                    #[doc = "Get the raw &[u8] value of the body field, without copying"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body_raw(&self) -> &[u8] {
                        let off = 2usize;
                        let packet_length = 8;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());

                        &self.packet[off..end]
                    }

                    #[doc = "Get the raw &mut [u8] value of the body field, without copying"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body_raw_mut(&mut self) -> &mut [u8] {
                        let off = 2usize;
                        let packet_length = 8;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());

                        &mut self.packet[off..end]
                    }

                    #[doc = "Get the value of the body field (copies contents)"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body(&self) -> Vec<u8> {
                        let off = 2usize;
                        let packet_length = 8;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());
                        let packet = &self.packet[off..end];

                        packet.to_vec()
                    }
                }.to_string()
            );

            assert_eq!(
                FieldMutator::new(&field, length_funcs).tokens().to_string(),
                quote! {
                   #[doc = "Set the value of the body field (copies contents)"]
                   #[inline]
                   #[allow(trivial_numeric_casts)]
                   #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                   pub fn set_body(&mut self, vals: &[u8]) {
                       let off = 2usize;
                       let packet_length = 8;
                       let end = ::std::cmp::min(off + packet_length, self.packet.len());
                       let packet = &mut self.packet[off..end];

                       packet.copy_from_slice(vals)
                   }
                }.to_string()
            );
        }
        // #[length = "4+4"]
        {
            let field = Field::parse(iter.next().unwrap()).unwrap();

            assert_eq!(
                field
                    .as_vec()
                    .map(|(_, _, _, packet_length)| packet_length.into_token_stream().to_string())
                    .unwrap(),
                "4 + 4"
            );

            assert_eq!(
                FieldAccessor::new(&field, true, length_funcs)
                    .tokens()
                    .to_string(),
                quote! {
                    #[doc = "Get the raw &[u8] value of the body field, without copying"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body_raw(&self) -> &[u8] {
                        let off = 2usize;
                        let packet_length = 4 + 4;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());

                        &self.packet[off..end]
                    }

                    #[doc = "Get the raw &mut [u8] value of the body field, without copying"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body_raw_mut(&mut self) -> &mut [u8] {
                        let off = 2usize;
                        let packet_length = 4 + 4;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());

                        &mut self.packet[off..end]
                    }

                    #[doc = "Get the value of the body field (copies contents)"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body(&self) -> Vec<u8> {
                        let off = 2usize;
                        let packet_length = 4 + 4;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());
                        let packet = &self.packet[off..end];

                        packet.to_vec()
                    }
                }.to_string()
            );

            assert_eq!(
                FieldMutator::new(&field, length_funcs).tokens().to_string(),
                quote! {
                   #[doc = "Set the value of the body field (copies contents)"]
                   #[inline]
                   #[allow(trivial_numeric_casts)]
                   #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                   pub fn set_body(&mut self, vals: &[u8]) {
                       let off = 2usize;
                       let packet_length = 4 + 4;
                       let end = ::std::cmp::min(off + packet_length, self.packet.len());
                       let packet = &mut self.packet[off..end];

                       packet.copy_from_slice(vals)
                   }
                }.to_string()
            );
        }
        // #[length = "self.pkt_len/2"]
        {
            let field = Field::parse(iter.next().unwrap()).unwrap();

            assert_eq!(
                field
                    .as_vec()
                    .map(|(_, _, _, packet_length)| packet_length.into_token_stream().to_string())
                    .unwrap(),
                "self . pkt_len / 2"
            );

            assert_eq!(
                FieldAccessor::new(&field, true, length_funcs)
                    .tokens()
                    .to_string(),
                quote! {
                    #[doc = "Get the raw &[u8] value of the body field, without copying"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body_raw(&self) -> &[u8] {
                        let off = 2usize;
                        let packet_length = self.pkt_len / 2;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());

                        &self.packet[off..end]
                    }

                    #[doc = "Get the raw &mut [u8] value of the body field, without copying"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body_raw_mut(&mut self) -> &mut [u8] {
                        let off = 2usize;
                        let packet_length = self.pkt_len / 2;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());

                        &mut self.packet[off..end]
                    }

                    #[doc = "Get the value of the body field (copies contents)"]
                    #[inline]
                    #[allow(trivial_numeric_casts)]
                    #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                    pub fn get_body(&self) -> Vec<u8> {
                        let off = 2usize;
                        let packet_length = self.pkt_len / 2;
                        let end = ::std::cmp::min(off + packet_length, self.packet.len());
                        let packet = &self.packet[off..end];

                        packet.to_vec()
                    }
                }.to_string()
            );

            assert_eq!(
                FieldMutator::new(&field, length_funcs).tokens().to_string(),
                quote! {
                   #[doc = "Set the value of the body field (copies contents)"]
                   #[inline]
                   #[allow(trivial_numeric_casts)]
                   #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                   pub fn set_body(&mut self, vals: &[u8]) {
                       let off = 2usize;
                       let packet_length = self.pkt_len / 2;
                       let end = ::std::cmp::min(off + packet_length, self.packet.len());
                       let packet = &mut self.packet[off..end];

                       packet.copy_from_slice(vals)
                   }
                }.to_string()
            );
        }
    }

    #[test]
    fn test_payload_field() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[payload]
                body: Vec<u8>,
            }
        };

        let field = Field::parse(fields.named.into_iter().next().unwrap()).unwrap();

        assert_eq!(field.name(), "body");
        assert_eq!(
            field.as_vec(),
            Some((&ident!("u8"), 8, Some(Endianness::Big), None))
        );

        let length_funcs = &[Length::Bits(16)][..];

        assert_eq!(
            FieldAccessor::new(&field, false, length_funcs)
                .tokens()
                .to_string(),
            quote! {
                #[doc = "Get the value of the body field (copies contents)" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn get_body(&self) -> Vec <u8> {
                    let off = 2usize;
                    let packet = &self.packet[off..];
                    packet.to_vec()
                }
            }.to_string()
        );

        assert_eq!(
            FieldMutator::new(&field, length_funcs).tokens().to_string(),
            quote! {
               #[doc = "Set the value of the body field (copies contents)"]
               #[inline]
               #[allow(trivial_numeric_casts)]
               #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
               pub fn set_body(&mut self, vals: &[u8]) {
                   let off = 2usize;
                   let packet = &mut self.packet[off..];
                   packet.copy_from_slice(vals)
               }
            }.to_string()
        );
    }

    #[test]
    fn test_payload_field_with_u16() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[payload]
                body: Vec<u16>,
            }
        };

        let field = Field::parse(fields.named.into_iter().next().unwrap()).unwrap();

        assert_eq!(field.name(), "body");
        assert_eq!(
            field.as_vec(),
            Some((&ident!("u16"), 16, Some(Endianness::Big), None))
        );

        let length_funcs = &[Length::Bits(16)][..];

        assert_eq!(
            FieldAccessor::new(&field, false, length_funcs)
                .tokens()
                .to_string(),
            quote! {
                #[doc = "Get the value of the body field (copies contents)" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
                pub fn get_body(&self) -> Vec <u16> {
                    let off = 2usize;
                    let packet = &self.packet[off..];
                    packet.chunks(off).map(|chunk| {
                        <::byteorder::BigEndian as ::byteorder::ByteOrder>::read_u16(&chunk[0usize..])
                    }).collect()
                }
            }.to_string()
        );

        assert_eq!(
            FieldMutator::new(&field, length_funcs).tokens().to_string(),
            quote! {
               #[doc = "Set the value of the body field (copies contents)"]
               #[inline]
               #[allow(trivial_numeric_casts)]
               #[cfg_attr(feature = "clippy", allow(used_underscore_binding))]
               pub fn set_body(&mut self, vals: &[u16]) {
                   let off = 2usize;
                   let packet = &mut self.packet[off..];
                   let buf = vals.iter().flat_map(|&v| {
                       let mut buf = vec![0u8; 2usize];
                       <::byteorder::BigEndian as ::byteorder::ByteOrder>::write_u16(&mut buf[0usize..], v);
                       buf.into_iter()
                    }).collect::<Vec<_>>();

                    packet.copy_from_slice(buf.as_slice())
               }
            }.to_string()
        );
    }

    #[test]
    fn test_custom_field() {
        let fields: syn::FieldsNamed = parse_quote! {
            {
                #[construct_with(u16)]
                pub hardware_type: ArpHardwareType,

                #[construct_with(u8, u8, u8, u8, u8, u8)]
                pub sender_hw_addr: MacAddr,

                #[payload]
                pub body: Body,
            }
        };

        let mut iter = fields.named.into_iter();
        let hardware_type = Field::parse(iter.next().unwrap()).unwrap();

        assert_eq!(hardware_type.name(), "hardware_type");
        assert_eq!(hardware_type.as_custom(), Some(&[ident!("u16")][..]));

        let length_funcs = &[Length::Bits(16)][..];

        assert_eq!(
            FieldAccessor::new(&hardware_type, true, length_funcs)
                .tokens()
                .to_string(),
            quote!{
                #[doc="Get the value of the hardware_type field" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn get_hardware_type(&self) -> ArpHardwareType {
                    ArpHardwareType::new(
                        <::byteorder::BigEndian as ::byteorder::ByteOrder>::read_u16(&self.packet[2usize..])
                    )
                }
            }.to_string()
        );

        assert_eq!(
            FieldMutator::new(&hardware_type, length_funcs)
                .tokens()
                .to_string(),
            quote!{
                #[doc="Set the value of the hardware_type field"]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn set_hardware_type(&mut self, val: ArpHardwareType) {
                    use pnet_macros_support::packet::PrimitiveValues;
                    let vals = val.to_primitive_values();

                    <::byteorder::BigEndian as ::byteorder::ByteOrder>::write_u16(&mut self.packet[2usize..], vals.0usize);
                }
            }.to_string()
        );

        let sender_hw_addr = Field::parse(iter.next().unwrap()).unwrap();

        assert_eq!(sender_hw_addr.name(), "sender_hw_addr");
        assert_eq!(
            sender_hw_addr.as_custom(),
            Some(
                &[
                    ident!("u8"),
                    ident!("u8"),
                    ident!("u8"),
                    ident!("u8"),
                    ident!("u8"),
                    ident!("u8")
                ][..],
            )
        );

        assert_eq!(
            FieldAccessor::new(&sender_hw_addr, true, length_funcs)
                .tokens()
                .to_string(),
            quote!{
                #[doc="Get the value of the sender_hw_addr field" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn get_sender_hw_addr(&self) -> MacAddr {
                    MacAddr::new(
                        self.packet[2usize],
                        self.packet[3usize],
                        self.packet[4usize],
                        self.packet[5usize],
                        self.packet[6usize],
                        self.packet[7usize]
                    )
                }
            }.to_string()
        );

        assert_eq!(
            FieldMutator::new(&sender_hw_addr, length_funcs)
                .tokens()
                .to_string(),
            quote!{
                #[doc="Set the value of the sender_hw_addr field"]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn set_sender_hw_addr(&mut self, val: MacAddr) {
                    use pnet_macros_support::packet::PrimitiveValues;
                    let vals = val.to_primitive_values();

                    self.packet[2usize] = vals.0usize;
                    self.packet[3usize] = vals.1usize;
                    self.packet[4usize] = vals.2usize;
                    self.packet[5usize] = vals.3usize;
                    self.packet[6usize] = vals.4usize;
                    self.packet[7usize] = vals.5usize;
                }
            }.to_string()
        );

        let body = Field::parse(iter.next().unwrap()).unwrap();

        assert_eq!(body.name(), "body");
        assert_eq!(body.as_custom(), Some(&[][..]));

        assert_eq!(
            FieldAccessor::new(&body, true, length_funcs)
                .tokens()
                .to_string(),
            quote!{
                #[doc="Get the value of the body field" ]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn get_body(&self) -> Body {
                    Body::new(&self.packet[2usize..])
                }
            }.to_string()
        );

        assert_eq!(
            FieldMutator::new(&body, length_funcs).tokens().to_string(),
            quote!{
                #[doc="Set the value of the body field"]
                #[inline]
                #[allow(trivial_numeric_casts)]
                #[cfg_attr(feature="clippy", allow(used_underscore_binding))]
                pub fn set_body(&mut self, val: Body) {
                    use pnet_macros_support::packet::PrimitiveValues;
                    let vals = val.to_primitive_values();

                    self.packet[2usize..2usize + ::std::mem::size_of_val(vals)].copy_from_slice(&vals[..]);
                }
            }.to_string()
        );
    }

    #[test]
    fn test_read_operations() {
        let read_ops = [
            (0, 8, Some(Endianness::Little), quote! { packet[0usize] }),
            (8, 16, Some(Endianness::Big), quote! { <::byteorder::BigEndian as ::byteorder::ByteOrder>::read_u16(&packet[1usize..]) }),
            (16, 24, None, quote! { <::byteorder::NativeEndian as ::byteorder::ByteOrder>::read_u24(&packet[2usize..]) }),
            (24, 32, Some(Endianness::Little), quote! { <::byteorder::LittenEndia as ::byteorder::ByteOrder>::read_u32(&packet[3usize..]) }),
            (32, 48, Some(Endianness::Big), quote! { <::byteorder::BigEndian as ::byteorder::ByteOrder>::read_u48(&packet[4usize..]) }),
            (40, 64, None, quote! { <::byteorder::NativeEndian as ::byteorder::ByteOrder>::read_u64(&packet[5usize..]) }),
            (48, 40, Some(Endianness::Little), quote! { <::byteorder::LittenEndia as ::byteorder::ByteOrder>::read_uint(&packet[6usize..], 5usize) }),
        ];

        for &(bits_offset, bits, endianness, ref code) in &read_ops {
            assert_eq!(
                read_operations(bits_offset, bits, endianness, quote! { packet }).to_string(),
                code.to_string()
            );
        }
    }

    #[test]
    fn test_write_operations() {
        let write_ops = [
            (0, 8, Some(Endianness::Little), quote! { packet[0usize] = val; }),
            (8, 16, Some(Endianness::Big), quote! { <::byteorder::BigEndian as ::byteorder::ByteOrder>::write_u16(&mut packet[1usize..], val); }),
            (16, 24, None, quote! { <::byteorder::NativeEndian as ::byteorder::ByteOrder>::write_u24(&mut packet[2usize..], val); }),
            (24, 32, Some(Endianness::Little), quote! { <::byteorder::LittenEndian as ::byteorder::ByteOrder>::write_u32(&mut packet[3usize..], val); }),
            (32, 48, Some(Endianness::Big), quote! { <::byteorder::BigEndian as ::byteorder::ByteOrder>::write_u48(&mut packet[4usize..], val); }),
            (40, 64, None, quote! { <::byteorder::NativeEndian as ::byteorder::ByteOrder>::write_u64(&mut packet[5usize..], val); }),
            (48, 40, Some(Endianness::Little), quote! { <::byteorder::LittenEndian as ::byteorder::ByteOrder>::write_uint(&mut packet[6usize..], 5usize, val); }),
        ];

        for &(bits_offset, bits, endianness, ref code) in &write_ops {
            assert_eq!(
                write_operations(
                    bits_offset,
                    bits,
                    endianness,
                    quote! { packet },
                    quote! { val }
                ).to_string(),
                code.to_string()
            );
        }
    }
}
