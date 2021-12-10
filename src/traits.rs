// This file is part of Substrate.

// Copyright (C) 2017-2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Primitives for the runtime modules.

use crate::{
	codec::{Codec, Decode, Encode, MaxEncodedLen},
	digest::Digest,
	scale_info::{MetaType, StaticTypeInfo, TypeInfo},
	transaction_validity::{
		TransactionSource, TransactionValidity, TransactionValidityError, UnknownTransaction,
		ValidTransaction,
	},
	DispatchResult,
};
use impl_trait_for_tuples::impl_for_tuples;
#[cfg(feature = "std")]
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp_application_crypto::AppKey;
pub use sp_arithmetic::traits::{
	AtLeast32Bit, AtLeast32BitUnsigned, Bounded, CheckedAdd, CheckedDiv, CheckedMul, CheckedShl,
	CheckedShr, CheckedSub, IntegerSquareRoot, One, SaturatedConversion, Saturating,
	UniqueSaturatedFrom, UniqueSaturatedInto, Zero,
};
use sp_core::{self, Hasher, TypeId};

use std::{
	self,
	convert::{TryFrom, TryInto},
	fmt::Debug,
	marker::PhantomData,
	prelude::*,
};
#[cfg(feature = "std")]
use std::fmt::Display;
#[cfg(feature = "std")]
use std::str::FromStr;

/// A lazy value.
pub trait Lazy<T: ?Sized> {
	/// Get a reference to the underlying value.
	///
	/// This will compute the value if the function is invoked for the first time.
	fn get(&mut self) -> &T;
}

impl<'a> Lazy<[u8]> for &'a [u8] {
	fn get(&mut self) -> &[u8] {
		&**self
	}
}

/// Some type that is able to be collapsed into an account ID. It is not possible to recreate the
/// original value from the account ID.
pub trait IdentifyAccount {
	/// The account ID that this can be transformed into.
	type AccountId;
	/// Transform into an account.
	fn into_account(self) -> Self::AccountId;
}

impl IdentifyAccount for sp_core::ed25519::Public {
	type AccountId = Self;
	fn into_account(self) -> Self {
		self
	}
}

impl IdentifyAccount for sp_core::sr25519::Public {
	type AccountId = Self;
	fn into_account(self) -> Self {
		self
	}
}

impl IdentifyAccount for sp_core::ecdsa::Public {
	type AccountId = Self;
	fn into_account(self) -> Self {
		self
	}
}

/// Means of signature verification.
pub trait Verify {
	/// Type of the signer.
	type Signer: IdentifyAccount;
	/// Verify a signature.
	///
	/// Return `true` if signature is valid for the value.
	fn verify<L: Lazy<[u8]>>(
		&self,
		msg: L,
		signer: &<Self::Signer as IdentifyAccount>::AccountId,
	) -> bool;
}

impl Verify for sp_core::ed25519::Signature {
	type Signer = sp_core::ed25519::Public;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::ed25519::Public) -> bool {
		sp_io::crypto::ed25519_verify(self, msg.get(), signer)
	}
}

impl Verify for sp_core::sr25519::Signature {
	type Signer = sp_core::sr25519::Public;

	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::sr25519::Public) -> bool {
		sp_io::crypto::sr25519_verify(self, msg.get(), signer)
	}
}

impl Verify for sp_core::ecdsa::Signature {
	type Signer = sp_core::ecdsa::Public;
	fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sp_core::ecdsa::Public) -> bool {
		match sp_io::crypto::secp256k1_ecdsa_recover_compressed(
			self.as_ref(),
			&sp_io::hashing::blake2_256(msg.get()),
		) {
			Ok(pubkey) => signer.as_ref() == &pubkey[..],
			_ => false,
		}
	}
}

/// Means of signature verification of an application key.
pub trait AppVerify {
	/// Type of the signer.
	type AccountId;
	/// Verify a signature. Return `true` if signature is valid for the value.
	fn verify<L: Lazy<[u8]>>(&self, msg: L, signer: &Self::AccountId) -> bool;
}

impl<
		S: Verify<Signer = <<T as AppKey>::Public as sp_application_crypto::AppPublic>::Generic>
			+ From<T>,
		T: sp_application_crypto::Wraps<Inner = S>
			+ sp_application_crypto::AppKey
			+ sp_application_crypto::AppSignature
			+ AsRef<S>
			+ AsMut<S>
			+ From<S>,
	> AppVerify for T
where
	<S as Verify>::Signer: IdentifyAccount<AccountId = <S as Verify>::Signer>,
	<<T as AppKey>::Public as sp_application_crypto::AppPublic>::Generic: IdentifyAccount<
		AccountId = <<T as AppKey>::Public as sp_application_crypto::AppPublic>::Generic,
	>,
{
	type AccountId = <T as AppKey>::Public;
	fn verify<L: Lazy<[u8]>>(&self, msg: L, signer: &<T as AppKey>::Public) -> bool {
		use sp_application_crypto::IsWrappedBy;
		let inner: &S = self.as_ref();
		let inner_pubkey =
			<<T as AppKey>::Public as sp_application_crypto::AppPublic>::Generic::from_ref(&signer);
		Verify::verify(inner, msg, inner_pubkey)
	}
}

/// An error type that indicates that the origin is invalid.
#[derive(Encode, Decode, Debug)]
pub struct BadOrigin;

impl From<BadOrigin> for &'static str {
	fn from(_: BadOrigin) -> &'static str {
		"Bad origin"
	}
}

/// An error that indicates that a lookup failed.
#[derive(Encode, Decode, Debug)]
pub struct LookupError;

impl From<LookupError> for &'static str {
	fn from(_: LookupError) -> &'static str {
		"Can not lookup"
	}
}

impl From<LookupError> for TransactionValidityError {
	fn from(_: LookupError) -> Self {
		UnknownTransaction::CannotLookup.into()
	}
}

/// Means of changing one type into another in a manner dependent on the source type.
pub trait Lookup {
	/// Type to lookup from.
	type Source;
	/// Type to lookup into.
	type Target;
	/// Attempt a lookup.
	fn lookup(&self, s: Self::Source) -> Result<Self::Target, LookupError>;
}

/// Means of changing one type into another in a manner dependent on the source type.
/// This variant is different to `Lookup` in that it doesn't (can cannot) require any
/// context.
pub trait StaticLookup {
	/// Type to lookup from.
	type Source: Codec + Clone + PartialEq + Debug + TypeInfo;
	/// Type to lookup into.
	type Target;
	/// Attempt a lookup.
	fn lookup(s: Self::Source) -> Result<Self::Target, LookupError>;
	/// Convert from Target back to Source.
	fn unlookup(t: Self::Target) -> Self::Source;
}

/// A lookup implementation returning the input value.
#[derive(Default)]
pub struct IdentityLookup<T>(PhantomData<T>);
impl<T: Codec + Clone + PartialEq + Debug + TypeInfo> StaticLookup for IdentityLookup<T> {
	type Source = T;
	type Target = T;
	fn lookup(x: T) -> Result<T, LookupError> {
		Ok(x)
	}
	fn unlookup(x: T) -> T {
		x
	}
}

impl<T> Lookup for IdentityLookup<T> {
	type Source = T;
	type Target = T;
	fn lookup(&self, x: T) -> Result<T, LookupError> {
		Ok(x)
	}
}

/// A lookup implementation returning the `AccountId` from a `MultiAddress`.
pub struct AccountIdLookup<AccountId, AccountIndex>(PhantomData<(AccountId, AccountIndex)>);
impl<AccountId, AccountIndex> StaticLookup for AccountIdLookup<AccountId, AccountIndex>
where
	AccountId: Codec + Clone + PartialEq + Debug,
	AccountIndex: Codec + Clone + PartialEq + Debug,
	crate::MultiAddress<AccountId, AccountIndex>: Codec + StaticTypeInfo,
{
	type Source = crate::MultiAddress<AccountId, AccountIndex>;
	type Target = AccountId;
	fn lookup(x: Self::Source) -> Result<Self::Target, LookupError> {
		match x {
			crate::MultiAddress::Id(i) => Ok(i),
			_ => Err(LookupError),
		}
	}
	fn unlookup(x: Self::Target) -> Self::Source {
		crate::MultiAddress::Id(x)
	}
}

/// Perform a StaticLookup where there are multiple lookup sources of the same type.
impl<A, B> StaticLookup for (A, B)
where
	A: StaticLookup,
	B: StaticLookup<Source = A::Source, Target = A::Target>,
{
	type Source = A::Source;
	type Target = A::Target;

	fn lookup(x: Self::Source) -> Result<Self::Target, LookupError> {
		A::lookup(x.clone()).or_else(|_| B::lookup(x))
	}
	fn unlookup(x: Self::Target) -> Self::Source {
		A::unlookup(x)
	}
}

/// Extensible conversion trait. Generic over both source and destination types.
pub trait Convert<A, B> {
	/// Make conversion.
	fn convert(a: A) -> B;
}

impl<A, B: Default> Convert<A, B> for () {
	fn convert(_: A) -> B {
		Default::default()
	}
}

/// A structure that performs identity conversion.
pub struct Identity;
impl<T> Convert<T, T> for Identity {
	fn convert(a: T) -> T {
		a
	}
}

/// A structure that performs standard conversion using the standard Rust conversion traits.
pub struct ConvertInto;
impl<A, B: From<A>> Convert<A, B> for ConvertInto {
	fn convert(a: A) -> B {
		a.into()
	}
}

/// Convenience type to work around the highly unergonomic syntax needed
/// to invoke the functions of overloaded generic traits, in this case
/// `TryFrom` and `TryInto`.
pub trait CheckedConversion {
	/// Convert from a value of `T` into an equivalent instance of `Option<Self>`.
	///
	/// This just uses `TryFrom` internally but with this
	/// variant you can provide the destination type using turbofish syntax
	/// in case Rust happens not to assume the correct type.
	fn checked_from<T>(t: T) -> Option<Self>
	where
		Self: TryFrom<T>,
	{
		<Self as TryFrom<T>>::try_from(t).ok()
	}
	/// Consume self to return `Some` equivalent value of `Option<T>`.
	///
	/// This just uses `TryInto` internally but with this
	/// variant you can provide the destination type using turbofish syntax
	/// in case Rust happens not to assume the correct type.
	fn checked_into<T>(self) -> Option<T>
	where
		Self: TryInto<T>,
	{
		<Self as TryInto<T>>::try_into(self).ok()
	}
}
impl<T: Sized> CheckedConversion for T {}

/// Multiply and divide by a number that isn't necessarily the same type. Basically just the same
/// as `Mul` and `Div` except it can be used for all basic numeric types.
pub trait Scale<Other> {
	/// The output type of the product of `self` and `Other`.
	type Output;

	/// @return the product of `self` and `other`.
	fn mul(self, other: Other) -> Self::Output;

	/// @return the integer division of `self` and `other`.
	fn div(self, other: Other) -> Self::Output;

	/// @return the modulo remainder of `self` and `other`.
	fn rem(self, other: Other) -> Self::Output;
}
macro_rules! impl_scale {
	($self:ty, $other:ty) => {
		impl Scale<$other> for $self {
			type Output = Self;
			fn mul(self, other: $other) -> Self::Output {
				self * (other as Self)
			}
			fn div(self, other: $other) -> Self::Output {
				self / (other as Self)
			}
			fn rem(self, other: $other) -> Self::Output {
				self % (other as Self)
			}
		}
	};
}
impl_scale!(u128, u128);
impl_scale!(u128, u64);
impl_scale!(u128, u32);
impl_scale!(u128, u16);
impl_scale!(u128, u8);
impl_scale!(u64, u64);
impl_scale!(u64, u32);
impl_scale!(u64, u16);
impl_scale!(u64, u8);
impl_scale!(u32, u32);
impl_scale!(u32, u16);
impl_scale!(u32, u8);
impl_scale!(u16, u16);
impl_scale!(u16, u8);
impl_scale!(u8, u8);

/// Trait for things that can be clear (have no bits set). For numeric types, essentially the same
/// as `Zero`.
pub trait Clear {
	/// True iff no bits are set.
	fn is_clear(&self) -> bool;

	/// Return the value of Self that is clear.
	fn clear() -> Self;
}

impl<T: Default + Eq + PartialEq> Clear for T {
	fn is_clear(&self) -> bool {
		*self == Self::clear()
	}
	fn clear() -> Self {
		Default::default()
	}
}

/// A meta trait for all bit ops.
pub trait SimpleBitOps:
	Sized
	+ Clear
	+ std::ops::BitOr<Self, Output = Self>
	+ std::ops::BitXor<Self, Output = Self>
	+ std::ops::BitAnd<Self, Output = Self>
{
}
impl<
		T: Sized
			+ Clear
			+ std::ops::BitOr<Self, Output = Self>
			+ std::ops::BitXor<Self, Output = Self>
			+ std::ops::BitAnd<Self, Output = Self>,
	> SimpleBitOps for T
{
}

/// Abstraction around hashing
// Stupid bug in the Rust compiler believes derived
// traits must be fulfilled by all type parameters.
pub trait Hash:
	'static
	+ MaybeSerializeDeserialize
	+ Debug
	+ Clone
	+ Eq
	+ PartialEq
	+ Hasher<Out = <Self as Hash>::Output>
{
	/// The hash type produced.
	type Output: Member
		+ MaybeSerializeDeserialize
		+ Debug
		+ std::hash::Hash
		+ AsRef<[u8]>
		+ AsMut<[u8]>
		+ Copy
		+ Default
		+ Encode
		+ Decode
		+ MaxEncodedLen
		+ TypeInfo;

	/// Produce the hash of some byte-slice.
	fn hash(s: &[u8]) -> Self::Output {
		<Self as Hasher>::hash(s)
	}

	/// Produce the hash of some codec-encodable value.
	fn hash_of<S: Encode>(s: &S) -> Self::Output {
		Encode::using_encoded(s, <Self as Hasher>::hash)
	}

	/// The ordered Patricia tree root of the given `input`.
	fn ordered_trie_root(input: Vec<Vec<u8>>) -> Self::Output;

	/// The Patricia tree root of the given mapping.
	fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> Self::Output;
}

/// Blake2-256 Hash implementation.
#[derive(PartialEq, Eq, Clone, Debug, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct BlakeTwo256;

impl Hasher for BlakeTwo256 {
	type Out = sp_core::H256;
	type StdHasher = hash256_std_hasher::Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(s: &[u8]) -> Self::Out {
		sp_io::hashing::blake2_256(s).into()
	}
}

impl Hash for BlakeTwo256 {
	type Output = sp_core::H256;

	fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> Self::Output {
		sp_io::trie::blake2_256_root(input)
	}

	fn ordered_trie_root(input: Vec<Vec<u8>>) -> Self::Output {
		sp_io::trie::blake2_256_ordered_root(input)
	}
}

/// Keccak-256 Hash implementation.
#[derive(PartialEq, Eq, Clone, Debug, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Keccak256;

impl Hasher for Keccak256 {
	type Out = sp_core::H256;
	type StdHasher = hash256_std_hasher::Hash256StdHasher;
	const LENGTH: usize = 32;

	fn hash(s: &[u8]) -> Self::Out {
		sp_io::hashing::keccak_256(s).into()
	}
}

impl Hash for Keccak256 {
	type Output = sp_core::H256;

	fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> Self::Output {
		sp_io::trie::keccak_256_root(input)
	}

	fn ordered_trie_root(input: Vec<Vec<u8>>) -> Self::Output {
		sp_io::trie::keccak_256_ordered_root(input)
	}
}

/// Something that can be checked for equality and printed out to a debug channel if bad.
pub trait CheckEqual {
	/// Perform the equality check.
	fn check_equal(&self, other: &Self);
}

impl CheckEqual for sp_core::H256 {
	#[cfg(feature = "std")]
	fn check_equal(&self, other: &Self) {
		use sp_core::hexdisplay::HexDisplay;
		if self != other {
			println!(
				"Hash: given={}, expected={}",
				HexDisplay::from(self.as_fixed_bytes()),
				HexDisplay::from(other.as_fixed_bytes()),
			);
		}
	}

	#[cfg(not(feature = "std"))]
	fn check_equal(&self, other: &Self) {
		if self != other {
			"Hash not equal".print();
			self.as_bytes().print();
			other.as_bytes().print();
		}
	}
}

impl CheckEqual for super::generic::DigestItem {
	#[cfg(feature = "std")]
	fn check_equal(&self, other: &Self) {
		if self != other {
			println!("DigestItem: given={:?}, expected={:?}", self, other);
		}
	}

	#[cfg(not(feature = "std"))]
	fn check_equal(&self, other: &Self) {
		if self != other {
			"DigestItem not equal".print();
			(&Encode::encode(self)[..]).print();
			(&Encode::encode(other)[..]).print();
		}
	}
}

sp_core::impl_maybe_marker!(
	/// A type that implements Display when in std environment.
	trait MaybeDisplay: Display;

	/// A type that implements FromStr when in std environment.
	trait MaybeFromStr: FromStr;

	/// A type that implements Hash when in std environment.
	trait MaybeHash: std::hash::Hash;

	/// A type that implements Serialize when in std environment.
	trait MaybeSerialize: Serialize;

	/// A type that implements Serialize, DeserializeOwned and Debug when in std environment.
	trait MaybeSerializeDeserialize: DeserializeOwned, Serialize;

	/// A type that implements MallocSizeOf.
	trait MaybeMallocSizeOf: parity_util_mem::MallocSizeOf;
);

/// A type that can be used in runtime structures.
pub trait Member: Send + Sync + Sized + Debug + Eq + PartialEq + Clone + 'static {}
impl<T: Send + Sync + Sized + Debug + Eq + PartialEq + Clone + 'static> Member for T {}

/// Determine if a `MemberId` is a valid member.
pub trait IsMember<MemberId> {
	/// Is the given `MemberId` a valid member?
	fn is_member(member_id: &MemberId) -> bool;
}

/// Something which fulfills the abstract idea of a Substrate header. It has types for a `Number`,
/// a `Hash` and a `Hashing`. It provides access to an `extrinsics_root`, `state_root` and
/// `parent_hash`, as well as a `digest` and a block `number`.
///
/// You can also create a `new` one from those fields.
pub trait Header
{
	/// Header number.
	type Number: Member
		+ MaybeSerializeDeserialize
		+ Debug
		+ std::hash::Hash
		+ Copy
		+ MaybeDisplay
		+ AtLeast32BitUnsigned
		+ Codec
		+ std::str::FromStr
		+ MaybeMallocSizeOf;
	/// Header hash type
	type Hash: Member
		+ MaybeSerializeDeserialize
		+ Debug
		+ std::hash::Hash
		+ Ord
		+ Copy
		+ MaybeDisplay
		+ Default
		+ SimpleBitOps
		+ Codec
		+ AsRef<[u8]>
		+ AsMut<[u8]>
		+ MaybeMallocSizeOf
		+ TypeInfo;
	/// Hashing algorithm
	type Hashing: Hash<Output = Self::Hash>;

	/// Creates new header.
	fn new(
		number: Self::Number,
		extrinsics_root: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Digest,
	) -> Self;

	/// Returns a reference to the header number.
	fn number(&self) -> &Self::Number;
	/// Sets the header number.
	fn set_number(&mut self, number: Self::Number);

	/// Returns a reference to the extrinsics root.
	fn extrinsics_root(&self) -> &Self::Hash;
	/// Sets the extrinsic root.
	fn set_extrinsics_root(&mut self, root: Self::Hash);

	/// Returns a reference to the state root.
	fn state_root(&self) -> &Self::Hash;
	/// Sets the state root.
	fn set_state_root(&mut self, root: Self::Hash);

	/// Returns a reference to the parent hash.
	fn parent_hash(&self) -> &Self::Hash;
	/// Sets the parent hash.
	fn set_parent_hash(&mut self, hash: Self::Hash);

	/// Returns a reference to the digest.
	fn digest(&self) -> &Digest;
	/// Get a mutable reference to the digest.
	fn digest_mut(&mut self) -> &mut Digest;

	/// Returns the hash of the header.
	fn hash(&self) -> Self::Hash {
		<Self::Hashing as Hash>::hash_of(self)
	}
}
