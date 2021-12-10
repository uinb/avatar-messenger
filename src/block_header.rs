use std::fmt::Debug;
use crate::digest::Digest;
use sp_core::U256;
use std::convert::TryFrom;
use crate::traits::{Hash as HashT};


pub struct Header<Number: Copy + Into<U256> + TryFrom<U256>, Hash: HashT> {
    /// The parent hash.
    pub parent_hash: Hash::Output,
    /// The block number.
    #[cfg_attr(
    feature = "std",
    serde(serialize_with = "serialize_number", deserialize_with = "deserialize_number")
    )]
    #[codec(compact)]
    pub number: Number,
    /// The state trie merkle root
    pub state_root: Hash::Output,
    /// The merkle root of the extrinsics.
    pub extrinsics_root: Hash::Output,
    /// A chain-specific digest of data useful for light clients or referencing auxiliary data.
    pub digest: Digest,
}
/*

pub trait Header
{

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
/*    fn hash(&self) -> Self::Hash {
        <Self::Hashing as Hash>::hash_of(self)
    }*/
}
*/