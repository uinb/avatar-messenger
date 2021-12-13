use std::fmt::Debug;
use crate::digest::Digest;
use sp_core::U256;
use sp_core::H256;
use std::convert::TryFrom;
use codec::{Codec, Decode, Encode};
use crate::BlakeTwo256;
use hash_db::Hasher;

#[derive(Encode, Decode, PartialEq, Eq, Clone)]
pub struct Header {
    /// The parent hash.
    pub parent_hash: H256,
    /// The block number.
    #[cfg_attr(
    feature = "std",
    serde(serialize_with = "serialize_number", deserialize_with = "deserialize_number")
    )]
    #[codec(compact)]
    pub number: u64,
    /// The state trie merkle root
    pub state_root: H256,
    /// The merkle root of the extrinsics.
    pub extrinsics_root: H256,
    /// A chain-specific digest of data useful for light clients or referencing auxiliary data.
    pub digest: Digest,
}

impl Header {

    pub fn new(
       parent_hash: H256,
        block_number: u64,
        state_root: H256,
        extrinsics_root: H256,
        digest: Digest
    ) ->Self{

        Self {
            parent_hash: parent_hash,
            number: block_number,
            state_root: state_root,
            extrinsics_root: extrinsics_root,
            digest: digest
        }
    }

    pub fn hash(&self) -> H256 {

        Encode::using_encoded(self, BlakeTwo256::hash)
    }

}