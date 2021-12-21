use crate::trie_lib::{Layout, TrieConfiguration};
use hash_db::Hasher;
use std::hash::Hash;
use sp_core::{blake2_256, H256};
use crate::http_objects::*;
use reqwest::Client;

mod trie_lib;
mod trie_stream;
mod node_codec;
mod node_header;
mod error;
mod digest;
mod block_header;
mod http_objects;

use codec::{Encode, Decode, Input, Compact};
use hash256_std_hasher::Hash256StdHasher;
use sp_core::bytes::from_hex;
use block_header::Header;

/// Constants used into trie simplification codec.
mod trie_constants {
    pub const EMPTY_TRIE: u8 = 0;
    pub const NIBBLE_SIZE_BOUND: usize = u16::max_value() as usize;
    pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
    pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
    pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
}
use std::str::FromStr;
use crate::digest::{DigestItem, Digest};
use std::convert::TryFrom;
use std::collections::HashMap;
use serde::de::value::U64Deserializer;
use serde::Deserializer;
//use parity_scale_codec::Decode;

/// Blake2-256 Hash implementation.
#[derive(PartialEq, Eq, Clone,Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct BlakeTwo256;

impl Hasher for BlakeTwo256 {

    type Out = sp_core::H256;
    type StdHasher = hash256_std_hasher::Hash256StdHasher;
    const LENGTH: usize = 32;

    fn hash(s: &[u8]) -> Self::Out {
        blake2_256(s).into()
    }
}


fn encode_index(input: u32) -> Vec<u8> {
    codec::Encode::encode(&codec::Compact(input))
}

fn gen_extrinsic_root( v: Vec<String>) -> String{
    let mut leaves = vec![];
    for x in v {
        let leaf = from_hex(x.as_str()).unwrap();
        leaves.push(leaf);
    }
    let root = Layout::<BlakeTwo256>::ordered_trie_root(leaves).to_fixed_bytes();
    hex::encode(root)
}
fn main() {

    let mut a = GetBlockParams::default();
    a.push_param("0x8ccd1bd09f7c259ff55c7f90ecada929cefea9452cba7b857f41e465b97bc424");
    println!("{:?}", a);

    let client = reqwest::blocking::Client::new();
    let resp = client.post("http://localhost:9933").json(&a).send();
    let r = resp.unwrap().json::<HttpResponse<BlockResult>>().unwrap();
    println!("{:?}", r);
    let header = Header::from(r.result.block.header);
    println!("{:?}", header.hash());
    println!("{:?}",header.extrinsics_root);
    let extrinsics = r.result.block.extrinsics;
    let extrinsics_root = gen_extrinsic_root(extrinsics);
    println!("0x{}", extrinsics_root);

}
