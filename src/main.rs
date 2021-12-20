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



    //println!("{:?}",resp.unwrap().json::<HttpResponse<GetHeaderResponse>>().unwrap());

/*    //0xa46649ae81e0ab618b894175ea5155c6e8717aa5a755b3a4f422d063b979587f
    let a = from_hex("0x280402000b20a1ff837d01").unwrap();
    let b = from_hex("0xdd1a8400c6c08b37336550c0d64f1e24e38b72e2c627c5b15aa3ce7f42a2069aed74277201828639f26b7412188dff32856d78fcf1592deabf73ff4ed1651493bb5837cb6977f9e3c24e03a23acbfb9e1a9c283c8aeaf52599df1266d7452367220d351289007540000d01340c000000000000b4efe738ad9b5ec63d4b07b9cf6674fc0b5b5054847d742e7880e87cae5e2563549c00000101169d796416023558ef5c2580ef38c1c4f43f3c06f76ceab2412e6fc5d486a36eb0a9cb808dd4eb72f6264b4113c1a722479be205edc84d6ac5403d33d09b008701110600130000f44482916345a10fa10f000414240100000000010000000000d6ebfc1ca5f8800000000000000000009ea2c6486f6701000000000000000000e2a67a8b41b3800000000000000000009ea2c6486f6701000000000000009400fc15c27a022529b9e1402cac8dff2852119efa008fecc2ec5a1f189356b8691b000000000040b254edfe33ea14170000000000000000bcf0b5fcbebf80000000000000000040b254edfe33ea14170000000000000000c8ab336b5b7a80000000000000009400fc15c27a022529b9e1402cac8dff2852119efa008fecc2ec5a1f189356b8691b0100000000c489b9d1d659b06a030000000000000000000000000000000000000000000000c49185d403f255ce03000000000000000000000000000000000000000000009400b4efe738ad9b5ec63d4b07b9cf6674fc0b5b5054847d742e7880e87cae5e25630000000032806de53ea57167c71100000000000000000000000000000000000000000000320081f24773c3acc711000000000000000000000000000000000000000000009400b4efe738ad9b5ec63d4b07b9cf6674fc0b5b5054847d742e7880e87cae5e25630100000000d095b6c0efa898af000000000000000000000000000000000000000000000000d0d5977dc487d94b00000000000000000000000000000000000000000000008d074c4ffd4c4ff951f917155e35806affd1bbb46ea95da82d59649616f41e294f6a06697c65c5191440720dfb4d483eeeef152d8ade5f45dab989f9b7995f87363e733ac995fe9a18014c4ffa484f0151fc9a06eda604e76b7ab67b050cbbc2ff5db101cf6c7b3f097dba6128c0a96df9970d90fd39484ce4fc3c77ffe804755b7cb207f4477251b4f6d56cd32468105405485038b4baa41e5ba50fc2a14ad27a74b47709685fcb42ad3b364c31809bd7efeda54c4ffb51fbe5b5dc28c4b3a08234e529e527952a0550696f66b075e565ad62ce2f6db26c0e6665efc9341cc6b8bcb83e54f01c21706f1ce842d6ef781ac893f8d2214eff01510243162b2ed9b65e3548015c1443a08cb09e5ae45226c4f738052c4210e22320db0000000000000000000000000000000000000000000000000000000000000004506d292bd982d68d5e369a9d9f490f9f7b09d4b8d0ce27b069e47b005bbf50fc4f4c4ffb51015337a1404fb6da9453ef4f55da6e54ed34498c125d9d8e3f2edcda4b3e9d2dcd00000000000000000000000000000000000000000000000000000000000000045043ba0e3da900b0641cbe6cfc438e3122fe62c0eda25b6b64bd31904a88e715fe50b49d76e889d15ae724a2f228e974e53e210330cc9a581f2f6bf0f3ac6471baf148488d074c4ffd4c4ff951f917155e35806affd1bbb46ea95da82d59649616f41e294f6a06697c65c5191440720dfb4d483eeeef152d8ade5f45dab989f9b7995f87363e733ac995fe9a18014c4ffa484f0151fc9a06eda604e76b7ab67b050cbbc2ff5db101cf6c7b3f097dba6128c0a96df9970d90fd39484ce4fc3c77ffe804755b7cb207f4477251b4f6d56cd32468105405485038b4baa41e5ba50fc2a14ad27a74b47709685fcb42ad3b364c31809bd7efeda54c4ffb51fbe5b5dc28c4b3a08234e529e527952a0550696f66b075e565ad62ce2f6db26c0e6665efc9341cc6b8bcb83e54f01c21706f1ce842d6ef781ac893f8d2214eff01510243162b2ed9b65e3548015c1443a08cb09e5ae45226c4f738052c4210e22320db0000000000000000000000000000000000000000000000000000000000000004506d292bd982d68d5e369a9d9f490f9f7b09d4b8d0ce27b069e47b005bbf50fc4f4c4ffb51015337a1404fb6da9453ef4f55da6e54ed34498c125d9d8e3f2edcda4b3e9d2dcd00000000000000000000000000000000000000000000000000000000000000045043ba0e3da900b0641cbe6cfc438e3122fe62c0eda25b6b64bd31904a88e715fe50b49d76e889d15ae724a2f228e974e53e210330cc9a581f2f6bf0f3ac6471baf14848bff86e730bfc6c184170b30d29ef3f44aa9a242a4baa8efe9c2c07e97771f837").unwrap();

    let x = vec![a,b];
    let root = Layout::<BlakeTwo256>::ordered_trie_root(x).to_fixed_bytes();
    let s = hex::encode(root);
    println!("{:}",s);

  //  0x23e2b18a47227ec401c5c21db407270863dc169bc5195d1431de8da249461d98
    let di1 = DigestItem::decode(&mut from_hex("0x066175726120fe2a471000000000").unwrap().as_ref()).unwrap();
    let di2 = DigestItem::decode(&mut from_hex("0x056175726101015cd4037af4b2e7e5a76e02d3150dc74c72215432668eb2f7bd4e8253126aaa2100e1e985832e89589cf1db1bd2abff713a7f8fda043e898797c2a4d79ba34a87").unwrap().as_ref()).unwrap();
    let mut digest = Digest::default();
    digest.push(di1);
    digest.push(di2);
    let header = Header::new(H256::from_str("0x54528ec92a68130a96e8ca5dca763c724ce1c30cf74bfd76c9ed25bf67f47508".as_ref()).unwrap(),
                                                630839,
                             H256::from_str("0x25044c83970c7fa83e3356a3a7f1a67721dd20b674171842c5fc9bde5a05e6a6".as_ref()).unwrap(),
                             H256::from_str("0xa46649ae81e0ab618b894175ea5155c6e8717aa5a755b3a4f422d063b979587f".as_ref()).unwrap(),digest);

    let h  = header.hash();
    println!("{:}", hex::encode(h));*/

}
