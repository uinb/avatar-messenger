use reqwest::Body;
use serde::{Serialize, Deserialize};
use crate::block_header::Header;
use crate::digest::{Digest, DigestItem};
use sp_core::bytes::from_hex;
use std::str::FromStr;
use sp_core::H256;
use codec::Decode;
use codec::Compact;

#[derive(Debug)]
pub struct GetBlockHashParams<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    id: u8,
    params: Vec<u64>
}

#[derive(Serialize, Debug)]
pub struct GetBlockParams<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    id: u8,
    params: Vec<&'a str>
}


impl GetBlockParams<'static> {

   pub fn push_param(&mut self, blockhash: &'static str) {
       self.params.push(blockhash)
   }

}

impl Default for GetBlockParams<'static> {
    fn default() -> Self {
        Self {
            jsonrpc: "2.0",
            method: "chain_getBlock",
            id: 1,
            params: vec![]
        }
    }
}

#[derive(Serialize, Deserialize,Debug)]
pub struct HttpResponse<T> {
    pub jsonrpc: String,
    pub result: T,
    pub id: u64,
}


#[derive(Serialize, Deserialize,Debug)]
pub struct BlockResult {
    pub block: BlockResponse,
}


#[derive(Serialize, Deserialize,Debug)]
pub struct BlockResponse {
    pub extrinsics: Vec<String>,
    pub header: GetHeaderResponse

}

#[derive(Serialize, Deserialize,Debug)]
pub struct GetHeaderResponse {
    pub digest: Digests,
    #[serde(rename="extrinsicsRoot")]
    pub extrinsics_root: String,
    pub number: String,
    #[serde(rename="parentHash")]
    pub parent_hash: String,
    #[serde(rename="stateRoot")]
    pub state_root: String,
}

#[derive(Serialize, Deserialize,Debug)]
pub struct Digests{
    pub logs: Vec<String>
}


impl From<GetHeaderResponse> for Header{
    fn from( r: GetHeaderResponse) -> Self {

        let mut digest = Digest::default();
        for x in  r.digest.logs {
            let item = DigestItem::decode(&mut from_hex(x.as_str()).unwrap().as_ref()).unwrap();
            digest.push(item);
        }

        let bn_str = &r.number.as_str()[2..];
        let block_number = u64::from_str_radix(bn_str, 16).unwrap();
        let header = Header::new(H256::from_str(r.parent_hash.as_ref()).unwrap(),
                                 block_number,
                                 H256::from_str(r.stateRoot.as_ref()).unwrap(),
                                 H256::from_str(r.extrinsics_root.as_ref()).unwrap(), digest);
        header
    }
}


#[cfg(test)]
mod test{
    use crate::http_objects::GetBlockParams;

    #[test]
    fn test_create_params(){
        let a = GetBlockParams::default();
        println!("{:?}", a);
    }
}

