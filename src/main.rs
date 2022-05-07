use std::convert::TryFrom;
use std::{env, io};
use std::ops::{Range, Deref};
use std::sync::Arc;

use blake3;
use clap::Parser;
use ed25519_compact::{KeyPair, Signature, Seed, Noise};
use themelio_structs::{
    Address as ThemelioAddress,
    BlockHeight,
    CoinData,
    CoinID,
    Denom,
    Header,
    NetID,
    CoinValue,
    Transaction,
    TxKind,
    TxHash
};
use tmelcrypt::HashVal;

const DATA_BLOCK_HASH_KEY: &[u8; 13] = b"smt_datablock";
const NODE_HASH_KEY: &[u8; 8] = b"smt_node";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "")]
    blake3: String,

    #[clap(short, long)]
    ed25519: bool,
}

fn blake3_differential(data: &[u8]) -> String {
    let hash = *blake3::keyed_hash(blake3::hash(NODE_HASH_KEY).as_bytes(), data).as_bytes();

    hex::encode(hash)
}

fn ed25519_differential() -> String {
    String::from("Coming soon.")
}

fn main() {
    let args = Args::parse();

    if args.blake3.len() > 0 {
        let data = hex::decode(args.blake3.strip_prefix("0x").unwrap())
            .expect("Unable to convert input to bytes.");

        print!("0x{}", blake3_differential(&data));
    } else if args.ed25519 {
        print!("0x{}", ed25519_differential());
    } else {
        print!("0x")
    }
}