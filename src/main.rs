use std::convert::TryFrom;
use std::fmt::LowerHex;
use std::{env, io};
use std::ops::{Range, Deref};
use std::sync::Arc;

use blake3;
use clap::Parser;
use ed25519_compact::{KeyPair, Signature, Seed, Noise};
use themelio_structs::{
    Address,
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

const ERR_STRING: &str = "0x4572726f7220696e204646492070726f6772616d2e";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "")]
    blake3: String,

    #[clap(short, long, default_value = "")]
    ed25519: String,

    #[clap(short, long, default_value = "")]
    decode_integer: String,

    #[clap(short, long, default_value = "")]
    slice: String,

    #[clap(long, default_value_t = 0)]
    start: isize,

    #[clap(long, default_value_t = 0, allow_hyphen_values = true)]
    end: isize,

    #[clap(short, long, default_value = "")]
    integer_size: String
}

fn blake3_differential(data: &[u8]) -> String {
    let hash = *blake3::keyed_hash(
        blake3::hash(NODE_HASH_KEY).as_bytes(),
        data
    ).as_bytes();

    hex::encode(hash)
}

fn ed25519_differential(data: &[u8]) -> (String, String) {
    let keypair = KeyPair::from_seed(Seed::default());

    let signature = keypair.sk.sign(data, Some(Noise::generate()));

    (hex::encode(*keypair.pk), hex::encode(*signature))
}

fn decode_integer_differential(integer: u128) -> String {
    let encoded_integer = stdcode::serialize(&integer)
        .expect(ERR_STRING);

    hex::encode(encoded_integer)
}

fn integer_size_differential(integer: u128) -> String {
    let encoded_integer = stdcode::serialize(&integer)
        .expect(ERR_STRING);

    let encoded_integer_length = encoded_integer.len() as u128;

    format!("{:0>64x}{:0>64x}{:0>64x}{:0<64}", 0x40, encoded_integer_length, encoded_integer_length, hex::encode(encoded_integer))
}

fn slice_differential(data: &[u8], start: isize, end: isize) -> String {
    if start < end {
        let start = start as usize;
        let end = end as usize;

        hex::encode(&data[start..end])
    } else {
        let r_start = (end + 1) as usize;
        let r_end = (start + 1) as usize;
    
        let mut reverse_slice = data[r_start..r_end].to_vec();
        reverse_slice.reverse();

        hex::encode(reverse_slice)
    }
}

fn main() {
    let args = Args::parse();

    if args.blake3.len() > 0 {
        let data = hex::decode(args.blake3.strip_prefix("0x").unwrap())
            .expect(ERR_STRING);

        print!("0x{}", blake3_differential(&data));
    } else if args.ed25519.len() > 0 {
        let data = hex::decode(args.ed25519.strip_prefix("0x").unwrap())
            .expect(ERR_STRING);

        let key_and_signature = ed25519_differential(&data);

        print!("0x{}{}", key_and_signature.0, key_and_signature.1);
    } else if args.decode_integer.len() > 0 {
        let integer: u128 = args.decode_integer.parse()
            .expect(ERR_STRING);

        let encoded_integer = decode_integer_differential(integer);

        print!("0x{}", encoded_integer);
    } else if args.slice.len() > 0 {
        let data = hex::decode(args.slice.strip_prefix("0x").unwrap())
            .expect(ERR_STRING);

        print!("0x{}", slice_differential(&data, args.start, args.end));
    } else if args.integer_size.len() > 0 {
        let integer: u128 = args.integer_size.parse()
            .expect(ERR_STRING);
    
        let abi_encoded_integer_and_size = integer_size_differential(integer);

        print!("0x{}", abi_encoded_integer_and_size);
    } else {
        print!("0x");
    }
}