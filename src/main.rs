use std::convert::TryFrom;
use std::fmt::LowerHex;
use std::{env, io};
use std::ops::{Range, Deref};
use std::sync::Arc;

use blake3;
use clap::Parser;
use ed25519_compact::{KeyPair, Signature, Seed, Noise};
use rand::Rng;
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
    #[clap(long, default_value = "")]
    blake3: String,

    #[clap(long, default_value = "")]
    ed25519: String,

    #[clap(long, default_value = "")]
    decode_integer: String,

    #[clap(long, default_value_t = 0)]
    start: isize,

    #[clap(long, default_value_t = 0, allow_hyphen_values = true)]
    end: isize,

    #[clap(long, default_value = "")]
    integer_size: String,

    #[clap(long, default_value = "")]
    slice: String,

    #[clap(long, default_value = "")]
    extract_merkle_root: String,

    #[clap(long, default_value = "")]
    extract_block_height: String,

    #[clap(long, default_value = "")]
    modifier: String
}

fn blake3_differential(data: &[u8]) -> String {
    let hash = *blake3::keyed_hash(
        blake3::hash(NODE_HASH_KEY).as_bytes(),
        data
    ).as_bytes();

    hex::encode(hash)
}

fn ed25519_differential(data: &[u8]) -> String {
    let keypair = KeyPair::from_seed(Seed::default());

    let signature = keypair.sk.sign(data, Some(Noise::generate()));

    format!("{}{}", hex::encode(*keypair.pk), hex::encode(*signature))
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

fn random_header(modifier: u128) -> Header {
    if modifier == 0 {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height: BlockHeight(u64::MIN),
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(u128::MIN),
            fee_multiplier: u128::MIN,
            dosc_speed: u128::MIN,
            pools_hash: HashVal::random(),
            stakes_hash: HashVal::random(),
        }
    } else if modifier == u8::MAX.into() {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height: BlockHeight(u8::MAX.into()),
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(u8::MAX.into()),
            fee_multiplier: u8::MAX.into(),
            dosc_speed: u8::MAX.into(),
            pools_hash: HashVal::random(),
            stakes_hash: HashVal::random(),
        }
    } else if modifier == u16::MAX.into() {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height: BlockHeight(u16::MAX.into()),
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(u16::MAX.into()),
            fee_multiplier: u16::MAX.into(),
            dosc_speed: u16::MAX.into(),
            pools_hash: HashVal::random(),
            stakes_hash: HashVal::random(),
        }
    } else if modifier == u32::MAX.into() {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height: BlockHeight(u32::MAX.into()),
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(u32::MAX.into()),
            fee_multiplier: u32::MAX.into(),
            dosc_speed: u32::MAX.into(),
            pools_hash: HashVal::random(),
            stakes_hash: HashVal::random(),
        }
    } else if modifier == u64::MAX.into() {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height: BlockHeight(u64::MAX),
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(u64::MAX.into()),
            fee_multiplier: u64::MAX.into(),
            dosc_speed: u64::MAX.into(),
            pools_hash: HashVal::random(),
            stakes_hash: HashVal::random(),
        }
    } else if modifier == u128::MAX {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height: BlockHeight(u64::MAX),
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(u128::MAX),
            fee_multiplier: u128::MAX,
            dosc_speed: u128::MAX,
            pools_hash: HashVal::random(),
            stakes_hash: HashVal::random(),
        }
    } else {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height: BlockHeight(rand::thread_rng().gen()),
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(rand::thread_rng().gen()),
            fee_multiplier: rand::thread_rng().gen(),
            dosc_speed: rand::thread_rng().gen(),
            pools_hash: HashVal::random(),
            stakes_hash: HashVal::random(),
        }
    }
}

    fn extract_merkle_root_differential(modifier: u128) -> String {
        let header = random_header(modifier);
            
        let mut serialized_header = stdcode::serialize(&header)
        .expect(ERR_STRING);

        let serialized_header_length = serialized_header.len();

        let padding_length = serialized_header_length % 64;

        serialized_header.resize(serialized_header_length + padding_length, 0);

        format!(
            "{:0>64x}{}{:0>64x}{:0<64}",
            0x40,
            hex::encode(header.transactions_hash),
            serialized_header_length,
            hex::encode(serialized_header)
        )
    }

    fn extract_block_height_differential(block_height:u64, modifier: u128) -> String {
        let mut header = random_header(modifier);
        header.height = BlockHeight(block_height);

        let mut serialized_header = stdcode::serialize(&header)
            .expect(ERR_STRING);

        hex::encode(serialized_header)
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

        print!("0x{}", key_and_signature);
    } else if args.decode_integer.len() > 0 {
        let integer: u128 = args.decode_integer.parse()
            .expect(ERR_STRING);

        let encoded_integer = decode_integer_differential(integer);

        print!("0x{}", encoded_integer);
    } else if args.integer_size.len() > 0 {
        let integer: u128 = args.integer_size
            .parse()
            .expect(ERR_STRING);
    
        let abi_encoded_integer_and_size = integer_size_differential(integer);

        print!("0x{}", abi_encoded_integer_and_size);
    } else if args.slice.len() > 0 {
        let data = hex::decode(args.slice.strip_prefix("0x").unwrap())
            .expect(ERR_STRING);

        print!("0x{}", slice_differential(&data, args.start, args.end));
    } else if args.extract_merkle_root.len() > 0 {
        let modifier: u128 = args.extract_merkle_root
            .parse()
            .expect(ERR_STRING);

        let serialized_header_and_root = extract_merkle_root_differential(modifier);

        print!("0x{}", serialized_header_and_root);
    } else if args.extract_block_height.len() > 0 {
        let block_height: u64 = args.extract_block_height
            .parse()
            .expect(ERR_STRING);
        
        let modifier: u128 = args.modifier
            .parse()
            .expect(ERR_STRING);

        let serialized_header = extract_block_height_differential(block_height, modifier);

        print!("0x{}", serialized_header);
    } else {
        print!("0x");
    }
}
