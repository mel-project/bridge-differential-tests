mod cli;
use cli::{CLI, Subcommand};

use clap::Parser;
use ethers::{
    abi::ethabi::{self, Token},
    types::H160
};
use novasmt::{
    dense::DenseMerkleTree
};
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use stdcode::StdcodeSerializeExt;
use themelio_structs::{
    STAKE_EPOCH,
    Address,
    BlockHeight,
    CoinData,
    CoinID,
    Denom,
    Header,
    NetID,
    CoinValue,
    StakeDoc,
    Transaction,
    TxKind,
    TxHash,
};
use tip911_stakeset::{StakeSet, Tip911};
use tmelcrypt::{Ed25519SK, HashVal};

const BRIDGE_COVHASH: Address = Address(HashVal([0; 32]));

fn random_block_height(epoch: Option<u32>) -> BlockHeight {
    if let Some(epoch) = epoch {
        BlockHeight(epoch as u64 * STAKE_EPOCH + rand::thread_rng().gen_range(0..STAKE_EPOCH))
    } else {
        BlockHeight(rand::thread_rng().gen())
    }
}

fn random_coin_id() -> CoinID {
    CoinID {
        txhash: TxHash(HashVal::random()),
        index: rand::thread_rng().gen(),
    }
}

fn random_coindata() -> CoinData {
    let additional_data = (0..20)
        .map(|_| {
            rand::thread_rng().gen::<u8>()
        })
        .collect();

    CoinData {
        covhash: Address(HashVal::random()),
        value: CoinValue(rand::thread_rng().gen()),
        denom: random_denom(),
        additional_data
    }
}

fn random_denom() -> Denom {
    let denom_int = rand::thread_rng().gen_range(0..4);

    match denom_int {
        0 => Denom::Mel,
        1 => Denom::Sym,
        2 => Denom::Erg,
        _ => Denom::Custom(TxHash(HashVal::random()))
    }
}

fn random_header(block_height: Option<BlockHeight>, epoch: Option<u32>, modifier: Option<u128>) -> Header {
    let height: BlockHeight;

    if let Some(blk_height) = block_height {
        height = blk_height;
    } else if let Some(_) = epoch {
        height = random_block_height(epoch);
    } else if let Some(number) = modifier {
        height = BlockHeight(number as u64);
    } else {
        height = random_block_height(None)
    }

    if let Some(number) = modifier {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height,
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(number),
            fee_multiplier: number,
            dosc_speed: number,
            pools_hash: HashVal::random(),
            stakes_hash: HashVal::random(),
        }
    } else {
        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height,
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

fn random_stakedoc(epoch: Option<u64>) -> (StakeDoc, Ed25519SK) {
    let epoch = if let Some(epoch) = epoch {
        epoch
    } else {
        rand::thread_rng().gen()
    };

    let e_start = rand::thread_rng().gen_range(0..=epoch);
    let e_post_end: u64 = rand::thread_rng().gen_range(epoch + 1..u64::MAX);
    let keypair = Ed25519SK::generate();
    let syms_staked = CoinValue(rand::thread_rng().gen_range(0..u32::MAX as u128));

    (
        StakeDoc {
            pubkey: keypair.to_public(),
            e_start,
            e_post_end,
            syms_staked,
        },
        keypair
    )
}

fn random_stakes(num_stakedocs: u32, epoch: u64) -> (Vec<Ed25519SK>, Tip911) {
    let mut keys_and_stakes = (0..num_stakedocs)
        .into_par_iter()
        .map(|_| {
            let (stakedoc, keypair) = random_stakedoc(Some(epoch));
            let tx_hash = TxHash(HashVal::random());

            (keypair, tx_hash, stakedoc)
        })
        .collect::<Vec<(Ed25519SK, TxHash, StakeDoc)>>();

    keys_and_stakes.sort_unstable_by_key(|k| k.1);
    keys_and_stakes.sort_by_key(|k| k.2.syms_staked);

    let keys = keys_and_stakes
        .iter()
        .map(|k| k.0)
        .collect();

    let stakes: Vec<(TxHash, StakeDoc)> = keys_and_stakes
        .iter()
        .map(|k| (k.1, k.2))
        .collect();

    let stakeset = StakeSet::new(stakes.into_iter());

    (keys, stakeset.post_tip911(epoch))
}

fn random_transaction() -> Transaction {
    let limit: u32 = 32;

    let num_inputs: u32 = rand::thread_rng().gen_range(1..limit);
    let inputs = (0..num_inputs)
        .into_par_iter()
        .map(|_| {
            random_coin_id()
        })
        .collect();

    let num_outputs: u32 = rand::thread_rng().gen_range(1..limit);
    let outputs = (0..num_outputs)
        .into_par_iter()
        .map(|_| {
            random_coindata()
        })
        .collect();

    let num_covenants: u32 = rand::thread_rng().gen_range(1..limit);
    let covenants = (0..num_covenants)
        .into_par_iter()
        .map(|_| {
            let size = rand::thread_rng().gen_range(0..limit);
            let range = 0..size;
            let covenant = range
                .into_iter()
                .map(|_| {
                    rand::thread_rng().gen::<u8>()
                })
                .collect();

            covenant
        })
        .collect();

    let num_sigs: u32 = rand::thread_rng().gen_range(1..limit);
    let sigs = (0..num_sigs)
        .into_par_iter()
        .map(|_| {
            let size = rand::thread_rng().gen_range(0..limit);
            let range = 0..size;
            let sig = range
                .into_iter()
                .map(|_| {
                    rand::thread_rng().gen::<u8>()
                })
                .collect();

            sig
        })
        .collect();

    Transaction {
        kind: TxKind::Swap,
        inputs,
        outputs,
        fee: CoinValue(rand::thread_rng().gen()),
        covenants,
        data: (0..2).map(|_| { rand::thread_rng().gen::<u8>() }).collect(),
        sigs,
    }
}

fn create_datablocks(num_datablocks: u32) -> Vec<Transaction> {
    (0..num_datablocks)
        .map(|_| {
            random_transaction()
        })
        .collect::<Vec<Transaction>>()
}

fn batch_sign(data: &[u8], keys: Vec<Ed25519SK>) -> Vec<Vec<u8>> {
    let signatures = keys
        .into_par_iter()
        .map(|key| key.sign(&data))
        .collect();

    signatures
}

// differential tests
fn big_hash_differential() -> String {
    let num_stakedocs = 100;
    let epoch: u64 = rand::thread_rng().gen();
    let (_, stakes) = random_stakes(num_stakedocs, epoch);
    let tree = stakes.calculate_merkle();
    let datablocks = tree.data();
    let largest_blk = datablocks.last().unwrap();
    let big_hash = novasmt::hash_data(largest_blk);

    let tokens = [
        Token::Bytes(largest_blk.to_vec()),
        Token::FixedBytes(big_hash.to_vec())
    ];

    hex::encode(ethabi::encode(&tokens))
}

fn blake3_differential(data: Vec<u8>) -> String {
    let hash = novasmt::hash_data(&data);

    hex::encode(hash)
}

fn ed25519_differential(data: Vec<u8>) -> String {
    let keypair = Ed25519SK::generate();
    let pub_key = keypair.to_public().0;
    let signature = keypair.sign(&data);

    format!("{}{}", hex::encode(pub_key), hex::encode(signature))
}

fn decode_header_differential(modifier: u128) -> String {
    let header = random_header(None, None, Some(modifier));
    let encoded_header = header.stdcode();

    let tokens = [
        Token::Bytes(encoded_header),
        Token::Uint(header.height.0.into()),
        Token::FixedBytes(header.transactions_hash.to_vec()),
        Token::FixedBytes(header.stakes_hash.to_vec())
    ];

    hex::encode(ethabi::encode(&tokens))
}

fn decode_integer_differential(integer: u128) -> String {
    let encoded_integer = integer.stdcode();
    let encoded_integer_size = encoded_integer.len() as u128;

    let tokens = [
        Token::Bytes(encoded_integer),
        Token::Uint(encoded_integer_size.into())
    ];

    hex::encode(ethabi::encode(&tokens))
}

fn decode_transaction_differential(
    covhash: HashVal,
    value: u128,
    denom: Denom,
    recipient: ethers::abi::Address,
) -> String {
    let mut transaction = random_transaction();
    transaction.outputs[0].covhash = Address(covhash);
    transaction.outputs[0].value = CoinValue(value);
    transaction.outputs[0].denom = denom;
    transaction.outputs[0].additional_data = recipient.0.to_vec().into();

    hex::encode(transaction.stdcode())
}

fn verify_header_differential(num_stakedocs: u32) -> String {
    let epoch: u32 = rand::thread_rng().gen();
    let verifier_height = random_block_height(Some(epoch)).0;
    let header = random_header(None, Some(epoch), None).stdcode();

    let (keys, stakes) = random_stakes(num_stakedocs, epoch as u64);
    let tree = stakes.calculate_merkle();
    let dblks = tree.data();
    let dblk_idx = rand::thread_rng().gen_range(0..dblks.len());
    let dblk = dblks[dblk_idx].to_vec();
    let signatures = batch_sign(&header, keys[..=dblk_idx].to_vec());

    let datablock: (u128, u128, Vec<(TxHash, StakeDoc)>) = stdcode::deserialize(&dblk).unwrap();
    let dblk_stakes = StakeSet::new(datablock.2.into_iter());
    let dblk_votes = (0..=dblk_idx)
        .into_iter()
        .fold(0u128,|accum, idx| accum + dblk_stakes.votes(epoch as u64, keys[idx].to_public()));
    let total_votes = stakes.current_total.0;
    let enough_votes = if dblk_votes >= (total_votes * 2) / 3 { true } else { false };

    let tokens = [
        Token::Bool(enough_votes),
        Token::Bytes(header),
        Token::Uint(verifier_height.into()),
        Token::Bytes(dblk),
        Token::Array(
            signatures.iter().map(|signature| {
                let r = Token::FixedBytes(signature[0..32].to_vec());
                let s = Token::FixedBytes(signature[32..].to_vec());

                vec!(r, s)
            })
            .flatten()
            .collect()
        )
    ];

    hex::encode(ethabi::encode(&tokens))
}

fn verify_header_cross_epoch_differential(epoch: u32) -> String {
    let verifier_height = BlockHeight((epoch + 1) as u64 * STAKE_EPOCH - 1);
    let header = random_header(None, Some(epoch + 1), None).stdcode();

    let num_stakedocs = rand::thread_rng().gen_range(1..255);
    let (keys, stakes) = random_stakes(num_stakedocs, epoch as u64);
    let tree = stakes.calculate_merkle();
    let dblks = tree.data();
    let dblk_idx = rand::thread_rng().gen_range(0..dblks.len());
    let dblk = dblks[dblk_idx].to_vec();
    let signatures = batch_sign(&header, keys[..=dblk_idx].to_vec());

    let datablock: (u128, u128, Vec<(TxHash, StakeDoc)>) = stdcode::deserialize(&dblk).unwrap();
    let dblk_stakes = StakeSet::new(datablock.2.into_iter());
    let dblk_votes = (0..=dblk_idx)
        .into_iter()
        .fold(0u128,|accum, idx| accum + dblk_stakes.votes((epoch + 1) as u64, keys[idx].to_public()));
    let total_votes = stakes.next_total.0;
    let enough_votes = if dblk_votes >= (total_votes * 2) / 3 { true } else { false };

    let tokens = [
        Token::Bool(enough_votes),
        Token::Bytes(header),
        Token::Uint(verifier_height.0.into()),
        Token::Bytes(dblk),
        Token::Array(
            signatures.iter().map(|signature| {
                let r = Token::FixedBytes(signature[0..32].to_vec());
                let s = Token::FixedBytes(signature[32..].to_vec());

                vec!(r, s)
            })
            .flatten()
            .collect()
        )
    ];

    hex::encode(ethabi::encode(&tokens))
}

fn verify_stakes_differential(num_stakedocs: u32) -> String {
    let epoch = rand::thread_rng().gen();
    let (_, stakes) = random_stakes(num_stakedocs, epoch);
    let tree = stakes.calculate_merkle();
    let root = tree.root_hash();
    let dblk_idx = rand::thread_rng().gen_range(0..tree.data().len());
    let dblk = &tree.data()[dblk_idx];
    let proof = tree.proof(dblk_idx);

    let tokens = [
        Token::FixedBytes(root.into()),
        Token::Bytes(dblk.to_vec()),
        Token::Uint(dblk_idx.into()),
        Token::Array(
            proof.iter().map(|bytes32| Token::FixedBytes(bytes32.to_vec())).collect()
        )
    ];

    hex::encode(ethabi::encode(&tokens))
}

fn verify_transaction_differential(num_transactions: u32) -> String {
    let block_height = BlockHeight(rand::thread_rng().gen()).0;

    let index = rand::thread_rng().gen_range(0..num_transactions) as usize;
    let mut datablocks = create_datablocks(num_transactions);
    datablocks[index].outputs[0].covhash = BRIDGE_COVHASH;

    let tx_to_prove = datablocks
        .get(index)
        .ok_or("Unable to get tx datablock to prove.")
        .unwrap();

    let denom: HashVal  = match tx_to_prove.outputs[0].denom {
        Denom::Mel => HashVal([0; 32]),
        Denom::Sym => HashVal([0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Denom::Erg => HashVal([0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        Denom::Custom(tx_hash) => tx_hash.0,
        _ => HashVal::random()
    };

    let value = tx_to_prove
        .outputs[0]
        .value
        .0;

    let recipient = &tx_to_prove
        .outputs[0]
        .additional_data;

    let tx_bytes = tx_to_prove.stdcode();

    let datablocks_bytes = datablocks
        .clone()
        .into_par_iter()
        .map(|tx| {
            tx.stdcode()
        })
        .collect::<Vec<_>>();
    let tree = DenseMerkleTree::new(&datablocks_bytes);
    let transactions_hash = tree.root_hash().to_vec();
    let proof = &tree.proof(index);

    let tokens = [
        Token::FixedBytes(transactions_hash),
        Token::Bytes(tx_bytes),
        Token::Uint(index.into()),
        Token::Uint(block_height.into()),
        Token::Array(
            proof.iter().map(|bytes32| Token::FixedBytes(bytes32.to_vec())).collect()
        ),
        Token::Uint(denom.0.into()),
        Token::Uint(value.into()),
        Token::Address(H160(recipient.to_vec().try_into().unwrap()))
    ];

    hex::encode(ethabi::encode(&tokens))
}
fn main() {
    let cli = CLI::parse();

    match  cli.cmd {
        Subcommand::BigHash => print!("0x{}", big_hash_differential()),
        
        Subcommand::Blake3(data) => print!("0x{}", blake3_differential(hex::decode(data.bytes).unwrap())),

        Subcommand::Ed25519(data) => print!("0x{}", ed25519_differential(hex::decode(data.bytes).unwrap())),

        Subcommand::DecodeHeader(data) => print!("0x{}", decode_header_differential(data.modifier)),

        Subcommand::DecodeInteger(data) => print!("0x{}", decode_integer_differential(data.integer)),

        Subcommand::DecodeTransaction(data) => print!("0x{}", decode_transaction_differential(data.covhash, data.value, data.denom, data.recipient)),

        Subcommand::VerifyHeader(data) => print!("0x{}", verify_header_differential(data.num_stakedocs)),

        Subcommand::VerifyHeaderCrossEpoch(data) => print!("0x{}", verify_header_cross_epoch_differential(data.epoch)),

        Subcommand::VerifyStakes(data) => print!("0x{}", verify_stakes_differential(data.num_stakedocs)),

        Subcommand::VerifyTransaction(data) => print!("0x{}", verify_transaction_differential(data.num_transactions)),
    };
}