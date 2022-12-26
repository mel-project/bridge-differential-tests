mod cli;
use cli::{CLI, Subcommand};

use clap::Parser;
use ethers::abi::{
    ethabi::{self, Token},
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

fn batch_sign(data: Vec<u8>, keys: Vec<Ed25519SK>) -> Vec<Vec<u8>> {
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

    let largest_blk_len = largest_blk.len();

    let padding_len = if largest_blk_len % 64 == 0 {
        0
    } else {
        64 - largest_blk_len % 64
    };

    let big_hash = novasmt::hash_data(largest_blk);
    let big_hash = hex::encode(big_hash);

    let mut largest_blk_vec = largest_blk.to_vec();
    largest_blk_vec.resize(largest_blk_len + padding_len, 0);

    let encoded_blk = hex::encode(largest_blk_vec);

    format!("{:0>64x}{}{:0>64x}{}", 0x40, big_hash, largest_blk_len, encoded_blk)
}

fn blake3_differential(data: Vec<u8>) -> String {
    let hash = novasmt::hash_data(&data);

    hex::encode(hash)
}

fn ed25519_differential(data: Vec<u8>) -> String {
    let keypair = Ed25519SK::generate();
    let signature = keypair.sign(&data);

    format!("{}{}", hex::encode(keypair.to_public().0), hex::encode(signature))
}

fn decode_header_differential(modifier: u128) -> String {
    let header = random_header(None, None, Some(modifier));
        
    let mut header_bytes = header.stdcode();

    let header_bytes_len = header_bytes.len();

    let padding_len = if header_bytes_len % 64 == 0 {
        0
    } else {
        64 - header_bytes_len % 64
    };

    header_bytes.resize(header_bytes_len + padding_len, 0);

    format!(
        "{:0>64x}{:0>64x}{}{}{:0>64x}{:0<64}",
        0x80,
        header.height.0,
        hex::encode(header.transactions_hash),
        hex::encode(header.stakes_hash),
        header_bytes_len,
        hex::encode(header_bytes)
    )
}

fn decode_integer_differential(integer: u128) -> String {
    let encoded_integer = integer.stdcode();

    let encoded_integer_len = encoded_integer.len() as u128;

    format!("{:0>64x}{:0>64x}{:0>64x}{:0<64}", 0x40, encoded_integer_len, encoded_integer_len, hex::encode(encoded_integer))
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
    let signatures = batch_sign(header.stdcode(), keys);

    let datablock: (u128, u128, Vec<(TxHash, StakeDoc)>) = stdcode::deserialize(&dblk).unwrap();
    let enough_votes = if datablock.0 >= (stakes.current_total.0 * 2) / 3 { true } else { false };

    let token = [
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

    hex::encode(ethabi::encode(&token))
}

fn verify_header_cross_epoch_differential(epoch: u32) -> String {
    let verifier_height = Some(BlockHeight((epoch + 1) as u64 * STAKE_EPOCH - 1));
    let verifier = random_header(verifier_height, None, None);
    let header = random_header(None, Some(epoch + 1), None);

    let mut header_bytes = header.stdcode();

    let mut epoch_syms = CoinValue(0);
    let mut next_epoch_syms = CoinValue(0);
    let mut stakes = String::new();
    let mut signatures: Vec<Vec<u8>> = vec![];

    let num_stakedocs = rand::thread_rng().gen_range(8..100);

    for _ in 0..num_stakedocs {
        let (mut stakedoc, _) = random_stakedoc(Some((epoch - 1) as u64));
        let keypair = Ed25519SK::generate();
        stakedoc.pubkey = keypair.to_public();

        let signature = keypair.sign(&header_bytes);
        signatures.push(signature);

        epoch_syms += stakedoc.syms_staked;

        if stakedoc.e_start <= (epoch + 1) as u64 && stakedoc.e_post_end > (epoch + 1) as u64 {
            next_epoch_syms += stakedoc.syms_staked;
        }

        let stakedoc = hex::encode(
            stakedoc.stdcode()
        );
        stakes += &stakedoc;
    }

    let header_len = header_bytes.len();
    let header_padding_len = if header_len % 64 == 0 {
        0
    } else {
        64 - header_len % 64
    };

    header_bytes.resize(header_len + header_padding_len, 0);

    let header_str = hex::encode(header_bytes);


    let signatures_len = signatures.len();

    let mut signatures_str = String::new();
    for i in 0..signatures_len {
        signatures_str += &hex::encode(&signatures[i]);
    }

    let next_epoch_syms = hex::encode(next_epoch_syms.stdcode());
    stakes.insert_str(0, &next_epoch_syms);

    let epoch_syms = hex::encode(epoch_syms.stdcode());
    stakes.insert_str(0, &epoch_syms);

    let stakes_hash = novasmt::hash_data(&hex::decode(&stakes).unwrap());
    let stakes_hash = hex::encode(stakes_hash);

    let stakes_len = stakes.len();
    let stakes_padding_len = if stakes_len % 64 == 0 {
        0
    } else {
        64 - stakes_len % 64
    };

    stakes = format!(
        "{:0<width$}",
        stakes,
        width = stakes_len + stakes_padding_len
    );

    // return abi encoded: verifier's block height, verifier's stakes hash, header bytes,
    // StakeDocs array, and signatures array.
    format!(
        "{:0>64x}{}{:0>64x}{:0>64x}{:0>64x}{:0>64x}{}{:0>64x}{}{:0>64x}{}",
        verifier.height.0,
        stakes_hash,
        0xa0,
        0xc0 + header_str.len() / 2,
        0xe0 + header_str.len() / 2 + stakes.len() / 2,
        header_len,
        header_str,
        stakes_len / 2,
        stakes,
        signatures_len * 2,
        signatures_str
    )
}

fn verify_stakes_differential(num_stakedocs: u32) -> String {
    let epoch = rand::thread_rng().gen();
    let (_, stakes) = random_stakes(num_stakedocs, epoch);
    let tree = stakes.calculate_merkle();
    let root = tree.root_hash();
    let dblk_idx = rand::thread_rng().gen_range(0..tree.data().len());
    let dblk = &tree.data()[dblk_idx];
    let proof = tree.proof(dblk_idx);

    let token = [
        Token::FixedBytes(root.into()),
        Token::Bytes(dblk.to_vec()),
        Token::Uint(dblk_idx.into()),
        Token::Array(
            proof.iter().map(|bytes32| Token::FixedBytes(bytes32.to_vec())).collect()
        )
    ];

    hex::encode(ethabi::encode(&token))
}

fn verify_transaction_differential(num_transactions: u32) -> String {
    let block_height = BlockHeight(rand::thread_rng().gen());

    // create random transactions with ethereum addresses in additional_data of first output
    let mut datablocks = create_datablocks(num_transactions);

    let index: usize = rand::thread_rng()
        .gen_range(0..num_transactions)
        .try_into()
        .unwrap();

    datablocks[index].outputs[0].covhash = BRIDGE_COVHASH;

    let tx_to_prove = datablocks
        .get(index)
        .ok_or("Unable to get tx datablock to prove.")
        .unwrap();

    let denom = tx_to_prove
        .outputs[0]
        .denom;
    let denom: HashVal  = match denom {
        Denom::Mel => HashVal([0; 32]),
        Denom::Sym => HashVal([0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Denom::Erg => HashVal([0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        Denom::Custom(tx_hash) => tx_hash.0,
        _ => HashVal::random()
    };
    let denom = hex::encode(denom);

    let value: u128 = tx_to_prove
        .outputs[0]
        .value
        .into();

    let additional_data = &tx_to_prove
        .outputs[0]
        .additional_data;

    let mut additional_data_formatted: Vec<u8> = [0; 32].to_vec();

    for i in 0..20 {
        additional_data_formatted[i + 12] = additional_data[i];
    }

    let additional_data_formatted = hex::encode(additional_data_formatted);

    let mut tx_bytes = tx_to_prove.stdcode();

    let tx_bytes_len = tx_bytes.len();

    let tx_padding_len = if tx_bytes_len % 64 == 0 {
        0
    } else {
        64 - tx_bytes_len % 64
    };

    tx_bytes.resize(tx_bytes_len + tx_padding_len, 0);

    let tx_str = hex::encode(tx_bytes);

    let datablocks_serded = datablocks
        .into_par_iter()
        .map(|tx| {
            tx.stdcode()
        })
        .collect::<Vec<_>>();

    let tree = DenseMerkleTree::new(&datablocks_serded);

    let proof = &tree.proof(index);

    let mut proof_str = String::new();
    for i in 0..proof.len() {
        proof_str += &hex::encode(&proof[i])
    };

    let root = tree.root_hash();
    let root = hex::encode(root);

    format!(
        "{}{:0>64x}{:0>64x}{:0>64x}{:0>64x}{}{:0>64x}{}{:0>64x}{}{:0>64x}{}",
        root,
        0x100,
        index,
        block_height.0,
        0x120 + tx_str.len() / 2,
        denom,
        value,
        additional_data_formatted,
        tx_bytes_len,
        tx_str,
        proof.len(),
        proof_str
    )
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