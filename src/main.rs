use std::str::FromStr;

use blake3;
use clap::Parser;
use ed25519_compact::{
    KeyPair,
    Noise,
    Seed,
};
use novasmt::dense::DenseMerkleTree;
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
use tmelcrypt::{
    Ed25519SK,
    HashVal,
};


const BRIDGE_COVHASH: Address = Address(HashVal([0; 32]));

const DATA_BLOCK_HASH_KEY: &[u8; 13] = b"smt_datablock";
const NODE_HASH_KEY: &[u8; 8] = b"smt_node";

#[derive(Parser, Debug)]
struct Args {
    #[clap(long)]
    big_hash: bool,

    #[clap(long, default_value = "")]
    blake3: String,

    #[clap(long, default_value = "")]
    decode_header: String,

    #[clap(long, default_value = "")]
    decode_integer: String,

    #[clap(long, default_value = "")]
    decode_transaction: String,

    #[clap(long, default_value = "")]
    denom: String,

    #[clap(long, default_value = "")]
    ed25519: String,

    #[clap(long, default_value_t = 0, allow_hyphen_values = true)]
    end: isize,

    #[clap(long, default_value = "")]
    modifier: String,

    #[clap(long, default_value = "")]
    recipient: String,

    #[clap(long, default_value_t = 0)]
    start: isize,

    #[clap(long, default_value = "")]
    tx_hash: String,

    #[clap(long, default_value = "")]
    value: String,

    #[clap(long, default_value = "")]
    verify_header: String,

    #[clap(long, default_value = "")]
    verify_header_cross_epoch: String,

    #[clap(long, default_value = "")]
    verify_stakes: String,

    #[clap(long, default_value = "")]
    verify_transaction: String,
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

fn random_header(modifier: u128) -> Header {
    if modifier == 0 || modifier == u8::MAX as u128 || modifier == u16::MAX as u128 || modifier == u32::MAX as u128 ||
        modifier == u32::MAX as u128 || modifier == u64::MAX as u128 || modifier == u128::MAX {
        let block_height = if modifier > u64::MAX as u128 {
            u64::MAX
        } else {
            modifier as u64
        };

        Header {
            network: NetID::Mainnet,
            previous: HashVal::random(),
            height: BlockHeight(block_height),
            history_hash: HashVal::random(),
            coins_hash: HashVal::random(),
            transactions_hash: HashVal::random(),
            fee_pool: CoinValue(modifier),
            fee_multiplier: modifier,
            dosc_speed: modifier,
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

fn random_stakedoc(epoch: u64) -> StakeDoc {
    let e_start: u64;
    if epoch == 0 {
        e_start = 0;
    } else {
        e_start = rand::thread_rng()
            .gen_range(0..epoch);
    }

    let e_post_end: u64 = rand::thread_rng()
        .gen_range(epoch + 1..u64::MAX);

    StakeDoc {
        pubkey: Ed25519SK::generate().to_public(),
        e_start,
        e_post_end,
        syms_staked: CoinValue(rand::thread_rng().gen_range(0..u32::MAX as u128)),
    }
}

fn random_stakes(num_stakedocs: u32, epoch: u64) -> Tip911 {
    let stakes = (0..num_stakedocs)
        .into_par_iter()
        .map(|_| {
            (TxHash(HashVal::random()), random_stakedoc(epoch))
        })
        .collect::<Vec<(TxHash, StakeDoc)>>()
        .into_iter();

    let stakeset = StakeSet::new(stakes);

    stakeset.post_tip911(epoch)
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

// differential tests
fn big_hash_differential() -> String {
    let num_stakedocs = 100;
    let epoch: u64 = rand::thread_rng().gen();
    let stakes = random_stakes(num_stakedocs, epoch);
    let tree = stakes.calculate_merkle();
    let datablocks = tree.data();
    let largest_blk = datablocks.last().unwrap();

    let largest_blk_len = largest_blk.len();

    let padding_length = if largest_blk_len % 64 == 0 {
        0
    } else {
        64 - largest_blk_len % 64
    };

    let big_hash = *blake3::keyed_hash(
        blake3::hash(DATA_BLOCK_HASH_KEY).as_bytes(),
        &largest_blk,
    ).as_bytes();
    let big_hash = hex::encode(big_hash);

    let mut largest_blk_vec = largest_blk.to_vec();
    largest_blk_vec.resize(largest_blk_len + padding_length, 0);

    let encoded_blk = hex::encode(largest_blk_vec);

    format!("{:0>64x}{}{:0>64x}{}", 0x40, big_hash, largest_blk_len, encoded_blk)
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

fn decode_header_differential(modifier: u128) -> String {
    let header = random_header(modifier);
        
    let mut serialized_header = stdcode::serialize(&header)
    .unwrap();

    let serialized_header_length = serialized_header.len();

    let padding_length = if serialized_header_length % 64 == 0 {
        0
    } else {
        64 - serialized_header_length % 64
    };

    serialized_header.resize(serialized_header_length + padding_length, 0);

    format!(
        "{:0>64x}{:0>64x}{}{}{:0>64x}{:0<64}",
        0x80,
        header.height.0,
        hex::encode(header.transactions_hash),
        hex::encode(header.stakes_hash),
        serialized_header_length,
        hex::encode(serialized_header)
    )
}

fn decode_integer_differential(integer: u128) -> String {
    let encoded_integer = stdcode::serialize(&integer)
        .unwrap();

    let encoded_integer_length = encoded_integer.len() as u128;

    format!("{:0>64x}{:0>64x}{:0>64x}{:0<64}", 0x40, encoded_integer_length, encoded_integer_length, hex::encode(encoded_integer))
}

fn decode_transaction_differential(
    covhash: Address,
    value: u128,
    denom: Denom,
    recipient: String,
) -> String {
    let mut transaction = random_transaction();

    transaction.outputs[0].covhash = covhash;

    transaction.outputs[0].value = CoinValue(value);

    transaction.outputs[0].denom = denom;

    transaction.outputs[0].additional_data = hex::decode(recipient)
        .unwrap()
        .into();
    
    let serialized_transaction = stdcode::serialize(&transaction)
        .unwrap();

    hex::encode(serialized_transaction)
}

fn verify_header_differential(num_stakedocs: u32) -> String {
    let epoch: u64 = rand::thread_rng().gen_range(0..u32::MAX.into());
    let modifier: u128 = rand::thread_rng().gen();

    let mut verifier = random_header(modifier);

    let mut new_height = (epoch - 1) * STAKE_EPOCH;
    new_height += verifier.height.0 % STAKE_EPOCH;
    verifier.height = BlockHeight(new_height);

    let modifier: u128 = rand::thread_rng().gen();
    let mut header = random_header(modifier);
    header.height = verifier.height + BlockHeight(1);

    let mut header = stdcode::serialize(&header).unwrap();

    let mut epoch_syms = CoinValue(0);
    let mut next_epoch_syms = CoinValue(0);
    let mut stakes = String::new();
    let mut signatures: Vec<Vec<u8>> = vec![];

    for _ in 0..num_stakedocs {
        let mut stakedoc = random_stakedoc(epoch);
        let keypair = Ed25519SK::generate();
        stakedoc.pubkey = keypair.to_public();

        let signature = keypair.sign(&header);
        signatures.push(signature);

        epoch_syms += stakedoc.syms_staked;

        if stakedoc.e_start <= epoch + 1 && stakedoc.e_post_end > epoch + 1 {
            next_epoch_syms += stakedoc.syms_staked;
        }

        let stakedoc = hex::encode(
            stdcode::serialize(&stakedoc).unwrap()
        );
        stakes += &stakedoc;
    }

    let header_length = header.len();
    let header_padding_length = if header_length % 64 == 0 {
        0
    } else {
        64 - header_length % 64
    };

    header.resize(header_length + header_padding_length, 0);

    let header = hex::encode(header);


    let signatures_length = signatures.len();

    let mut signatures_str = String::new();
    for i in 0..signatures_length {
        signatures_str += &hex::encode(&signatures[i]);
    }

    let next_epoch_syms = hex::encode(stdcode::serialize(&next_epoch_syms).unwrap());
    stakes.insert_str(0, &next_epoch_syms);

    let epoch_syms = hex::encode(stdcode::serialize(&epoch_syms).unwrap());
    stakes.insert_str(0, &epoch_syms);

    let stakes_hash = blake3::keyed_hash(
        blake3::hash(DATA_BLOCK_HASH_KEY).as_bytes(),
        &hex::decode(&stakes).unwrap()
    );
    let stakes_hash = hex::encode(stakes_hash.as_bytes());

    let stakes_length = stakes.len();
    let stakes_padding_length = if stakes_length % 64 == 0 {
        0
    } else {
        64 - stakes_length % 64
    };

    stakes = format!(
        "{:0<width$}",
        stakes,
        width = stakes_length + stakes_padding_length
    );

    // return abi encoded: verifier's block height, verifier's stakes hash, header bytes,
    // StakeDocs array, and signatures array.
    format!(
        "{:0>64x}{}{:0>64x}{:0>64x}{:0>64x}{:0>64x}{}{:0>64x}{}{:0>64x}{}",
        verifier.height.0,
        stakes_hash,
        0xa0,
        0xc0 + header.len() / 2,
        0xe0 + header.len() / 2 + stakes.len() / 2,
        header_length,
        header,
        stakes_length / 2,
        stakes,
        signatures_length * 2,
        signatures_str
    )
}

fn verify_header_cross_epoch_differential(epoch: u64) -> String {
    let modifier: u128 = rand::thread_rng().gen();

    let mut verifier = random_header(modifier);

    let new_height = epoch * STAKE_EPOCH - 1;
    verifier.height = BlockHeight(new_height);

    let modifier: u128 = rand::thread_rng().gen();
    let mut header = random_header(modifier);
    header.height = BlockHeight(epoch * STAKE_EPOCH + rand::thread_rng().gen_range(0..200_000));

    let mut header = stdcode::serialize(&header).unwrap();

    let mut epoch_syms = CoinValue(0);
    let mut next_epoch_syms = CoinValue(0);
    let mut stakes = String::new();
    let mut signatures: Vec<Vec<u8>> = vec![];

    let num_stakedocs = rand::thread_rng().gen_range(8..100);

    for _ in 0..num_stakedocs {
        let mut stakedoc = random_stakedoc(epoch - 1);
        let keypair = Ed25519SK::generate();
        stakedoc.pubkey = keypair.to_public();

        let signature = keypair.sign(&header);
        signatures.push(signature);

        epoch_syms += stakedoc.syms_staked;

        if stakedoc.e_start <= epoch + 1 && stakedoc.e_post_end > epoch + 1 {
            next_epoch_syms += stakedoc.syms_staked;
        }

        let stakedoc = hex::encode(
            stdcode::serialize(&stakedoc).unwrap()
        );
        stakes += &stakedoc;
    }

    let header_length = header.len();
    let header_padding_length = if header_length % 64 == 0 {
        0
    } else {
        64 - header_length % 64
    };

    header.resize(header_length + header_padding_length, 0);

    let header = hex::encode(header);


    let signatures_length = signatures.len();

    let mut signatures_str = String::new();
    for i in 0..signatures_length {
        signatures_str += &hex::encode(&signatures[i]);
    }

    let next_epoch_syms = hex::encode(stdcode::serialize(&next_epoch_syms).unwrap());
    stakes.insert_str(0, &next_epoch_syms);

    let epoch_syms = hex::encode(stdcode::serialize(&epoch_syms).unwrap());
    stakes.insert_str(0, &epoch_syms);

    let stakes_hash = blake3::keyed_hash(
        blake3::hash(DATA_BLOCK_HASH_KEY).as_bytes(),
        &hex::decode(&stakes).unwrap()
    );
    let stakes_hash = hex::encode(stakes_hash.as_bytes());

    let stakes_length = stakes.len();
    let stakes_padding_length = if stakes_length % 64 == 0 {
        0
    } else {
        64 - stakes_length % 64
    };

    stakes = format!(
        "{:0<width$}",
        stakes,
        width = stakes_length + stakes_padding_length
    );

    // return abi encoded: verifier's block height, verifier's stakes hash, header bytes,
    // StakeDocs array, and signatures array.
    format!(
        "{:0>64x}{}{:0>64x}{:0>64x}{:0>64x}{:0>64x}{}{:0>64x}{}{:0>64x}{}",
        verifier.height.0,
        stakes_hash,
        0xa0,
        0xc0 + header.len() / 2,
        0xe0 + header.len() / 2 + stakes.len() / 2,
        header_length,
        header,
        stakes_length / 2,
        stakes,
        signatures_length * 2,
        signatures_str
    )
}

fn verify_stakes_differential(num_stakedocs: u32) -> String {
    let mut stakes= vec!();

    for _ in 0..num_stakedocs {
        stakes.append(
            &mut stdcode::serialize(
                &random_stakedoc(rand::thread_rng().gen())
            ).unwrap()
        );
    };

    let stakes_length = stakes.len();

    let stakes_padding_length = if stakes_length % 64 == 0 {
        0
    } else {
        64 - stakes_length % 64
    };

    let stakes_hash = *blake3::keyed_hash(
        blake3::hash(DATA_BLOCK_HASH_KEY).as_bytes(),
        &stakes
    )
    .as_bytes();
    let stakes_hash = hex::encode(stakes_hash);

    stakes.resize(stakes_length + stakes_padding_length, 0);

    let stakes = hex::encode(stakes);

    format!("{:0>64x}{}{:0>64x}{}", 0x40, stakes_hash, stakes_length,  stakes)
}

fn verify_tip911(num_stakedocs: u32) {}

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

    let mut serialized_tx = stdcode::serialize(&tx_to_prove)
        .expect("Unable to serialize tx.");

    let serialized_tx_length = serialized_tx.len();

    let tx_padding_length = if serialized_tx_length % 64 == 0 {
        0
    } else {
        64 - serialized_tx_length % 64
    };

    serialized_tx.resize(serialized_tx_length + tx_padding_length, 0);

    let serialized_tx = hex::encode(serialized_tx);

    let datablocks_serded = datablocks
        .into_par_iter()
        .map(|tx| {
            stdcode::serialize(&tx).unwrap().clone()
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

    // returns 
    // bytes32 transactionsHash,
    // bytes memory transaction,
    // uint256 txIndex,
    // uint256 blockHeight,
    // bytes32[] memory proof,
    // uint256 denom,
    // uint256 value,
    // address recipient
    format!(
        "{}{:0>64x}{:0>64x}{:0>64x}{:0>64x}{}{:0>64x}{}{:0>64x}{}{:0>64x}{}",
        root,
        0x100,
        index,
        block_height.0,
        0x120 + serialized_tx.len() / 2,
        denom,
        value,
        additional_data_formatted,
        serialized_tx_length,
        serialized_tx,
        proof.len(),
        proof_str
    )
}

fn main() {
    let args = Args::parse();

    if args.big_hash == true {
        print!("0x{}", big_hash_differential());
    } else if args.blake3.len() > 0 {
        let data = hex::decode(args.blake3.strip_prefix("0x").unwrap())
            .unwrap();

        print!("0x{}", blake3_differential(&data));
    } else if args.ed25519.len() > 0 {
        let data = hex::decode(args.ed25519.strip_prefix("0x").unwrap())
            .unwrap();

        let key_and_signature = ed25519_differential(&data);

        print!("0x{}", key_and_signature);
    } else if args.decode_header.len() > 0 {
        let modifier: u128 = args
            .decode_header
            .parse()
            .unwrap();

        let encoded_header_and_members = decode_header_differential(modifier);

        print!("0x{}", encoded_header_and_members);
    } else if args.decode_integer.len() > 0 {
        let integer: u128 = args.decode_integer
            .parse()
            .unwrap();
    
        let abi_encoded_integer_and_size = decode_integer_differential(integer);

        print!("0x{}", abi_encoded_integer_and_size);
    } else if args.decode_transaction.len() > 0 {
        let covhash = args
            .decode_transaction
            .strip_prefix("0x")
            .unwrap();
        let covhash: Address = Address(HashVal::from_str(covhash).unwrap());

        let value: u128 = args
            .value
            .parse()
            .unwrap();

        let denom: Denom = args
            .denom
            .parse()
            .unwrap();

        let recipient = args
            .recipient
            .strip_prefix("0x")
            .unwrap()
            .to_string();

        let serialized_tx = decode_transaction_differential(covhash, value, denom, recipient);

        print!("0x{}", serialized_tx);
    } else if args.verify_header.len() > 0 {
        let num_stakedocs: u32 = args
            .verify_header
            .parse()
            .unwrap();

        print!("0x{}", verify_header_differential(num_stakedocs));
    } else if args.verify_header_cross_epoch.len() > 0 {
        let epoch: u64 = args
            .verify_header_cross_epoch
            .parse()
            .unwrap();

        print!("0x{}", verify_header_cross_epoch_differential(epoch));
    } else if args.verify_stakes.len() > 0 {
        let num_stakedocs: u32 = args
            .verify_stakes
            .parse()
            .unwrap();

        print!("0x{}", verify_stakes_differential(num_stakedocs));
    } else if args.verify_transaction.len() > 0 {
        let num_transactions = args
            .verify_transaction
            .parse()
            .unwrap();

        print!("0x{}", verify_transaction_differential(num_transactions));
    } else {
        print!("0x");
    }
}