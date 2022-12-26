use clap::{Args, Parser};
use ethers;
use serde::{Deserialize};
use themelio_structs::Denom;
use tmelcrypt::HashVal;

#[derive(Clone, Deserialize, Debug, Parser)]
pub struct CLI {
    #[command(subcommand)]
    pub cmd: Subcommand,
}

#[derive(Clone, Debug, Deserialize, clap::Subcommand)]
pub enum Subcommand {
    BigHash,
    Blake3(Blake3Data),
    DecodeHeader(DecodeHeaderData),
    DecodeInteger(DecodeIntegerData),
    DecodeTransaction(DecodeTransactionData),
    Ed25519(Ed25519Data),
    VerifyHeader(VerifyHeaderData),
    VerifyHeaderCrossEpoch(VerifyHeaderCrossEpochData),
    VerifyStakes(VerifyStakesData),
    VerifyTransaction(VerifyTransactionData),
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct BigHashData {}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct Blake3Data {
    #[clap(long)]
    pub bytes: String,
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct DecodeHeaderData {
    #[clap(long)]
    pub modifier: u128,
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct DecodeIntegerData {
    #[clap(long)]
    pub integer: u128,
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct DecodeTransactionData {
    #[clap(long)]
    pub covhash: HashVal,

    #[clap(long)]
    pub value: u128,

    #[clap(long)]
    pub denom: Denom,

    #[clap(long)]
    pub recipient: ethers::abi::Address,
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct Ed25519Data {
    #[clap(long)]
    pub bytes: String,
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct VerifyHeaderData {
    #[clap(long)]
    pub num_stakedocs: u32
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct VerifyHeaderCrossEpochData {
    #[clap(long)]
    pub epoch: u32
}

#[derive(Args, Clone, Debug, Deserialize)]
pub struct VerifyStakesData {
    #[clap(long)]
    pub num_stakedocs: u32
}
#[derive(Args, Clone, Debug, Deserialize)]
pub struct VerifyTransactionData {
    #[clap(long)]
    pub num_transactions: u32
}