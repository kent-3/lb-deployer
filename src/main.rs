#![allow(unused)]

// .truecolor(255, 160, 10)

mod account;
mod constants;
mod utils;

use crate::{
    account::Account,
    constants::{CHAIN_ID, GRPC_URL, MNEMONIC},
    utils::{code_hash_by_code_id, execute, instantiate, sha256, store_code},
};
use color_eyre::{owo_colors::OwoColorize, Result};
use cosmwasm_std::{Addr, Binary};
use secretrs::{
    grpc_clients::{AuthQueryClient, ComputeQueryClient, RegistrationQueryClient, TxServiceClient},
    proto::secret::compute::v1beta1::QueryByCodeIdRequest,
    EncryptionUtils,
};
use serde::{Deserialize, Serialize};
use shade_protocol::{
    contract_interfaces::liquidity_book::*,
    utils::{asset::RawContract, InstantiateCallback},
    Contract,
};
use std::{path::Path, sync::OnceLock};
use tonic::transport::Channel;
use tracing::{debug, info, info_span};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

#[derive(Debug)]
pub struct Secret<T> {
    pub wallet: Account,
    pub utils: EncryptionUtils,
    pub auth: AuthQueryClient<T>,
    pub compute: ComputeQueryClient<T>,
    pub tx: TxServiceClient<T>,
}

static SECRET: OnceLock<Secret<Channel>> = OnceLock::new();

// static SECRET: Lazy<Secret<Channel>> = Lazy::new(|| {
//     let channel = Channel::builder(GRPC_URL.parse().unwrap()).connect_lazy();
//
//     let wallet = Wallet::from_mnemonic(MNEMONIC).expect("bad mnemonic");
//     let seed = sha256(wallet.addr().as_bytes());
//     let utils = EncryptionUtils::from_io_key(Some(seed), DEVNET_IO_PUBKEY);
//
//     Secret {
//         wallet,
//         utils,
//         auth: AuthQueryClient::new(channel.clone()),
//         compute: ComputeQueryClient::new(channel.clone()),
//         tx: TxServiceClient::new(channel.clone()),
//     }
// });

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedContractInfo {
    pub contract_address: String,
    pub code_hash: String,
    pub code_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedContracts {
    pub admin_auth: DeployedContractInfo,
    pub query_auth: DeployedContractInfo,
    pub snip20: DeployedContractInfo,
    pub lb_factory: DeployedContractInfo,
    pub lb_pair: DeployedContractInfo,
    pub lb_token: DeployedContractInfo,
    pub lb_router: DeployedContractInfo,
    pub lb_staking: DeployedContractInfo,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    ::color_eyre::install()?;

    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into());
    ::tracing_subscriber::fmt()
        .with_env_filter(filter)
        // .pretty()
        .without_time()
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .init();

    let channel = Channel::builder(GRPC_URL.parse()?).connect().await?;
    let secretrs = setup_client(channel).await?;
    let account = secretrs.wallet.id();
    let wallet_address = secretrs.wallet.addr();

    // Store Code
    let admin = Path::new("./code/admin.wasm.gz");
    let query_auth = Path::new("./code/query_auth.wasm.gz");
    let factory = Path::new("./code/lb_factory.wasm.gz");
    let pair = Path::new("./code/lb_pair.wasm.gz");
    let token = Path::new("./code/lb_token.wasm.gz");
    let staking = Path::new("./code/lb_staking.wasm.gz");
    let router = Path::new("./code/lb_router.wasm.gz");

    let admin_code_id = store_code(admin, 1_300_000).await?;
    let query_auth_code_id = store_code(query_auth, 1_800_000).await?;
    let factory_code_id = store_code(factory, 2_400_000).await?;
    let pair_code_id = store_code(pair, 5_000_000).await?;
    let token_code_id = store_code(token, 3_200_000).await?;
    let staking_code_id = store_code(staking, 3_800_000).await?;
    let router_code_id = store_code(router, 2_800_000).await?;

    let private_key = &secretrs.wallet.signing_key();
    let public_key = private_key.public_key();
    let public_key = secretrs::tendermint::PublicKey::from_raw_secp256k1(&public_key.to_bytes());

    let admin_code_hash = code_hash_by_code_id(admin_code_id).await?;
    // Instantiate

    let admin_init_msg = shade_protocol::contract_interfaces::admin::InstantiateMsg {
        super_admin: Some(wallet_address.to_string()),
    };

    info!("Instantiating admin...",);
    let admin = instantiate(admin_code_id, &admin_code_hash, &admin_init_msg, 50_000).await?;
    // info!(admin.address, admin.code_hash, "New contract!");

    let query_auth_code_hash = secretrs
        .compute
        .clone()
        .code_hash_by_code_id(QueryByCodeIdRequest {
            code_id: query_auth_code_id,
        })
        .await?
        .into_inner()
        .code_hash;

    let query_auth_init_msg = shade_protocol::contract_interfaces::query_auth::InstantiateMsg {
        admin_auth: Contract {
            address: Addr::unchecked(admin.address.clone()),
            code_hash: admin.code_hash.clone(),
        },
        prng_seed: Binary([1u8; 32].to_vec()),
    };

    info!("Instantiating query_auth...",);
    let query_auth = instantiate(
        query_auth_code_id,
        &query_auth_code_hash,
        &query_auth_init_msg,
        60_000,
    )
    .await?;

    let factory_code_hash = secretrs
        .compute
        .clone()
        .code_hash_by_code_id(QueryByCodeIdRequest {
            code_id: factory_code_id,
        })
        .await?
        .into_inner()
        .code_hash;

    let factory_init_msg = lb_factory::InstantiateMsg {
        admin_auth: admin.clone(),
        query_auth: admin.clone(),
        owner: Some(wallet_address.clone()),
        fee_recipient: wallet_address.clone(),
        recover_staking_funds_receiver: wallet_address.clone(),
        max_bins_per_swap: None,
    };

    info!("Instantiating lb_factory...",);
    let factory = instantiate(
        factory_code_id,
        &factory_code_hash,
        &factory_init_msg,
        70_000,
    )
    .await?;
    // info!("lb_factory:\n{}", serde_json::to_string_pretty(&factory)?);

    let pair_code_hash = secretrs
        .compute
        .clone()
        .code_hash_by_code_id(QueryByCodeIdRequest {
            code_id: pair_code_id,
        })
        .await?
        .into_inner()
        .code_hash;

    let execute_msg = lb_factory::ExecuteMsg::SetLbPairImplementation {
        implementation: lb_factory::ContractImplementation {
            id: pair_code_id,
            code_hash: pair_code_hash,
        },
    };

    let response = execute(&factory.address, &factory_code_hash, &execute_msg, 80_000).await?;

    println!("so far so good");
    Ok(())
}

pub async fn setup_client(
    channel: tonic::transport::Channel,
) -> Result<&'static Secret<tonic::transport::Channel>> {
    let mut secret_registration = RegistrationQueryClient::new(channel.clone());
    let enclave_key_bytes = secret_registration.tx_key(()).await?.into_inner().key;
    let enclave_key = hex::encode(&enclave_key_bytes);
    info!("Enclave IO Public Key: {:>4}", enclave_key.bright_blue());

    let mut enclave_key = [0u8; 32];
    enclave_key.copy_from_slice(&enclave_key_bytes[0..32]);

    let wallet = Account::from_mnemonic(MNEMONIC).expect("bad mnemonic");
    let wallet_address = wallet.addr();
    // TODO: figure out a more secure seed
    let seed = sha256(wallet.addr().as_bytes());
    let utils = EncryptionUtils::from_io_key(Some(seed), enclave_key);

    let secretrs = SECRET.get_or_init(|| Secret {
        wallet,
        utils,
        auth: AuthQueryClient::new(channel.clone()),
        compute: ComputeQueryClient::new(channel.clone()),
        tx: TxServiceClient::new(channel.clone()),
    });

    info!(
        "Initialized client with wallet address: {}",
        &wallet_address
    );
    info!("Connected to {GRPC_URL}\n");

    debug!(
        "Wallet encryption utils seed: {}",
        hex::encode(secretrs.utils.get_seed())
    );

    Ok(secretrs)
}
