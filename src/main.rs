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
use cosmwasm_std::{Addr, Binary, ContractInfo};
use secretrs::{
    // compute::ContractInfo,
    grpc_clients::{AuthQueryClient, ComputeQueryClient, RegistrationQueryClient, TxServiceClient},
    proto::secret::compute::v1beta1::QueryByCodeIdRequest,
    utils::EnigmaUtils,
};
use serde::{Deserialize, Serialize};
use shade_protocol::{contract_interfaces::liquidity_book::*, utils::asset::RawContract, Contract};
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use tonic::transport::Channel;
use tracing::{debug, info, info_span};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

#[derive(Debug)]
pub struct Secret<T> {
    pub wallet: Account,
    pub utils: EnigmaUtils,
    pub auth: AuthQueryClient<T>,
    pub compute: ComputeQueryClient<T>,
    pub tx: TxServiceClient<T>,
}

static SECRET: OnceLock<Secret<Channel>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedContractInfo {
    pub address: Addr,
    pub code_hash: String,
    pub code_id: u64,
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

impl DeployedContracts {
    pub fn new() -> Self {
        DeployedContracts {
            admin_auth: DeployedContractInfo {
                address: Addr::unchecked(""),
                code_hash: "".to_string(),
                code_id: 0,
            },
            query_auth: DeployedContractInfo {
                address: Addr::unchecked(""),
                code_hash: "".to_string(),
                code_id: 0,
            },
            snip20: DeployedContractInfo {
                address: Addr::unchecked(""),
                code_hash: "".to_string(),
                code_id: 0,
            },
            lb_factory: DeployedContractInfo {
                address: Addr::unchecked(""),
                code_hash: "".to_string(),
                code_id: 0,
            },
            lb_pair: DeployedContractInfo {
                address: Addr::unchecked(""),
                code_hash: "".to_string(),
                code_id: 0,
            },
            lb_token: DeployedContractInfo {
                address: Addr::unchecked(""),
                code_hash: "".to_string(),
                code_id: 0,
            },
            lb_router: DeployedContractInfo {
                address: Addr::unchecked(""),
                code_hash: "".to_string(),
                code_id: 0,
            },
            lb_staking: DeployedContractInfo {
                address: Addr::unchecked(""),
                code_hash: "".to_string(),
                code_id: 0,
            },
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    ::color_eyre::install()?;

    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::DEBUG.into());
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

    // TODO: After all this work, I'm not sure it's even a good idea...

    let mut deployment = DeployedContracts::new();

    let out_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let file = out_dir.join("lb_contracts.json");

    if file.exists() {
        let file_bytes = fs::read(&file)?;

        let prev_deploy = if let Ok(file_bytes) = fs::read(&file) {
            Some(serde_json::from_slice::<DeployedContracts>(&file_bytes)?)
        } else {
            None
        };

        debug!("{:#?}", prev_deploy);

        if let Some(prev_deploy) = prev_deploy {
            deployment.admin_auth = prev_deploy.admin_auth;
            deployment.query_auth = prev_deploy.query_auth;
            deployment.snip20 = prev_deploy.snip20;
        }
    }

    debug!("{:#?}", deployment);

    // Store Code
    let admin = Path::new("./code/admin.wasm.gz");
    let query_auth = Path::new("./code/query_auth.wasm.gz");
    let lb_factory = Path::new("./code/lb_factory.wasm.gz");
    let lb_pair = Path::new("./code/lb_pair.wasm.gz");
    let lb_token = Path::new("./code/lb_token.wasm.gz");
    let lb_router = Path::new("./code/lb_router.wasm.gz");
    let lb_staking = Path::new("./code/lb_staking.wasm.gz");

    let admin_code_id = store_code(admin, 1_300_000).await?;
    let query_auth_code_id = store_code(query_auth, 1_800_000).await?;
    let snip20_code_id = 0;
    let lb_factory_code_id = store_code(lb_factory, 2_400_000).await?;
    let lb_pair_code_id = store_code(lb_pair, 5_000_000).await?;
    let lb_token_code_id = store_code(lb_token, 3_200_000).await?;
    let lb_router_code_id = store_code(lb_router, 2_800_000).await?;
    let lb_staking_code_id = store_code(lb_staking, 3_800_000).await?;

    let private_key = &secretrs.wallet.signing_key();
    let public_key = private_key.public_key();
    let public_key = secretrs::tendermint::PublicKey::from_raw_secp256k1(&public_key.to_bytes());

    // TODO: hash the code directly
    let admin_code_hash = code_hash_by_code_id(admin_code_id).await?;
    let query_auth_code_hash = code_hash_by_code_id(query_auth_code_id).await?;
    let snip20_code_hash = "dummy".to_string();
    let lb_factory_code_hash = code_hash_by_code_id(lb_factory_code_id).await?;
    let lb_pair_code_hash = code_hash_by_code_id(lb_pair_code_id).await?;
    let lb_token_code_hash = code_hash_by_code_id(lb_token_code_id).await?;
    let lb_router_code_hash = code_hash_by_code_id(lb_router_code_id).await?;
    let lb_staking_code_hash = code_hash_by_code_id(lb_staking_code_id).await?;

    // Instantiate

    info!("Instantiating admin...",);
    let admin_init_msg = shade_protocol::contract_interfaces::admin::InstantiateMsg {
        super_admin: Some(wallet_address.to_string()),
    };
    let admin = instantiate(admin_code_id, &admin_code_hash, &admin_init_msg, 50_000).await?;

    info!("Instantiating query_auth...",);
    let query_auth_init_msg = shade_protocol::contract_interfaces::query_auth::InstantiateMsg {
        admin_auth: Contract {
            address: Addr::unchecked(admin.address.clone()),
            code_hash: admin.code_hash.clone(),
        },
        prng_seed: Binary([1u8; 32].to_vec()),
    };
    let query_auth = instantiate(
        query_auth_code_id,
        &query_auth_code_hash,
        &query_auth_init_msg,
        60_000,
    )
    .await?;

    info!("Instantiating lb_factory...",);
    let lb_factory_init_msg = lb_factory::InstantiateMsg {
        // TODO is it meant to be admin_auth or admin?
        admin_auth: RawContract {
            address: admin.address.to_string(),
            code_hash: admin.code_hash.to_string(),
        },
        query_auth: RawContract {
            address: query_auth.address.to_string(),
            code_hash: query_auth.code_hash.to_string(),
        },
        owner: Some(wallet_address.clone()),
        fee_recipient: wallet_address.clone(),
        recover_staking_funds_receiver: wallet_address.clone(),
        max_bins_per_swap: None,
    };
    let lb_factory = instantiate(
        lb_factory_code_id,
        &lb_factory_code_hash,
        &lb_factory_init_msg,
        70_000,
    )
    .await?;

    let execute_msg = lb_factory::ExecuteMsg::SetLbPairImplementation {
        implementation: lb_factory::ContractImplementation {
            id: lb_pair_code_id,
            code_hash: lb_pair_code_hash.to_string(),
        },
    };

    let set_lb_pair_implementation_response = execute(
        lb_factory.address.as_str(),
        &lb_factory_code_hash,
        &execute_msg,
        80_000,
    )
    .await?;

    let snip20 = ContractInfo {
        address: Addr::unchecked("dummy"),
        code_hash: "dummy".to_string(),
    };
    let lb_pair = ContractInfo {
        address: Addr::unchecked("dummy"),
        code_hash: "dummy".to_string(),
    };
    let lb_token = ContractInfo {
        address: Addr::unchecked("dummy"),
        code_hash: "dummy".to_string(),
    };
    let lb_router = ContractInfo {
        address: Addr::unchecked("dummy"),
        code_hash: "dummy".to_string(),
    };
    let lb_staking = ContractInfo {
        address: Addr::unchecked("dummy"),
        code_hash: "dummy".to_string(),
    };

    let deployment = DeployedContracts {
        admin_auth: DeployedContractInfo {
            address: admin.address,
            code_hash: admin.code_hash,
            code_id: admin_code_id,
        },
        query_auth: DeployedContractInfo {
            address: query_auth.address,
            code_hash: query_auth.code_hash,
            code_id: query_auth_code_id,
        },
        snip20: DeployedContractInfo {
            address: snip20.address,
            code_hash: snip20.code_hash,
            code_id: snip20_code_id,
        },
        lb_factory: DeployedContractInfo {
            address: lb_factory.address,
            code_hash: lb_factory.code_hash,
            code_id: lb_factory_code_id,
        },
        lb_pair: DeployedContractInfo {
            address: lb_pair.address,
            code_hash: lb_pair.code_hash,
            code_id: lb_pair_code_id,
        },
        lb_token: DeployedContractInfo {
            address: lb_token.address,
            code_hash: lb_token.code_hash,
            code_id: lb_token_code_id,
        },
        lb_router: DeployedContractInfo {
            address: lb_router.address,
            code_hash: lb_router.code_hash,
            code_id: lb_router_code_id,
        },
        lb_staking: DeployedContractInfo {
            address: lb_staking.address,
            code_hash: lb_staking.code_hash,
            code_id: lb_staking_code_id,
        },
    };

    debug!("{:#?}", deployment);

    // TODO: Serialize the DeployedContracts and write to a file.

    let out_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let serialized = serde_json::to_string(&deployment).expect("Failed to serialize deployment");
    let map_file_path = out_dir.join("lb_contracts.json");
    fs::write(&map_file_path, serialized).expect("Failed to write sf_token_map.json");

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
    let utils = EnigmaUtils::from_io_key(Some(seed), enclave_key);

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
