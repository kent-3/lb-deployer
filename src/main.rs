#![allow(unused)]

// .truecolor(255, 160, 10)

mod account;
mod constants;
mod support;
mod utils;

use crate::{
    account::Account,
    constants::{CHAIN_ID, GRPC_URL, MNEMONIC},
    support::snip20,
    utils::{check_gas, code_hash_by_code_id, execute, instantiate, sha256, store_code},
};
use color_eyre::{owo_colors::OwoColorize, Result};
use cosmwasm_std::{to_binary, Addr, Binary, ContractInfo, Uint128};
use lb_pair::{LbPair, RewardsDistributionAlgorithm};
use secretrs::{
    grpc_clients::{AuthQueryClient, ComputeQueryClient, RegistrationQueryClient, TxServiceClient},
    utils::EnigmaUtils,
};
use serde::{Deserialize, Serialize};
use shade_protocol::{
    contract_interfaces::liquidity_book::*, swap::core::TokenType, utils::asset::RawContract,
    Contract,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    ::color_eyre::install()?;

    let filter = EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()); // Default level for other crates
                                                                                        // .add_directive("lb_deployer=DEBUG".parse().unwrap()); // Debug level for this crate

    ::tracing_subscriber::fmt()
        .with_env_filter(filter)
        // .pretty()
        .without_time()
        .with_file(false)
        .with_line_number(false)
        .with_target(false)
        .init();

    let channel = Channel::builder(GRPC_URL.parse()?)
        .timeout(Duration::from_secs(60))
        .connect()
        .await?;
    let secretrs = setup_client(channel).await?;
    let wallet_address = secretrs.wallet.addr();

    // Store Code
    let admin = Path::new("./code/admin.wasm.gz");
    let query_auth = Path::new("./code/query_auth.wasm.gz");
    let snip20 = Path::new("./code/snip20.wasm.gz");
    let snip25 = Path::new("./code/snip25-amber.wasm.gz");
    let lb_factory = Path::new("./code/lb_factory.wasm.gz");
    let lb_pair = Path::new("./code/lb_pair.wasm.gz");
    let lb_token = Path::new("./code/lb_token.wasm.gz");
    let lb_router = Path::new("./code/lb_router.wasm.gz");
    let lb_staking = Path::new("./code/lb_staking.wasm.gz");

    let admin_code_id = store_code(admin, 1_300_000).await?;
    let query_auth_code_id = store_code(query_auth, 1_800_000).await?;
    let snip20_code_id = store_code(snip20, 1_600_000).await?;
    let snip25_code_id = store_code(snip25, 3_800_000).await?;
    let lb_factory_code_id = store_code(lb_factory, 2_500_000).await?;
    let lb_pair_code_id = store_code(lb_pair, 5_200_000).await?;
    let lb_token_code_id = store_code(lb_token, 3_300_000).await?;
    let lb_router_code_id = store_code(lb_router, 2_800_000).await?;
    let lb_staking_code_id = store_code(lb_staking, 3_800_000).await?;

    info!("Gas used to store codes: {}", check_gas());

    // TODO: hash the code directly
    let admin_code_hash = code_hash_by_code_id(admin_code_id).await?;
    let query_auth_code_hash = code_hash_by_code_id(query_auth_code_id).await?;
    let snip20_code_hash = code_hash_by_code_id(snip20_code_id).await?;
    let snip25_code_hash = code_hash_by_code_id(snip25_code_id).await?;
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

    // Make 2 Tokens

    info!("Instantiating snip20...",);
    let snip20_init_msg = snip20::InstantiateMsg {
        name: "Secret Secret".to_string(),
        admin: None,
        symbol: "SSCRT".to_string(),
        decimals: 6,
        initial_balances: Some(vec![snip20::InitialBalance {
            address: wallet_address.to_string(),
            amount: Uint128::MAX,
        }]),
        prng_seed: to_binary(b"secret_rocks")?,
        config: None,
        supported_denoms: Some(vec!["uscrt".to_string()]),
    };
    let snip20 = instantiate(snip20_code_id, &snip20_code_hash, &snip20_init_msg, 60_000).await?;

    info!("Instantiating snip25...",);
    let snip25_init_msg = snip20::InstantiateMsg {
        name: "Amber".to_string(),
        admin: None,
        symbol: "AMBER".to_string(),
        decimals: 6,
        initial_balances: Some(vec![snip20::InitialBalance {
            address: wallet_address.to_string(),
            amount: Uint128::MAX,
        }]),
        prng_seed: to_binary(b"amber_rocks")?,
        config: None,
        supported_denoms: None,
    };
    let snip25 = instantiate(snip25_code_id, &snip25_code_hash, &snip25_init_msg, 90_000).await?;

    // Factory Setup

    let address = lb_factory.address.as_str();
    let code_hash = lb_factory_code_hash.as_str();

    // Tell the Factory which codes to use when creating contracts.
    let set_lb_pair_implementation_msg = &lb_factory::ExecuteMsg::SetLbPairImplementation {
        implementation: lb_factory::ContractImplementation {
            id: lb_pair_code_id,
            code_hash: lb_pair_code_hash.to_string(),
        },
    };
    let set_lb_token_implementation_msg = &lb_factory::ExecuteMsg::SetLbTokenImplementation {
        implementation: lb_factory::ContractImplementation {
            id: lb_token_code_id,
            code_hash: lb_token_code_hash.to_string(),
        },
    };
    let set_staking_implementation_msg =
        &lb_factory::ExecuteMsg::SetStakingContractImplementation {
            implementation: lb_factory::ContractImplementation {
                id: lb_staking_code_id,
                code_hash: lb_staking_code_hash.to_string(),
            },
        };
    info!("Setting lb_pair implementation...",);
    execute(address, code_hash, set_lb_pair_implementation_msg, 80_000).await?;
    info!("Setting lb_token implementation...",);
    execute(address, code_hash, set_lb_token_implementation_msg, 80_000).await?;
    info!("Setting staking contract implementation...",);
    execute(address, code_hash, set_staking_implementation_msg, 80_000).await?;

    // TODO: determine sensible values
    let set_pair_preset_msg = &lb_factory::ExecuteMsg::SetPairPreset {
        bin_step: 100,
        base_factor: 5000,
        filter_period: 0,
        decay_period: 1,
        reduction_factor: 0,
        variable_fee_control: 0,
        protocol_share: 1000,
        max_volatility_accumulator: 350000,
        is_open: true,
        // TODO: all this staking stuff should not be here?
        total_reward_bins: 100,
        rewards_distribution_algorithm: RewardsDistributionAlgorithm::TimeBasedRewards,
        epoch_staking_index: 1,
        epoch_staking_duration: 10,
        expiry_staking_duration: Some(9),
    };
    info!("Setting pair presets for bin_step = 100...",);
    execute(address, code_hash, set_pair_preset_msg, 80_000).await?;

    let add_quote_asset_msg = &lb_factory::ExecuteMsg::AddQuoteAsset {
        asset: TokenType::CustomToken {
            contract_addr: Addr::unchecked(snip20.address.as_str()),
            token_code_hash: snip20_code_hash.to_string(),
        },
    };
    info!("Adding sSCRT as a quote asset...",);
    execute(address, code_hash, add_quote_asset_msg, 80_000).await?;

    let create_lb_pair_msg = &lb_factory::ExecuteMsg::CreateLbPair {
        token_x: TokenType::CustomToken {
            contract_addr: Addr::unchecked(snip25.address.as_str()),
            token_code_hash: snip25_code_hash.to_string(),
        },
        token_y: TokenType::CustomToken {
            contract_addr: Addr::unchecked(snip20.address.as_str()),
            token_code_hash: snip20_code_hash.to_string(),
        },
        active_id: 8_388_608,
        bin_step: 100,
        viewing_key: "lb_rocks".to_string(),
        entropy: "lb_rocks".to_string(),
    };

    info!("Creating an Lb Pair...",);
    let response = execute(address, code_hash, create_lb_pair_msg, 600_000).await?;

    let created_lb_pair = serde_json::from_slice::<LbPair>(&response)?;
    info!("{:#?}", created_lb_pair);

    let lb_pair = ContractInfo {
        address: created_lb_pair.contract.address,
        code_hash: created_lb_pair.contract.code_hash,
    };
    let lb_token = ContractInfo {
        address: Addr::unchecked(""),
        code_hash: lb_token_code_hash.to_string(),
    };
    let lb_router = ContractInfo {
        address: Addr::unchecked(""),
        code_hash: lb_router_code_hash.to_string(),
    };
    let lb_staking = ContractInfo {
        address: Addr::unchecked(""),
        code_hash: lb_staking_code_hash.to_string(),
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
        snip25: DeployedContractInfo {
            address: snip25.address,
            code_hash: snip25.code_hash,
            code_id: snip25_code_id,
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

    let out_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let serialized = serde_json::to_string(&deployment).expect("Failed to serialize deployment");
    let map_file_path = if CHAIN_ID == "pulsar-3" {
        out_dir.join("lb_contracts_pulsar.json")
    } else {
        out_dir.join("lb_contracts.json")
    };
    fs::write(&map_file_path, serialized).expect("Failed to write lb_contracts.json");

    println!("so far so good");
    println!("Total gas used: {}", check_gas());
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

    let wallet = Account::from_mnemonic(&MNEMONIC).expect("Failed to parse mnemonic");
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
    info!("Connected to {}\n", GRPC_URL);

    debug!(
        "Wallet encryption utils seed: {}",
        hex::encode(secretrs.utils.get_seed())
    );

    Ok(secretrs)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedContractInfo {
    pub address: Addr,
    pub code_hash: String,
    pub code_id: u64,
}

impl Default for DeployedContractInfo {
    fn default() -> Self {
        Self {
            address: Addr::unchecked(""),
            code_hash: "".to_string(),
            code_id: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedContracts {
    pub admin_auth: DeployedContractInfo,
    pub query_auth: DeployedContractInfo,
    pub snip20: DeployedContractInfo,
    pub snip25: DeployedContractInfo,
    pub lb_factory: DeployedContractInfo,
    pub lb_pair: DeployedContractInfo,
    pub lb_token: DeployedContractInfo,
    pub lb_router: DeployedContractInfo,
    pub lb_staking: DeployedContractInfo,
}

impl DeployedContracts {
    pub fn new() -> Self {
        DeployedContracts {
            admin_auth: DeployedContractInfo::default(),
            query_auth: DeployedContractInfo::default(),
            snip20: DeployedContractInfo::default(),
            snip25: DeployedContractInfo::default(),
            lb_factory: DeployedContractInfo::default(),
            lb_pair: DeployedContractInfo::default(),
            lb_token: DeployedContractInfo::default(),
            lb_router: DeployedContractInfo::default(),
            lb_staking: DeployedContractInfo::default(),
        }
    }
}
