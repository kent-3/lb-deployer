// #![allow(unused)]

use crate::{
    constants::{CHAIN_ID, GAS_PRICE},
    SECRET,
};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use color_eyre::{
    eyre::{eyre, OptionExt},
    owo_colors::OwoColorize,
    Result,
};
use cosmwasm_std::{Addr, ContractInfo};
use prost::Message;
use regex::Regex;
use secretrs::{
    compute::{MsgExecuteContract, MsgInstantiateContract, MsgStoreCode},
    proto::{
        cosmos::{
            auth::v1beta1::{BaseAccount, QueryAccountRequest},
            base::abci::v1beta1::{TxMsgData, TxResponse},
            tx::v1beta1::BroadcastTxRequest,
        },
        secret::compute::v1beta1::{
            MsgExecuteContractResponse, MsgInstantiateContractResponse, MsgStoreCodeResponse,
            QueryByCodeIdRequest,
        },
    },
    tx::{Body, Fee, Msg, SignDoc, SignerInfo},
    AccountId, Coin,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{path::Path, str::FromStr};
use tracing::{debug, error, info, instrument};

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

// TODO: Addr validate function

// fn addr_validate(human: &str) -> Result<Addr> {
//     let source_human_address = human;
//
//     let canonical_address = match bech32::decode(source_human_address) {
//         Err(err) => {
//             debug!(
//                 "addr_validate() error while trying to decode human address {:?} as bech32: {:?}",
//                 source_human_address, err
//             );
//             return write_to_memory(instance, err.to_string().as_bytes()).map(|n| n as i32);
//         }
//         Ok((_prefix, canonical_address)) => canonical_address,
//     };
//
//     let normalized_human_address = match bech32::encode(
//         BECH32_PREFIX_ACC_ADDR, // like we do in human_address()
//         canonical_address.clone(),
//     ) {
//         Err(err) => {
//             // Assaf: IMO This can never fail. From looking at bech32::encode, it only fails
//             // because input prefix issues. For us the prefix is always "secert" which is valid.
//             debug!("addr_validate() error while trying to encode canonical address {:?} to human: {:?}",  &canonical_address, err);
//             return write_to_memory(instance, err.to_string().as_bytes()).map(|n| n as i32);
//         }
//         Ok(normalized_human_address) => normalized_human_address,
//     };
//
//     if source_human_address != normalized_human_address {
//         return write_to_memory(instance, b"Address is not normalized").map(|n| n as i32);
//     }
// }

fn block_height(metadata: tonic::metadata::MetadataMap) -> u32 {
    let http_headers = metadata.into_headers();
    let block_height_header = http_headers
        .get("x-cosmos-block-height")
        .expect("x-cosmos-block-height missing");

    let block_height_str = block_height_header
        .to_str()
        .expect("Failed to convert header value to string");

    u32::from_str(block_height_str).expect("Failed to parse block height into u32")
}

pub async fn query_account(address: impl Into<String>) -> Result<(BaseAccount, u32)> {
    let address = address.into();
    let mut auth_client = SECRET.get().unwrap().auth.clone();

    let request = QueryAccountRequest { address };
    let response = auth_client.account(request).await?;

    let (metadata, response, _) = response.into_parts();
    let block_height = block_height(metadata);

    let account = response
        .account
        .and_then(|any| any.to_msg::<BaseAccount>().ok())
        .ok_or_eyre("No account")?;

    Ok((account, block_height))
}

pub async fn store_code(path: &Path, gas: u64) -> Result<u64> {
    info!("Storing code: {}", path.display());

    let secretrs = SECRET.get().unwrap();
    let mut tx_client = secretrs.tx.clone();

    let private_key = &secretrs.wallet.signing_key();
    let public_key = private_key.public_key();
    let sender = public_key.account_id("secret")?;
    let address = sender.to_string();

    let wasm_byte_code = std::fs::read(path)?;
    let msg_store_code = MsgStoreCode {
        sender,
        wasm_byte_code,
        // TODO: set these fields
        source: None,
        builder: None,
    };

    // TODO: extract this part to a 'prepare_and_sign' function
    let (account, block_height) = query_account(address).await?;

    let chain_id = CHAIN_ID.parse()?;
    let account_number = account.account_number;
    let sequence = account.sequence;
    let memo = "";
    let timeout_height = block_height + 10;

    let gas_fee_amount = gas as u128 * GAS_PRICE / 1_000_000;
    let gas_fee = Coin {
        amount: gas_fee_amount,
        denom: "uscrt".parse()?,
    };

    let tx_body = Body::new(vec![msg_store_code.to_any()?], memo, timeout_height);
    let signer_info = SignerInfo::single_direct(Some(public_key), sequence);
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(gas_fee, gas));
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number)?;

    let tx_signed = sign_doc.sign(private_key)?;
    let tx_bytes = tx_signed.to_bytes()?;
    // EOF

    let tx_response: TxResponse = tx_client
        .broadcast_tx(BroadcastTxRequest { tx_bytes, mode: 1 })
        .await?
        .into_inner()
        .tx_response
        .expect("tx_response field missing");

    process_tx(&tx_response, None)?;

    let tx_msg_data = TxMsgData::decode(hex::decode(&tx_response.data)?.as_ref())?;

    // this approach is simplest, but assumes there is only one message in the tx
    #[allow(deprecated)] // it's not actually deprecated for Secret on cosmos SDK v0.45
    let msg_data = tx_msg_data.data.first().expect("empty data field");

    // the message was a MsgStoreCode, so the data is a MsgStoreCodeResponse
    let MsgStoreCodeResponse { code_id } = MsgStoreCodeResponse::decode(msg_data.data.as_slice())?;
    // info!("Code ID: {}", code_id.bright_white());

    let file = path.file_name().unwrap().to_string_lossy().to_string();
    info!(code_id, code = file, tx_hash = tx_response.txhash);

    Ok(code_id)

    // // this approach can find the message no matter which index it is, but only the first match
    //
    // // "/secret.compute.v1beta1.MsgStoreCodeResponse"
    // let type_url = <MsgStoreCodeResponse as Name>::type_url();
    //
    // #[allow(deprecated)] // it's not actually deprecated for Secret on cosmos SDK v0.45
    // for msg_data in tx_msg_data.data {
    //     match msg_data.msg_type.as_str() {
    //         // the message was a MsgStoreCode, so the data is a MsgStoreCodeResponse
    //         type_url => {
    //             let mut decoded =
    //                 MsgStoreCodeResponse::decode(msg_data.data.as_slice())?;
    //             let code_id = decoded.code_id;
    //             info!("Code ID => {}", code_id.bright_white());
    //             return Ok(code_id);
    //         }
    //         _ => {}
    //     }
    // }
    //
    // Err(eyre!("No code id found"))

    // another approach, effectively the same as above, but works when there are multiple MsgData
    // of the same type. collects them all into a Vec.
    // #[allow(deprecated)] // it's not actually deprecated for Secret on cosmos SDK v0.45
    // let code_id: Vec<u64> = tx_msg_data
    //     .data
    //     .into_iter()
    //     .filter_map(|msg_data| {
    //         MsgStoreCodeResponse::decode(msg_data.data.as_slice()).ok()
    //     })
    //     .map(|decoded| decoded.code_id)
    //     .collect();
}

fn extract_code_id(tx_response: &TxResponse) -> Option<u64> {
    tx_response
        .logs
        .iter()
        .flat_map(|log| &log.events)
        .flat_map(|event| &event.attributes)
        .find(|attribute| attribute.key == "code_id")
        .map(|attribute| attribute.value.clone())
        .and_then(|value| value.parse::<u64>().ok())
}

pub async fn instantiate<T: Serialize>(
    code_id: u64,
    code_hash: &str,
    init_msg: &T,
    gas: u64,
) -> Result<ContractInfo> {
    info!(
        "Instantiating code {}...\n{}",
        code_id,
        serde_json::to_string_pretty(&init_msg)?
    );

    let secretrs = SECRET.get().unwrap();
    let mut tx_client = secretrs.tx.clone();

    let private_key = &secretrs.wallet.signing_key();
    let public_key = private_key.public_key();
    let sender = public_key.account_id("secret")?;
    let address = sender.to_string();

    let label = format!("{}-{}", &sender.to_string(), code_id);

    let encrypted = secretrs.utils.encrypt(code_hash, &init_msg)?;
    let nonce = encrypted.nonce();
    let init_msg = encrypted.into_inner();

    let msg_instantiate_contract = MsgInstantiateContract {
        sender,
        admin: None,
        code_id,
        label,
        init_msg,
    };

    let (account, block_height) = query_account(address).await?;

    let chain_id = CHAIN_ID.parse()?;
    let account_number = account.account_number;
    let sequence = account.sequence;
    let memo = "";
    let timeout_height = block_height + 10;

    let gas_fee_amount = gas as u128 * GAS_PRICE / 1_000_000;
    let gas_fee = Coin {
        amount: gas_fee_amount,
        denom: "uscrt".parse()?,
    };

    let tx_body = Body::new(
        vec![msg_instantiate_contract.to_any()?],
        memo,
        timeout_height,
    );
    let signer_info = SignerInfo::single_direct(Some(public_key), sequence);
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(gas_fee, gas));
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number)?;

    let tx_signed = sign_doc.sign(private_key)?;
    let tx_bytes = tx_signed.to_bytes()?;

    let tx_response: TxResponse = tx_client
        .broadcast_tx(BroadcastTxRequest { tx_bytes, mode: 1 })
        .await?
        .into_inner()
        .tx_response
        .unwrap();

    // TODO: use nonce to decrypt response (see previous work on rsecret client)

    process_tx(&tx_response, Some(nonce))?;

    let tx_msg_data = TxMsgData::decode(hex::decode(&tx_response.data)?.as_ref())?;

    // this approach is simplest, but assumes there is only one message in the tx
    #[allow(deprecated)] // it's not actually deprecated for Secret on cosmos SDK v0.45
    let msg_data = tx_msg_data.data.first().expect("empty data field");

    // the message was a MsgInstantiateContract, so the data is a MsgInstantiateContractResponse
    let MsgInstantiateContractResponse { address, data } =
        MsgInstantiateContractResponse::decode(msg_data.data.as_slice())?;

    info!(address, code_hash, "New contract!");

    if !&data.is_empty() {
        let decrypted_bytes = secretrs.utils.decrypt(&nonce, &data)?;
        let decrypted_b64_string = String::from_utf8(decrypted_bytes)?;
        let decoded_bytes = BASE64_STANDARD.decode(decrypted_b64_string)?;
        let data = String::from_utf8(decoded_bytes)?;
        info!(data);
    }

    let contract = ContractInfo {
        address: Addr::unchecked(address),
        code_hash: code_hash.into(),
    };

    Ok(contract)
}

pub async fn execute<T: Serialize + std::fmt::Debug>(
    contract: &str,
    code_hash: &str,
    msg: &T,
    gas: u64,
) -> Result<Vec<u8>> {
    info!("Executing:\n{}", serde_json::to_string_pretty(msg)?);

    let secretrs = SECRET.get().unwrap();
    let mut tx_client = secretrs.tx.clone();

    let private_key = &secretrs.wallet.signing_key();
    let public_key = private_key.public_key();
    let sender = public_key.account_id("secret")?;
    let address = sender.to_string();

    let encrypted = secretrs.utils.encrypt(code_hash, &msg)?;
    let nonce = encrypted.nonce();
    let msg = encrypted.into_inner();

    let msg_execute_contract = MsgExecuteContract {
        sender,
        contract: AccountId::from_str(contract)?,
        msg,
        sent_funds: vec![],
    };

    let (account, block_height) = query_account(address).await?;

    let chain_id = CHAIN_ID.parse()?;
    let account_number = account.account_number;
    let sequence = account.sequence;
    let memo = "";
    let timeout_height = block_height + 10;

    let gas_fee_amount = gas as u128 * GAS_PRICE / 1_000_000;
    let gas_fee = Coin {
        amount: gas_fee_amount,
        denom: "uscrt".parse()?,
    };

    let tx_body = Body::new(vec![msg_execute_contract.to_any()?], memo, timeout_height);
    let signer_info = SignerInfo::single_direct(Some(public_key), sequence);
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(gas_fee, gas));
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number)?;

    let tx_signed = sign_doc.sign(private_key)?;
    let tx_bytes = tx_signed.to_bytes()?;

    let tx_response: TxResponse = tx_client
        .broadcast_tx(BroadcastTxRequest { tx_bytes, mode: 1 })
        .await?
        .into_inner()
        .tx_response
        .unwrap();

    // TODO: use nonce to decrypt response (see previous work on rsecret client)

    process_tx(&tx_response, Some(nonce))?;

    let tx_msg_data = TxMsgData::decode(hex::decode(&tx_response.data)?.as_ref())?;
    debug!("{:?}", tx_msg_data);

    // this approach is simplest, but assumes there is only one message in the tx
    #[allow(deprecated)] // it's not actually deprecated for Secret on cosmos SDK v0.45
    let msg_data = tx_msg_data.data.first().expect("empty data field");

    // the message was a MsgExecuteContract, so the data is a MsgExecuteContractResponse
    let MsgExecuteContractResponse { data } =
        MsgExecuteContractResponse::decode(msg_data.data.as_slice())?;

    if !data.is_empty() {
        let decrypted_bytes = secretrs.utils.decrypt(&nonce, &data)?;
        let decrypted_b64_string = String::from_utf8(decrypted_bytes)?;
        let decoded_bytes = BASE64_STANDARD.decode(decrypted_b64_string)?;
        let data = String::from_utf8(decoded_bytes)?;
        info!("data: {}", data);
        return Ok(data.into_bytes());
    }

    Ok(data)
}

pub async fn code_hash_by_code_id(code_id: u64) -> Result<String> {
    let code_hash = SECRET
        .get()
        .unwrap()
        .compute
        .clone()
        .code_hash_by_code_id(QueryByCodeIdRequest { code_id })
        .await?
        .into_inner()
        .code_hash;

    Ok(code_hash)
}

fn process_tx(tx: &TxResponse, nonce: Option<[u8; 32]>) -> Result<()> {
    debug!("{:#?}", tx);

    if tx.code != 0 {
        process_tx_error(tx, nonce);
    }

    process_gas(tx);

    Ok(())
}

fn process_tx_error(tx: &TxResponse, nonce: Option<[u8; 32]>) -> Result<()> {
    error!(tx_hash = tx.txhash, "Transaction failed");

    let re = Regex::new(r"encrypted: (.*?):").unwrap();
    let error = if let Some(caps) = re.captures(&tx.raw_log) {
        let encrypted_bytes = BASE64_STANDARD.decode(&caps[1])?;
        if let Some(nonce) = nonce {
            let decrypted_bytes = SECRET
                .get()
                .unwrap()
                .utils
                .decrypt(&nonce, &encrypted_bytes)?;
            let decrypted_string = String::from_utf8(decrypted_bytes)?;
            Err(eyre!("{}", decrypted_string))
        } else {
            Err(eyre!("{}", tx.raw_log))
        }
    } else {
        Err(eyre!("{}", tx.raw_log))
    };

    error.inspect_err(|e| error!("{e}"))
}

fn process_gas(tx: &TxResponse) {
    let gas_used = tx.gas_used;
    let gas_wanted = tx.gas_wanted;
    let ratio = (gas_used * 100) / gas_wanted;

    // TODO: refine ranges
    let colored_ratio = if ratio >= 95 {
        format!("({ratio}%)").red().to_string()
    } else if ratio > 90 && ratio < 95 {
        format!("({ratio}%)").yellow().to_string()
    } else {
        format!("({ratio}%)").green().to_string()
    };

    let recommended = (100 * gas_used) / 90;
    let rounded_recommended = if recommended < 100_000 {
        ((recommended + 9_999) / 10_000) * 10_000
    } else {
        ((recommended + 99_999) / 100_000) * 100_000
    };

    info!(
        "Gas used: {}/{} {}, Recommended: {}",
        gas_used.yellow(),
        gas_wanted.yellow(),
        colored_ratio,
        rounded_recommended.bright_blue()
    );
}

// fn extract_attributes(
//     tx_response: &TxResponse,
// ) -> (Option<String>, Option<String>, Option<String>) {
//     let mut fee: Option<String> = None;
//     let mut fee_payer: Option<String> = None;
//     let mut acc_seq: Option<String> = None;
//
//     for event in &tx_response.events {
//         for attr in &event.attributes {
//             match attr.key.as_ref() {
//                 b"fee" => fee = Some(String::from_utf8_lossy(&attr.value).to_string()),
//                 b"fee_payer" => fee_payer = Some(String::from_utf8_lossy(&attr.value).to_string()),
//                 b"acc_seq" => acc_seq = Some(String::from_utf8_lossy(&attr.value).to_string()),
//                 _ => {}
//             }
//         }
//     }
//     debug!(?fee, ?fee_payer, ?acc_seq);
//
//     (fee, fee_payer, acc_seq)
// }

// async fn prepare_and_sign() -> Result<Vec<u8>> {
//     let (account, block_height) = query_account(address).await?;
//
//     let chain_id = CHAIN_ID.parse()?;
//     let account_number = account.account_number;
//     let sequence = account.sequence;
//     let memo = "";
//     let timeout_height = block_height + 10;
//
//     let gas_fee_amount = gas as u128 * GAS_PRICE / 1_000_000;
//     let gas_fee = Coin {
//         amount: gas_fee_amount,
//         denom: "uscrt".parse()?,
//     };
//
//     let tx_body = Body::new(
//         vec![msg_instantiate_contract.to_any()?],
//         memo,
//         timeout_height,
//     );
//     let signer_info = SignerInfo::single_direct(Some(public_key), sequence);
//     let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(gas_fee, gas));
//     let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number)?;
//
//     let tx_signed = sign_doc.sign(private_key)?;
//     let tx_bytes = tx_signed.to_bytes()?;
// }
