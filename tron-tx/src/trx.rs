use std::collections::HashMap;

use chrono::Utc;
use hex::{FromHex, ToHex};
use proto::core::{Transaction, Transaction_Contract as Contract, Transaction_Contract_ContractType as ContractType,
                  Transaction_raw as TransactionRaw, TransferContract};
use protobuf::Message;
use protobuf::well_known_types::Any;
use serde_json::json;

use crate::error::Error;
use crate::jsont;

// To calculate bandwidth
pub const MAX_RESULT_SIZE_IN_TX: usize = 64;

pub fn timestamp_millis() -> i64 {
    Utc::now().timestamp_millis()
}

/// Parse command line amount to amount in pb.
#[inline]
pub fn parse_amount(amount: &str) -> Result<i64, Error> {
    if amount.is_empty() {
        return Err(Error::Runtime("can not parse empty amount"));
    }
    Ok(amount.replace("_", "").parse()?)
}

/// Parse command line amount to amount in pb.
pub fn parse_amount_with_surfix(amount: &str, surfix: &str, precision: u32) -> Result<i64, Error> {
    if amount.is_empty() {
        return Err(Error::Runtime("can not parse empty amount"));
    }
    let length = amount.as_bytes().len();
    if amount.ends_with(surfix) {
        String::from_utf8_lossy(&amount.as_bytes()[..length - 3])
            .replace("_", "")
            .parse::<i64>()
            .map(|v| v * (10 as i64).pow(precision))
            .map_err(Error::from)
    } else if surfix == "TRX" && amount.ends_with("SUN") {
        Ok(String::from_utf8_lossy(&amount.as_bytes()[..length - 3])
            .replace("_", "")
            .parse()?)
    } else {
        Ok(amount.replace("_", "").parse()?)
    }
}

#[inline]
pub fn format_amount_with_surfix(amount: i64, surfix: &str, precision: u32) -> String {
    format!("{} {}", amount as f64 / (10 as f64).powf(precision as f64), surfix)
}


pub struct TransactionHandler<'a, C> {
    contract: C,
    params: &'a HashMap<&'a str, &'a str>,
    raw_trx_fn: Option<Box<dyn FnMut(&mut TransactionRaw) -> () + 'static>>,
    txid: Option<[u8; 32]>,
    broadcasted: bool,
}

impl<'a, C: ContractPbExt> TransactionHandler<'a, C> {
    pub fn handle(contract: C, params: &'a HashMap<&'a str, &'a str>) -> Self {
        TransactionHandler {
            contract,
            params,
            raw_trx_fn: None,
            txid: None,
            broadcasted: false,
        }
    }

    pub fn map_raw_transaction<F>(&mut self, f: F) -> &mut Self
        where
            F: FnMut(&mut TransactionRaw) -> () + 'static,
    {
        self.raw_trx_fn = Some(Box::new(f));
        self
    }

    /// Extract the filled Transaction.raw
    pub fn to_raw_transaction(&mut self) -> Result<TransactionRaw, Error> {
        let params = self.params;

        // packing contract to TransactionRaw
        let any = self.contract.as_google_any()?;

        let mut contract = Contract::new();
        contract.set_field_type(self.contract.contract_type());
        contract.set_parameter(any);
        if let Some(val) = params.get("permission-id") {
            contract.set_Permission_id(val.parse()?);
        }

        let mut raw = TransactionRaw::new();
        raw.set_contract(vec![contract].into());

        if let Some(memo) = params.get("memo") {
            raw.set_data(memo.as_bytes().to_owned())
        }

        if let Some(f) = self.raw_trx_fn.as_mut() {
            f(&mut raw);
        }

        if let Some(fee_limit_amount) = params.get("fee-limit") {
            let limit = parse_amount_with_surfix(fee_limit_amount, "TRX", 6)?;
            raw.set_fee_limit(limit);
        }

        let expiration = params.get("expiration").unwrap_or(&"60").parse::<i64>()?;
        raw.set_expiration(timestamp_millis() + 1000 * expiration);

        println!("Transaction formed");

        // fill ref_block info
        //TODO: use latest ref block from service
        /*
        let ref_block = match params.get("ref-block") {
            Some(num) => {
                let mut req = NumberMessage::new();
                req.set_num(num.parse()?);
                let block = executor::block_on(
                    client::GRPC_CLIENT
                        .get_block_by_num2(Default::default(), req)
                        .drop_metadata(),
                )?;
                block
            }
            None => {
                let block = executor::block_on(
                    client::GRPC_CLIENT
                        .get_now_block2(Default::default(), Default::default())
                        .drop_metadata(),
                )?;
                block
            }
        };
        let ref_block_number = ref_block.get_block_header().get_raw_data().number;
        raw.set_ref_block_bytes(vec![
            ((ref_block_number & 0xff00) >> 8) as u8,
            (ref_block_number & 0xff) as u8,
        ]);
        raw.set_ref_block_hash(ref_block.blockid[8..16].to_owned());
        */

        raw.set_timestamp(timestamp_millis());
        Ok(raw)
    }

    /// Resume running from a Transaction.raw
    pub fn sign(&mut self, raw: TransactionRaw) -> Result<(), Error> {
        let params = self.params;

        // signature
        /*
        let txid = crypto::sha256(&raw.write_to_bytes()?);
        self.txid = Some(txid);
         */

        let mut req = Transaction::new();
        req.set_raw_data(raw);

        let mut json = serde_json::to_value(&req)?;
        jsont::fix_transaction(&mut json)?;
        json["raw_data_hex"] = json!(req.get_raw_data().write_to_bytes()?.encode_hex::<String>());
        //json["txID"] = json!(txid.encode_hex::<String>());
        println!("{:}", serde_json::to_string_pretty(&json)?);

        Ok(())

        /*
        // special signature routine for Sun-Network
        let digest = if let Some(chain_id) = unsafe { CHAIN_ID } {
            let mut raw = (&txid[..]).to_owned();
            raw.extend(Vec::from_hex(chain_id)?);
            crypto::sha256(&raw)
        } else {
            txid
        };
        let mut signatures: Vec<Vec<u8>> = Vec::new();
        if !matches.is_present("skip-sign") {
            let signature = if let Some(raw_key) = matches.value_of("private-key") {
                eprintln!("! Signing using raw private key from --private-key");
                let priv_key = raw_key.parse::<Private>()?;
                priv_key.sign_digest(&digest)?[..].to_owned()
            } else {
                let owner_address = matches
                    .value_of("account")
                    .and_then(|addr| addr.parse().ok())
                    .or_else(|| extract_owner_address_from_parameter(raw.contract[0].get_parameter()).ok())
                    .ok_or(Error::Runtime("can not determine owner address for signing"))?;
                eprintln!("! Signing using wallet key {:}", owner_address);
                sign_digest(&digest, &owner_address)?
            };
            // NOTE: signature can have arbitrary surfix.
            signatures.push(signature);
        }

        let mut req = Transaction::new();
        req.set_raw_data(raw);
        req.set_signature(signatures.into());

        eprintln!("! TX: {:}", txid.encode_hex::<String>());

        // skip-sign implies dont-broadcast
        if matches.is_present("skip-sign") || matches.is_present("dont-broadcast") {
            let mut json = serde_json::to_value(&req)?;
            jsont::fix_transaction(&mut json)?;
            json["raw_data_hex"] = json!(req.get_raw_data().write_to_bytes()?.encode_hex::<String>());
            json["txID"] = json!(txid.encode_hex::<String>());
            println!("{:}", serde_json::to_string_pretty(&json)?);

            Ok(())
        } else {
            eprintln!("! Bandwidth: {}", req.compute_size() as usize + MAX_RESULT_SIZE_IN_TX);

            let payload = executor::block_on(
                client::GRPC_CLIENT
                    .broadcast_transaction(Default::default(), req)
                    .drop_metadata(),
            )?;
            let mut result = serde_json::to_value(&payload)?;
            jsont::fix_api_return(&mut result);
            eprintln!("got => {:}", serde_json::to_string_pretty(&result)?);

            if result["result"].as_bool().unwrap_or(false) {
                self.broadcasted = true;
                Ok(())
            } else {
                Err(Error::Runtime("broadcast transaction failed!"))
            }
        }
         */
    }

    pub fn prepare(&mut self) -> Result<(), Error> {
        let raw = self.to_raw_transaction()?;
        self.sign(raw)
    }

    /*
    pub fn watch<F>(&mut self, on_success: F) -> Result<(), Error>
        where
            F: Fn(TransactionInfo) -> Result<(), Error>,
    {
        if !self.broadcasted {
            return Ok(());
        }
        if let Some(ref txid) = self.txid {
            eprintln!("! Watching ... sleep for 4 secs");
            thread::sleep(Duration::from_secs(4));
            let mut req = BytesMessage::new();
            req.set_value(txid[..].to_owned());
            let trx_info = executor::block_on(
                client::GRPC_CLIENT
                    .get_transaction_info_by_id(Default::default(), req)
                    .drop_metadata(),
            )?;
            let mut json = serde_json::to_value(&trx_info)?;
            jsont::fix_transaction_info(&mut json);

            println!("{:}", serde_json::to_string_pretty(&json)?);
            if trx_info.get_result() == TransactionInfoCode::SUCESS {
                on_success(trx_info)?;
            }
        }
        Ok(())
    }
     */
}

/// Helper trait for packing contract.
pub trait ContractPbExt: Message {
    fn contract_type(&self) -> ContractType;

    /// Convert Pb to protobuf::well_known_types::Any
    fn as_google_any(&self) -> Result<Any, protobuf::ProtobufError> {
        Ok(Any {
            type_url: format!("type.googleapis.com/protocol.{:?}", self.contract_type()),
            value: self.write_to_bytes()?,
            ..Default::default()
        })
    }
}

macro_rules! impl_contract_pb_ext_for {
    ($contract_ty:ident) => {
        impl ContractPbExt for $contract_ty {
            fn contract_type(&self) -> ContractType {
                ContractType::$contract_ty
            }
        }
    };
}


impl_contract_pb_ext_for!(TransferContract);