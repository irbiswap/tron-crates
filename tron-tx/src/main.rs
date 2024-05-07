mod trx;
mod error;
mod jsont;

use std::collections::HashMap;
use keys::Address;
use proto::core::TransferContract;
use crate::error::Error;

use crate::trx::TransactionHandler;

fn main() -> Result<(), Error> {
    println!("hello world");

    let sender = "TKiY3hzNNdvZq1EqzcGtZc1Za4a8NGm7RK".parse::<Address>()
        .or_else(|_| Err(Error::Runtime("wrong sender address format")))?;
        /*
        .value_of("SENDER")
        .and_then(|s| s.parse::<Address>().ok())
        .ok_or(Error::Runtime("wrong sender address format"))?;
         */
    let recipient = "TKiY3hzNNdvZq1EqzcGtZc1Za4a8NGm7RK".parse::<Address>()
        .or_else(|_| Err(Error::Runtime("wrong recipient address format")))?;
    let amount = "1";

    let transfer_contract = TransferContract {
        owner_address: sender.as_bytes().to_owned(),
        to_address: recipient.as_bytes().to_owned(),
        amount: trx::parse_amount_with_surfix(amount, "TRX", 6)?,
        ..Default::default()
    };

    TransactionHandler::handle(transfer_contract, &HashMap::new()).prepare()
}