// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! Ethcore client application.

#![warn(missing_docs)]

extern crate ansi_term;
extern crate docopt;
#[macro_use]
extern crate clap;
extern crate dir;
extern crate env_logger;
extern crate futures;
extern crate futures_cpupool;
extern crate atty;
extern crate jsonrpc_core;
extern crate num_cpus;
extern crate number_prefix;
extern crate parking_lot;
extern crate regex;
extern crate rlp;
extern crate rpassword;
extern crate rustc_hex;
extern crate semver;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate toml;

extern crate ethcore;
extern crate ethcore_bytes as bytes;
extern crate ethcore_io as io;
extern crate ethcore_light as light;
extern crate ethcore_logger;
extern crate ethcore_miner as miner;
extern crate ethcore_network as network;
extern crate ethcore_private_tx;
extern crate ethcore_service;
extern crate ethcore_sync as sync;
extern crate ethcore_transaction as transaction;
extern crate ethereum_types;
extern crate ethkey;
extern crate kvdb;
extern crate node_health;
extern crate panic_hook;
extern crate parity_hash_fetch as hash_fetch;
extern crate parity_ipfs_api;
extern crate parity_local_store as local_store;
extern crate parity_reactor;
extern crate parity_rpc;
extern crate parity_updater as updater;
extern crate parity_version;
extern crate parity_whisper;
extern crate path;
extern crate rpc_cli;
extern crate node_filter;
extern crate keccak_hash as hash;
extern crate journaldb;
extern crate registrar;

#[macro_use]
extern crate log as rlog;

#[cfg(feature="secretstore")]
extern crate ethcore_secretstore;

#[cfg(feature = "dapps")]
extern crate parity_dapps;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[cfg(windows)] extern crate winapi;

#[cfg(test)]
extern crate tempdir;

mod account;
mod blockchain;
mod cache;
mod cli;
mod configuration;
mod dapps;
mod export_hardcoded_sync;
mod ipfs;
mod deprecated;
mod helpers;
mod informant;
mod light_helpers;
mod modules;
mod params;
mod presale;
mod rpc;
mod rpc_apis;
mod run;
mod secretstore;
mod signer;
mod snapshot;
mod upgrade;
mod url;
mod user_defaults;
mod whisper;
mod db;

use std::net::{TcpListener};
use std::io::BufReader;
use std::fs::File;
use ansi_term::Style;
use hash::keccak_buffer;
use cli::Args;
use configuration::{Cmd, Execute};
use deprecated::find_deprecated;
use ethcore_logger::{Config as LogConfig, setup_log};

pub use self::configuration::Configuration;
pub use self::run::RunningClient;

fn print_hash_of(maybe_file: Option<String>) -> Result<String, String> {
	if let Some(file) = maybe_file {
		let mut f = BufReader::new(File::open(&file).map_err(|_| "Unable to open file".to_owned())?);
		let hash = keccak_buffer(&mut f).map_err(|_| "Unable to read from file".to_owned())?;
		Ok(format!("{:x}", hash))
	} else {
		Err("Streaming from standard input not yet supported. Specify a file.".to_owned())
	}
}

/// Action that Parity performed when running `start`.
pub enum ExecutionAction {
	/// The execution didn't require starting a node, and thus has finished.
	/// Contains the string to print on stdout, if any.
	Instant(Option<String>),

	/// The client has started running and must be shut down manually by calling `shutdown`.
	///
	/// If you don't call `shutdown()`, execution will continue in the background.
	Running(RunningClient),
}

fn execute<Cr, Rr>(command: Execute, on_client_rq: Cr, on_updater_rq: Rr) -> Result<ExecutionAction, String>
	where Cr: Fn(String) + 'static + Send,
		  Rr: Fn() + 'static + Send
{
	// TODO: move this to `main()` and expose in the C API so that users can setup logging the way
	// 		they want
	let logger = setup_log(&command.logger).expect("Logger is initialized only once; qed");

	match command.cmd {
		Cmd::Run(run_cmd) => {
			if run_cmd.ui_conf.enabled && !run_cmd.ui_conf.info_page_only {
				warn!("{}", Style::new().bold().paint("Parity browser interface is deprecated. It's going to be removed in the next version, use standalone Parity UI instead."));
				warn!("{}", Style::new().bold().paint("Standalone Parity UI: https://github.com/Parity-JS/shell/releases"));
			}

			if run_cmd.ui && run_cmd.dapps_conf.enabled {
				// Check if Parity is already running
				let addr = format!("{}:{}", run_cmd.ui_conf.interface, run_cmd.ui_conf.port);
				if !TcpListener::bind(&addr as &str).is_ok() {
					return open_ui(&run_cmd.ws_conf, &run_cmd.ui_conf, &run_cmd.logger_config).map(|_| ExecutionAction::Instant(None));
				}
			}

			// start ui
			if run_cmd.ui {
				open_ui(&run_cmd.ws_conf, &run_cmd.ui_conf, &run_cmd.logger_config)?;
			}

			if let Some(ref dapp) = run_cmd.dapp {
				open_dapp(&run_cmd.dapps_conf, &run_cmd.http_conf, dapp)?;
			}

			let outcome = run::execute(run_cmd, logger, on_client_rq, on_updater_rq)?;
			Ok(ExecutionAction::Running(outcome))
		},
		Cmd::Version => Ok(ExecutionAction::Instant(Some(Args::print_version()))),
		Cmd::Hash(maybe_file) => print_hash_of(maybe_file).map(|s| ExecutionAction::Instant(Some(s))),
		Cmd::Account(account_cmd) => account::execute(account_cmd).map(|s| ExecutionAction::Instant(Some(s))),
		Cmd::ImportPresaleWallet(presale_cmd) => presale::execute(presale_cmd).map(|s| ExecutionAction::Instant(Some(s))),
		Cmd::Blockchain(blockchain_cmd) => blockchain::execute(blockchain_cmd).map(|_| ExecutionAction::Instant(None)),
		Cmd::SignerToken(ws_conf, ui_conf, logger_config) => signer::execute(ws_conf, ui_conf, logger_config).map(|s| ExecutionAction::Instant(Some(s))),
		Cmd::SignerSign { id, pwfile, port, authfile } => rpc_cli::signer_sign(id, pwfile, port, authfile).map(|s| ExecutionAction::Instant(Some(s))),
		Cmd::SignerList { port, authfile } => rpc_cli::signer_list(port, authfile).map(|s| ExecutionAction::Instant(Some(s))),
		Cmd::SignerReject { id, port, authfile } => rpc_cli::signer_reject(id, port, authfile).map(|s| ExecutionAction::Instant(Some(s))),
		Cmd::Snapshot(snapshot_cmd) => snapshot::execute(snapshot_cmd).map(|s| ExecutionAction::Instant(Some(s))),
		Cmd::ExportHardcodedSync(export_hs_cmd) => export_hardcoded_sync::execute(export_hs_cmd).map(|s| ExecutionAction::Instant(Some(s))),
	}
}

/// Starts the parity client.
///
/// `on_client_rq` is the action to perform when the client receives an RPC request to be restarted
/// with a different chain.
///
/// `on_updater_rq` is the action to perform when the updater has a new binary to execute.
///
/// The first parameter is the command line arguments that you would pass when running the parity
/// binary.
///
/// On error, returns what to print on stderr.
pub fn start<Cr, Rr>(conf: Configuration, on_client_rq: Cr, on_updater_rq: Rr) -> Result<ExecutionAction, String>
	where Cr: Fn(String) + 'static + Send,
			Rr: Fn() + 'static + Send
{
	let deprecated = find_deprecated(&conf.args);
	for d in deprecated {
		println!("{}", d);
	}

	execute(conf.into_command()?, on_client_rq, on_updater_rq)
}

fn open_ui(ws_conf: &rpc::WsConfiguration, ui_conf: &rpc::UiConfiguration, logger_config: &LogConfig) -> Result<(), String> {
	if !ui_conf.enabled {
		return Err("Cannot use UI command with UI turned off.".into())
	}

	let token = signer::generate_token_and_url(ws_conf, ui_conf, logger_config)?;
	// Open a browser
	url::open(&token.url).map_err(|e| format!("{}", e))?;
	// Print a message
	println!("{}", token.message);
	Ok(())
}

fn open_dapp(dapps_conf: &dapps::Configuration, rpc_conf: &rpc::HttpConfiguration, dapp: &str) -> Result<(), String> {
	if !dapps_conf.enabled {
		return Err("Cannot use DAPP command with Dapps turned off.".into())
	}

	let url = format!("http://{}:{}/{}/", rpc_conf.interface, rpc_conf.port, dapp);
	url::open(&url).map_err(|e| format!("{}", e))?;
	Ok(())
}
