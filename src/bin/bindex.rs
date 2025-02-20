use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    thread,
    time::Instant,
};

use bindex::{address, Location, ScriptHash};

use bitcoin::consensus::deserialize;
use bitcoin_slices::{bsl, Parse};
use chrono::{TimeZone, Utc};
use clap::{Parser, ValueEnum};
use log::*;

#[derive(tabled::Tabled)]
struct Row {
    txid: String,
    time: String,
    height: String,
    offset: String,
    delta: String,
    balance: String,
    ms: String,
    bytes: String,
}

impl Row {
    fn dots() -> Self {
        let s = "...";
        Self {
            txid: s.to_owned(),
            time: s.to_owned(),
            height: s.to_owned(),
            offset: s.to_owned(),
            delta: s.to_owned(),
            balance: s.to_owned(),
            ms: s.to_owned(),
            bytes: s.to_owned(),
        }
    }
}

struct Status<'a> {
    map: HashMap<&'a bitcoin::Script, Vec<Location<'a>>>,
    locations: BTreeSet<Location<'a>>,
}

impl<'a> Status<'a> {
    fn create(
        index: &'a address::Index,
        scripts: &'a HashSet<bitcoin::ScriptBuf>,
    ) -> Result<Self, address::Error> {
        let t = std::time::Instant::now();
        let mut map = HashMap::with_capacity(scripts.len());
        let mut locations = BTreeSet::new();
        for script in scripts {
            let key = script.as_script();
            let values = index.find(key)?;
            // sort and dedup transaction locations to be analyzed
            locations.extend(values.iter());
            map.insert(key, values);
        }
        info!(
            "{} address history: {} txs ({:?})",
            map.len(),
            locations.len(),
            t.elapsed()
        );
        Ok(Self { map, locations })
    }

    fn sync_sqlite(&self, path: &Path, index: &address::Index) -> rusqlite::Result<()> {
        let t = Instant::now();
        let conn = rusqlite::Connection::open(path)?;
        conn.execute("BEGIN", [])?;

        // sync transaction history
        conn.execute(
            r"
            CREATE TABLE IF NOT EXISTS history (
                script_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                block_offset INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                PRIMARY KEY (script_hash, block_hash, block_offset)
            ) WITHOUT ROWID",
            [],
        )?;
        let mut history_rows = 0;
        let mut stmt = conn.prepare("INSERT OR IGNORE INTO history VALUES (?1, ?2, ?3, ?4)")?;
        for (script, locations) in &self.map {
            let script_hash_hex = ScriptHash::new(script).to_string();
            for loc in locations {
                let block_hash_hex = loc.indexed_header.hash().to_string();
                history_rows +=
                    stmt.execute((&script_hash_hex, &block_hash_hex, loc.offset, loc.height))?;
            }
        }

        // sync transaction cache
        conn.execute(
            r"
            CREATE TABLE IF NOT EXISTS txcache (
                block_hash TEXT NOT NULL,
                block_offset INTEGER NOT NULL,
                tx_id TEXT,
                tx_bytes BLOB,
                PRIMARY KEY (block_hash, block_offset)
            ) WITHOUT ROWID",
            [],
        )?;
        let mut txcache_rows = 0;
        let mut stmt_insert = conn
            .prepare("INSERT OR IGNORE INTO txcache(block_hash, block_offset) VALUES (?1, ?2)")?;
        let mut stmt_update = conn.prepare(
            "UPDATE txcache SET tx_bytes = ?3, tx_id = ?4 WHERE block_hash = ?1 AND block_offset = ?2",
        )?;
        for loc in &self.locations {
            let block_hash_hex = loc.indexed_header.hash().to_string();
            let inserted = stmt_insert.execute((&block_hash_hex, loc.offset))?;
            if inserted > 0 {
                // fetch transaction bytes only if needed
                let tx_bytes = index.get_tx_bytes(loc).expect("missing tx bytes");
                let parsed = bsl::Transaction::parse(&tx_bytes).expect("invalid tx");
                let txid = bitcoin::Txid::from(parsed.parsed().txid()).to_string();
                txcache_rows +=
                    stmt_update.execute((&block_hash_hex, loc.offset, tx_bytes, txid))?;
            }
        }

        conn.execute("COMMIT", [])?;
        let dt = t.elapsed();
        info!(
            "added {} history rows, {} txcache rows to {:?}, took {:?}",
            history_rows, txcache_rows, path, dt
        );
        Ok(())
    }

    fn print_history(
        &self,
        index: &address::Index,
        history_limit: usize,
    ) -> Result<(), address::Error> {
        if self.map.is_empty() {
            return Ok(());
        }
        if self.locations.is_empty() {
            return Ok(());
        }

        let t = std::time::Instant::now();
        let mut rows = Vec::with_capacity(self.locations.len());
        let mut total_bytes = 0;
        let mut unspent = HashMap::<bitcoin::OutPoint, bitcoin::Amount>::new();
        let mut balance = bitcoin::SignedAmount::ZERO;
        for loc in &self.locations {
            let t = std::time::Instant::now();
            let tx_bytes = index.get_tx_bytes(loc)?;
            total_bytes += tx_bytes.len();
            let tx: bitcoin::Transaction = deserialize(&tx_bytes).expect("bad tx bytes");
            let txid = tx.compute_txid();
            let dt = t.elapsed();
            let mut delta = bitcoin::SignedAmount::ZERO;
            for txi in tx.input {
                if let Some(spent) = unspent.remove(&txi.previous_output) {
                    delta -= spent.to_signed().expect("spent overflow");
                }
            }
            for (n, txo) in tx.output.into_iter().enumerate() {
                if self.map.contains_key(txo.script_pubkey.as_script()) {
                    delta += txo.value.to_signed().expect("txo.value overflow");
                    unspent.insert(
                        bitcoin::OutPoint::new(txid, n.try_into().unwrap()),
                        txo.value,
                    );
                }
            }
            balance += delta;
            rows.push(Row {
                txid: txid.to_string(),
                time: format!(
                    "{}",
                    Utc.timestamp_opt(loc.indexed_header.header().time.into(), 0)
                        .unwrap()
                ),
                height: loc.height.to_string(),
                offset: loc.offset.to_string(),
                delta: format!("{:+.8}", delta.to_btc()),
                balance: format!("{:.8}", balance.to_btc()),
                ms: format!("{:.3}", dt.as_micros() as f64 / 1e3),
                bytes: tx_bytes.len().to_string(),
            });
        }

        let dt = t.elapsed();
        info!(
            "fetched {} txs, {:.3} MB, balance: {}, UTXOs: {} ({:?})",
            self.locations.len(),
            total_bytes as f64 / 1e6,
            balance,
            unspent.len(),
            dt,
        );

        if history_limit > 0 {
            let is_truncated = rows.len() > history_limit;
            rows.reverse();
            rows.truncate(history_limit);
            if is_truncated {
                rows.push(Row::dots());
            }

            let mut tbl = tabled::Table::new(rows);
            tbl.with(tabled::settings::Style::rounded());
            tbl.modify(
                tabled::settings::object::Rows::new(1..),
                tabled::settings::Alignment::right(),
            );
            if is_truncated {
                tbl.modify(
                    tabled::settings::object::LastRow,
                    tabled::settings::Alignment::center(),
                );
            }
            println!("{}", tbl);
        }
        Ok(())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Network {
    Bitcoin,
    Testnet,
    Testnet4,
    Regtest,
    Signet,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
/// Bitcoin address indexer
struct Args {
    #[arg(value_enum, short = 'n', long = "network", default_value_t = Network::Bitcoin)]
    network: Network,

    #[arg(short = 'l', long = "limit", default_value_t = 100)]
    history_limit: usize,

    #[arg(short = 'a', long = "address-file")]
    address_file: Option<PathBuf>,

    #[arg(short = 's', long = "status-cache")]
    status_cache: Option<String>,
}

fn open_index(args: &Args) -> Result<address::Index, address::Error> {
    let default_rpc_port = match args.network {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Testnet4 => 48332,
        Network::Regtest => 18443,
        Network::Signet => 38332,
    };

    let default_index_dir = match args.network {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
    };

    let url = format!("http://localhost:{}", default_rpc_port);
    let db_path = format!("db/{default_index_dir}");
    info!("index DB: {}, node URL: {}", db_path, url);

    address::Index::open(db_path, url)
}

fn collect_scripts(args: &Args) -> std::io::Result<HashSet<bitcoin::ScriptBuf>> {
    let addresses = args.address_file.as_ref().map_or_else(
        || Ok(String::new()),
        |path| {
            if path == Path::new("-") {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                return Ok(buf);
            }
            std::fs::read_to_string(path)
        },
    )?;
    let scripts: HashSet<_> = addresses
        .split_whitespace()
        .map(|addr| {
            bitcoin::Address::from_str(addr)
                .unwrap()
                .assume_checked()
                .script_pubkey()
        })
        .collect();
    if let Some(path) = args.address_file.as_ref() {
        info!("watching {} addresses from {:?}", scripts.len(), path);
    }
    Ok(scripts)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    env_logger::builder().format_timestamp_micros().init();
    let status_cache = Path::new(match args.status_cache {
        Some(ref s) => s.as_str(),
        None => ":memory:",
    });

    let scripts = collect_scripts(&args)?;
    let mut index = open_index(&args)?;
    let mut updated = true;
    loop {
        while index.sync(1000)?.indexed_blocks > 0 {
            updated = true;
        }
        if updated {
            let status = Status::create(&index, &scripts)?;
            status.print_history(&index, args.history_limit)?;
            status.sync_sqlite(status_cache, &index)?;
            updated = false;
        }
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
