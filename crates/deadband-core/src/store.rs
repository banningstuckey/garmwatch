//! SQLite storage for the asset inventory, connections, and events.
//!
//! One local database file on the user's own machine — per the
//! local-first rule, nothing here syncs, phones home, or uploads.
//! In-memory databases are supported for tests and throwaway lab runs.
//!
//! Schema (Phase 0, deliberately small; later phases extend it):
//!
//! - `devices`     — one row per discovered device, keyed by IP.
//! - `connections` — one row per observed conversation, keyed by
//!   (src, dst, port, protocol).
//! - `events`      — the timestamped event log the UI and the baselines
//!   read from.

use crate::model::{Device, DeviceRole, Event, EventKind, PurdueLevel};
use crate::profile::{mix_from_str, mix_to_string, DeviceProfile, ProfileRecorder, RegisterStat};
use rusqlite::{params, Connection, OptionalExtension};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

/// Storage failures (open / schema / query).
#[derive(Debug)]
pub struct StoreError(rusqlite::Error);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> StoreError {
        StoreError(err)
    }
}

/// Result alias for storage operations.
pub type Result<T> = std::result::Result<T, StoreError>;

/// The engine's SQLite store.
pub struct Store {
    conn: Connection,
    /// Behavior profiles (feature program): aggregated in memory by
    /// the recorder, flushed to the profile tables in batches —
    /// a response per poll must not mean a write per poll.
    profiles: RefCell<ProfileRecorder>,
    /// Devices whose profiles changed since the last flush.
    profile_dirty: RefCell<HashSet<IpAddr>>,
    /// Observations since open (drives the flush cadence).
    profile_ops: Cell<u64>,
}

/// The `prev_hash` of the first chained record: a fixed marker,
/// not the hash of anything, so a verifier can recognise where a
/// chain begins (at install, or after a data clear restarts it).
pub const CHAIN_GENESIS: &str = "garmwatch-audit-chain-v1:genesis";

/// The outcome of walking the audit chain (see `Store::verify_chain`).
#[derive(Debug, Clone, PartialEq)]
pub struct ChainVerification {
    /// Every row in the events table.
    pub total_records: usize,
    /// Rows written before the chain existed (NULL hash) that sit
    /// before the chain starts. They are reported, never hidden —
    /// and never silently treated as chained.
    pub pre_chain_records: usize,
    /// Rows carrying a verified chain link.
    pub chained_records: usize,
    /// True when every chained row's fingerprint matches its
    /// content and its predecessor.
    pub ok: bool,
    /// The first record where verification failed, when it did.
    pub break_id: Option<i64>,
    /// Why verification failed, in plain language.
    pub break_reason: Option<String>,
    /// Fingerprint of the newest chained record — the anchor a
    /// filed evidence report pins down.
    pub head: Option<String>,
}

impl ChainVerification {
    /// A store with nothing chained yet (fresh install, fresh clear).
    pub fn empty() -> ChainVerification {
        ChainVerification {
            total_records: 0,
            pre_chain_records: 0,
            chained_records: 0,
            ok: true,
            break_id: None,
            break_reason: None,
            head: None,
        }
    }

    /// Verification itself could not run (a storage failure) — the
    /// report must say so rather than claim the chain is intact.
    pub fn unavailable(reason: String) -> ChainVerification {
        ChainVerification {
            total_records: 0,
            pre_chain_records: 0,
            chained_records: 0,
            ok: false,
            break_id: None,
            break_reason: Some(reason),
            head: None,
        }
    }
}

/// One record's chain fingerprint: SHA-256 over its predecessor's
/// fingerprint and the record's own stored fields, newline-joined.
/// The format is part of the evidence contract — it is written
/// down in docs/audit-evidence.md so anyone can recompute it.
fn chain_hash(
    prev_hash: &str,
    id: i64,
    timestamp: i64,
    kind: &str,
    src_ip: &str,
    dst_ip: &str,
    summary: &str,
) -> String {
    crate::sha256::sha256_hex(&format!(
        "{prev_hash}\n{id}\n{timestamp}\n{kind}\n{src_ip}\n{dst_ip}\n{summary}"
    ))
}

impl Store {
    /// Opens (creating if needed) the database at `path` and ensures
    /// the schema exists.
    pub fn open(path: impl AsRef<Path>) -> Result<Store> {
        let store = Store {
            conn: Connection::open(path)?,
            profiles: RefCell::new(ProfileRecorder::new()),
            profile_dirty: RefCell::new(HashSet::new()),
            profile_ops: Cell::new(0),
        };
        store.init_schema()?;
        store.load_profiles()?;
        Ok(store)
    }

    /// Opens a throwaway in-memory database (tests, lab demos).
    pub fn open_in_memory() -> Result<Store> {
        let store = Store {
            conn: Connection::open_in_memory()?,
            profiles: RefCell::new(ProfileRecorder::new()),
            profile_dirty: RefCell::new(HashSet::new()),
            profile_ops: Cell::new(0),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Creates the Phase 0 schema if it does not already exist.
    /// Idempotent — safe to run on every open.
    pub fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS devices (
                id         INTEGER PRIMARY KEY,
                ip         TEXT NOT NULL UNIQUE,
                mac        TEXT,
                level      TEXT,
                role       TEXT NOT NULL DEFAULT 'unknown',
                label      TEXT,
                first_seen INTEGER NOT NULL,
                last_seen  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connections (
                id           INTEGER PRIMARY KEY,
                src_ip       TEXT NOT NULL,
                dst_ip       TEXT NOT NULL,
                dst_port     INTEGER NOT NULL,
                protocol     TEXT NOT NULL DEFAULT 'unknown',
                first_seen   INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                packet_count INTEGER NOT NULL DEFAULT 0,
                byte_count   INTEGER NOT NULL DEFAULT 0,
                UNIQUE (src_ip, dst_ip, dst_port, protocol)
            );

            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                kind      TEXT NOT NULL,
                src_ip    TEXT,
                dst_ip    TEXT,
                summary   TEXT NOT NULL,
                prev_hash TEXT,
                hash      TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
            CREATE INDEX IF NOT EXISTS idx_connections_pair ON connections (src_ip, dst_ip);

            CREATE TABLE IF NOT EXISTS profile_devices (
                ip              TEXT PRIMARY KEY,
                responses       INTEGER NOT NULL DEFAULT 0,
                polls           INTEGER NOT NULL DEFAULT 0,
                interval_sum_ms INTEGER NOT NULL DEFAULT 0,
                interval_count  INTEGER NOT NULL DEFAULT 0,
                first_seen_s    INTEGER NOT NULL DEFAULT 0,
                last_seen_s     INTEGER NOT NULL DEFAULT 0,
                last_request_ms INTEGER,
                function_mix    TEXT NOT NULL DEFAULT '',
                clients         TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS quarantine (
                ip      TEXT PRIMARY KEY,
                by_user TEXT NOT NULL,
                at_s    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS profile_registers (
                ip       TEXT NOT NULL,
                function INTEGER NOT NULL,
                address  INTEGER NOT NULL,
                min_v    INTEGER NOT NULL,
                max_v    INTEGER NOT NULL,
                last_v   INTEGER NOT NULL,
                samples  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (ip, function, address)
            );
            ",
        )?;
        // Hash-chain columns (v0.3.2): databases written before the
        // chain existed gain them in place. Their existing rows keep
        // NULL hashes — verification reports them honestly as
        // pre-chain records rather than folding them in on trust.
        let has_hash: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'hash'",
            [],
            |row| row.get(0),
        )?;
        if has_hash == 0 {
            self.conn.execute_batch(
                "ALTER TABLE events ADD COLUMN prev_hash TEXT;
                 ALTER TABLE events ADD COLUMN hash TEXT;",
            )?;
        }
        Ok(())
    }

    /// Inserts a device, or refreshes `last_seen` if its IP is already
    /// known. Returns the device's row id.
    pub fn add_device(&self, device: &Device) -> Result<i64> {
        self.conn.execute(
            "
            INSERT INTO devices (ip, mac, level, role, label, first_seen, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen
            ",
            params![
                device.ip.to_string(),
                device.mac,
                device.level.map(|level| level.label()),
                device.role.as_tag(),
                device.label,
                device.first_seen,
                device.last_seen,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// All stored devices, oldest first.
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, mac, level, role, label, first_seen, last_seen
             FROM devices ORDER BY first_seen, id",
        )?;
        let rows = stmt.query_map([], |row| {
            let ip_text: String = row.get(1)?;
            let level_text: Option<String> = row.get(3)?;
            let role_text: String = row.get(4)?;
            Ok(Device {
                id: row.get(0)?,
                // IPs were written by us from IpAddr::to_string; a parse
                // failure would mean a corrupted/hand-edited database —
                // fall back to loopback rather than failing the listing.
                ip: ip_text.parse().unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1])),
                mac: row.get(2)?,
                level: level_text.as_deref().and_then(level_from_label),
                role: DeviceRole::from_tag(&role_text),
                label: row.get(5)?,
                first_seen: row.get(6)?,
                last_seen: row.get(7)?,
            })
        })?;
        let mut devices = Vec::new();
        for device in rows {
            devices.push(device?);
        }
        Ok(devices)
    }

    /// Writes a confirmed placement (level + role) for a device —
    /// the human-confirmed half of the placement inference loop.
    /// Returns false if the IP is unknown.
    pub fn update_device_placement(
        &self,
        ip: std::net::IpAddr,
        level: crate::model::PurdueLevel,
        role: crate::model::DeviceRole,
    ) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE devices SET level = ?2, role = ?3 WHERE ip = ?1",
            params![ip.to_string(), level.label(), role.as_tag()],
        )?;
        Ok(changed > 0)
    }

    /// Wipes all learned data (devices, connections, events) — the
    /// Settings "start over" path. Baselines rebuild from scratch.
    pub fn clear_all(&self) -> Result<()> {
        self.conn.execute_batch(
            "DELETE FROM events; DELETE FROM connections; DELETE FROM devices;
             DELETE FROM profile_devices; DELETE FROM profile_registers; DELETE FROM quarantine;",
        )?;
        self.profiles.borrow_mut().clear();
        self.profile_dirty.borrow_mut().clear();
        Ok(())
    }

    // ---- behavior profiles (feature program) ---------------------

    /// Feeds one parsed packet to the behavior recorder. Called for
    /// every packet the pipeline processes; the recorder ignores
    /// anything that is not Modbus. Flushes changed profiles to
    /// SQLite every 32 observations.
    pub fn record_packet_profile(&self, parsed: &crate::parse::ParsedPacket) {
        let changed = self.profiles.borrow_mut().observe(parsed);
        if let Some(ip) = changed {
            self.profile_dirty.borrow_mut().insert(ip);
            let ops = self.profile_ops.get() + 1;
            self.profile_ops.set(ops);
            if ops % 32 == 0 {
                let _ = self.flush_profiles();
            }
        }
    }

    /// One device's behavior profile, if anything has been recorded.
    pub fn device_profile(&self, ip: IpAddr) -> Option<DeviceProfile> {
        self.profiles.borrow().profile(ip).cloned()
    }

    /// How many devices have behavior profiles.
    pub fn profile_device_count(&self) -> usize {
        self.profiles.borrow().profiles().len()
    }

    /// Persists every profile changed since the last flush. Rows
    /// are rewritten per device (bounded: at most
    /// MAX_REGISTERS_PER_DEVICE register rows), so this stays cheap.
    pub fn flush_profiles(&self) -> Result<()> {
        let dirty: Vec<IpAddr> = self.profile_dirty.borrow_mut().drain().collect();
        let recorder = self.profiles.borrow();
        for ip in dirty {
            let Some(profile) = recorder.profile(ip) else { continue };
            let clients = profile
                .clients
                .iter()
                .map(|client| client.to_string())
                .collect::<Vec<_>>()
                .join(",");
            self.conn.execute(
                "INSERT INTO profile_devices (ip, responses, polls, interval_sum_ms, interval_count,
                                              first_seen_s, last_seen_s, last_request_ms, function_mix, clients)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(ip) DO UPDATE SET responses = excluded.responses, polls = excluded.polls,
                     interval_sum_ms = excluded.interval_sum_ms, interval_count = excluded.interval_count,
                     first_seen_s = excluded.first_seen_s, last_seen_s = excluded.last_seen_s,
                     last_request_ms = excluded.last_request_ms, function_mix = excluded.function_mix,
                     clients = excluded.clients",
                params![
                    ip.to_string(),
                    profile.responses as i64,
                    profile.polls as i64,
                    profile.interval_sum_ms,
                    profile.interval_count as i64,
                    profile.first_seen_s,
                    profile.last_seen_s,
                    profile.last_request_ms,
                    mix_to_string(&profile.function_mix),
                    clients,
                ],
            )?;
            self.conn.execute("DELETE FROM profile_registers WHERE ip = ?1", params![ip.to_string()])?;
            for ((function, address), stat) in &profile.registers {
                self.conn.execute(
                    "INSERT INTO profile_registers (ip, function, address, min_v, max_v, last_v, samples)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        ip.to_string(),
                        i64::from(*function),
                        i64::from(*address),
                        i64::from(stat.min),
                        i64::from(stat.max),
                        i64::from(stat.last),
                        stat.samples as i64,
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// Hydrates the recorder from the profile tables (at open).
    fn load_profiles(&self) -> Result<()> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, responses, polls, interval_sum_ms, interval_count, first_seen_s,
                    last_seen_s, last_request_ms, function_mix, clients
             FROM profile_devices",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?;
        let mut loaded: Vec<DeviceProfile> = Vec::new();
        for row in rows {
            let (ip, responses, polls, sum, count, first, last, last_req, mix, clients) = row?;
            let Ok(ip) = ip.parse::<IpAddr>() else { continue };
            let mut profile = DeviceProfile::new(ip);
            profile.responses = responses as u64;
            profile.polls = polls as u64;
            profile.interval_sum_ms = sum;
            profile.interval_count = count as u64;
            profile.first_seen_s = first;
            profile.last_seen_s = last;
            profile.last_request_ms = last_req;
            profile.function_mix = mix_from_str(&mix);
            profile.clients = clients
                .split(',')
                .filter_map(|text| text.parse::<IpAddr>().ok())
                .collect();
            loaded.push(profile);
        }
        drop(stmt);
        let mut stmt = self.conn.prepare(
            "SELECT ip, function, address, min_v, max_v, last_v, samples FROM profile_registers",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let mut registers: Vec<(String, (u8, u16), RegisterStat)> = Vec::new();
        for row in rows {
            let (ip, function, address, min, max, last, samples) = row?;
            registers.push((
                ip,
                (function as u8, address as u16),
                RegisterStat { min: min as u16, max: max as u16, last: last as u16, samples: samples as u64 },
            ));
        }
        drop(stmt);
        let mut recorder = self.profiles.borrow_mut();
        for (ip_text, key, stat) in registers {
            if let Ok(ip) = ip_text.parse::<IpAddr>() {
                if let Some(profile) = loaded.iter_mut().find(|profile| profile.ip == ip) {
                    profile.registers.insert(key, stat);
                }
            }
        }
        for profile in loaded {
            recorder.insert_loaded(profile);
        }
        Ok(())
    }

    /// Number of stored devices.
    pub fn device_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?)
    }

    /// Appends an event to the log, chained to the record before
    /// it (see `verify_chain`). Returns its row id.
    ///
    /// The fingerprint covers the row id, so it can only be
    /// computed after the insert: the row lands with its
    /// predecessor's fingerprint, then its own is set — both on
    /// this one connection, and every caller of the store writes
    /// through the app's single store lock, so the chain cannot
    /// fork.
    pub fn record_event(&self, event: &Event) -> Result<i64> {
        let kind = event_kind_tag(&event.kind);
        let src_ip = event.src_ip.map(|ip| ip.to_string());
        let dst_ip = event.dst_ip.map(|ip| ip.to_string());
        let prev_hash: String = self
            .conn
            .query_row(
                "SELECT hash FROM events WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| CHAIN_GENESIS.to_string());
        self.conn.execute(
            "INSERT INTO events (timestamp, kind, src_ip, dst_ip, summary, prev_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.timestamp,
                kind,
                src_ip,
                dst_ip,
                event.summary,
                prev_hash,
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        let hash = chain_hash(
            &prev_hash,
            id,
            event.timestamp,
            kind,
            src_ip.as_deref().unwrap_or(""),
            dst_ip.as_deref().unwrap_or(""),
            &event.summary,
        );
        self.conn.execute(
            "UPDATE events SET hash = ?1 WHERE id = ?2",
            params![hash, id],
        )?;
        Ok(id)
    }

    /// Walks the whole event log in order and checks the hash
    /// chain: every chained record's stored fingerprint must equal
    /// the recomputed one, and each record must name its actual
    /// predecessor. An edited record fails the first check; a
    /// deleted or reordered one fails the second. Records written
    /// before the chain existed are counted as pre-chain, never
    /// silently passed.
    pub fn verify_chain(&self) -> Result<ChainVerification> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, kind, src_ip, dst_ip, summary, prev_hash, hash
             FROM events ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })?;
        let mut result = ChainVerification::empty();
        let mut started = false;
        let mut expected_prev = CHAIN_GENESIS.to_string();
        for row in rows {
            let (id, timestamp, kind, src_ip, dst_ip, summary, prev_hash, hash) = row?;
            result.total_records += 1;
            let (prev_hash, hash) = match (prev_hash, hash) {
                (Some(p), Some(h)) => (p, h),
                _ => {
                    if started {
                        result.ok = false;
                        result.break_id = Some(id);
                        result.break_reason = Some(
                            "this record carries no chain fingerprint but sits after the \
                             chain started — it was written outside the chain or stripped \
                             of its fingerprint"
                                .to_string(),
                        );
                        return Ok(result);
                    }
                    result.pre_chain_records += 1;
                    continue;
                }
            };
            started = true;
            if prev_hash != expected_prev {
                result.ok = false;
                result.break_id = Some(id);
                result.break_reason = Some(
                    "this record's predecessor fingerprint does not match the record \
                     before it — a record was deleted, inserted, or reordered"
                        .to_string(),
                );
                return Ok(result);
            }
            let recomputed = chain_hash(
                &prev_hash,
                id,
                timestamp,
                &kind,
                src_ip.as_deref().unwrap_or(""),
                dst_ip.as_deref().unwrap_or(""),
                &summary,
            );
            if recomputed != hash {
                result.ok = false;
                result.break_id = Some(id);
                result.break_reason = Some(
                    "this record's content no longer matches the fingerprint taken \
                     when it was written — the record was altered"
                        .to_string(),
                );
                return Ok(result);
            }
            result.chained_records += 1;
            // The next record must name THIS record's fingerprint.
            expected_prev = hash.clone();
            result.head = Some(hash);
        }
        Ok(result)
    }

    /// Number of stored events.
    pub fn event_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?)
    }

    /// True when a device with this IP is already in the inventory.
    pub fn device_exists(&self, ip: std::net::IpAddr) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM devices WHERE ip = ?1",
            params![ip.to_string()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Records one packet against a connection: inserts the row on
    /// first sight (returns `true`), otherwise bumps packet/byte
    /// counters and `last_seen` (returns `false`).
    pub fn record_connection(&self, conn: &crate::model::Connection) -> Result<bool> {
        let existing: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM connections
             WHERE src_ip = ?1 AND dst_ip = ?2 AND dst_port = ?3 AND protocol = ?4",
            params![
                conn.src_ip.to_string(),
                conn.dst_ip.to_string(),
                conn.dst_port,
                conn.protocol.as_tag(),
            ],
            |row| row.get(0),
        )?;
        if existing > 0 {
            self.conn.execute(
                "UPDATE connections
                 SET last_seen = ?1, packet_count = packet_count + ?2,
                     byte_count = byte_count + ?3
                 WHERE src_ip = ?4 AND dst_ip = ?5 AND dst_port = ?6 AND protocol = ?7",
                params![
                    conn.last_seen,
                    conn.packet_count as i64,
                    conn.byte_count as i64,
                    conn.src_ip.to_string(),
                    conn.dst_ip.to_string(),
                    conn.dst_port,
                    conn.protocol.as_tag(),
                ],
            )?;
            return Ok(false);
        }
        self.conn.execute(
            "INSERT INTO connections
             (src_ip, dst_ip, dst_port, protocol, first_seen, last_seen, packet_count, byte_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                conn.src_ip.to_string(),
                conn.dst_ip.to_string(),
                conn.dst_port,
                conn.protocol.as_tag(),
                conn.first_seen,
                conn.last_seen,
                conn.packet_count as i64,
                conn.byte_count as i64,
            ],
        )?;
        Ok(true)
    }

    /// All stored connections, busiest first (the map's conduits).
    pub fn list_connections(&self) -> Result<Vec<crate::model::Connection>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, src_ip, dst_ip, dst_port, protocol, first_seen, last_seen,
                    packet_count, byte_count
             FROM connections ORDER BY packet_count DESC, id",
        )?;
        let rows = stmt.query_map([], |row| {
            let src_text: String = row.get(1)?;
            let dst_text: String = row.get(2)?;
            let protocol_text: String = row.get(4)?;
            Ok(crate::model::Connection {
                id: row.get(0)?,
                src_ip: src_text.parse().unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1])),
                dst_ip: dst_text.parse().unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1])),
                dst_port: row.get::<_, i64>(3)? as u16,
                protocol: crate::model::Protocol::from_tag(&protocol_text),
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
                packet_count: row.get::<_, i64>(7)? as u64,
                byte_count: row.get::<_, i64>(8)? as u64,
            })
        })?;
        let mut connections = Vec::new();
        for conn in rows {
            connections.push(conn?);
        }
        Ok(connections)
    }

    /// (writer, target) pairs that have ever written, reconstructed
    /// from stored Modbus command events — the rules layer's baseline
    /// of "who normally writes to whom" when it starts cold.
    pub fn write_pairs(&self) -> Result<Vec<(std::net::IpAddr, std::net::IpAddr)>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT src_ip, dst_ip FROM events
             WHERE kind IN ('modbus_command', 'dnp3_command') AND instr(summary, 'WRITE') > 0
               AND src_ip IS NOT NULL AND dst_ip IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            let src: String = row.get(0)?;
            let dst: String = row.get(1)?;
            Ok((src, dst))
        })?;
        let mut pairs = Vec::new();
        for row in rows {
            let (src, dst) = row?;
            if let (Ok(src), Ok(dst)) = (src.parse(), dst.parse()) {
                pairs.push((src, dst));
            }
        }
        Ok(pairs)
    }

    /// The most recent alert event, if any (the analyst's subject).
    pub fn latest_alert(&self) -> Result<Option<Event>> {
        Ok(self
            .recent_events(500)?
            .into_iter()
            .find(|event| event.kind == EventKind::AlertRaised))
    }

    /// How many alert events have been stored (the Rules view counter).
    pub fn alert_count(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE kind = 'alert_raised'",
            [],
            |row| row.get(0),
        )?)
    }

    /// Stored events matching a parsed query, newest first.
    /// The WHERE clause comes from [`crate::query::Query::to_sql`];
    /// values are always bound parameters, never interpolated.
    pub fn query_events(&self, query: &crate::query::Query, limit: i64) -> Result<Vec<Event>> {
        let (where_sql, mut params) = query.to_sql();
        params.push(rusqlite::types::Value::Integer(limit.max(1)));
        let sql = format!(
            "SELECT id, timestamp, kind, src_ip, dst_ip, summary \
             FROM events WHERE {where_sql} ORDER BY id DESC LIMIT ?"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(params.iter()),
            |row| {
                let kind_text: String = row.get(2)?;
                let src_text: Option<String> = row.get(3)?;
                let dst_text: Option<String> = row.get(4)?;
                Ok(Event {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    kind: kind_from_tag(&kind_text),
                    src_ip: src_text.as_deref().and_then(|text| text.parse().ok()),
                    dst_ip: dst_text.as_deref().and_then(|text| text.parse().ok()),
                    summary: row.get(5)?,
                })
            },
        )?;
        let mut events = Vec::new();
        for event in rows {
            events.push(event?);
        }
        Ok(events)
    }

    /// Events at or after `since_s`, newest first, capped at
    /// `limit` — the suspicion score's raw material.
    pub fn events_since(&self, since_s: i64, limit: i64) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, kind, src_ip, dst_ip, summary
             FROM events WHERE timestamp >= ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since_s, limit], |row| {
            let kind_text: String = row.get(2)?;
            let src_text: Option<String> = row.get(3)?;
            let dst_text: Option<String> = row.get(4)?;
            Ok(Event {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                kind: kind_from_tag(&kind_text),
                src_ip: src_text.as_deref().and_then(|text| text.parse().ok()),
                dst_ip: dst_text.as_deref().and_then(|text| text.parse().ok()),
                summary: row.get(5)?,
            })
        })?;
        let mut events = Vec::new();
        for event in rows {
            events.push(event?);
        }
        Ok(events)
    }

    // ---- quarantine state (feature program) ----------------------

    /// Marks a device quarantined, with who ordered it and when.
    pub fn set_quarantined(&self, ip: IpAddr, by_user: &str, at_s: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO quarantine (ip, by_user, at_s) VALUES (?1, ?2, ?3)
             ON CONFLICT(ip) DO UPDATE SET by_user = excluded.by_user, at_s = excluded.at_s",
            params![ip.to_string(), by_user, at_s],
        )?;
        Ok(())
    }

    /// Releases a device from quarantine.
    pub fn clear_quarantined(&self, ip: IpAddr) -> Result<()> {
        self.conn.execute("DELETE FROM quarantine WHERE ip = ?1", params![ip.to_string()])?;
        Ok(())
    }

    /// Every quarantined device: ip → (who ordered it, when).
    pub fn quarantined(&self) -> Result<std::collections::HashMap<IpAddr, (String, i64)>> {
        let mut stmt = self.conn.prepare("SELECT ip, by_user, at_s FROM quarantine")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?;
        let mut out = std::collections::HashMap::new();
        for row in rows {
            let (ip, user, at_s) = row?;
            if let Ok(ip) = ip.parse::<IpAddr>() {
                out.insert(ip, (user, at_s));
            }
        }
        Ok(out)
    }

    /// The most recent events, newest first (the UI's initial backlog).
    /// Kind tags are mapped back lossily — a stored Modbus event keeps
    /// its summary text, which carries the detail the log displays.
    pub fn recent_events(&self, limit: i64) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, kind, src_ip, dst_ip, summary
             FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let kind_text: String = row.get(2)?;
            let src_text: Option<String> = row.get(3)?;
            let dst_text: Option<String> = row.get(4)?;
            Ok(Event {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                kind: kind_from_tag(&kind_text),
                src_ip: src_text.as_deref().and_then(|text| text.parse().ok()),
                dst_ip: dst_text.as_deref().and_then(|text| text.parse().ok()),
                summary: row.get(5)?,
            })
        })?;
        let mut events = Vec::new();
        for event in rows {
            events.push(event?);
        }
        Ok(events)
    }
}

/// Inverse of [`event_kind_tag`], lossy for kinds that carry data
/// (their detail survives in the event summary text).
pub(crate) fn kind_from_tag(tag: &str) -> EventKind {
    match tag {
        "device_discovered" => EventKind::DeviceDiscovered,
        "connection_observed" => EventKind::ConnectionObserved,
        "modbus_command" => EventKind::ModbusCommand { function_code: 0, is_write: false },
        "dnp3_command" => EventKind::Dnp3Command { function_code: 0, is_write: false },
        "alert_raised" => EventKind::AlertRaised,
        "analyst_note" => EventKind::AnalystNote,
        "operator_action" => EventKind::OperatorAction,
        _ => EventKind::PacketObserved,
    }
}

/// Maps a stored level label ("3.5") back to a [`PurdueLevel`].
fn level_from_label(label: &str) -> Option<PurdueLevel> {
    PurdueLevel::ALL.iter().copied().find(|level| level.label() == label)
}

/// Stable storage tag for an [`EventKind`].
fn event_kind_tag(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::PacketObserved => "packet_observed",
        EventKind::DeviceDiscovered => "device_discovered",
        EventKind::ConnectionObserved => "connection_observed",
        EventKind::ModbusCommand { .. } => "modbus_command",
        EventKind::Dnp3Command { .. } => "dnp3_command",
        EventKind::AlertRaised => "alert_raised",
        EventKind::AnalystNote => "analyst_note",
        EventKind::OperatorAction => "operator_action",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn schema_init_is_idempotent() {
        let store = Store::open_in_memory().expect("open in-memory store");
        store.init_schema().expect("second init must also succeed");
        assert_eq!(store.device_count().unwrap(), 0);
        assert_eq!(store.event_count().unwrap(), 0);
    }

    #[test]
    fn devices_round_trip_with_level_and_role() {
        let store = Store::open_in_memory().unwrap();
        let mut plc = Device::new(ip(10, 0, 2, 15), 100);
        plc.level = Some(PurdueLevel::Control);
        plc.role = DeviceRole::Plc;
        plc.label = Some("Main PLC".to_string());

        store.add_device(&plc).unwrap();
        // Re-adding the same IP updates, never duplicates.
        store.add_device(&plc).unwrap();
        assert_eq!(store.device_count().unwrap(), 1);

        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].level, Some(PurdueLevel::Control));
        assert_eq!(devices[0].role, DeviceRole::Plc);
        assert_eq!(devices[0].label.as_deref(), Some("Main PLC"));
    }

    #[test]
    fn profiles_persist_across_reopen() {
        // The twin's feedstock must survive restarts: record one
        // poll round trip, flush, reopen, and the profile — values
        // included — is still there.
        let dir = std::env::temp_dir().join(format!("garmwatch-profile-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.db");
        let _ = std::fs::remove_file(&path);
        {
            let store = Store::open(&path).unwrap();
            let request = crate::sim::build_modbus_read(
                "02:db:00:00:02:0a", "02:db:00:00:01:0b",
                [10, 0, 2, 10], [10, 0, 1, 11], 40000, 1, 3, 100, 4, 7,
            );
            let response = crate::sim::build_modbus_read_response(
                "02:db:00:00:01:0b", "02:db:00:00:02:0a",
                [10, 0, 1, 11], [10, 0, 2, 10], 40000, 1, 3, &[10, 20, 30, 40], 7,
            );
            for (ts, frame) in [(1_700_000_000_000, request), (1_700_000_000_040, response)] {
                let packet = crate::source::Packet { timestamp_ms: ts, data: frame };
                let parsed = crate::parse::parse_packet(&packet).unwrap();
                store.record_packet_profile(&parsed);
            }
            store.flush_profiles().unwrap();
        }
        let store = Store::open(&path).unwrap();
        let profile = store
            .device_profile("10.0.1.11".parse::<IpAddr>().unwrap())
            .expect("profile survived reopen");
        assert_eq!(profile.responses, 1);
        assert_eq!(profile.polls, 1);
        assert_eq!(profile.registers.get(&(3, 102)).map(|stat| stat.last), Some(30));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn clear_all_wipes_everything() {
        let store = Store::open_in_memory().unwrap();
        let plc = Device::new(ip(10, 0, 2, 15), 100);
        store.add_device(&plc).unwrap();
        store
            .record_event(&Event::new(200, EventKind::DeviceDiscovered, "new device"))
            .unwrap();
        assert_eq!(store.device_count().unwrap(), 1);
        assert_eq!(store.event_count().unwrap(), 1);
        store.clear_all().unwrap();
        assert_eq!(store.device_count().unwrap(), 0);
        assert_eq!(store.event_count().unwrap(), 0);
        assert!(store.list_connections().unwrap().is_empty());
    }

    #[test]
    fn events_are_recorded_and_counted() {
        let store = Store::open_in_memory().unwrap();
        let mut event = Event::new(200, EventKind::DeviceDiscovered, "new device 10.0.2.15");
        event.src_ip = Some(ip(10, 0, 2, 15));
        store.record_event(&event).unwrap();
        store.record_event(&Event::new(201, EventKind::PacketObserved, "poll")).unwrap();
        assert_eq!(store.event_count().unwrap(), 2);
    }

    #[test]
    fn connections_upsert_and_count() {
        use crate::model::{Connection, Protocol};
        let store = Store::open_in_memory().unwrap();
        let conn = Connection {
            id: None,
            src_ip: ip(10, 0, 2, 10),
            dst_ip: ip(10, 0, 1, 11),
            dst_port: 502,
            protocol: Protocol::ModbusTcp,
            first_seen: 10,
            last_seen: 10,
            packet_count: 1,
            byte_count: 66,
        };
        assert!(store.record_connection(&conn).unwrap(), "first sight inserts");
        assert!(!store.record_connection(&conn).unwrap(), "second sight updates");
        let listed = store.list_connections().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].packet_count, 2);
        assert_eq!(listed[0].protocol, Protocol::ModbusTcp);
        let count: i64 = store
            .conn
            .query_row("SELECT packet_count FROM connections", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn recent_events_come_back_newest_first() {
        let store = Store::open_in_memory().unwrap();
        assert!(!store.device_exists(ip(10, 0, 1, 11)).unwrap());
        store.record_event(&Event::new(1, EventKind::PacketObserved, "first")).unwrap();
        store.record_event(&Event::new(2, EventKind::PacketObserved, "second")).unwrap();
        let recent = store.recent_events(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].summary, "second");
        assert_eq!(recent[1].summary, "first");
    }

    // ---- audit hash chain (v0.3.2) --------------------------------

    #[test]
    fn chain_verifies_fresh_records() {
        let store = Store::open_in_memory().unwrap();
        let mut first = Event::new(100, EventKind::DeviceDiscovered, "new device");
        first.src_ip = Some("10.0.1.11".parse().unwrap());
        store.record_event(&first).unwrap();
        store
            .record_event(&Event::new(101, EventKind::PacketObserved, "poll"))
            .unwrap();
        store
            .record_event(&Event::new(102, EventKind::OperatorAction, "Ignored actor 10.0.9.77"))
            .unwrap();
        let check = store.verify_chain().unwrap();
        assert!(check.ok, "fresh chain must verify: {:?}", check.break_reason);
        assert_eq!(check.total_records, 3);
        assert_eq!(check.chained_records, 3);
        assert_eq!(check.pre_chain_records, 0);
        let head = check.head.expect("a chained store has a head");
        assert_eq!(head.len(), 64);
        assert!(head.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn chain_detects_an_edited_record() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_event(&Event::new(100, EventKind::PacketObserved, "one"))
            .unwrap();
        let target = store
            .record_event(&Event::new(101, EventKind::AlertRaised, "an alert"))
            .unwrap();
        store
            .record_event(&Event::new(102, EventKind::PacketObserved, "three"))
            .unwrap();
        // Forge history the way an attacker with the file would.
        store
            .conn
            .execute("UPDATE events SET summary = 'nothing happened' WHERE id = ?1", params![target])
            .unwrap();
        let check = store.verify_chain().unwrap();
        assert!(!check.ok);
        assert_eq!(check.break_id, Some(target));
        assert!(check.break_reason.unwrap().contains("altered"));
    }

    #[test]
    fn chain_detects_a_deleted_record() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_event(&Event::new(100, EventKind::PacketObserved, "one"))
            .unwrap();
        let middle = store
            .record_event(&Event::new(101, EventKind::PacketObserved, "two"))
            .unwrap();
        let last = store
            .record_event(&Event::new(102, EventKind::PacketObserved, "three"))
            .unwrap();
        store
            .conn
            .execute("DELETE FROM events WHERE id = ?1", params![middle])
            .unwrap();
        let check = store.verify_chain().unwrap();
        assert!(!check.ok);
        assert_eq!(check.break_id, Some(last));
        assert!(check.break_reason.unwrap().contains("deleted"));
    }

    #[test]
    fn chain_counts_pre_chain_rows_honestly() {
        let store = Store::open_in_memory().unwrap();
        // A row written before the chain existed (no fingerprints).
        store
            .conn
            .execute(
                "INSERT INTO events (timestamp, kind, summary) VALUES (50, 'packet_observed', 'legacy')",
                [],
            )
            .unwrap();
        store
            .record_event(&Event::new(100, EventKind::PacketObserved, "one"))
            .unwrap();
        store
            .record_event(&Event::new(101, EventKind::PacketObserved, "two"))
            .unwrap();
        let check = store.verify_chain().unwrap();
        assert!(check.ok, "legacy rows before the chain are fine: {:?}", check.break_reason);
        assert_eq!(check.pre_chain_records, 1);
        assert_eq!(check.chained_records, 2);
        // The first chained record must open at the genesis marker.
        let prev: String = store
            .conn
            .query_row(
                "SELECT prev_hash FROM events WHERE hash IS NOT NULL ORDER BY id ASC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(prev, CHAIN_GENESIS);
    }

    #[test]
    fn chain_restarts_after_clear() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_event(&Event::new(100, EventKind::PacketObserved, "one"))
            .unwrap();
        store.clear_all().unwrap();
        store
            .record_event(&Event::new(200, EventKind::OperatorAction, "Stored data cleared"))
            .unwrap();
        let check = store.verify_chain().unwrap();
        assert!(check.ok);
        assert_eq!(check.total_records, 1);
        assert_eq!(check.chained_records, 1);
    }

    #[test]
    fn schema_migration_adds_chain_columns() {
        let store = Store::open_in_memory().unwrap();
        store
            .record_event(&Event::new(100, EventKind::PacketObserved, "before"))
            .unwrap();
        // Simulate a pre-chain database: drop the columns, re-open.
        store
            .conn
            .execute_batch("ALTER TABLE events DROP COLUMN prev_hash; ALTER TABLE events DROP COLUMN hash;")
            .unwrap();
        store.init_schema().unwrap();
        store
            .record_event(&Event::new(101, EventKind::PacketObserved, "after"))
            .unwrap();
        let check = store.verify_chain().unwrap();
        assert!(check.ok, "migrated store must verify: {:?}", check.break_reason);
        assert_eq!(check.pre_chain_records, 1);
        assert_eq!(check.chained_records, 1);
    }
}
