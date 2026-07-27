use std::env;
use std::net::{IpAddr, Ipv4Addr};

const MIN_CONFIGURED_PEERS: usize = 3;
const MAX_CONFIGURED_PEERS: usize = 512;
const MIN_CONFIGURED_CONNECTIONS: usize = 10;
const MAX_CONFIGURED_CONNECTIONS: usize = 4096;
const MIN_SHRED_SIZE: usize = 1024;
const MAX_SHRED_SIZE: usize = 1024 * 1024;
const MIN_ERASURE_SHARDS: usize = 1;
const MAX_ERASURE_SHARDS: usize = 128;
const MAX_ERASURE_PARITY: usize = 128;
const MAX_ERASURE_TOTAL_SHARDS: usize = 256;

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub port: u16,
    pub bind_ip: IpAddr,
    pub max_peers: usize,
    pub max_connections: usize,
    pub seed_nodes: Vec<String>,
    pub velocity_enabled: bool,
    pub max_shred_size: usize,
    pub erasure_shards: usize,
    pub erasure_parity: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            port: 7177,
            bind_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            max_peers: 50,
            max_connections: 200,
            seed_nodes: Vec::new(),
            velocity_enabled: false,
            max_shred_size: 32 * 1024, // 32KB
            erasure_shards: 16,
            erasure_parity: 4,
        }
    }
}

impl NetworkConfig {
    fn clamp_usize(value: usize, min: usize, max: usize) -> usize {
        value.max(min).min(max)
    }

    fn normalize_runtime_limits(&mut self) {
        self.max_peers =
            Self::clamp_usize(self.max_peers, MIN_CONFIGURED_PEERS, MAX_CONFIGURED_PEERS);
        self.max_connections = Self::clamp_usize(
            self.max_connections,
            self.max_peers.max(MIN_CONFIGURED_CONNECTIONS),
            MAX_CONFIGURED_CONNECTIONS,
        );
        self.max_shred_size =
            Self::clamp_usize(self.max_shred_size, MIN_SHRED_SIZE, MAX_SHRED_SIZE);
        self.erasure_shards =
            Self::clamp_usize(self.erasure_shards, MIN_ERASURE_SHARDS, MAX_ERASURE_SHARDS);
        self.erasure_parity = self.erasure_parity.min(MAX_ERASURE_PARITY);

        let total_erasure_shards = self.erasure_shards.saturating_add(self.erasure_parity);
        if total_erasure_shards > MAX_ERASURE_TOTAL_SHARDS {
            self.erasure_parity = MAX_ERASURE_TOTAL_SHARDS.saturating_sub(self.erasure_shards);
        }
    }

    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(port) = env::var("ALPHANUMERIC_PORT") {
            match port.trim().parse::<u16>() {
                // This arm does NOT assign, so the default port stands. Say that,
                // rather than claiming an ephemeral bind that never happens.
                Ok(0) => eprintln!(
                    "WARNING: ALPHANUMERIC_PORT='0' is not a usable listen port; ignoring it and using {}.",
                    config.port
                ),
                Ok(p) => config.port = p,
                // Mirror BIND_IP below: warn loudly instead of silently swallowing a bad value,
                // so an operator whose override was ignored actually finds out.
                Err(_) => eprintln!(
                    "WARNING: ALPHANUMERIC_PORT='{}' is not a valid port; ignoring it and using {}.",
                    port, config.port
                ),
            }
        }

        if let Ok(bind_ip) = env::var("ALPHANUMERIC_BIND_IP") {
            match bind_ip.parse::<IpAddr>() {
                Ok(ip) => config.bind_ip = ip,
                // Don't silently ignore a bad value and fall back to the default bind address —
                // an operator who fat-fingers this could otherwise unknowingly bind wider than
                // intended. Surface it loudly so the effective bind address is never a surprise.
                Err(_) => eprintln!(
                    "WARNING: ALPHANUMERIC_BIND_IP='{}' is not a valid IP address; ignoring it \
                     and using the default bind address {}.",
                    bind_ip, config.bind_ip
                ),
            }
        }

        if let Ok(max_peers) = env::var("ALPHANUMERIC_MAX_PEERS") {
            match max_peers.trim().parse::<usize>() {
                Ok(n) => {
                    config.max_peers =
                        Self::clamp_usize(n, MIN_CONFIGURED_PEERS, MAX_CONFIGURED_PEERS)
                }
                Err(_) => eprintln!(
                    "WARNING: ALPHANUMERIC_MAX_PEERS='{}' is not a valid number; ignoring it and using {}.",
                    max_peers, config.max_peers
                ),
            }
        }

        if let Ok(max_connections) = env::var("ALPHANUMERIC_MAX_CONNECTIONS") {
            let max_connections = max_connections.trim();
            match max_connections.parse::<usize>() {
                Ok(max_connections) => {
                    config.max_connections = Self::clamp_usize(
                        max_connections,
                        MIN_CONFIGURED_CONNECTIONS,
                        MAX_CONFIGURED_CONNECTIONS,
                    );
                }
                Err(_) => eprintln!(
                    "WARNING: ALPHANUMERIC_MAX_CONNECTIONS='{}' is not a valid number; ignoring it and using {}.",
                    max_connections, config.max_connections
                ),
            }
        }

        if let Ok(velocity_enabled) = env::var("ALPHANUMERIC_VELOCITY_ENABLED") {
            let velocity_enabled = velocity_enabled.trim().to_ascii_lowercase();
            match velocity_enabled.as_str() {
                "1" | "true" | "on" | "yes" => config.velocity_enabled = true,
                "0" | "false" | "off" | "no" => config.velocity_enabled = false,
                "" => {
                    eprintln!(
                        "WARNING: ALPHANUMERIC_VELOCITY_ENABLED is empty; using {}.",
                        config.velocity_enabled
                    )
                }
                _ => {
                    eprintln!(
                        "WARNING: ALPHANUMERIC_VELOCITY_ENABLED='{}' is not a valid boolean; using {}.",
                        velocity_enabled, config.velocity_enabled
                    )
                }
            }
        }

        if let Ok(max_shred_size) = env::var("ALPHANUMERIC_MAX_SHRED_SIZE") {
            let max_shred_size = max_shred_size.trim();
            match max_shred_size.parse::<usize>() {
                Ok(size) => {
                    config.max_shred_size = Self::clamp_usize(size, MIN_SHRED_SIZE, MAX_SHRED_SIZE);
                }
                Err(_) => eprintln!(
                    "WARNING: ALPHANUMERIC_MAX_SHRED_SIZE='{}' is not a valid number; ignoring it and using {}.",
                    max_shred_size, config.max_shred_size
                ),
            }
        }

        if let Ok(seed_nodes) = env::var("ALPHANUMERIC_SEED_NODES")
            .or_else(|_| env::var("ALPHANUMERIC_BOOTSTRAP_PEERS"))
        {
            config.seed_nodes = seed_nodes
                .split(',')
                .filter_map(|s| {
                    let t = s.trim();
                    (!t.is_empty()).then(|| t.to_owned())
                })
                .collect();
        }

        if let Ok(erasure_shards) = env::var("ALPHANUMERIC_ERASURE_SHARDS") {
            let erasure_shards = erasure_shards.trim();
            match erasure_shards.parse::<usize>() {
                Ok(shards) => {
                    config.erasure_shards =
                        Self::clamp_usize(shards, MIN_ERASURE_SHARDS, MAX_ERASURE_SHARDS);
                }
                Err(_) => eprintln!(
                    "WARNING: ALPHANUMERIC_ERASURE_SHARDS='{}' is not a valid number; ignoring it and using {}.",
                    erasure_shards, config.erasure_shards
                ),
            }
        }

        if let Ok(erasure_parity) = env::var("ALPHANUMERIC_ERASURE_PARITY") {
            let erasure_parity = erasure_parity.trim();
            match erasure_parity.parse::<usize>() {
                Ok(parity) => {
                    config.erasure_parity = parity.min(MAX_ERASURE_PARITY);
                }
                Err(_) => eprintln!(
                    "WARNING: ALPHANUMERIC_ERASURE_PARITY='{}' is not a valid number; ignoring it and using {}.",
                    erasure_parity, config.erasure_parity
                ),
            }
        }

        config.normalize_runtime_limits();
        config
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "blockchain.db".to_string(),
        }
    }
}

impl DatabaseConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(path) = env::var("ALPHANUMERIC_DB_PATH") {
            config.path = path;
        }

        config
    }
}

#[derive(Debug, Clone, Default)]
pub struct AppConfig {
    pub network: NetworkConfig,
    pub database: DatabaseConfig,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            network: NetworkConfig::from_env(),
            database: DatabaseConfig::from_env(),
        }
    }

    pub fn log_config(&self) {
        println!(
            "Alphanumeric port={} bind={} peers={} conns={} velocity={} seeds={} db={}",
            self.network.port,
            self.network.bind_ip,
            self.network.max_peers,
            self.network.max_connections,
            self.network.velocity_enabled,
            self.network.seed_nodes.len(),
            self.database.path
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_config_clamps_peer_and_connection_limits() {
        let mut config = NetworkConfig {
            max_peers: 0,
            max_connections: 0,
            ..Default::default()
        };
        config.normalize_runtime_limits();
        assert_eq!(config.max_peers, MIN_CONFIGURED_PEERS);
        assert_eq!(config.max_connections, MIN_CONFIGURED_CONNECTIONS);

        let mut config = NetworkConfig {
            max_peers: usize::MAX,
            max_connections: usize::MAX,
            ..Default::default()
        };
        config.normalize_runtime_limits();
        assert_eq!(config.max_peers, MAX_CONFIGURED_PEERS);
        assert_eq!(config.max_connections, MAX_CONFIGURED_CONNECTIONS);
    }

    #[test]
    fn network_config_connections_never_fall_below_peer_limit() {
        let mut config = NetworkConfig {
            max_peers: 400,
            max_connections: 20,
            ..Default::default()
        };
        config.normalize_runtime_limits();
        assert_eq!(config.max_peers, 400);
        assert_eq!(config.max_connections, 400);
    }

    #[test]
    fn network_config_clamps_shred_and_erasure_limits() {
        let mut config = NetworkConfig {
            max_shred_size: 1,
            erasure_shards: 0,
            erasure_parity: usize::MAX,
            ..Default::default()
        };
        config.normalize_runtime_limits();
        assert_eq!(config.max_shred_size, MIN_SHRED_SIZE);
        assert_eq!(config.erasure_shards, MIN_ERASURE_SHARDS);
        assert_eq!(config.erasure_parity, MAX_ERASURE_PARITY);

        let mut config = NetworkConfig {
            max_shred_size: usize::MAX,
            erasure_shards: usize::MAX,
            erasure_parity: usize::MAX,
            ..Default::default()
        };
        config.normalize_runtime_limits();
        assert_eq!(config.max_shred_size, MAX_SHRED_SIZE);
        assert_eq!(config.erasure_shards, MAX_ERASURE_SHARDS);
        assert_eq!(config.erasure_parity, MAX_ERASURE_PARITY);
    }
}
