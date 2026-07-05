use std::env;
use std::net::{IpAddr, Ipv4Addr};

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
            seed_nodes: vec![
                "seed.alphanumeric.network:7177".to_string(),
                "seed2.alphanumeric.network:7177".to_string(),
                "a9seed.mynode.network:7177".to_string(),
            ],
            velocity_enabled: false,
            max_shred_size: 32 * 1024, // 32KB
            erasure_shards: 16,
            erasure_parity: 4,
        }
    }
}

impl NetworkConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(port) = env::var("ALPHANUMERIC_PORT") {
            if let Ok(port) = port.parse::<u16>() {
                config.port = port;
            }
        }

        if let Ok(bind_ip) = env::var("ALPHANUMERIC_BIND_IP") {
            if let Ok(ip) = bind_ip.parse::<IpAddr>() {
                config.bind_ip = ip;
            }
        }

        if let Ok(max_peers) = env::var("ALPHANUMERIC_MAX_PEERS") {
            if let Ok(max_peers) = max_peers.parse::<usize>() {
                config.max_peers = max_peers;
            }
        }

        if let Ok(max_connections) = env::var("ALPHANUMERIC_MAX_CONNECTIONS") {
            if let Ok(max_connections) = max_connections.parse::<usize>() {
                config.max_connections = max_connections;
            }
        }

        if let Ok(seed_nodes) = env::var("ALPHANUMERIC_SEED_NODES") {
            config.seed_nodes = seed_nodes
                .split(',')
                .filter_map(|s| {
                    let t = s.trim();
                    (!t.is_empty()).then(|| t.to_owned())
                })
                .collect();
        }

        if let Ok(velocity_enabled) = env::var("ALPHANUMERIC_VELOCITY_ENABLED") {
            config.velocity_enabled = velocity_enabled.eq_ignore_ascii_case("true");
        }

        if let Ok(max_shred_size) = env::var("ALPHANUMERIC_MAX_SHRED_SIZE") {
            if let Ok(size) = max_shred_size.parse::<usize>() {
                config.max_shred_size = size;
            }
        }

        if let Ok(erasure_shards) = env::var("ALPHANUMERIC_ERASURE_SHARDS") {
            if let Ok(shards) = erasure_shards.parse::<usize>() {
                config.erasure_shards = shards;
            }
        }

        if let Ok(erasure_parity) = env::var("ALPHANUMERIC_ERASURE_PARITY") {
            if let Ok(parity) = erasure_parity.parse::<usize>() {
                config.erasure_parity = parity;
            }
        }

        config
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub path: String,
    pub max_size: Option<u64>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "blockchain.db".to_string(),
            max_size: Some(10 * 1024 * 1024 * 1024), // 10GB
        }
    }
}

impl DatabaseConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(path) = env::var("ALPHANUMERIC_DB_PATH") {
            config.path = path;
        }

        if let Ok(max_size) = env::var("ALPHANUMERIC_MAX_DB_SIZE") {
            if let Ok(size) = max_size.parse::<u64>() {
                config.max_size = Some(size);
            }
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
