use std::env;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub port: u16,
    pub bind_ip: IpAddr,
    pub max_peers: usize,
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
            seed_nodes: vec![
                "seed.alphanumeric.network:7177".to_string(),
                "seed2.alphanumeric.network:7177".to_string(),
                "a9seed.mynode.network:7177".to_string(),
            ],
            velocity_enabled: true,
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

        if let Ok(seed_nodes) = env::var("ALPHANUMERIC_SEED_NODES") {
            config.seed_nodes = seed_nodes
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        if let Ok(velocity_enabled) = env::var("ALPHANUMERIC_VELOCITY_ENABLED") {
            config.velocity_enabled = velocity_enabled.to_lowercase() == "true";
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

#[derive(Debug, Clone)]
pub struct MiningConfig {
    pub enabled: bool,
    pub threads: usize,
    pub difficulty_target: u64,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threads: num_cpus::get(),
            difficulty_target: 200,
        }
    }
}

impl MiningConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(enabled) = env::var("ALPHANUMERIC_MINING_ENABLED") {
            config.enabled = enabled.to_lowercase() == "true";
        }

        if let Ok(threads) = env::var("ALPHANUMERIC_MINING_THREADS") {
            if let Ok(threads) = threads.parse::<usize>() {
                config.threads = if threads == 0 { num_cpus::get() } else { threads };
            }
        }

        if let Ok(difficulty) = env::var("ALPHANUMERIC_DIFFICULTY_TARGET") {
            if let Ok(difficulty) = difficulty.parse::<u64>() {
                config.difficulty_target = difficulty;
            }
        }

        config
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub network: NetworkConfig,
    pub database: DatabaseConfig,
    pub mining: MiningConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            database: DatabaseConfig::default(),
            mining: MiningConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            network: NetworkConfig::from_env(),
            database: DatabaseConfig::from_env(),
            mining: MiningConfig::from_env(),
        }
    }

    pub fn log_config(&self) {
        let mining_info = if self.mining.enabled {
            format!(" mining={} threads={} target={}", 
                self.mining.enabled, self.mining.threads, self.mining.difficulty_target)
        } else {
            format!(" mining={}", self.mining.enabled)
        };
        
        print!("Alphanumeric port={} bind={} peers={} velocity={} seeds={} db={}{}", 
            self.network.port, 
            self.network.bind_ip, 
            self.network.max_peers, 
            self.network.velocity_enabled, 
            self.network.seed_nodes.len(), 
            self.database.path,
            mining_info
        );
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
    }
}