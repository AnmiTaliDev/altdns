use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use configparser::ini::Ini;
use tracing::{info, warn, error};

/// Конфигурация DNS резолвера
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub listen_addr: SocketAddr,
    pub upstream_servers: Vec<String>,
    pub cache_size: usize,
    pub cache_ttl: Duration,
    pub timeout: Duration,
    pub max_retries: u32,
}

/// Конфигурация логирования
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: String,
    pub file: Option<String>,
}

/// Конфигурация производительности
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    pub max_concurrent: usize,
    pub buffer_size: usize,
    pub stats: bool,
}

/// Основная структура конфигурации
#[derive(Debug, Clone)]
pub struct AltDnsConfig {
    pub resolver: ResolverConfig,
    pub logging: LogConfig,
    pub performance: PerformanceConfig,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:53".parse().unwrap(),
            upstream_servers: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            cache_size: 1000,
            cache_ttl: Duration::from_secs(300), // 5 минут
            timeout: Duration::from_secs(5),
            max_retries: 2,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 1000,
            buffer_size: 512,
            stats: true,
        }
    }
}

impl Default for AltDnsConfig {
    fn default() -> Self {
        Self {
            resolver: ResolverConfig::default(),
            logging: LogConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl AltDnsConfig {
    /// Загружает конфигурацию из INI файла
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.to_path_buf()));
        }
        
        let mut ini = Ini::new();
        ini.load(path).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        
        let mut config = AltDnsConfig::default();
        
        // Загружаем секцию [resolver]
        if let Some(resolver_section) = ini.get_map_ref().get("resolver") {
            config.resolver = Self::parse_resolver_config(resolver_section)?;
        }
        
        // Загружаем секцию [logging]
        if let Some(logging_section) = ini.get_map_ref().get("logging") {
            config.logging = Self::parse_logging_config(logging_section)?;
        }
        
        // Загружаем секцию [performance]
        if let Some(performance_section) = ini.get_map_ref().get("performance") {
            config.performance = Self::parse_performance_config(performance_section)?;
        }
        
        info!("Configuration loaded from {}", path.display());
        Ok(config)
    }
    
    /// Парсит секцию [resolver]
    fn parse_resolver_config(
        section: &std::collections::HashMap<String, Option<String>>
    ) -> Result<ResolverConfig, ConfigError> {
        let mut config = ResolverConfig::default();
        
        if let Some(Some(listen)) = section.get("listen") {
            config.listen_addr = listen.parse()
                .map_err(|e: std::net::AddrParseError| ConfigError::InvalidValue("listen".to_string(), e.to_string()))?;
        }
        
        if let Some(Some(upstream)) = section.get("upstream") {
            // Парсим список серверов, разделенных запятыми
            config.upstream_servers = upstream
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            
            if config.upstream_servers.is_empty() {
                config.upstream_servers = vec!["8.8.8.8:53".to_string()];
            }
        }
        
        if let Some(Some(cache_size)) = section.get("cache_size") {
            config.cache_size = cache_size.parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::InvalidValue("cache_size".to_string(), e.to_string()))?;
        }
        
        if let Some(Some(cache_ttl)) = section.get("cache_ttl") {
            let ttl_seconds: u64 = cache_ttl.parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::InvalidValue("cache_ttl".to_string(), e.to_string()))?;
            config.cache_ttl = Duration::from_secs(ttl_seconds);
        }
        
        if let Some(Some(timeout)) = section.get("timeout") {
            let timeout_seconds: u64 = timeout.parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::InvalidValue("timeout".to_string(), e.to_string()))?;
            config.timeout = Duration::from_secs(timeout_seconds);
        }
        
        if let Some(Some(max_retries)) = section.get("max_retries") {
            config.max_retries = max_retries.parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::InvalidValue("max_retries".to_string(), e.to_string()))?;
        }
        
        Ok(config)
    }
    
    /// Парсит секцию [logging]
    fn parse_logging_config(
        section: &std::collections::HashMap<String, Option<String>>
    ) -> Result<LogConfig, ConfigError> {
        let mut config = LogConfig::default();
        
        if let Some(Some(level)) = section.get("level") {
            // Валидируем уровень логирования
            match level.as_str() {
                "trace" | "debug" | "info" | "warn" | "error" => {
                    config.level = level.clone();
                }
                _ => {
                    return Err(ConfigError::InvalidValue(
                        "level".to_string(),
                        format!("Invalid log level: {}", level)
                    ));
                }
            }
        }
        
        if let Some(Some(file)) = section.get("file") {
            config.file = Some(file.clone());
        }
        
        Ok(config)
    }
    
    /// Парсит секцию [performance]
    fn parse_performance_config(
        section: &std::collections::HashMap<String, Option<String>>
    ) -> Result<PerformanceConfig, ConfigError> {
        let mut config = PerformanceConfig::default();
        
        if let Some(Some(max_concurrent)) = section.get("max_concurrent") {
            config.max_concurrent = max_concurrent.parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::InvalidValue("max_concurrent".to_string(), e.to_string()))?;
        }
        
        if let Some(Some(buffer_size)) = section.get("buffer_size") {
            config.buffer_size = buffer_size.parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::InvalidValue("buffer_size".to_string(), e.to_string()))?;
        }
        
        if let Some(Some(stats)) = section.get("stats") {
            config.stats = stats.parse()
                .map_err(|e: std::str::ParseBoolError| ConfigError::InvalidValue("stats".to_string(), e.to_string()))?;
        }
        
        Ok(config)
    }
    
    /// Валидирует конфигурацию
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Проверяем адрес прослушивания
        if self.resolver.listen_addr.port() == 0 {
            return Err(ConfigError::ValidationError("Invalid listen port".to_string()));
        }
        
        // Проверяем upstream серверы
        if self.resolver.upstream_servers.is_empty() {
            return Err(ConfigError::ValidationError("At least one upstream server must be specified".to_string()));
        }
        
        // Валидируем формат upstream серверов
        for server in &self.resolver.upstream_servers {
            if server.is_empty() {
                return Err(ConfigError::ValidationError("Upstream server cannot be empty".to_string()));
            }
            // Попробуем парсить server:port формат
            if !server.contains(':') {
                return Err(ConfigError::ValidationError(format!("Invalid upstream server format: {}", server)));
            }
        }
        
        // Проверяем размер кэша
        if self.resolver.cache_size == 0 {
            return Err(ConfigError::ValidationError("Cache size must be greater than 0".to_string()));
        }
        
        // Проверяем размер буфера
        if self.performance.buffer_size < 512 {
            warn!("Buffer size is less than 512 bytes, this may cause issues with large DNS packets");
        }
        
        Ok(())
    }
}

/// Ошибки конфигурации
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    FileNotFound(std::path::PathBuf),
    
    #[error("Failed to parse configuration: {0}")]
    ParseError(String),
    
    #[error("Invalid value for '{0}': {1}")]
    InvalidValue(String, String),
    
    #[error("Configuration validation failed: {0}")]
    ValidationError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_default_config() {
        let config = AltDnsConfig::default();
        assert_eq!(config.resolver.listen_addr.to_string(), "127.0.0.1:53");
        assert_eq!(config.resolver.upstream_server, "8.8.8.8:53");
        assert_eq!(config.resolver.cache_size, 1000);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.performance.buffer_size, 512);
    }
    
    #[test]
    fn test_config_validation() {
        let config = AltDnsConfig::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_from_file() {
        let config_content = r#"
[resolver]
listen = 127.0.0.1:5353
upstream = 1.1.1.1:53
cache_size = 500

[logging]
level = debug

[performance]
max_concurrent = 2000
        "#;
        
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), config_content).unwrap();
        
        let config = AltDnsConfig::from_file(temp_file.path()).unwrap();
        assert_eq!(config.resolver.listen_addr.port(), 5353);
        assert_eq!(config.resolver.upstream_server, "1.1.1.1:53");
        assert_eq!(config.resolver.cache_size, 500);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.performance.max_concurrent, 2000);
    }
}