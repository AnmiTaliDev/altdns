mod config;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Semaphore};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use tracing::{info, warn, error, debug};
use config::{AltDnsConfig, ConfigError};

// DNS парсинг структуры
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsQuery {
    name: String,
    qtype: u16,
    qclass: u16,
}

// Простая структура для кэширования DNS ответов
#[derive(Clone)]
struct CacheEntry {
    data: Vec<u8>,
    expires: Instant,
    original_id: u16, // Сохраняем оригинальный ID запроса
}

// Статистика запросов
#[derive(Debug, Default)]
pub struct QueryStats {
    pub total_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub upstream_timeouts: u64,
    pub upstream_errors: u64,
    pub parse_errors: u64,
}

// Основная структура DNS сервера
pub struct AltDns {
    cache: Arc<RwLock<HashMap<DnsQuery, CacheEntry>>>,
    resolver: TokioAsyncResolver,
    config: AltDnsConfig,
    semaphore: Arc<Semaphore>,
    stats: Arc<RwLock<QueryStats>>,
}

impl AltDns {
    pub async fn new(config: AltDnsConfig) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Initializing AltDns with config: {:?}", config);
        
        // Валидируем конфигурацию
        config.validate().map_err(|e| format!("Config validation failed: {}", e))?;
        
        // Создаем resolver с custom upstream
        let upstream_parts: Vec<&str> = config.resolver.upstream_server.split(':').collect();
        let upstream_ip = upstream_parts[0].parse()?;
        let upstream_port = if upstream_parts.len() > 1 {
            upstream_parts[1].parse().unwrap_or(53)
        } else {
            53
        };
        
        let resolver_config = ResolverConfig::from_parts(
            None,
            vec![],
            trust_dns_resolver::config::NameServerConfigGroup::from_ips_clear(
                &[upstream_ip],
                upstream_port,
                true,
            ),
        );
        
        let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());
        
        Ok(AltDns {
            cache: Arc::new(RwLock::new(HashMap::new())),
            resolver,
            semaphore: Arc::new(Semaphore::new(config.performance.max_concurrent)),
            stats: Arc::new(RwLock::new(QueryStats::default())),
            config,
        })
    }
    
    // Парсинг DNS запроса для извлечения доменного имени
    fn parse_dns_query(data: &[u8]) -> Result<(DnsQuery, u16), String> {
        if data.len() < 12 {
            return Err("DNS packet too short".to_string());
        }
        
        // Извлекаем ID запроса (первые 2 байта)
        let query_id = u16::from_be_bytes([data[0], data[1]]);
        
        // Проверяем что это запрос (QR bit = 0)
        if data[2] & 0x80 != 0 {
            return Err("Not a DNS query".to_string());
        }
        
        // Извлекаем количество вопросов
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        if qdcount != 1 {
            return Err("Multiple questions not supported".to_string());
        }
        
        // Парсим доменное имя, начиная с 12-го байта
        let mut pos = 12;
        let mut name_parts = Vec::new();
        
        while pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;
            
            if len == 0 {
                break; // Конец имени
            }
            
            if len > 63 || pos + len > data.len() {
                return Err("Invalid label length".to_string());
            }
            
            let label = String::from_utf8_lossy(&data[pos..pos + len]);
            name_parts.push(label.to_string());
            pos += len;
        }
        
        if pos + 4 > data.len() {
            return Err("Incomplete DNS question".to_string());
        }
        
        // Извлекаем QTYPE и QCLASS
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        
        let domain_name = name_parts.join(".");
        
        Ok((DnsQuery {
            name: domain_name,
            qtype,
            qclass,
        }, query_id))
    }
    
    // Модификация DNS ответа для замены ID
    fn modify_dns_response_id(mut data: Vec<u8>, new_id: u16) -> Vec<u8> {
        if data.len() >= 2 {
            let id_bytes = new_id.to_be_bytes();
            data[0] = id_bytes[0];
            data[1] = id_bytes[1];
        }
        data
    }
    
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let socket = Arc::new(UdpSocket::bind(&self.config.resolver.listen_addr).await?);
        info!("AltDns listening on {}", self.config.resolver.listen_addr);
        
        let mut buf = vec![0u8; self.config.performance.buffer_size];
        
        // Запускаем периодическую очистку кэша
        let _cache_cleaner = self.start_cache_cleaner();
        
        // Запускаем вывод статистики если включено
        let _stats_printer = if self.config.performance.stats {
            Some(self.start_stats_printer())
        } else {
            None
        };
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((size, client_addr)) => {
                    let query_data = buf[..size].to_vec();
                    
                    // Ограничиваем количество одновременных запросов
                    let permit = self.semaphore.clone().acquire_owned().await.unwrap();
                    
                    let cache = self.cache.clone();
                    let resolver = self.resolver.clone();
                    let socket = socket.clone();
                    let config = self.config.clone();
                    let stats = self.stats.clone();
                    
                    // Обрабатываем каждый запрос в отдельной задаче
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_query(
                            query_data,
                            client_addr,
                            cache,
                            resolver,
                            socket,
                            config,
                            stats,
                        ).await {
                            error!("Error handling query from {}: {}", client_addr, e);
                        }
                        drop(permit); // Освобождаем семафор
                    });
                }
                Err(e) => {
                    error!("Error receiving UDP packet: {}", e);
                }
            }
        }
    }
    
    // Периодическая очистка просроченных записей кэша
    async fn start_cache_cleaner(&self) -> tokio::task::JoinHandle<()> {
        let cache = self.cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut cache_write = cache.write().await;
                let now = Instant::now();
                cache_write.retain(|_, entry| entry.expires > now);
                debug!("Cache cleanup completed, {} entries remaining", cache_write.len());
            }
        })
    }
    
    // Периодический вывод статистики
    async fn start_stats_printer(&self) -> tokio::task::JoinHandle<()> {
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // каждые 5 минут
            loop {
                interval.tick().await;
                let stats_read = stats.read().await;
                if stats_read.total_queries > 0 {
                    let cache_hit_rate = (stats_read.cache_hits as f64 / stats_read.total_queries as f64) * 100.0;
                    info!("Stats: total={}, cache_hits={}, cache_misses={}, hit_rate={:.1}%, timeouts={}, errors={}, parse_errors={}", 
                        stats_read.total_queries,
                        stats_read.cache_hits,
                        stats_read.cache_misses,
                        cache_hit_rate,
                        stats_read.upstream_timeouts,
                        stats_read.upstream_errors,
                        stats_read.parse_errors
                    );
                }
            }
        })
    }
    
    async fn handle_query(
        query_data: Vec<u8>,
        client_addr: std::net::SocketAddr,
        cache: Arc<RwLock<HashMap<DnsQuery, CacheEntry>>>,
        _resolver: TokioAsyncResolver,
        socket: Arc<UdpSocket>,
        config: AltDnsConfig,
        stats: Arc<RwLock<QueryStats>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Handling query from {}", client_addr);
        
        // Обновляем статистику
        {
            let mut stats_write = stats.write().await;
            stats_write.total_queries += 1;
        }
        
        // Парсим DNS запрос
        let (dns_query, original_id) = match Self::parse_dns_query(&query_data) {
            Ok(parsed) => parsed,
            Err(e) => {
                debug!("Failed to parse DNS query: {}", e);
                let mut stats_write = stats.write().await;
                stats_write.parse_errors += 1;
                return Ok(());
            }
        };
        
        debug!("Parsed DNS query: {} (type: {}, class: {})", dns_query.name, dns_query.qtype, dns_query.qclass);
        
        // Проверяем кэш
        {
            let cache_read = cache.read().await;
            if let Some(entry) = cache_read.get(&dns_query) {
                if entry.expires > Instant::now() {
                    debug!("Cache hit for query: {}", dns_query.name);
                    
                    // Модифицируем ответ с правильным ID
                    let response = Self::modify_dns_response_id(entry.data.clone(), original_id);
                    socket.send_to(&response, client_addr).await?;
                    
                    // Обновляем статистику
                    {
                        let mut stats_write = stats.write().await;
                        stats_write.cache_hits += 1;
                    }
                    return Ok(());
                }
            }
        }
        
        debug!("Cache miss for query: {}, forwarding to upstream", dns_query.name);
        
        // Обновляем статистику
        {
            let mut stats_write = stats.write().await;
            stats_write.cache_misses += 1;
        }
        
        // Форвардим запрос к upstream серверу
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
        upstream_socket.send_to(&query_data, &config.resolver.upstream_server).await?;
        
        // Получаем ответ от upstream
        let mut response_buf = vec![0u8; config.performance.buffer_size];
        match tokio::time::timeout(
            config.resolver.timeout,
            upstream_socket.recv(&mut response_buf)
        ).await {
            Ok(Ok(response_size)) => {
                let response_data = response_buf[..response_size].to_vec();
                
                // Кэшируем ответ
                {
                    let mut cache_write = cache.write().await;
                    
                    // Ограничиваем размер кэша
                    if cache_write.len() >= config.resolver.cache_size {
                        // Простая стратегия: удаляем первый элемент
                        if let Some(key) = cache_write.keys().next().cloned() {
                            cache_write.remove(&key);
                        }
                    }
                    
                    cache_write.insert(dns_query.clone(), CacheEntry {
                        data: response_data.clone(),
                        expires: Instant::now() + config.resolver.cache_ttl,
                        original_id,
                    });
                }
                
                // Отправляем ответ клиенту
                socket.send_to(&response_data, client_addr).await?;
                debug!("Forwarded response for {} to {}", dns_query.name, client_addr);
            }
            Ok(Err(e)) => {
                error!("Error receiving from upstream: {}", e);
                let mut stats_write = stats.write().await;
                stats_write.upstream_errors += 1;
            }
            Err(_) => {
                warn!("Timeout waiting for upstream response for {}", dns_query.name);
                let mut stats_write = stats.write().await;
                stats_write.upstream_timeouts += 1;
            }
        }
        
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    // Инициализация логирования
    tracing_subscriber::fmt::init();
    
    info!("Starting AltDns v{}", env!("CARGO_PKG_VERSION"));
    
    // Загружаем конфигурацию
    let config = match AltDnsConfig::from_file("altdns.conf") {
        Ok(config) => {
            info!("Loaded configuration from altdns.conf");
            config
        }
        Err(ConfigError::FileNotFound(_)) => {
            warn!("Configuration file altdns.conf not found, using defaults");
            AltDnsConfig::default()
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };
    
    // Создаем и запускаем DNS сервер
    let dns_server = match AltDns::new(config).await {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to create DNS server: {}", e);
            std::process::exit(1);
        }
    };
    
    // Обработка сигналов для graceful shutdown
    tokio::select! {
        result = dns_server.run() => {
            if let Err(e) = result {
                error!("DNS server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down gracefully");
        }
    }
    
    info!("AltDns stopped");
}