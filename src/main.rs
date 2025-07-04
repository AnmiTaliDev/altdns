mod config;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::path::Path;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Semaphore};
use tokio::fs;
use tracing::{info, warn, error, debug};
use regex::Regex;
use crate::config::{AltDnsConfig, ConfigError};

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
    original_id: u16,
    dnssec_validated: bool,
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
    pub failover_switches: u64,
    pub dnssec_validated: u64,
    pub dnssec_failed: u64,
    pub blocked_queries: u64,
    pub ads_blocked: u64,
    pub malware_blocked: u64,
}

// DNS Filtering Engine
#[derive(Debug)]
struct DnsFilter {
    blocklist: HashSet<String>,
    whitelist: HashSet<String>,
    ad_patterns: Vec<Regex>,
    malware_patterns: Vec<Regex>,
}

impl DnsFilter {
    async fn new(config: &AltDnsConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let mut filter = DnsFilter {
            blocklist: HashSet::new(),
            whitelist: HashSet::new(),
            ad_patterns: Vec::new(),
            malware_patterns: Vec::new(),
        };
        
        // Загружаем blocklist
        if Path::new(&config.security.blocklist_path).exists() {
            match fs::read_to_string(&config.security.blocklist_path).await {
                Ok(content) => {
                    for line in content.lines() {
                        let domain = line.trim();
                        if !domain.is_empty() && !domain.starts_with('#') {
                            filter.blocklist.insert(domain.to_lowercase());
                        }
                    }
                    info!("Loaded {} domains from blocklist", filter.blocklist.len());
                }
                Err(e) => warn!("Failed to load blocklist: {}", e),
            }
        }
        
        // Загружаем whitelist
        if Path::new(&config.security.whitelist_path).exists() {
            match fs::read_to_string(&config.security.whitelist_path).await {
                Ok(content) => {
                    for line in content.lines() {
                        let domain = line.trim();
                        if !domain.is_empty() && !domain.starts_with('#') {
                            filter.whitelist.insert(domain.to_lowercase());
                        }
                    }
                    info!("Loaded {} domains from whitelist", filter.whitelist.len());
                }
                Err(e) => warn!("Failed to load whitelist: {}", e),
            }
        }
        
        // Компилируем паттерны для блокировки рекламы
        if config.security.block_ads {
            let ad_patterns = vec![
                r".*\.ads\.",
                r".*\.doubleclick\.",
                r".*\.googleadservices\.",
                r".*\.googlesyndication\.",
                r".*\.googletagmanager\.",
                r".*\.googletag\.",
                r".*analytics\.",
                r".*telemetry\.",
                r".*tracking\.",
                r".*metrics\.",
            ];
            
            for pattern in ad_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    filter.ad_patterns.push(regex);
                }
            }
            info!("Loaded {} ad blocking patterns", filter.ad_patterns.len());
        }
        
        // Компилируем паттерны для блокировки malware
        if config.security.block_malware {
            let malware_patterns = vec![
                r".*\.tk$",      // Подозрительные TLD
                r".*\.ml$", 
                r".*\.ga$",
                r".*\.cf$",
                r".*phishing.*",
                r".*malware.*",
                r".*virus.*",
                r".*trojan.*",
            ];
            
            for pattern in malware_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    filter.malware_patterns.push(regex);
                }
            }
            info!("Loaded {} malware blocking patterns", filter.malware_patterns.len());
        }
        
        Ok(filter)
    }
    
    fn should_block(&self, domain: &str, config: &AltDnsConfig) -> (bool, &'static str) {
        let domain_lower = domain.to_lowercase();
        
        // Проверяем whitelist первым (всегда разрешаем)
        if self.whitelist.contains(&domain_lower) {
            return (false, "whitelisted");
        }
        
        // Проверяем прямое попадание в blocklist
        if self.blocklist.contains(&domain_lower) {
            return (true, "blocklist");
        }
        
        // Проверяем рекламные паттерны
        if config.security.block_ads {
            for pattern in &self.ad_patterns {
                if pattern.is_match(&domain_lower) {
                    return (true, "ads");
                }
            }
        }
        
        // Проверяем malware паттерны
        if config.security.block_malware {
            for pattern in &self.malware_patterns {
                if pattern.is_match(&domain_lower) {
                    return (true, "malware");
                }
            }
        }
        
        (false, "allowed")
    }
}

// Простой DNSSEC валидатор
struct DnssecValidator {
    enabled: bool,
    require_validation: bool,
}

impl DnssecValidator {
    fn new(config: &AltDnsConfig) -> Self {
        Self {
            enabled: config.security.enable_dnssec,
            require_validation: config.security.require_dnssec,
        }
    }
    
    fn validate_response(&self, response_data: &[u8], domain: &str) -> (bool, bool) {
        if !self.enabled {
            return (true, false); // Разрешаем, но не валидировано
        }
        
        // Простая проверка наличия DNSSEC записей в ответе
        let has_dnssec_records = self.check_dnssec_records(response_data);
        
        if has_dnssec_records {
            // В реальной реализации здесь была бы полная DNSSEC валидация
            // Для демо считаем что все записи с DNSSEC валидны
            debug!("DNSSEC validation successful for {}", domain);
            (true, true) // Разрешаем и валидировано
        } else if self.require_validation {
            debug!("DNSSEC validation failed for {} (no DNSSEC records)", domain);
            (false, false) // Блокируем если требуется DNSSEC
        } else {
            debug!("DNSSEC not found for {}, but not required", domain);
            (true, false) // Разрешаем, но не валидировано
        }
    }
    
    fn check_dnssec_records(&self, response_data: &[u8]) -> bool {
        if response_data.len() < 12 {
            return false;
        }
        
        // Проверяем наличие DNSSEC флагов в заголовке
        let flags = u16::from_be_bytes([response_data[2], response_data[3]]);
        let authentic_data = (flags & 0x0020) != 0; // AD bit
        let _checking_disabled = (flags & 0x0010) != 0; // CD bit
        
        // Проверяем наличие дополнительных записей (могут содержать DNSSEC)
        let arcount = u16::from_be_bytes([response_data[10], response_data[11]]);
        
        authentic_data || arcount > 0
    }
}

// Структура для отслеживания состояния upstream серверов
#[derive(Debug, Clone)]
struct UpstreamServer {
    address: String,
    failures: u32,
    last_failure: Option<Instant>,
}

impl UpstreamServer {
    fn new(address: String) -> Self {
        Self {
            address,
            failures: 0,
            last_failure: None,
        }
    }
    
    fn is_healthy(&self) -> bool {
        // Сервер считается здоровым если:
        // 1. Нет недавних ошибок (< 3 за последние 60 секунд)
        // 2. Или прошло больше 60 секунд с последней ошибки
        if let Some(last_failure) = self.last_failure {
            let time_since_failure = Instant::now().duration_since(last_failure);
            if time_since_failure < Duration::from_secs(60) {
                return self.failures < 3;
            }
        }
        true
    }
    
    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());
    }
    
    fn record_success(&mut self) {
        self.failures = 0;
        self.last_failure = None;
    }
}

// Основная структура DNS сервера
pub struct AltDns {
    cache: Arc<RwLock<HashMap<DnsQuery, CacheEntry>>>,
    config: AltDnsConfig,
    semaphore: Arc<Semaphore>,
    stats: Arc<RwLock<QueryStats>>,
    upstream_servers: Arc<RwLock<Vec<UpstreamServer>>>,
    dns_filter: Arc<DnsFilter>,
    dnssec_validator: DnssecValidator,
}

impl AltDns {
    pub async fn new(config: AltDnsConfig) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Initializing AltDns with config: {:?}", config);
        
        // Валидируем конфигурацию
        config.validate().map_err(|e| format!("Config validation failed: {}", e))?;
        
        // Инициализируем upstream серверы
        let upstream_servers: Vec<UpstreamServer> = config.resolver.upstream_servers
            .iter()
            .map(|addr| UpstreamServer::new(addr.clone()))
            .collect();
        
        info!("Configured {} upstream servers: {:?}", 
              upstream_servers.len(), 
              config.resolver.upstream_servers);
        
        // Инициализируем DNS фильтр
        let dns_filter = Arc::new(DnsFilter::new(&config).await?);
        
        // Инициализируем DNSSEC валидатор
        let dnssec_validator = DnssecValidator::new(&config);
        
        Ok(AltDns {
            cache: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(config.performance.max_concurrent)),
            stats: Arc::new(RwLock::new(QueryStats::default())),
            upstream_servers: Arc::new(RwLock::new(upstream_servers)),
            dns_filter,
            dnssec_validator,
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
    
    // Создание NXDOMAIN ответа для заблокированных доменов
    fn create_nxdomain_response(query_data: &[u8], query_id: u16) -> Vec<u8> {
        if query_data.len() < 12 {
            return Vec::new();
        }
        
        let mut response = query_data.to_vec();
        
        // Устанавливаем правильный ID
        let id_bytes = query_id.to_be_bytes();
        response[0] = id_bytes[0];
        response[1] = id_bytes[1];
        
        // Устанавливаем флаги: QR=1 (response), RCODE=3 (NXDOMAIN)
        response[2] = 0x81; // QR=1, OPCODE=0, AA=0, TC=0, RD=1
        response[3] = 0x83; // RA=1, Z=0, RCODE=3 (NXDOMAIN)
        
        response
    }
    
    // Создание SERVFAIL ответа для DNSSEC ошибок
    fn create_servfail_response(query_data: &[u8], query_id: u16) -> Vec<u8> {
        if query_data.len() < 12 {
            return Vec::new();
        }
        
        let mut response = query_data.to_vec();
        
        // Устанавливаем правильный ID
        let id_bytes = query_id.to_be_bytes();
        response[0] = id_bytes[0];
        response[1] = id_bytes[1];
        
        // Устанавливаем флаги: QR=1 (response), RCODE=2 (SERVFAIL)
        response[2] = 0x81; // QR=1, OPCODE=0, AA=0, TC=0, RD=1
        response[3] = 0x82; // RA=1, Z=0, RCODE=2 (SERVFAIL)
        
        response
    }
    
    // Выбор лучшего upstream сервера с поддержкой failover
    async fn get_best_upstream(&self) -> String {
        let servers = self.upstream_servers.read().await;
        
        // Сначала пробуем найти здоровый сервер
        for server in servers.iter() {
            if server.is_healthy() {
                return server.address.clone();
            }
        }
        
        // Если все серверы нездоровы, берем первый (fallback)
        if let Some(server) = servers.first() {
            return server.address.clone();
        }
        
        // Последний fallback на Google DNS
        "8.8.8.8:53".to_string()
    }
    
    // Отметить успешный запрос к серверу
    async fn record_upstream_success(&self, server_addr: &str) {
        let mut servers = self.upstream_servers.write().await;
        for server in servers.iter_mut() {
            if server.address == server_addr {
                server.record_success();
                break;
            }
        }
    }
    
    // Отметить ошибку запроса к серверу
    async fn record_upstream_failure(&self, server_addr: &str) {
        let mut servers = self.upstream_servers.write().await;
        for server in servers.iter_mut() {
            if server.address == server_addr {
                server.record_failure();
                debug!("Upstream {} marked as unhealthy (failures: {})", server_addr, server.failures);
                break;
            }
        }
    }
    
    // Попытка запроса к upstream серверу с retry логикой
    async fn try_upstream_query(
        &self, 
        query_data: &[u8], 
        dns_query: &DnsQuery
    ) -> Result<Vec<u8>, String> {
        let max_retries = self.config.resolver.max_retries;
        let timeout = self.config.resolver.timeout;
        
        for attempt in 0..=max_retries {
            let upstream_addr = self.get_best_upstream().await;
            debug!("Attempting query to {} (attempt {}/{})", upstream_addr, attempt + 1, max_retries + 1);
            
            let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(socket) => socket,
                Err(e) => {
                    error!("Failed to bind socket: {}", e);
                    continue;
                }
            };
            
            // Отправляем запрос
            if let Err(e) = upstream_socket.send_to(query_data, &upstream_addr).await {
                error!("Failed to send to {}: {}", upstream_addr, e);
                self.record_upstream_failure(&upstream_addr).await;
                continue;
            }
            
            // Получаем ответ с таймаутом
            let mut response_buf = vec![0u8; self.config.performance.buffer_size];
            match tokio::time::timeout(timeout, upstream_socket.recv(&mut response_buf)).await {
                Ok(Ok(response_size)) => {
                    let response_data = response_buf[..response_size].to_vec();
                    self.record_upstream_success(&upstream_addr).await;
                    debug!("Successful response from {} for {}", upstream_addr, dns_query.name);
                    return Ok(response_data);
                }
                Ok(Err(e)) => {
                    error!("Socket error from {}: {}", upstream_addr, e);
                    self.record_upstream_failure(&upstream_addr).await;
                }
                Err(_) => {
                    warn!("Timeout from {} for {} (attempt {})", upstream_addr, dns_query.name, attempt + 1);
                    self.record_upstream_failure(&upstream_addr).await;
                }
            }
            
            // Если не последняя попытка, проверим failover
            if attempt < max_retries {
                let mut stats_write = self.stats.write().await;
                stats_write.failover_switches += 1;
                debug!("Switching to next upstream server for {}", dns_query.name);
            }
        }
        
        Err(format!("All upstream servers failed for {}", dns_query.name))
    }
    
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let socket: Arc<UdpSocket> = Arc::new(UdpSocket::bind(&self.config.resolver.listen_addr).await?);
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
                    let socket = socket.clone();
                    let config = self.config.clone();
                    let stats = self.stats.clone();
                    
                    let dns_filter = self.dns_filter.clone();
                    let dnssec_validator = DnssecValidator::new(&config);
                    let upstream_servers = self.upstream_servers.clone();
                    
                    let altdns_instance = AltDns {
                        cache: cache.clone(),
                        config: config.clone(),
                        semaphore: self.semaphore.clone(),
                        stats: stats.clone(),
                        upstream_servers,
                        dns_filter,
                        dnssec_validator,
                    };
                    
                    // Обрабатываем каждый запрос в отдельной задаче
                    tokio::spawn(async move {
                        if let Err(e) = altdns_instance.handle_query(
                            query_data,
                            client_addr,
                            cache,
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
            let mut interval = tokio::time::interval(Duration::from_secs(60));
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
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // каждые 5 минут
            loop {
                interval.tick().await;
                let stats_read = stats.read().await;
                if stats_read.total_queries > 0 {
                    let cache_hit_rate = (stats_read.cache_hits as f64 / stats_read.total_queries as f64) * 100.0;
                    info!("Stats: total={}, cache_hits={}, cache_misses={}, hit_rate={:.1}%, timeouts={}, errors={}, dnssec_ok={}, blocked={}, ads_blocked={}, malware_blocked={}, failovers={}", 
                        stats_read.total_queries,
                        stats_read.cache_hits,
                        stats_read.cache_misses,
                        cache_hit_rate,
                        stats_read.upstream_timeouts,
                        stats_read.upstream_errors,
                        stats_read.dnssec_validated,
                        stats_read.blocked_queries,
                        stats_read.ads_blocked,
                        stats_read.malware_blocked,
                        stats_read.failover_switches
                    );
                }
            }
        })
    }
    
    async fn handle_query(
        &self,
        query_data: Vec<u8>,
        client_addr: std::net::SocketAddr,
        cache: Arc<RwLock<HashMap<DnsQuery, CacheEntry>>>,
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
        
        // DNS FILTERING - Проверяем блокировку
        if config.security.enable_filtering {
            let (should_block, block_reason) = self.dns_filter.should_block(&dns_query.name, &config);
            
            if should_block {
                info!("            // BLOCKED: {} (reason: {})", dns_query.name, block_reason);
                
                // Обновляем статистику блокировок
                {
                    let mut stats_write = stats.write().await;
                    stats_write.blocked_queries += 1;
                    match block_reason {
                        "ads" => stats_write.ads_blocked += 1,
                        "malware" => stats_write.malware_blocked += 1,
                        _ => {}
                    }
                }
                
                // Отправляем NXDOMAIN ответ
                let blocked_response = Self::create_nxdomain_response(&query_data, original_id);
                socket.send_to(&blocked_response, client_addr).await?;
                return Ok(());
            }
        }
        
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
                        if entry.dnssec_validated {
                            stats_write.dnssec_validated += 1;
                        }
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
        
        // Форвардим запрос к upstream серверам с failover
        match self.try_upstream_query(&query_data, &dns_query).await {
            Ok(response_data) => {
                // DNSSEC VALIDATION
                let (dnssec_valid, dnssec_validated) = self.dnssec_validator.validate_response(&response_data, &dns_query.name);
                
                if !dnssec_valid {
                    warn!("DNSSEC validation failed for {}", dns_query.name);
                    let mut stats_write = stats.write().await;
                    stats_write.dnssec_failed += 1;
                    
                    // Отправляем SERVFAIL если DNSSEC обязателен
                    let servfail_response = Self::create_servfail_response(&query_data, original_id);
                    socket.send_to(&servfail_response, client_addr).await?;
                    return Ok(());
                }
                
                if dnssec_validated {
                    debug!("DNSSEC validation successful for {}", dns_query.name);
                    let mut stats_write = stats.write().await;
                    stats_write.dnssec_validated += 1;
                }
                
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
                        dnssec_validated,
                    });
                }
                
                // Отправляем ответ клиенту
                socket.send_to(&response_data, client_addr).await?;
                debug!("Forwarded response for {} to {}", dns_query.name, client_addr);
            }
            Err(e) => {
                error!("All upstream servers failed: {}", e);
                let mut stats_write = stats.write().await;
                stats_write.upstream_errors += 1;
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