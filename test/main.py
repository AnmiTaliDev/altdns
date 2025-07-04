#!/usr/bin/env python3
"""
AltDns Test Suite
Comprehensive testing for altdns microkernel DNS resolver

Author: AnmiTaliDev <annmitali198@gmail.com>
License: Apache-2.0
"""

import socket
import time
import threading
import subprocess
import json
import sys
import os
from typing import List, Dict, Any, Optional
import dns.resolver
import dns.message
import dns.query

class AltDnsTest:
    def __init__(self, server_host="127.0.0.1", server_port=5353):
        self.server_host = server_host
        self.server_port = server_port
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [server_host]
        self.resolver.port = server_port
        self.test_results = []
        
    def log(self, message: str, level: str = "INFO"):
        """Логирование с временной меткой"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
        
    def test_basic_resolution(self) -> bool:
        """Тест базового разрешения DNS"""
        self.log("Testing basic DNS resolution...")
        
        test_domains = [
            "google.com",
            "github.com", 
            "stackoverflow.com",
            "rust-lang.org",
            "example.com"
        ]
        
        success_count = 0
        for domain in test_domains:
            try:
                start_time = time.time()
                answer = self.resolver.resolve(domain, 'A')
                end_time = time.time()
                
                response_time = (end_time - start_time) * 1000  # в миллисекундах
                ips = [str(rdata) for rdata in answer]
                
                self.log(f"✅ {domain}: {ips} ({response_time:.1f}ms)")
                success_count += 1
                
            except Exception as e:
                self.log(f"❌ {domain}: {str(e)}", "ERROR")
                
        success_rate = (success_count / len(test_domains)) * 100
        self.test_results.append({
            "test": "basic_resolution",
            "success_rate": success_rate,
            "domains_tested": len(test_domains),
            "domains_successful": success_count
        })
        
        self.log(f"Basic resolution test: {success_count}/{len(test_domains)} successful ({success_rate:.1f}%)")
        return success_count == len(test_domains)
    
    def test_cache_performance(self) -> bool:
        """Тест производительности кэша"""
        self.log("Testing cache performance...")
        
        domain = "google.com"
        times = []
        
        # Первый запрос (cache miss)
        try:
            start_time = time.time()
            self.resolver.resolve(domain, 'A')
            first_time = (time.time() - start_time) * 1000
            times.append(first_time)
            self.log(f"First request (cache miss): {first_time:.1f}ms")
            
            # Последующие запросы (cache hits)
            for i in range(5):
                time.sleep(0.1)  # Небольшая пауза
                start_time = time.time()
                self.resolver.resolve(domain, 'A')
                cache_time = (time.time() - start_time) * 1000
                times.append(cache_time)
                self.log(f"Cached request #{i+1}: {cache_time:.1f}ms")
            
            # Анализ результатов
            avg_cache_time = sum(times[1:]) / len(times[1:])
            improvement = ((first_time - avg_cache_time) / first_time) * 100
            
            self.test_results.append({
                "test": "cache_performance",
                "first_request_ms": first_time,
                "avg_cached_ms": avg_cache_time,
                "improvement_percent": improvement,
                "times": times
            })
            
            self.log(f"Cache performance: {improvement:.1f}% improvement")
            return improvement > 10  # Ожидаем минимум 10% улучшения
            
        except Exception as e:
            self.log(f"❌ Cache test failed: {str(e)}", "ERROR")
            return False
    
    def test_concurrent_requests(self) -> bool:
        """Тест конкурентных запросов"""
        self.log("Testing concurrent requests...")
        
        domains = ["google.com", "github.com", "stackoverflow.com", "example.com"] * 5
        results = []
        errors = []
        
        def query_domain(domain: str):
            try:
                start_time = time.time()
                answer = self.resolver.resolve(domain, 'A')
                end_time = time.time()
                
                results.append({
                    "domain": domain,
                    "time_ms": (end_time - start_time) * 1000,
                    "ips": [str(rdata) for rdata in answer]
                })
            except Exception as e:
                errors.append({"domain": domain, "error": str(e)})
        
        # Запускаем конкурентные запросы
        threads = []
        start_time = time.time()
        
        for domain in domains:
            thread = threading.Thread(target=query_domain, args=(domain,))
            threads.append(thread)
            thread.start()
        
        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        success_rate = (len(results) / len(domains)) * 100
        avg_response_time = sum(r["time_ms"] for r in results) / len(results) if results else 0
        
        self.test_results.append({
            "test": "concurrent_requests",
            "total_requests": len(domains),
            "successful_requests": len(results),
            "failed_requests": len(errors),
            "success_rate": success_rate,
            "total_time_sec": total_time,
            "avg_response_time_ms": avg_response_time
        })
        
        self.log(f"Concurrent test: {len(results)}/{len(domains)} successful ({success_rate:.1f}%)")
        self.log(f"Total time: {total_time:.2f}s, Avg response: {avg_response_time:.1f}ms")
        
        if errors:
            self.log(f"Errors: {len(errors)}", "WARN")
            for error in errors[:3]:  # Показываем первые 3 ошибки
                self.log(f"  - {error['domain']}: {error['error']}", "WARN")
        
        return success_rate >= 95  # Ожидаем минимум 95% успешных запросов
    
    def test_failover_resilience(self) -> bool:
        """Тест устойчивости к failover (требует специальной конфигурации)"""
        self.log("Testing failover resilience...")
        
        # Этот тест требует запуска altdns с несколькими upstream серверами
        # где первый сервер недоступен
        
        try:
            # Пробуем несколько запросов подряд
            success_count = 0
            for i in range(10):
                try:
                    answer = self.resolver.resolve("google.com", 'A')
                    success_count += 1
                except:
                    pass
            
            failover_success_rate = (success_count / 10) * 100
            
            self.test_results.append({
                "test": "failover_resilience", 
                "success_rate": failover_success_rate,
                "note": "Requires special config with unreachable primary upstream"
            })
            
            self.log(f"Failover test: {success_count}/10 successful ({failover_success_rate:.1f}%)")
            return failover_success_rate >= 80
            
        except Exception as e:
            self.log(f"❌ Failover test failed: {str(e)}", "ERROR")
            return False
    
    def test_different_record_types(self) -> bool:
        """Тест различных типов DNS записей"""
        self.log("Testing different DNS record types...")
        
        test_cases = [
            ("google.com", "A"),
            ("google.com", "AAAA"), 
            ("google.com", "MX"),
            ("google.com", "NS"),
            ("google.com", "TXT"),
        ]
        
        success_count = 0
        for domain, record_type in test_cases:
            try:
                start_time = time.time()
                answer = self.resolver.resolve(domain, record_type)
                end_time = time.time()
                
                response_time = (end_time - start_time) * 1000
                record_count = len(answer)
                
                self.log(f"✅ {domain} {record_type}: {record_count} records ({response_time:.1f}ms)")
                success_count += 1
                
            except Exception as e:
                self.log(f"❌ {domain} {record_type}: {str(e)}", "WARN")
        
        success_rate = (success_count / len(test_cases)) * 100
        
        self.test_results.append({
            "test": "record_types",
            "success_rate": success_rate,
            "types_tested": len(test_cases),
            "types_successful": success_count
        })
        
        self.log(f"Record types test: {success_count}/{len(test_cases)} successful ({success_rate:.1f}%)")
        return success_count >= len(test_cases) - 1  # Позволяем 1 неудачу
    
    def test_server_availability(self) -> bool:
        """Тест доступности сервера"""
        self.log("Testing server availability...")
        
        try:
            # Проверяем что порт открыт
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Отправляем простой DNS запрос
            test_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
            sock.sendto(test_query, (self.server_host, self.server_port))
            
            response, addr = sock.recvfrom(512)
            sock.close()
            
            if len(response) >= 12:  # Минимальный размер DNS ответа
                self.log(f"✅ Server responding on {self.server_host}:{self.server_port}")
                
                self.test_results.append({
                    "test": "server_availability",
                    "server_responsive": True,
                    "response_size": len(response)
                })
                return True
            else:
                self.log(f"❌ Invalid response from server", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"❌ Server not available: {str(e)}", "ERROR")
            self.test_results.append({
                "test": "server_availability",
                "server_responsive": False,
                "error": str(e)
            })
            return False
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Запуск всех тестов"""
        self.log("🚀 Starting AltDns Test Suite")
        self.log("=" * 50)
        
        tests = [
            ("Server Availability", self.test_server_availability),
            ("Basic DNS Resolution", self.test_basic_resolution),
            ("Cache Performance", self.test_cache_performance), 
            ("Concurrent Requests", self.test_concurrent_requests),
            ("Different Record Types", self.test_different_record_types),
            ("Failover Resilience", self.test_failover_resilience),
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            self.log(f"\n--- {test_name} ---")
            try:
                if test_func():
                    self.log(f"✅ {test_name} PASSED", "SUCCESS")
                    passed += 1
                else:
                    self.log(f"❌ {test_name} FAILED", "FAIL")
            except Exception as e:
                self.log(f"💥 {test_name} CRASHED: {str(e)}", "ERROR")
        
        # Итоговый отчет
        self.log("\n" + "=" * 50)
        self.log(f"🏁 Test Results: {passed}/{total} tests passed ({(passed/total)*100:.1f}%)")
        
        if passed == total:
            self.log("🎉 ALL TESTS PASSED! AltDns is working perfectly! 🚀", "SUCCESS")
        elif passed >= total * 0.8:
            self.log("⚠️  Most tests passed, but some issues detected", "WARN")
        else:
            self.log("❌ Multiple test failures - check AltDns configuration", "FAIL")
        
        # Сохраняем результаты в JSON
        results_summary = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "server": f"{self.server_host}:{self.server_port}",
            "tests_passed": passed,
            "tests_total": total,
            "success_rate": (passed / total) * 100,
            "detailed_results": self.test_results
        }
        
        with open("altdns_test_results.json", "w") as f:
            json.dump(results_summary, f, indent=2)
        
        self.log("📊 Detailed results saved to altdns_test_results.json")
        
        return results_summary

def main():
    """Главная функция"""
    if len(sys.argv) > 1:
        server_host = sys.argv[1]
    else:
        server_host = "127.0.0.1"
    
    if len(sys.argv) > 2:
        server_port = int(sys.argv[2])
    else:
        server_port = 5353
    
    print(f"AltDns Test Suite")
    print(f"Testing server: {server_host}:{server_port}")
    print(f"Author: AnmiTaliDev")
    print()
    
    # Проверяем что установлен dnspython
    try:
        import dns.resolver
    except ImportError:
        print("❌ Error: dnspython not installed")
        print("Install with: pip install dnspython")
        sys.exit(1)
    
    # Запускаем тесты
    tester = AltDnsTest(server_host, server_port)
    results = tester.run_all_tests()
    
    # Возвращаем код выхода
    if results["success_rate"] >= 80:
        sys.exit(0)  # Успех
    else:
        sys.exit(1)  # Ошибка

if __name__ == "__main__":
    main()