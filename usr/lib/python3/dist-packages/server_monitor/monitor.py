#!/usr/bin/env python3
import requests
import psutil
import platform
import json
import subprocess
import socket
import time
from datetime import datetime
import apt
import os
import fcntl
import sys
import logging
import asyncio
import websockets
import hmac
import hashlib
import argparse

class ServerMonitor:
    def __init__(self, api_url: str, api_key: str):
        """
        ServerMonitor sınıfını başlat
        
        Args:
            api_url: API'nin URL'i (http:// veya https:// ile başlamalı)
            api_key: API anahtarı
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.headers = {'Authorization': f'Bearer {api_key}'}
        self.verify_ssl = api_url.startswith('https://')
        self.ws_server = None
        # Varsayılan port
        self.ws_port = 8765

    def configure(self, **kwargs):
        """Ek yapılandırma parametrelerini ayarla"""
        if 'ws_port' in kwargs:
            try:
                port = int(kwargs['ws_port'])
                if 1024 <= port <= 65535:
                    self.ws_port = port
                else:
                    logging.warning(f"Geçersiz port numarası: {port}. Varsayılan port kullanılacak: 8765")
            except ValueError:
                logging.warning(f"Geçersiz port değeri: {kwargs['ws_port']}. Varsayılan port kullanılacak: 8765")

    async def verify_client(self, websocket):
        """WebSocket bağlantısı için API anahtarı doğrulaması yap"""
        try:
            auth_message = await websocket.recv()
            auth_data = json.loads(auth_message)
            
            if 'api_key' not in auth_data:
                await websocket.close(1008, 'API anahtarı gerekli')
                return False
                
            # HMAC ile API anahtarı doğrulaması
            expected_key = hmac.new(
                self.api_key.encode(),
                auth_data.get('timestamp', '').encode(),
                hashlib.sha256
            ).hexdigest()
            
            if hmac.compare_digest(auth_data['api_key'], expected_key):
                return True
            else:
                await websocket.close(1008, 'Geçersiz API anahtarı')
                return False
        except Exception as e:
            logging.error(f"Doğrulama hatası: {str(e)}")
            await websocket.close(1011, 'Doğrulama hatası')
            return False

    async def execute_command(self, command: str) -> dict:
        """Komutu root yetkisi ile çalıştır"""
        try:
            # Komutu doğrudan çalıştır (zaten root yetkisi ile çalışıyor)
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout.decode() if stdout else '',
                'stderr': stderr.decode() if stderr else '',
                'return_code': process.returncode,
                'command': command
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'command': command
            }

    async def handle_websocket(self, websocket, path):
        """WebSocket bağlantılarını yönet"""
        # İzin verilen komutlar listesi
        ALLOWED_COMMANDS = {
            'services',           # Servis listesi
            'process',           # Process listesi
            'kill',             # Process sonlandır
            'stop',             # Process durdur
            'continue',         # Process devam ettir
            'process_info',     # Process detayı
            'service_start',    # Servis başlat
            'service_stop',     # Servis durdur
            'service_restart',  # Servis yeniden başlat
            'service_status',   # Servis durumu
            'resources'         # CPU, RAM, Disk kullanımı
        }

        client = websocket.remote_address
        logging.info(f"Yeni bağlantı: {client[0]}:{client[1]}")
        
        if not await self.verify_client(websocket):
            logging.warning(f"Doğrulama başarısız: {client[0]}:{client[1]}")
            return

        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if 'command' not in data:
                        await websocket.send(json.dumps({
                            'success': False,
                            'error': 'Komut parametresi gerekli'
                        }))
                        continue

                    command = data['command']
                    
                    # Sadece izin verilen komutları çalıştır
                    if command not in ALLOWED_COMMANDS:
                        await websocket.send(json.dumps({
                            'success': False,
                            'error': 'Bu komuta izin verilmiyor',
                            'command': command
                        }))
                        logging.warning(f"İzinsiz komut denemesi ({client[0]}:{client[1]}): {command}")
                        continue

                    logging.info(f"Komut alındı ({client[0]}:{client[1]}): {command}")
                    
                    # Özel komutları kontrol et
                    if command == 'services':
                        # Servis bilgilerini al
                        result = {
                            'success': True,
                            'data': self.get_services_info(),
                            'command': command
                        }
                    elif command == 'process':
                        # Process bilgilerini al
                        result = {
                            'success': True,
                            'data': self.get_process_info(),
                            'command': command
                        }
                    elif command == 'kill':
                        # Process sonlandır
                        if 'pid' not in data:
                            result = {
                                'success': False,
                                'error': 'PID parametresi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"kill -9 {data['pid']}")
                    elif command == 'stop':
                        # Process durdur
                        if 'pid' not in data:
                            result = {
                                'success': False,
                                'error': 'PID parametresi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"kill -STOP {data['pid']}")
                    elif command == 'continue':
                        # Process devam ettir
                        if 'pid' not in data:
                            result = {
                                'success': False,
                                'error': 'PID parametresi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"kill -CONT {data['pid']}")
                    elif command == 'process_info':
                        # Tek bir process hakkında detaylı bilgi
                        if 'pid' not in data:
                            result = {
                                'success': False,
                                'error': 'PID parametresi gerekli',
                                'command': command
                            }
                        else:
                            try:
                                process = psutil.Process(int(data['pid']))
                                with process.oneshot():
                                    result = {
                                        'success': True,
                                        'data': {
                                            'pid': process.pid,
                                            'name': process.name(),
                                            'status': process.status(),
                                            'username': process.username(),
                                            'cpu_percent': process.cpu_percent(),
                                            'memory_percent': process.memory_percent(),
                                            'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                                            'cmdline': process.cmdline(),
                                            'num_threads': process.num_threads(),
                                            'memory_info': {
                                                'rss': process.memory_info().rss,
                                                'vms': process.memory_info().vms
                                            },
                                            'connections': [
                                                {
                                                    'fd': c.fd,
                                                    'family': c.family,
                                                    'type': c.type,
                                                    'laddr': c.laddr._asdict() if c.laddr else None,
                                                    'raddr': c.raddr._asdict() if c.raddr else None,
                                                    'status': c.status
                                                } for c in process.connections()
                                            ],
                                            'open_files': [f.path for f in process.open_files()],
                                            'nice': process.nice(),
                                            'ionice': process.ionice()._asdict(),
                                            'cpu_affinity': process.cpu_affinity(),
                                            'num_ctx_switches': process.num_ctx_switches()._asdict(),
                                            'ppid': process.ppid()
                                        },
                                        'command': command
                                    }
                            except psutil.NoSuchProcess:
                                result = {
                                    'success': False,
                                    'error': f'Process bulunamadı: {data["pid"]}',
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }
                    elif command == 'system':
                        # Tüm sistem bilgilerini al
                        result = {
                            'success': True,
                            'data': self.collect_system_info(),
                            'command': command
                        }
                    elif command == 'disk':
                        # Disk bilgilerini al
                        result = {
                            'success': True,
                            'data': self.get_disk_info(),
                            'command': command
                        }
                    elif command == 'network':
                        # Ağ bilgilerini al
                        result = {
                            'success': True,
                            'data': self.get_ip_addresses(),
                            'command': command
                        }
                    elif command == 'updates':
                        # Güncelleme bilgilerini al
                        result = {
                            'success': True,
                            'data': self.get_package_updates(),
                            'command': command
                        }
                    elif command == 'htop':
                        # HTOP bilgilerini al
                        result = {
                            'success': True,
                            'data': self.get_htop_info(),
                            'command': command
                        }
                    elif command == 'service_start':
                        # Servisi başlat
                        if 'name' not in data:
                            result = {
                                'success': False,
                                'error': 'Servis adı parametresi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"systemctl start {data['name']}")
                    elif command == 'service_stop':
                        # Servisi durdur
                        if 'name' not in data:
                            result = {
                                'success': False,
                                'error': 'Servis adı parametresi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"systemctl stop {data['name']}")
                    elif command == 'service_restart':
                        # Servisi yeniden başlat
                        if 'name' not in data:
                            result = {
                                'success': False,
                                'error': 'Servis adı parametresi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"systemctl restart {data['name']}")
                    elif command == 'service_status':
                        # Servis durumunu sorgula
                        if 'name' not in data:
                            result = {
                                'success': False,
                                'error': 'Servis adı parametresi gerekli',
                                'command': command
                            }
                        else:
                            status_result = await self.execute_command(f"systemctl status {data['name']}")
                            if status_result['success']:
                                # Servis durumunu ayrıştır
                                status_lines = status_result['stdout'].split('\n')
                                service_info = {
                                    'name': data['name'],
                                    'active': False,
                                    'status': 'unknown',
                                    'description': '',
                                    'loaded': False,
                                    'pid': None,
                                    'memory': '',
                                    'cpu': '',
                                    'since': '',
                                    'tasks': '',
                                    'log': []
                                }
                                
                                for line in status_lines:
                                    line = line.strip()
                                    if 'Loaded:' in line:
                                        service_info['loaded'] = 'loaded' in line.lower()
                                    elif 'Active:' in line:
                                        service_info['active'] = 'active' in line.lower()
                                        if '(' in line and ')' in line:
                                            service_info['status'] = line.split('(')[1].split(')')[0]
                                    elif 'Main PID:' in line:
                                        try:
                                            service_info['pid'] = int(line.split()[2])
                                        except:
                                            pass
                                    elif 'Memory:' in line:
                                        service_info['memory'] = line.split(':')[1].strip()
                                    elif 'CPU:' in line:
                                        service_info['cpu'] = line.split(':')[1].strip()
                                    elif 'Tasks:' in line:
                                        service_info['tasks'] = line.split(':')[1].strip()
                                    elif line.startswith('●'):
                                        service_info['description'] = line.lstrip('●').strip()
                                    elif line.startswith('Since:'):
                                        service_info['since'] = line.split(':', 1)[1].strip()
                                    elif line:
                                        service_info['log'].append(line)
                                
                                result = {
                                    'success': True,
                                    'data': service_info,
                                    'command': command
                                }
                            else:
                                result = status_result
                    elif command == 'resources':
                        # CPU, RAM ve Disk kullanım bilgilerini al
                        memory = psutil.virtual_memory()
                        result = {
                            'success': True,
                            'data': {
                                'cpu': {
                                    'cores': psutil.cpu_count(),
                                    'usage_percent': psutil.cpu_percent(interval=1)
                                },
                                'memory': {
                                    'total_gb': round(memory.total / (1024**3), 2),
                                    'used_gb': round(memory.used / (1024**3), 2),
                                    'free_gb': round(memory.free / (1024**3), 2),
                                    'usage_percent': memory.percent
                                },
                                'disks': self.get_disk_info()
                            },
                            'command': command
                        }
                    else:
                        # Normal sistem komutu çalıştır
                        result = await self.execute_command(command)
                    
                    # Sonucu gönder
                    await websocket.send(json.dumps(result))
                    
                    # Komut logunu kaydet
                    logging.info(f"Komut tamamlandı ({client[0]}:{client[1]}): {command} (Başarılı: {result['success']})")
                    
                except json.JSONDecodeError:
                    logging.error(f"Geçersiz JSON formatı ({client[0]}:{client[1]})")
                    await websocket.send(json.dumps({
                        'success': False,
                        'error': 'Geçersiz JSON formatı'
                    }))
        except websockets.exceptions.ConnectionClosed:
            logging.info(f"Bağlantı kapandı: {client[0]}:{client[1]}")
        except Exception as e:
            logging.error(f"WebSocket hatası ({client[0]}:{client[1]}): {str(e)}")
            try:
                await websocket.send(json.dumps({
                    'success': False,
                    'error': str(e)
                }))
            except:
                pass

    async def start_websocket_server(self):
        """WebSocket sunucusunu başlat"""
        try:
            # Sunucunun IP adreslerini al
            hostname = socket.gethostname()
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            logging.info(f"Sunucu IP adresleri: {ip_addresses}")
            
            # SSL bağlamı oluştur
            ssl_context = None
            if self.verify_ssl:
                import ssl
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                # SSL sertifikası varsa kullan
                if os.path.exists('/etc/server-monitor/cert.pem'):
                    ssl_context.load_cert_chain(
                        '/etc/server-monitor/cert.pem',
                        '/etc/server-monitor/key.pem'
                    )
            
            # WebSocket sunucusunu başlat
            self.ws_server = await websockets.serve(
                self.handle_websocket,
                "0.0.0.0",  # Tüm arayüzlerden bağlantı kabul et
                self.ws_port,
                ping_interval=30,
                ping_timeout=10,
                ssl=ssl_context,
                # Dış bağlantılar için gerekli ayarlar
                compression=None,
                max_size=10_485_760,  # 10MB
                max_queue=32,
                read_limit=65536,
                write_limit=65536
            )
            
            # Socket ayarlarını yapılandır
            for sock in self.ws_server.sockets:
                # IPv4 socket'lerini yapılandır
                if sock.family == socket.AF_INET:
                    # Socket seçeneklerini ayarla
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    # TCP Keepalive ayarları
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
                    
                    addr = sock.getsockname()
                    logging.info(f"WebSocket dinleniyor: {addr[0]}:{addr[1]}")
            
            logging.info(f"WebSocket sunucusu başarıyla başlatıldı - Port: {self.ws_port}")
            
            # Sunucu çalışmaya devam etsin
            while True:
                await asyncio.sleep(1)
            
        except Exception as e:
            logging.error(f"WebSocket sunucusu başlatılamadı: {str(e)}")
            raise

    def run(self):
        """Ana döngüyü başlat"""
        try:
            # Yeni event loop oluştur
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Sunucuyu çalıştır
            loop.run_until_complete(self.run_server())
            
        except Exception as e:
            logging.error(f"Ana döngü hatası: {str(e)}")
            raise
        finally:
            # Event loop'u temizle
            try:
                loop.stop()
                loop.close()
            except:
                pass

    def is_apt_locked(self):
        """APT kilit durumunu kontrol et"""
        lock_files = [
            "/var/lib/dpkg/lock",
            "/var/lib/apt/lists/lock",
            "/var/cache/apt/archives/lock",
            "/var/lib/dpkg/lock-frontend"
        ]
        
        for lock_file in lock_files:
            if os.path.exists(lock_file):
                try:
                    with open(lock_file, 'r') as f:
                        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        fcntl.flock(f, fcntl.LOCK_UN)
                except (IOError, BlockingIOError):
                    return True
        return False

    def wait_for_apt(self):
        """APT'nin serbest kalmasını bekle"""
        attempt = 1
        while self.is_apt_locked():
            print(f"APT kilitli, bekleniyor... (Deneme {attempt})")
            time.sleep(5)
            attempt += 1

    def get_ip_addresses(self):
        ip_addresses = {}
        interfaces = psutil.net_if_addrs()
        
        for interface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    ip_addresses[interface] = {
                        'ip': addr.address,
                        'netmask': addr.netmask,
                        'mac': next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
                    }
        return ip_addresses

    def get_package_updates(self):
        """Mevcut paket güncellemelerini kontrol et"""
        try:
            # APT'nin serbest olmasını bekle
            self.wait_for_apt()
            
            # Paket listesini güncelle
            subprocess.run(['apt-get', 'update'], check=True, capture_output=True)
            
            # APT cache'i aç
            cache = apt.Cache()
            cache.open()
            cache.upgrade(True)  # Dist-upgrade simülasyonu
            
            updates = []
            for pkg in cache.get_changes():
                if pkg.is_upgradable:
                    updates.append({
                        'package': pkg.name,
                        'current_version': pkg.installed.version,
                        'new_version': pkg.candidate.version,
                        'architecture': pkg.architecture(),
                        'distribution': pkg.candidate.origins[0].archive
                    })
            
            return {
                'count': len(updates),
                'packages': updates
            }
        except Exception as e:
            print(f"Güncellemeler kontrol edilirken hata: {str(e)}")
            return {'count': 0, 'packages': []}

    def get_process_info(self):
        """Sistem process bilgilerini al"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'cpu_percent': round(pinfo['cpu_percent'] or 0, 1),
                        'memory_percent': round(pinfo['memory_percent'] or 0, 1),
                        'status': pinfo['status']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                
            # CPU kullanımına göre sırala
            processes = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)
            
            return {
                'processes': processes,
                'total_processes': len(processes),
                'stats': {
                    'running': len([p for p in processes if p['status'] == 'running']),
                    'sleeping': len([p for p in processes if p['status'] == 'sleeping']),
                    'stopped': len([p for p in processes if p['status'] == 'stopped']),
                    'zombie': len([p for p in processes if p['status'] == 'zombie'])
                }
            }
        except Exception as e:
            logging.error(f"Process bilgileri alınırken hata oluştu: {str(e)}")
            return {
                'processes': [],
                'total_processes': 0,
                'stats': {
                    'running': 0,
                    'sleeping': 0,
                    'stopped': 0,
                    'zombie': 0
                }
            }

    def collect_system_info(self):
        # OS bilgilerini al
        try:
            with open('/etc/os-release') as f:
                os_info = dict(line.strip().split('=', 1) for line in f if '=' in line)
            os_version = {
                'name': os_info.get('NAME', '').strip('"'),
                'version': os_info.get('VERSION', '').strip('"'),
                'id': os_info.get('ID', '').strip('"'),
                'version_id': os_info.get('VERSION_ID', '').strip('"')
            }
        except:
            os_version = {
                'name': platform.system(),
                'version': platform.release(),
                'version_id': platform.version()
            }

        memory = psutil.virtual_memory()
        
        system_info = {
            'system': {
                'hostname': platform.node(),
                'os': os_version,
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version()
            },
            'network': {
                'interfaces': self.get_ip_addresses()
            },
            'resources': {
                'cpu': {
                    'cores': psutil.cpu_count(),
                    'usage_percent': psutil.cpu_percent(interval=1)
                },
                'memory': {
                    'total_gb': round(memory.total / (1024**3), 2),
                    'used_gb': round(memory.used / (1024**3), 2),
                    'free_gb': round(memory.free / (1024**3), 2),
                    'usage_percent': memory.percent
                },
                'disks': self.get_disk_info()
            },
            'timestamp': datetime.now().isoformat(),
            'updates': self.get_package_updates(),
            'processes': self.get_process_info(),
            'services': self.get_services_info()
        }
        
        return system_info

    def get_disk_info(self):
        """Disk kullanım bilgilerini al"""
        disks = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'total_gb': round(usage.total / (1024**3), 2),
                    'used_gb': round(usage.used / (1024**3), 2),
                    'free_gb': round(usage.free / (1024**3), 2),
                    'usage_percent': round(usage.percent, 1)
                })
            except:
                continue
        return disks

    def send_system_info(self):
        """Sistem bilgilerini API'ye gönder ve config'deki süre kadar bekle"""
        try:
            system_info = self.collect_system_info()
            response = requests.post(
                f"{self.api_url}/api/system-info",
                headers=self.headers,
                json=system_info,
                verify=False if self.api_url.startswith('https://') else True
            )
            logging.info(f"Bilgiler gönderildi: {response.status_code}")
            return True
        except Exception as e:
            logging.error(f"Sistem bilgileri gönderilemedi: {str(e)}")
            return False

    async def start_system_info_loop(self):
        """Sistem bilgilerini periyodik olarak gönder"""
        while True:
            try:
                # Config dosyasını oku
                with open('/etc/server-monitor/config.json', 'r') as f:
                    config = json.load(f)
                
                # Sistem bilgilerini gönder
                self.send_system_info()
                
                # Config'deki süre kadar bekle
                await asyncio.sleep(config.get('check_interval', 30))
            except Exception as e:
                logging.error(f"Sistem bilgisi gönderme döngüsü hatası: {str(e)}")
                await asyncio.sleep(5)  # Hata durumunda 5 saniye bekle

    async def run_server(self):
        """WebSocket sunucusunu ve sistem bilgisi gönderme döngüsünü başlat"""
        try:
            # Her iki görevi de başlat
            await asyncio.gather(
                self.start_websocket_server(),
                self.start_system_info_loop()
            )
        except Exception as e:
            logging.error(f"Sunucu çalıştırma hatası: {str(e)}")
            raise

    def get_htop_info(self):
        """htop bilgilerini al"""
        try:
            # Önce htop'un yüklü olup olmadığını kontrol et
            if subprocess.run(['which', 'htop'], capture_output=True).returncode == 0:
                htop_info = subprocess.check_output(['htop', '-b', '-d', '1']).decode('utf-8')
                return htop_info
            else:
                logging.warning("htop yüklü değil. htop bilgileri alınamadı.")
                return "htop not installed"
        except Exception as e:
            logging.error(f"htop bilgileri alınırken hata oluştu: {str(e)}")
            return "htop error"

    def get_services_info(self):
        """Systemd servis bilgilerini al"""
        try:
            # systemctl list-units --type=service komutu ile servisleri listele
            cmd = ['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--no-legend', '--plain']
            output = subprocess.check_output(cmd, universal_newlines=True)
            
            services = []
            for line in output.splitlines():
                # Her satırı parçalara ayır ve Unicode karakterleri temizle
                parts = [part.strip() for part in line.strip().split(maxsplit=4) if part.strip()]
                if len(parts) >= 4:
                    service_name = parts[0].replace('●', '').strip()  # Unicode karakteri kaldır
                    if not service_name.endswith('.service'):
                        continue
                        
                    load_state = parts[1]
                    active_state = parts[2]
                    sub_state = parts[3]
                    description = parts[4] if len(parts) > 4 else ''
                    
                    # Servis detaylarını al
                    try:
                        cmd_status = ['systemctl', 'show', service_name]
                        status_output = subprocess.check_output(cmd_status, universal_newlines=True)
                        
                        details = {}
                        for status_line in status_output.splitlines():
                            if '=' in status_line:
                                key, value = status_line.split('=', 1)
                                details[key] = value
                        
                        services.append({
                            'name': service_name,
                            'load_state': load_state,
                            'active_state': active_state,
                            'sub_state': sub_state,
                            'description': description or details.get('Description', ''),
                            'main_pid': details.get('MainPID', '0'),
                            'load_error': details.get('LoadError', ''),
                            'fragment_path': details.get('FragmentPath', '')
                        })
                    except subprocess.CalledProcessError:
                        continue
                    
            return {
                'total_services': len(services),
                'services': services,
                'stats': {
                    'active': len([s for s in services if s['active_state'] == 'active']),
                    'inactive': len([s for s in services if s['active_state'] == 'inactive']),
                    'failed': len([s for s in services if s['active_state'] == 'failed'])
                }
            }
        except Exception as e:
            logging.error(f"Servis bilgileri alınırken hata oluştu: {str(e)}")
            return {
                'total_services': 0,
                'services': [],
                'stats': {
                    'active': 0,
                    'inactive': 0,
                    'failed': 0
                }
            }

def main():
    """Ana program döngüsü"""
    # Argüman parser'ı oluştur
    parser = argparse.ArgumentParser(
        description='Server Monitor - Linux Sunucu İzleme Aracı',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Zorunlu argümanlar
    parser.add_argument(
        'api_url',
        type=str,
        help='API URL (örn: https://monitor.example.com)'
    )
    
    parser.add_argument(
        'api_key',
        type=str,
        help='API Anahtarı'
    )
    
    # Opsiyonel argümanlar
    parser.add_argument(
        '--port',
        '-p',
        type=int,
        default=8765,
        dest='ws_port',
        help='WebSocket port numarası'
    )
    
    # Argümanları ayrıştır
    args = parser.parse_args()
    
    # Port numarasını kontrol et
    if not (1024 <= args.ws_port <= 65535):
        parser.error(f"Port numarası 1024-65535 arasında olmalıdır: {args.ws_port}")
    
    # Loglama ayarlarını yapılandır
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Yapılandırma dosyasını oluştur
        config = {
            'api_url': args.api_url,
            'api_key': args.api_key,
            'check_interval': 30,
            'ws_port': args.ws_port
        }
        
        # Config dizini yoksa oluştur
        os.makedirs('/etc/server-monitor', exist_ok=True)
        
        # İlk konfigürasyon mu kontrol et
        is_first_config = not os.path.exists('/etc/server-monitor/config.json')
        
        # Config dosyasını kaydet
        with open('/etc/server-monitor/config.json', 'w') as f:
            json.dump(config, f, indent=4)
            logging.info(f"Yapılandırma kaydedildi: {config}")
        
        # İlk konfigürasyon ise UFW kuralını ekle
        if is_first_config:
            try:
                # UFW'nin yüklü olup olmadığını kontrol et
                if subprocess.run(['which', 'ufw'], capture_output=True).returncode == 0:
                    # UFW kuralını ekle
                    subprocess.run(['ufw', 'allow', f'{args.ws_port}/tcp', 'comment', 'Server Monitor WebSocket'], check=True)
                    logging.info(f"UFW kuralı eklendi: port {args.ws_port}/tcp")
            except Exception as e:
                logging.error(f"UFW kuralı eklenirken hata oluştu: {str(e)}")
        
        # Monitor nesnesini oluştur
        monitor = ServerMonitor(
            config['api_url'],
            config['api_key']
        )
        
        # WebSocket port yapılandırması
        monitor.configure(ws_port=config['ws_port'])
        
        # Ana döngüyü başlat
        monitor.run()
                
    except Exception as e:
        logging.error(f"Hata oluştu: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 