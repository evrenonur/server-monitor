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

class ServerMonitor:
    def __init__(self, api_url: str, api_key: str):
        """
        ServerMonitor sınıfını başlat
        
        Args:
            api_url: API'nin URL'i (http:// veya https:// ile başlamalı)
            api_key: API anahtarı
        """
        # URL şemasını otomatik eklemeyi kaldır
        self.api_url = api_url.rstrip('/')
        self.headers = {'Authorization': f'Bearer {api_key}'}
        # SSL doğrulamasını devre dışı bırak
        self.verify_ssl = api_url.startswith('https://')

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
        try:
            system_info = self.collect_system_info()
            response = requests.post(
                f"{self.api_url}/api/system-info",
                headers=self.headers,
                json=system_info,
                verify=False if self.api_url.startswith('https://') else True  # HTTPS için SSL doğrulamasını devre dışı bırak
            )
            logging.info(f"Bilgiler gönderildi: {response.status_code}")
            return True
        except Exception as e:
            logging.error(f"Sistem bilgileri gönderilemedi: {str(e)}")
            return False
    
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
    # Loglama ayarlarını yapılandır
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Yapılandırma dosyasını oku
        with open('/etc/server-monitor/config.json', 'r') as f:
            config = json.load(f)
            logging.info(f"Yapılandırma yüklendi: {config}")
        
        # Gerekli yapılandırma var mı kontrol et
        if not config.get('api_url') or not config.get('api_key'):
            logging.error("API URL ve API Key yapılandırılmamış!")
            sys.exit(1)
        
        # Monitor nesnesini oluştur
        monitor = ServerMonitor(
            config['api_url'],
            config['api_key']
        )
        
        # Ana döngü
        while True:
            try:
                logging.debug("Sistem bilgileri gönderiliyor...")
                monitor.send_system_info()
                logging.info("Sistem bilgileri başarıyla gönderildi")
                time.sleep(config.get('check_interval', 300))
            except Exception as e:
                logging.error(f"Hata oluştu: {str(e)}", exc_info=True)
                time.sleep(60)
                
    except FileNotFoundError:
        logging.error("Yapılandırma dosyası bulunamadı!")
        sys.exit(1)

if __name__ == '__main__':
    main() 