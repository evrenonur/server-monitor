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

class ServerMonitor:
    def __init__(self, api_url: str, api_key: str):
        if not api_url.startswith(('http://', 'https://')):
            api_url = 'https://' + api_url
        self.api_url = api_url.rstrip('/')
        self.headers = {'Authorization': f'Bearer {api_key}'}

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
            'updates': self.get_package_updates()
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
                f"{self.api_url}/system-info",
                headers=self.headers,
                json=system_info
            )
            print(f"Bilgiler gönderildi: {response.status_code}")
            return True
        except Exception as e:
            print(f"Hata oluştu: {str(e)}")
            return False

def main():
    while True:
        try:
            with open('/etc/server-monitor/config.json', 'r') as f:
                config = json.load(f)
            
            monitor = ServerMonitor(
                config['api_url'],
                config['api_key']
            )
            monitor.send_system_info()
            
            interval = config.get('check_interval', 300)
            time.sleep(interval)
            
        except Exception as e:
            print(f"Hata oluştu: {str(e)}")
            time.sleep(60)

if __name__ == '__main__':
    main() 