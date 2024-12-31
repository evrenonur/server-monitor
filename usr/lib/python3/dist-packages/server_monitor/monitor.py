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
import shutil
import fnmatch
import base64
import magic
import pwd
import grp

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
        """WebSocket bağlantısı için API üzerinden token doğrulaması yap"""
        try:
            # URL'den token'ı al
            query_string = websocket.path.split('?')[-1]
            params = dict(param.split('=') for param in query_string.split('&')) if '?' in websocket.path else {}
            token = params.get('token')
            
            if not token:
                await websocket.close(1008, 'Token gerekli')
                return False
                
            # API'den token doğrulaması
            try:
                response = requests.get(
                    f"{self.api_url}/api/validate-token",
                    headers={'Authorization': f"Bearer {token}"},
                    verify=False if self.api_url.startswith('https://') else True
                )
                
                if response.status_code == 200 and response.json().get('valid'):
                    return True
                else:
                    await websocket.close(1008, 'Geçersiz token')
                    return False
                    
            except Exception as e:
                logging.error(f"Token doğrulama hatası: {str(e)}")
                await websocket.close(1011, 'Token doğrulama hatası')
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
            'resources',        # CPU, RAM, Disk kullanımı
            'docker-resources', # Docker bilgileri
            'docker-images',    # Docker imajları
            'docker-volumes',   # Docker volume'leri
            'docker-start',     # Container başlat
            'docker-stop',      # Container durdur
            'docker-restart',   # Container yeniden başlat
            'docker-remove',    # Container sil
            'docker-pause',     # Container duraklat
            'docker-unpause',   # Container devam ettir
            'docker-image-pull',    # Docker imajı çek
            'docker-image-remove',  # Docker imajı sil
            'docker-image-tag',     # Docker imajı etiketle
            'docker-image-inspect', # Docker imajı incele
            'docker-volume-create', # Docker volume oluştur
            'docker-volume-remove', # Docker volume sil
            'docker-volume-inspect',# Docker volume incele
            'docker-volume-prune',  # Kullanılmayan volume'leri temizle
            'file-list',           # Dizin içeriğini listele
            'file-info',           # Dosya bilgilerini getir
            'file-read',           # Dosya içeriğini oku
            'file-write',          # Dosya içeriğini yaz/güncelle
            'file-delete',         # Dosya/dizin sil
            'file-move',           # Dosya/dizin taşı
            'file-copy',           # Dosya/dizin kopyala
            'file-chmod',          # Dosya/dizin izinlerini değiştir
            'file-chown',          # Dosya/dizin sahibini değiştir
            'file-mkdir',          # Yeni dizin oluştur
            'file-search',         # Dosya/dizin ara
            'file-download',       # Dosya indir (base64)
            'file-upload',         # Dosya yükle (base64)
            'file-exists'          # Dosya/dizin varlık kontrolü
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
                    elif command == 'docker-resources':
                        # Docker bilgilerini al
                        result = {
                            'success': True,
                            'data': self.get_docker_info(),
                            'command': command
                        }
                    elif command == 'docker-images':
                        # Docker imajlarını al
                        result = {
                            'success': True,
                            'data': self.get_docker_images(),
                            'command': command
                        }
                    elif command == 'docker-volumes':
                        # Docker volume'lerini al
                        result = {
                            'success': True,
                            'data': self.get_docker_volumes(),
                            'command': command
                        }
                    elif command == 'docker-start':
                        # Container'ı başlat
                        if 'container' not in data:
                            result = {
                                'success': False,
                                'error': 'Container ID veya ismi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"docker start {data['container']}")
                    elif command == 'docker-stop':
                        # Container'ı durdur
                        if 'container' not in data:
                            result = {
                                'success': False,
                                'error': 'Container ID veya ismi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"docker stop {data['container']}")
                    elif command == 'docker-restart':
                        # Container'ı yeniden başlat
                        if 'container' not in data:
                            result = {
                                'success': False,
                                'error': 'Container ID veya ismi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"docker restart {data['container']}")
                    elif command == 'docker-remove':
                        # Container'ı sil
                        if 'container' not in data:
                            result = {
                                'success': False,
                                'error': 'Container ID veya ismi gerekli',
                                'command': command
                            }
                        else:
                            # Önce container'ı durdur, sonra sil
                            await self.execute_command(f"docker stop {data['container']}")
                            result = await self.execute_command(f"docker rm {data['container']}")
                    elif command == 'docker-pause':
                        # Container'ı duraklat
                        if 'container' not in data:
                            result = {
                                'success': False,
                                'error': 'Container ID veya ismi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"docker pause {data['container']}")
                    elif command == 'docker-unpause':
                        # Container'ı devam ettir
                        if 'container' not in data:
                            result = {
                                'success': False,
                                'error': 'Container ID veya ismi gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"docker unpause {data['container']}")
                    elif command == 'docker-image-pull':
                        # Docker imajı çek
                        if 'image' not in data:
                            result = {
                                'success': False,
                                'error': 'İmaj adı gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"docker pull {data['image']}")
                    elif command == 'docker-image-remove':
                        # Docker imajı sil
                        if 'image' not in data:
                            result = {
                                'success': False,
                                'error': 'İmaj adı veya ID\'si gerekli',
                                'command': command
                            }
                        else:
                            # Önce imajı kullanan container'ları kontrol et
                            check_containers = await self.execute_command(f"docker ps -a --filter ancestor={data['image']} --format '{{{{.ID}}}}'")
                            if check_containers['stdout'].strip():
                                result = {
                                    'success': False,
                                    'error': 'Bu imaj kullanımda olan container\'lar var. Önce container\'ları silmelisiniz.',
                                    'containers': check_containers['stdout'].strip().split('\n'),
                                    'command': command
                                }
                            else:
                                # Force parametresi varsa zorla sil
                                force_param = '--force' if data.get('force') else ''
                                result = await self.execute_command(f"docker rmi {force_param} {data['image']}")
                    elif command == 'docker-image-tag':
                        # Docker imajı etiketle
                        if 'source' not in data or 'target' not in data:
                            result = {
                                'success': False,
                                'error': 'Kaynak ve hedef etiketler gerekli',
                                'command': command
                            }
                        else:
                            result = await self.execute_command(f"docker tag {data['source']} {data['target']}")
                    elif command == 'docker-image-inspect':
                        # Docker imajı detaylı inceleme
                        if 'image' not in data:
                            result = {
                                'success': False,
                                'error': 'İmaj adı veya ID\'si gerekli',
                                'command': command
                            }
                        else:
                            inspect_result = await self.execute_command(f"docker image inspect {data['image']}")
                            if inspect_result['success']:
                                try:
                                    # JSON çıktısını parse et
                                    inspect_data = json.loads(inspect_result['stdout'])
                                    result = {
                                        'success': True,
                                        'data': inspect_data,
                                        'command': command
                                    }
                                except json.JSONDecodeError:
                                    result = {
                                        'success': False,
                                        'error': 'İmaj detayları alınamadı',
                                        'command': command
                                    }
                            else:
                                result = inspect_result
                    elif command == 'docker-volume-create':
                        # Docker volume oluştur
                        if 'name' not in data:
                            result = {
                                'success': False,
                                'error': 'Volume adı gerekli',
                                'command': command
                            }
                        else:
                            # Opsiyonel parametreler
                            driver = f"--driver {data['driver']}" if 'driver' in data else ''
                            opts = ''
                            if 'opts' in data and isinstance(data['opts'], dict):
                                for key, value in data['opts'].items():
                                    opts += f" --opt {key}={value}"
                            
                            labels = ''
                            if 'labels' in data and isinstance(data['labels'], dict):
                                for key, value in data['labels'].items():
                                    labels += f" --label {key}={value}"
                            
                            result = await self.execute_command(
                                f"docker volume create {driver}{opts}{labels} {data['name']}"
                            )
                    
                    elif command == 'docker-volume-remove':
                        # Docker volume sil
                        if 'name' not in data:
                            result = {
                                'success': False,
                                'error': 'Volume adı gerekli',
                                'command': command
                            }
                        else:
                            # Önce volume'ü kullanan container'ları kontrol et
                            check_containers = await self.execute_command(
                                f"docker ps -a --filter volume={data['name']} --format '{{{{.ID}}}}'"
                            )
                            if check_containers['stdout'].strip():
                                result = {
                                    'success': False,
                                    'error': 'Bu volume kullanımda olan container\'lar var. Önce container\'ları silmelisiniz.',
                                    'containers': check_containers['stdout'].strip().split('\n'),
                                    'command': command
                                }
                            else:
                                # Force parametresi varsa zorla sil
                                force_param = '--force' if data.get('force') else ''
                                result = await self.execute_command(f"docker volume rm {force_param} {data['name']}")
                    
                    elif command == 'docker-volume-inspect':
                        # Docker volume detaylı inceleme
                        if 'name' not in data:
                            result = {
                                'success': False,
                                'error': 'Volume adı gerekli',
                                'command': command
                            }
                        else:
                            inspect_result = await self.execute_command(f"docker volume inspect {data['name']}")
                            if inspect_result['success']:
                                try:
                                    # JSON çıktısını parse et
                                    inspect_data = json.loads(inspect_result['stdout'])
                                    result = {
                                        'success': True,
                                        'data': inspect_data,
                                        'command': command
                                    }
                                except json.JSONDecodeError:
                                    result = {
                                        'success': False,
                                        'error': 'Volume detayları alınamadı',
                                        'command': command
                                    }
                            else:
                                result = inspect_result
                    
                    elif command == 'docker-volume-prune':
                        # Kullanılmayan volume'leri temizle
                        force_param = '--force' if data.get('force') else ''
                        result = await self.execute_command(f"docker volume prune {force_param}")
                    elif command == 'file-list':
                        # Dizin içeriğini listele
                        if 'path' not in data:
                            result = {
                                'success': False,
                                'error': 'Dizin yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                items = []
                                for item in os.listdir(path):
                                    item_path = os.path.join(path, item)
                                    stat = os.stat(item_path)
                                    items.append({
                                        'name': item,
                                        'path': item_path,
                                        'type': 'directory' if os.path.isdir(item_path) else 'file',
                                        'size': stat.st_size,
                                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                                        'permissions': oct(stat.st_mode)[-3:],
                                        'owner': stat.st_uid,
                                        'group': stat.st_gid
                                    })
                                result = {
                                    'success': True,
                                    'data': {
                                        'path': path,
                                        'items': items
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-info':
                        # Dosya bilgilerini getir
                        if 'path' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                stat = os.stat(path)
                                result = {
                                    'success': True,
                                    'data': {
                                        'name': os.path.basename(path),
                                        'path': path,
                                        'type': 'directory' if os.path.isdir(path) else 'file',
                                        'size': stat.st_size,
                                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                                        'permissions': oct(stat.st_mode)[-3:],
                                        'owner': stat.st_uid,
                                        'group': stat.st_gid,
                                        'is_symlink': os.path.islink(path),
                                        'mimetype': magic.from_file(path, mime=True) if os.path.isfile(path) else None
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-read':
                        # Dosya içeriğini oku
                        if 'path' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                if not os.path.isfile(path):
                                    result = {
                                        'success': False,
                                        'error': 'Belirtilen yol bir dosya değil',
                                        'command': command
                                    }
                                else:
                                    with open(path, 'rb') as f:
                                        content = f.read()
                                        # Base64 encode binary content
                                        content_b64 = base64.b64encode(content).decode('utf-8')
                                        result = {
                                            'success': True,
                                            'data': {
                                                'path': path,
                                                'size': len(content),
                                                'content': content_b64,
                                                'encoding': 'base64'
                                            },
                                            'command': command
                                        }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-write':
                        # Dosya içeriğini yaz/güncelle
                        if 'path' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                mode = int(str(data.get('mode', '0644')), 8)
                                
                                # Üst dizini oluştur
                                os.makedirs(os.path.dirname(path), exist_ok=True)
                                
                                # İçeriği decode et
                                content = b''
                                if 'content' in data:
                                    content = base64.b64decode(data['content'])
                                
                                # Dosyayı yaz
                                write_mode = 'ab' if data.get('append', False) else 'wb'
                                with open(path, write_mode) as f:
                                    f.write(content)
                                
                                # İzinleri ayarla
                                os.chmod(path, mode)
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'path': path,
                                        'size': len(content),
                                        'mode': oct(mode)[2:]
                                    },
                                    'command': command
                                }
                            except PermissionError:
                                result = {
                                    'success': False,
                                    'error': f'Dosya oluşturmak/güncellemek için yetkiniz yok: {path}',
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-delete':
                        # Dosya/dizin sil
                        if 'path' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya/dizin yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                if os.path.isdir(path):
                                    if data.get('recursive', False):
                                        shutil.rmtree(path)
                                    else:
                                        os.rmdir(path)
                                else:
                                    os.remove(path)
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'path': path,
                                        'type': 'directory' if os.path.isdir(path) else 'file'
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-move':
                        # Dosya/dizin taşı
                        if 'source' not in data or 'target' not in data:
                            result = {
                                'success': False,
                                'error': 'Kaynak ve hedef yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                source = os.path.abspath(data['source'])
                                target = os.path.abspath(data['target'])
                                shutil.move(source, target)
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'source': source,
                                        'target': target
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-copy':
                        # Dosya/dizin kopyala
                        if 'source' not in data or 'target' not in data:
                            result = {
                                'success': False,
                                'error': 'Kaynak ve hedef yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                source = os.path.abspath(data['source'])
                                target = os.path.abspath(data['target'])
                                
                                if os.path.isdir(source):
                                    shutil.copytree(source, target)
                                else:
                                    shutil.copy2(source, target)
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'source': source,
                                        'target': target
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-chmod':
                        # Dosya/dizin izinlerini değiştir
                        if 'path' not in data or 'mode' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya yolu ve izin modu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                mode = int(str(data['mode']), 8)
                                os.chmod(path, mode)
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'path': path,
                                        'mode': oct(mode)[2:]
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-chown':
                        # Dosya/dizin sahibini değiştir
                        if 'path' not in data or 'user' not in data or 'group' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya yolu, kullanıcı ve grup bilgisi gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                uid = pwd.getpwnam(data['user']).pw_uid
                                gid = grp.getgrnam(data['group']).gr_gid
                                os.chown(path, uid, gid)
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'path': path,
                                        'user': data['user'],
                                        'group': data['group']
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-mkdir':
                        # Yeni dizin oluştur
                        if 'path' not in data:
                            result = {
                                'success': False,
                                'error': 'Dizin yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                mode = int(str(data.get('mode', '0755')), 8)
                                
                                # Eğer bu yolda bir dosya varsa hata ver
                                if os.path.isfile(path):
                                    result = {
                                        'success': False,
                                        'error': f'Bu yolda bir dosya var: {path}',
                                        'command': command
                                    }
                                # Eğer bu yolda bir dizin varsa ve exist_ok false ise hata ver
                                elif os.path.isdir(path) and not data.get('exist_ok', False):
                                    result = {
                                        'success': False,
                                        'error': f'Bu yolda bir dizin var: {path}',
                                        'command': command
                                    }
                                # Dizin yoksa veya exist_ok true ise oluştur
                                else:
                                    os.makedirs(path, mode=mode, exist_ok=data.get('exist_ok', False))
                                    result = {
                                        'success': True,
                                        'data': {
                                            'path': path,
                                            'mode': oct(mode)[2:]
                                        },
                                        'command': command
                                    }
                            except PermissionError:
                                result = {
                                    'success': False,
                                    'error': f'Klasör oluşturmak için yetkiniz yok: {path}',
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-search':
                        # Dosya/dizin ara
                        if 'path' not in data or 'pattern' not in data:
                            result = {
                                'success': False,
                                'error': 'Arama yolu ve deseni gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                pattern = data['pattern']
                                recursive = data.get('recursive', True)
                                
                                matches = []
                                if recursive:
                                    for root, dirs, files in os.walk(path):
                                        for item in dirs + files:
                                            if fnmatch.fnmatch(item, pattern):
                                                item_path = os.path.join(root, item)
                                                stat = os.stat(item_path)
                                                matches.append({
                                                    'name': item,
                                                    'path': item_path,
                                                    'type': 'directory' if os.path.isdir(item_path) else 'file',
                                                    'size': stat.st_size,
                                                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                                                })
                                else:
                                    for item in os.listdir(path):
                                        if fnmatch.fnmatch(item, pattern):
                                            item_path = os.path.join(path, item)
                                            stat = os.stat(item_path)
                                            matches.append({
                                                'name': item,
                                                'path': item_path,
                                                'type': 'directory' if os.path.isdir(item_path) else 'file',
                                                'size': stat.st_size,
                                                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                                            })
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'path': path,
                                        'pattern': pattern,
                                        'matches': matches
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-download':
                        # Dosya indir
                        if 'path' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                if not os.path.isfile(path):
                                    result = {
                                        'success': False,
                                        'error': 'Belirtilen yol bir dosya değil',
                                        'command': command
                                    }
                                else:
                                    with open(path, 'rb') as f:
                                        content = f.read()
                                        content_b64 = base64.b64encode(content).decode('utf-8')
                                        result = {
                                            'success': True,
                                            'data': {
                                                'name': os.path.basename(path),
                                                'path': path,
                                                'size': len(content),
                                                'content': content_b64,
                                                'encoding': 'base64'
                                            },
                                            'command': command
                                        }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }

                    elif command == 'file-upload':
                        # Dosya yükle
                        if 'path' not in data or 'content' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya yolu ve içerik gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                content = base64.b64decode(data['content'])
                                
                                os.makedirs(os.path.dirname(path), exist_ok=True)
                                with open(path, 'wb') as f:
                                    f.write(content)
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'path': path,
                                        'size': len(content)
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }
                    
                    elif command == 'file-exists':
                        # Dosya/dizin varlık kontrolü
                        if 'path' not in data:
                            result = {
                                'success': False,
                                'error': 'Dosya/dizin yolu gerekli',
                                'command': command
                            }
                        else:
                            try:
                                path = os.path.abspath(data['path'])
                                exists = os.path.exists(path)
                                is_file = os.path.isfile(path) if exists else False
                                is_dir = os.path.isdir(path) if exists else False
                                is_link = os.path.islink(path) if exists else False
                                
                                result = {
                                    'success': True,
                                    'data': {
                                        'exists': exists,
                                        'path': path,
                                        'type': 'file' if is_file else ('directory' if is_dir else ('link' if is_link else None)),
                                        'is_file': is_file,
                                        'is_dir': is_dir,
                                        'is_link': is_link,
                                        'readable': os.access(path, os.R_OK) if exists else False,
                                        'writable': os.access(path, os.W_OK) if exists else False,
                                        'executable': os.access(path, os.X_OK) if exists else False
                                    },
                                    'command': command
                                }
                            except Exception as e:
                                result = {
                                    'success': False,
                                    'error': str(e),
                                    'command': command
                                }
                    
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

    def get_docker_info(self):
        """Docker bilgilerini al"""
        try:
            # Docker çalışıyor mu kontrol et
            docker_ps = subprocess.run(['docker', 'ps', '-a', '--format', '{{json .}}'], capture_output=True, text=True)
            if docker_ps.returncode != 0:
                return {
                    'error': 'Docker servis durumu kontrol edilemiyor',
                    'running': False
                }

            # Docker sistem bilgilerini al
            docker_info = subprocess.run(['docker', 'info', '--format', '{{json .}}'], capture_output=True, text=True)
            info = json.loads(docker_info.stdout) if docker_info.returncode == 0 else {}

            # Tüm container'ları al (çalışan, durmuş, vs.)
            containers = []
            if docker_ps.stdout:
                for line in docker_ps.stdout.strip().split('\n'):
                    if line:
                        container = json.loads(line)
                        # Container detaylarını al
                        container_inspect = subprocess.run(
                            ['docker', 'inspect', container['ID']], 
                            capture_output=True, text=True
                        )
                        if container_inspect.returncode == 0:
                            details = json.loads(container_inspect.stdout)[0]
                            container['Created'] = details.get('Created')
                            container['State'] = details.get('State', {})
                            container['Config'] = {
                                'Image': details.get('Config', {}).get('Image'),
                                'Cmd': details.get('Config', {}).get('Cmd'),
                                'Entrypoint': details.get('Config', {}).get('Entrypoint'),
                                'Env': details.get('Config', {}).get('Env'),
                                'Labels': details.get('Config', {}).get('Labels')
                            }
                            container['NetworkSettings'] = {
                                'IPAddress': details.get('NetworkSettings', {}).get('IPAddress'),
                                'Ports': details.get('NetworkSettings', {}).get('Ports'),
                                'Networks': details.get('NetworkSettings', {}).get('Networks')
                            }
                            container['Mounts'] = details.get('Mounts', [])
                            
                            # Eğer container çalışıyorsa stats'ları al
                            if container['State'].get('Running'):
                                container_stats = subprocess.run(
                                    ['docker', 'stats', container['ID'], '--no-stream', '--format', '{{json .}}'],
                                    capture_output=True, text=True
                                )
                                if container_stats.returncode == 0 and container_stats.stdout:
                                    stats = json.loads(container_stats.stdout)
                                    container['stats'] = stats
                            else:
                                container['stats'] = None

                        containers.append(container)

            # Docker disk kullanımı
            docker_df = subprocess.run(['docker', 'system', 'df', '--format', '{{json .}}'], capture_output=True, text=True)
            disk_usage = []
            if docker_df.returncode == 0:
                for line in docker_df.stdout.strip().split('\n'):
                    if line:
                        disk_usage.append(json.loads(line))

            return {
                'running': True,
                'version': info.get('ServerVersion', 'unknown'),
                'containers': {
                    'total': info.get('Containers', 0),
                    'running': info.get('ContainersRunning', 0),
                    'paused': info.get('ContainersPaused', 0),
                    'stopped': info.get('ContainersStopped', 0)
                },
                'images': info.get('Images', 0),
                'driver': info.get('Driver', 'unknown'),
                'memory_limit': info.get('MemoryLimit', False),
                'swap_limit': info.get('SwapLimit', False),
                'kernel_version': info.get('KernelVersion', 'unknown'),
                'operating_system': info.get('OperatingSystem', 'unknown'),
                'cpu_count': info.get('NCPU', 0),
                'total_memory': info.get('MemTotal', 0),
                'disk_usage': disk_usage,
                'all_containers': containers  # Tüm container'lar burada
            }
        except Exception as e:
            logging.error(f"Docker bilgileri alınırken hata oluştu: {str(e)}")
            return {
                'error': str(e),
                'running': False
            }

    def get_docker_images(self):
        """Docker imajlarını listele"""
        try:
            # Docker imajlarını al
            images = subprocess.run(['docker', 'images', '--format', '{{json .}}'], capture_output=True, text=True)
            if images.returncode != 0:
                return {
                    'error': 'Docker imajları listelenemiyor',
                    'success': False
                }

            image_list = []
            if images.stdout:
                for line in images.stdout.strip().split('\n'):
                    if line:
                        image = json.loads(line)
                        # İmaj detaylarını al
                        image_inspect = subprocess.run(
                            ['docker', 'image', 'inspect', image['ID']], 
                            capture_output=True, text=True
                        )
                        if image_inspect.returncode == 0:
                            details = json.loads(image_inspect.stdout)[0]
                            image['Created'] = details.get('Created')
                            image['Architecture'] = details.get('Architecture')
                            image['Os'] = details.get('Os')
                            image['Author'] = details.get('Author', '')
                            image['Labels'] = details.get('Config', {}).get('Labels', {})
                        
                        image_list.append(image)

            return {
                'success': True,
                'images': image_list,
                'total': len(image_list)
            }
        except Exception as e:
            logging.error(f"Docker imajları alınırken hata oluştu: {str(e)}")
            return {
                'error': str(e),
                'success': False
            }

    def get_docker_volumes(self):
        """Docker volume'lerini listele"""
        try:
            # Docker volume'lerini al
            volumes = subprocess.run(['docker', 'volume', 'ls', '--format', '{{json .}}'], capture_output=True, text=True)
            if volumes.returncode != 0:
                return {
                    'error': 'Docker volume\'leri listelenemiyor',
                    'success': False
                }

            volume_list = []
            if volumes.stdout:
                for line in volumes.stdout.strip().split('\n'):
                    if line:
                        volume = json.loads(line)
                        # Volume detaylarını al
                        volume_inspect = subprocess.run(
                            ['docker', 'volume', 'inspect', volume['Name']], 
                            capture_output=True, text=True
                        )
                        if volume_inspect.returncode == 0:
                            details = json.loads(volume_inspect.stdout)[0]
                            volume['Driver'] = details.get('Driver')
                            volume['Mountpoint'] = details.get('Mountpoint')
                            volume['Labels'] = details.get('Labels', {})
                            volume['Options'] = details.get('Options', {})
                            volume['Scope'] = details.get('Scope')
                        
                        volume_list.append(volume)

            return {
                'success': True,
                'volumes': volume_list,
                'total': len(volume_list)
            }
        except Exception as e:
            logging.error(f"Docker volume'leri alınırken hata oluştu: {str(e)}")
            return {
                'error': str(e),
                'success': False
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