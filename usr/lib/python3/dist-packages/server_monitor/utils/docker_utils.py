#!/usr/bin/env python3
import subprocess
import json
import logging
import asyncio


def get_docker_info():
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

def get_docker_images():
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

def get_docker_volumes():
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

async def execute_docker_command(command: str) -> dict:
    """Docker komutunu çalıştır ve sonucu döndür"""
    try:
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