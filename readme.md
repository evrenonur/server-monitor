# 🖥️ Server Monitor - Linux Sunucu İzleme Aracı

Linux sunucularınızı uzaktan izlemek ve yönetmek için geliştirilmiş araç.

## 📊 Özellikler

* CPU, RAM ve disk kullanımı
* Ağ arayüzleri takibi
* Process yönetimi
* Servis yönetimi
* Paket güncelleme kontrolü
* Otomatik veri gönderimi
* SSL sertifika desteği
* WebSocket üzerinden uzaktan komut çalıştırma
* Docker desteği
* Dosya yönetimi


## 📥 Kurulum

Debian/Ubuntu için:
```bash
sudo dpkg -i server-monitor-0.1.0.deb
sudo apt-get install -f
```

## ⚙️ Yapılandırma

```bash
sudo server-monitor API_URL API_KEY [--port PORT]
```

Örnek:
```bash
# Varsayılan port (8765) ile:
sudo server-monitor https://monitor.example.com zDXsaVFgNgCGmWtaQUDQC1BkjqSPTiLmPXnCcdp6EK8qPFGalM09NqG2N5d4OqcP

# Özel port ile:
sudo server-monitor https://monitor.example.com zDXsaVFgNgCGmWtaQUDQC1BkjqSPTiLmPXnCcdp6EK8qPFGalM09NqG2N5d4OqcP --port 9000
```

## 🔄 Servis Yönetimi

| İşlem | Komut |
|-------|-------|
| Başlatma | `sudo systemctl start server-monitor` |
| Durdurma | `sudo systemctl stop server-monitor` |
| Durum kontrolü | `sudo systemctl status server-monitor` |
| Log görüntüleme | `sudo journalctl -u server-monitor -f` |

## 🔧 Yapılandırma Dosyası

Konum: `/etc/server-monitor/config.json`

```json
{
    "api_url": "https://monitor.example.com",
    "api_key": "your-api-key",
    "check_interval": 30,
    "ws_port": 8765
}
```

### Parametreler

| Parametre | Açıklama | Varsayılan |
|-----------|-----------|------------|
| api_url | API adresi | - |
| api_key | API kimlik anahtarı | - |
| check_interval | Veri gönderim aralığı (sn) | 30 |
| ws_port | WebSocket port numarası | 8765 |

## 🔒 Güvenlik Notları

* API anahtarınızı güvenli saklayın
* HTTPS kullanın
* Yapılandırma dosyası izinleri: 640
* WebSocket portu için güvenlik duvarı kurallarını ayarlayın
* WebSocket bağlantıları için HMAC doğrulaması kullanılır

## 🗑️ Kaldırma

```bash
sudo dpkg -P server-monitor
```

## 💻 Geliştirme

Gereksinimler:
* Python 3.8+
* python3-requests
* python3-psutil
* python3-apt
* python3-websockets
* jq

### Paket Oluşturma
```bash
./build.sh
```

### Hızlı Yeniden Kurulum
```bash
./rebuild.sh
```

## 🌐 WebSocket API Kullanımı

WebSocket üzerinden komut çalıştırmak için önce doğrulama yapmanız gerekir:

```python
import websockets
import json
import time
import hmac
import hashlib

async def send_command(api_key: str, command: str, ws_port: int = 8765):
    uri = f"ws://sunucu:{ws_port}"
    
    async with websockets.connect(uri) as websocket:
        # Doğrulama
        timestamp = str(int(time.time()))
        auth_key = hmac.new(
            api_key.encode(),
            timestamp.encode(),
            hashlib.sha256
        ).hexdigest()
        
        await websocket.send(json.dumps({
            'api_key': auth_key,
            'timestamp': timestamp
        }))
        
        # Komutu gönder
        await websocket.send(json.dumps({
            'command': command
        }))
        
        # Yanıtı al
        response = await websocket.recv()
        return json.loads(response)
```

---
Server Monitor v0.1.0 🚀