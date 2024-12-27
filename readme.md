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

## 📥 Kurulum

Debian/Ubuntu için:
```bash
sudo dpkg -i server-monitor-0.1.0.deb
sudo apt-get install -f
```

## ⚙️ Yapılandırma

```bash
sudo server-monitor API_URL API_KEY
```

Örnek:
```bash
sudo server-monitor https://monitor.example.com zDXsaVFgNgCGmWtaQUDQC1BkjqSPTiLmPXnCcdp6EK8qPFGalM09NqG2N5d4OqcP
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
    "check_interval": 30
}
```

### Parametreler

| Parametre | Açıklama |
|-----------|-----------|
| api_url | API adresi |
| api_key | API kimlik anahtarı |
| check_interval | Veri gönderim aralığı (sn) |

## 🔒 Güvenlik Notları

* API anahtarınızı güvenli saklayın
* HTTPS kullanın
* Yapılandırma dosyası izinleri: 640

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
* jq

### Paket Oluşturma
```bash
./build.sh
```

### Hızlı Yeniden Kurulum
```bash
./rebuild.sh
```

---
Server Monitor v0.1.0 🚀