#!/bin/bash

# Mevcut paketi kaldır
echo "Mevcut paketi kaldırılıyor..."
sudo dpkg -P server-monitor
sudo rm -rf /usr/lib/python3/dist-packages/server_monitor
sudo rm -f /etc/systemd/system/server-monitor.service
sudo rm -rf /etc/server-monitor

# Yeni paketi oluştur ve kur
echo "Yeni paket oluşturuluyor..."
sudo ./build.sh

echo "Yeni paket kuruluyor..."
sudo dpkg -i server-monitor-0.1.0.deb
sudo apt-get install -f

echo "İşlem tamamlandı!" 