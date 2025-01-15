#!/bin/bash
set -e

# Geçici dizin oluştur
TEMP_DIR=$(mktemp -d)
PKG_NAME="server-monitor"
PKG_VERSION="0.1.0"
BUILD_DIR="$TEMP_DIR/$PKG_NAME-$PKG_VERSION"

# Ana dizin yapısını oluştur
mkdir -p "$BUILD_DIR"
cp -r DEBIAN "$BUILD_DIR/"
cp -r etc "$BUILD_DIR/"
cp -r usr "$BUILD_DIR/"

# Python paket dizinini oluştur
mkdir -p "$BUILD_DIR/usr/lib/python3/dist-packages/server_monitor"
touch "$BUILD_DIR/usr/lib/python3/dist-packages/server_monitor/__init__.py"

# Monitor modülünü kopyala
cp usr/lib/python3/dist-packages/server_monitor/monitor.py "$BUILD_DIR/usr/lib/python3/dist-packages/server_monitor/"

# İzinleri ayarla
chmod -R 755 "$BUILD_DIR/DEBIAN"
chmod -R 755 "$BUILD_DIR/usr"
chmod -R 755 "$BUILD_DIR/etc"

# Debian paketini oluştur
dpkg-deb --build --root-owner-group "$BUILD_DIR" "$PKG_NAME-$PKG_VERSION.deb"

# Geçici dizini temizle
rm -rf "$TEMP_DIR"

echo "Paket oluşturuldu: $PKG_NAME-$PKG_VERSION.deb"
