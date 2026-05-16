#!/bin/bash
# Build BlueTeam .deb package

set -e

echo "🔵 Building BlueTeam .deb package..."

# Clean previous builds
rm -rf packaging/deb/usr packaging/deb/etc packaging/deb/var

# Create directory structure
mkdir -p packaging/deb/usr/lib/blueteam
mkdir -p packaging/deb/usr/bin
mkdir -p packaging/deb/usr/local/bin
mkdir -p packaging/deb/etc/blueteam
mkdir -p packaging/deb/etc/systemd/system
mkdir -p packaging/deb/var/lib/blueteam
mkdir -p packaging/deb/var/log/blueteam

# Copy files
echo "📁 Copying files..."
cp -r backend ml packaging/deb/usr/lib/blueteam/
cp bin/blueteam-daemon packaging/deb/usr/bin/
cp bin/blueteam packaging/deb/usr/local/bin/
cp etc/blueteam.conf packaging/deb/etc/blueteam/
cp systemd/blueteam.service packaging/deb/etc/systemd/system/
cp requirements.txt packaging/deb/usr/lib/blueteam/

# Set permissions
chmod 755 packaging/deb/usr/bin/blueteam-daemon
chmod 755 packaging/deb/usr/local/bin/blueteam
chmod 644 packaging/deb/etc/blueteam/blueteam.conf
chmod 644 packaging/deb/etc/systemd/system/blueteam.service
chmod 755 packaging/deb/DEBIAN/preinst
chmod 755 packaging/deb/DEBIAN/postinst

# Build package
echo "📦 Building package..."
cd packaging/deb
dpkg-deb --build . ../blueteam_2.0.0-1_amd64.deb
cd ../..

echo "✅ Package built: packaging/blueteam_2.0.0-1_amd64.deb"
ls -lh packaging/blueteam_2.0.0-1_amd64.deb
