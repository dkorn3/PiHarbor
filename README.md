Installation

PiHarbor is designed to run on a Raspberry Pi 3 Model B as a network gateway, providing routing, NAT, DNS, DHCP, firewalling, Wi-Fi access point functionality, traffic monitoring, and a web-based dashboard.

Requirements
Raspberry Pi 3 Model B
Raspberry Pi OS Lite (64-bit)
Internet connection through Ethernet
Wi-Fi interface capable of operating as an access point
git
sudo access
Fresh Installation

Clone the PiHarbor repository:

cd ~
git clone https://github.com/dk3/PiHarbor.git
cd PiHarbor

Make the installation script executable:

chmod +x scripts/setup.sh

Run the installer:

sudo ./scripts/setup.sh

The setup script configures the Raspberry Pi as a PiHarbor network gateway and installs the required services and configuration files.
