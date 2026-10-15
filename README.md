# PiHarbor 

<p align="center">
  <img src="PiHarborLogo.PNG" alt="PiHarbor Logo" width="220">
</p>

<p align="center">
  A Raspberry Pi-based router and Wi-Fi access point built with Linux and Python, featuring routing, NAT, DHCP, DNS, firewalling, ad blocking, and network monitoring through a web-based dashboard.
</p>

---

## Installation

PiHarbor is designed to run on a Raspberry Pi 3 Model B as a network gateway, providing routing, NAT, DNS, DHCP, firewalling, Wi-Fi access point functionality, traffic monitoring, ad blocking, and a web-based dashboard.

### Requirements

- Raspberry Pi 3 Model B
- Raspberry Pi OS Lite (64-bit)
- Internet connection through Ethernet
- Wi-Fi interface capable of operating as an access point
- `git`
- `sudo` access
- A fresh Raspberry Pi OS installation is recommended

### Fresh Installation

#### 1. Clone the repository

Open a terminal on the Raspberry Pi and run:

```bash
cd ~
git clone https://github.com/dk3/PiHarbor.git
cd PiHarbor
```

#### 2. Make the installation script executable

```bash
chmod +x scripts/setup.sh
```

#### 3. Run the installer

```bash
sudo ./scripts/setup.sh
```

The setup script configures the Raspberry Pi as a PiHarbor network gateway and installs the required services and configuration files.

Depending on the setup script and system configuration, installation may modify network settings and service configurations. Connect to the Raspberry Pi locally or through a reliable management connection before proceeding.

#### 4. Reboot if required

If the installer requests a reboot, run:

```bash
sudo reboot
```

Allow the Raspberry Pi to finish booting before continuing.

### Accessing the Dashboard

After installation, connect a device to the PiHarbor network and open a web browser.

Enter the Raspberry Pi's LAN IP address in the address bar. The default address is:

```text
http://192.168.50.1
```

The address may differ if the LAN configuration has been changed.

The dashboard provides an overview of system health, network interfaces, connected devices, network activity, and available gateway features.

### Verifying the Installation

Check that the Raspberry Pi has the expected network interfaces:

```bash
ip -br addr
```

Check the status of the network gateway services:

```bash
systemctl --type=service --state=running
```

Verify that the dashboard responds locally:

```bash
curl -I http://127.0.0.1
```

If the dashboard is unavailable, inspect the system logs and service status to identify the issue.

### Troubleshooting

**Dashboard is unavailable**

- Confirm that the Raspberry Pi has completed booting.
- Verify that the web application is running.
- Check that the device is connected to the correct network.
- Confirm the Raspberry Pi's current LAN IP address.

**Clients cannot connect to the internet**

- Verify that the Ethernet connection provides internet access.
- Check the WAN and LAN interface assignments.
- Confirm that IP forwarding, NAT, and firewall rules are configured correctly.
- Verify that DHCP and DNS services are running.

**Wi-Fi access point is unavailable**

- Confirm that the Wi-Fi interface supports access point mode.
- Check the wireless interface configuration and access point service status.
- Review system logs for service startup or configuration errors.

### Notes

- PiHarbor is intended to operate as a network gateway, so its setup may change the Raspberry Pi's networking configuration.
- Use an Ethernet connection for WAN connectivity.
- Ensure that the Raspberry Pi is accessible for troubleshooting before applying network changes.
- Configuration details, interface names, IP addresses, and available features may vary depending on the installation and system configuration.
