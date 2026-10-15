 <p align="center">
  <img src="PiHarborLogo.png" alt="PiHarbor Logo" width="220">
</p>

<p align="center">
  A Raspberry Pi-based router and Wi-Fi access point built with Linux and Python, featuring routing, NAT, DHCP, DNS, firewalling, ad blocking, and network monitoring through a web-based dashboard.
</p>

---

## 1. Hardware Requirements

- Raspberry Pi 3 Model B
- Ethernet connection for internet access
- MicroSD card with sufficient storage
- Power supply compatible with the Raspberry Pi

## 2. Software Requirements

- Raspberry Pi OS Lite (64-bit)
- `git`
- `sudo` access
- A fresh Raspberry Pi OS installation is recommended

## 3. Installation

PiHarbor configures a Raspberry Pi as a network gateway, providing routing, NAT, DNS, DHCP, firewalling, Wi-Fi access point functionality, ad blocking, traffic monitoring, and a web-based dashboard.

### 3.1 Clone the Repository

Open a terminal on the Raspberry Pi and run:

```bash
cd ~
git clone https://github.com/dkorn3/PiHarbor.git
cd PiHarbor
```

### 3.2 Make the Installation Script Executable

```bash
chmod +x scripts/setup.sh
```

### 3.3 Run the Installer

```bash
sudo ./scripts/setup.sh
```

The setup script configures the Raspberry Pi as a PiHarbor network gateway and installs the required services and configuration files.

Installation may modify network settings and service configurations. Use a local console or another reliable management connection before proceeding.

### 3.4 Reboot if Required

If the installer requests a reboot, run:

```bash
sudo reboot
```

Allow the Raspberry Pi to finish booting before continuing.

## 4. Accessing the Dashboard

Connect a device to the PiHarbor network and open a web browser.

Enter the Raspberry Pi's LAN IP address:

```text
http://192.168.50.1
```

The default address may differ if the LAN configuration has been changed.

The dashboard provides an overview of system health, network interfaces, connected devices, network activity, and available gateway features.

## 5. Verifying the Installation

### 5.1 Check Network Interfaces

```bash
ip -br addr
```

### 5.2 Check Running Services

```bash
systemctl --type=service --state=running
```

### 5.3 Verify the Dashboard

```bash
curl -I http://127.0.0.1
```

If the dashboard is unavailable, inspect the application service status and system logs to identify the issue.

## 6. Troubleshooting

### Dashboard Is Unavailable

- Confirm that the Raspberry Pi has completed booting.
- Verify that the web application is running.
- Check that the device is connected to the correct network.
- Confirm the Raspberry Pi's current LAN IP address.

### Clients Cannot Connect to the Internet

- Verify that the Ethernet connection provides internet access.
- Check the WAN and LAN interface assignments.
- Confirm that IP forwarding, NAT, and firewall rules are configured correctly.
- Verify that DHCP and DNS services are running.

### Wi-Fi Access Point Is Unavailable

- Confirm that the Wi-Fi interface supports access point mode.
- Check the wireless interface configuration and access point service status.
- Review system logs for service startup or configuration errors.

## 7. Notes

- PiHarbor is intended to operate as a network gateway, so installation may change the Raspberry Pi's networking configuration.
- Ethernet is used for WAN connectivity.
- Ensure that the Raspberry Pi remains accessible for troubleshooting before applying network changes.
- Interface names, IP addresses, and available features may vary depending on the installation and system configuration.
