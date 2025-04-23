# OpenConnect VPN Server Installation Script

A comprehensive installation script for setting up Cisco AnyConnect-compatible VPN server (ocserv) on Debian 12 and Ubuntu 24.04.

**Date:** April 23, 2025

## Features

This script provides a complete solution for installing and managing an OpenConnect VPN server:

- **Easy Installation:** Automated setup for Debian 12 and Ubuntu 24.04
- **Certificate Options:** Choice between self-signed certificates and Let's Encrypt trusted certificates
- **DNS Configuration:** Configurable DNS with defaults for Cloudflare (1.1.1.1) or Google DNS
- **User Management:** Create, list, delete, lock, and unlock VPN users
- **Network Configuration:** Automatic setup of IP forwarding and firewall rules (supports both UFW and iptables)
- **Certificate Management:** Tools to maintain, check, and renew TLS certificates

## Prerequisites

- A server running Debian 12 or Ubuntu 24.04
- Root access
- For Let's Encrypt certificates: A registered domain name pointing to your server
- Port 443 should be open and accessible (for VPN connections)
- Port 80 should be temporarily available for Let's Encrypt validation (if using Let's Encrypt)

## Quick Start

1. Download the installation script:
   ```bash
   wget https://path/to/install_ocserv.sh
   ```

2. Make the script executable:
   ```bash
   chmod +x install_ocserv.sh
   ```

3. Run the script as root:
   ```bash
   sudo ./install_ocserv.sh
   ```

4. Follow the on-screen prompts to complete the installation

## Menu Options

The script provides an interactive menu with the following options:

1. **Install OpenConnect Server** - Run the full installation process
2. **User Management** - Create, delete, list, lock, or unlock VPN users
3. **View Server Status** - Check the current status of the VPN service
4. **Restart Server** - Restart the VPN service
5. **Show Server Configuration** - Display the current configuration file
6. **Modify DNS Settings** - Change the DNS servers provided to VPN clients
7. **Certificate Management** - Create or renew SSL certificates
8. **Exit** - Exit the script

## Certificate Options

The script offers two certificate options:

### Self-signed Certificates
- Quick to set up
- No domain name required
- Clients will see security warnings
- Need to distribute CA certificate to clients

#### Using Self-signed Certificates with Clients

When using self-signed certificates, VPN clients will display security warnings about untrusted certificates. This is normal and doesn't affect the functionality or encryption strength of the VPN connection.

To make clients work smoothly with self-signed certificates:

1. **For Cisco AnyConnect:**
   - When connecting for the first time, you'll see a warning about an untrusted server
   - Check the box "Always trust this VPN server and import the certificate"
   - Click "Connect Anyway"

2. **For OpenConnect CLI:**
   - Use the `--servercert` option to specify the server's certificate hash
   - Example: `openconnect --servercert SHA256:fingerprint_here vpn.example.com`
   - Alternatively, use `--no-cert-check` (less secure): `openconnect --no-cert-check vpn.example.com`

3. **For Mobile Clients:**
   - Install the CA certificate on your device (export it from `/etc/ocserv/ssl/ca.pem`)
   - For Android: Settings → Security → Install from storage
   - For iOS: Profile installation via Safari or email

4. **Distributing the CA Certificate:**
   - After installation, copy the CA certificate from the server:
     ```bash
     # On the server
     cat /etc/ocserv/ssl/ca.pem
     ```
   - Save this content to a file named `vpn-ca.pem` on your client device
   - Import this certificate to your client's trusted certificate store

This additional configuration is not needed when using Let's Encrypt certificates.

### Let's Encrypt Certificates
- Trusted by all major clients and browsers
- Requires a valid domain name
- Automatic renewal process
- More professional solution

## DNS Configuration

You can configure DNS servers provided to VPN clients:

1. **Cloudflare DNS** (Default): 1.1.1.1, 1.0.0.1
2. **Google DNS**: 8.8.8.8, 8.8.4.4
3. **Custom DNS**: Specify your own DNS servers

## Connecting to the VPN

After installation, you can connect to the VPN using any of these clients:

- **Cisco AnyConnect Secure Mobility Client**
- **OpenConnect** (Linux, macOS, Windows)
- **GlobalProtect** clients
- Most modern native VPN clients on iOS and Android

### Connection Details:
- **Server**: Your server's IP address or domain name
- **Port**: 443 (both TCP and UDP)
- **Protocol**: AnyConnect or OpenConnect
- **Username/Password**: As configured during installation

## Troubleshooting

If you encounter issues with the VPN connection:

1. Check the server status:
   ```bash
   sudo systemctl status ocserv
   ```

2. View the logs:
   ```bash
   sudo journalctl -u ocserv
   ```

3. Verify your firewall is configured correctly:
   ```bash
   sudo ufw status
   ```
   or
   ```bash
   sudo iptables -L
   ```

4. Ensure port 443 is open and accessible from the internet

## Security Considerations

- The script configures the OpenConnect server to use strong encryption
- User passwords are stored securely using ocpasswd
- Certificate keys are protected with proper permissions
- For production environments, Let's Encrypt certificates are recommended

## License

This script is provided under the MIT license.

## Credits

Created for easy deployment of OpenConnect VPN servers on Debian and Ubuntu systems.

---

For bug reports or feature requests, please submit issues via GitHub.