#!/bin/bash

# OpenConnect Server (ocserv) Installation Script
# Supports: Debian 12 and Ubuntu 24.04
# Created: April 23, 2025

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Default DNS servers - now using Cloudflare DNS
DEFAULT_PRIMARY_DNS="1.1.1.1"
DEFAULT_SECONDARY_DNS="1.0.0.1"

# Function to display messages
function echo_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

function echo_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

function echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo_error "This script must be run as root"
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo_error "Cannot detect operating system"
fi

# Check if OS is supported
if [ "$OS" == "debian" ] && [ "$VERSION_ID" == "12" ]; then
    echo_message "Detected Debian 12"
    SUPPORTED=true
elif [ "$OS" == "ubuntu" ] && [ "$VERSION_ID" == "24.04" ]; then
    echo_message "Detected Ubuntu 24.04"
    SUPPORTED=true
else
    echo_error "Unsupported OS. This script only works on Debian 12 or Ubuntu 24.04"
fi

# Function to install dependencies
function install_dependencies() {
    echo_message "Updating package lists..."
    apt update

    echo_message "Installing required packages..."
    apt install -y ocserv openssl gnutls-bin
}

# Function to create SSL certificate with OpenSSL (self-signed)
function create_self_signed_certificate() {
    echo_message "Creating self-signed SSL certificates for OpenConnect server..."
    
    # Create directory for certificates if it doesn't exist
    mkdir -p /etc/ocserv/ssl

    # Get server hostname or IP
    read -p "Enter server's public IP address or hostname: " SERVER_ADDRESS
    
    # Generate CA key and certificate
    openssl genrsa -out /etc/ocserv/ssl/ca-key.pem 4096
    openssl req -new -x509 -days 3650 -key /etc/ocserv/ssl/ca-key.pem \
        -out /etc/ocserv/ssl/ca.pem -subj "/CN=OpenConnect VPN CA"
    
    # Generate server key and certificate signing request
    openssl genrsa -out /etc/ocserv/ssl/server-key.pem 2048
    openssl req -new -key /etc/ocserv/ssl/server-key.pem \
        -out /etc/ocserv/ssl/server-csr.pem -subj "/CN=$SERVER_ADDRESS"
    
    # Sign the server certificate with our CA
    openssl x509 -req -days 3650 -in /etc/ocserv/ssl/server-csr.pem \
        -CA /etc/ocserv/ssl/ca.pem -CAkey /etc/ocserv/ssl/ca-key.pem \
        -CAcreateserial -out /etc/ocserv/ssl/server-cert.pem
    
    # Set proper permissions
    chmod 600 /etc/ocserv/ssl/server-key.pem
    chmod 600 /etc/ocserv/ssl/ca-key.pem
    
    echo_message "Self-signed SSL certificates created successfully"
    CERT_TYPE="self-signed"
}

# Function to create Let's Encrypt certificate using certbot
function create_letsencrypt_certificate() {
    echo_message "Setting up Let's Encrypt certificate for OpenConnect server..."
    
    # Check if certbot is installed, if not install it
    if ! command -v certbot &> /dev/null; then
        echo_message "Installing certbot..."
        apt update
        apt install -y certbot
    fi
    
    # Create directory for certificates if it doesn't exist
    mkdir -p /etc/ocserv/ssl
    
    # Get domain name for the certificate
    read -p "Enter your domain name (e.g., vpn.example.com): " DOMAIN_NAME
    
    # Check if domain resolves correctly (basic check)
    echo_message "Checking if domain $DOMAIN_NAME is properly configured..."
    if ! host $DOMAIN_NAME &> /dev/null; then
        echo_warning "Domain $DOMAIN_NAME does not appear to resolve. DNS might not be configured correctly."
        echo_warning "Let's Encrypt validation might fail if DNS is not properly set up."
        read -p "Do you want to continue anyway? (y/n): " CONTINUE
        if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
            echo_message "Certificate creation aborted. Please configure DNS properly and try again."
            return 1
        fi
    fi
    
    # Temporarily stop ocserv to free port 443 if it's running
    if systemctl is-active --quiet ocserv; then
        echo_message "Temporarily stopping ocserv service to obtain certificate..."
        systemctl stop ocserv
    fi
    
    # Get certificate using standalone mode
    echo_message "Obtaining Let's Encrypt certificate for $DOMAIN_NAME..."
    certbot certonly --standalone --preferred-challenges http \
        --agree-tos --no-eff-email \
        -d $DOMAIN_NAME \
        --cert-name ocserv
    
    if [ $? -ne 0 ]; then
        echo_error "Failed to obtain Let's Encrypt certificate. Check your domain and DNS settings."
    fi
    
    # Link certificates to ocserv directory
    ln -sf /etc/letsencrypt/live/ocserv/fullchain.pem /etc/ocserv/ssl/server-cert.pem
    ln -sf /etc/letsencrypt/live/ocserv/privkey.pem /etc/ocserv/ssl/server-key.pem
    ln -sf /etc/letsencrypt/live/ocserv/chain.pem /etc/ocserv/ssl/ca.pem
    
    # Set up auto-renewal hook
    mkdir -p /etc/letsencrypt/renewal-hooks/post
    cat > /etc/letsencrypt/renewal-hooks/post/ocserv-restart << EOF
#!/bin/bash
systemctl restart ocserv
EOF
    chmod +x /etc/letsencrypt/renewal-hooks/post/ocserv-restart
    
    echo_message "Let's Encrypt certificate obtained and linked successfully"
    echo_message "Certificate will auto-renew via the certbot timer"
    CERT_TYPE="letsencrypt"
}

# Function to choose and create SSL certificate
function create_ssl_certificate() {
    echo_message "Certificate Options:"
    echo "1. Self-signed certificate (works immediately, but will give security warnings)"
    echo "2. Let's Encrypt certificate (requires domain name, but trusted by browsers)"
    
    read -p "Select certificate type [1-2]: " CERT_OPTION
    
    case $CERT_OPTION in
        1)
            create_self_signed_certificate
            ;;
        2)
            create_letsencrypt_certificate
            ;;
        *)
            echo_warning "Invalid option, using self-signed certificate"
            create_self_signed_certificate
            ;;
    esac
}

# Function to configure ocserv
function configure_ocserv() {
    echo_message "Configuring OpenConnect server..."
    
    # Backup original config
    cp /etc/ocserv/ocserv.conf /etc/ocserv/ocserv.conf.orig
    
    # DNS Configuration
    echo_message "DNS Server Configuration:"
    echo "1. Use Cloudflare DNS (1.1.1.1, 1.0.0.1)"
    echo "2. Use Google DNS (8.8.8.8, 8.8.4.4)"
    echo "3. Use Custom DNS"
    
    read -p "Select DNS option [1-3, default=1]: " DNS_OPTION
    DNS_OPTION=${DNS_OPTION:-1}
    
    case $DNS_OPTION in
        1)
            PRIMARY_DNS=$DEFAULT_PRIMARY_DNS
            SECONDARY_DNS=$DEFAULT_SECONDARY_DNS
            echo_message "Using Cloudflare DNS"
            ;;
        2)
            PRIMARY_DNS="8.8.8.8"
            SECONDARY_DNS="8.8.4.4"
            echo_message "Using Google DNS"
            ;;
        3)
            read -p "Enter primary DNS server: " PRIMARY_DNS
            read -p "Enter secondary DNS server (press Enter to skip): " SECONDARY_DNS
            PRIMARY_DNS=${PRIMARY_DNS:-$DEFAULT_PRIMARY_DNS}
            echo_message "Using custom DNS settings"
            ;;
        *)
            PRIMARY_DNS=$DEFAULT_PRIMARY_DNS
            SECONDARY_DNS=$DEFAULT_SECONDARY_DNS
            echo_warning "Invalid option, using Cloudflare DNS"
            ;;
    esac
    
    # Create a new basic configuration
    cat > /etc/ocserv/ocserv.conf << EOF
# OpenConnect VPN server configuration

auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = 443
udp-port = 443
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/ocserv/ssl/server-cert.pem
server-key = /etc/ocserv/ssl/server-key.pem
ca-cert = /etc/ocserv/ssl/ca.pem
isolate-workers = true
max-clients = 16
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = true
cert-user-oid = 2.5.4.3
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true

ipv4-network = 192.168.10.0/24
ipv4-netmask = 255.255.255.0
dns = $PRIMARY_DNS
EOF

    # Add secondary DNS if provided
    if [ ! -z "$SECONDARY_DNS" ]; then
        echo "dns = $SECONDARY_DNS" >> /etc/ocserv/ocserv.conf
    fi
    
    # Continue with the rest of the config
    cat >> /etc/ocserv/ocserv.conf << EOF
ping-leases = false

route = default
no-route = 192.168.10.0/255.255.255.0
EOF

    echo_message "OpenConnect server configuration completed with DNS: $PRIMARY_DNS"
    if [ ! -z "$SECONDARY_DNS" ]; then
        echo_message "Secondary DNS: $SECONDARY_DNS"
    fi
}

# Function to enable IP forwarding and configure firewall
function configure_network() {
    echo_message "Configuring network settings..."
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/60-custom.conf
    sysctl -p /etc/sysctl.d/60-custom.conf
    
    # Configure firewall
    if command -v ufw > /dev/null; then
        echo_message "Configuring UFW firewall..."
        # Enable UFW
        ufw enable
        
        # Allow OpenConnect port
        ufw allow 443/tcp
        ufw allow 443/udp
        
        # Enable IP masquerading
        ufw route allow in on vpns out on $(ip route get 8.8.8.8 | awk '{print $5; exit}')
        
        # Get the primary network interface
        PRIMARY_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
        
        # Update before.rules to enable masquerading
        sed -i '/^# End required lines/a\# NAT rules for OpenConnect VPN\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 192.168.10.0/24 -o '"$PRIMARY_INTERFACE"' -j MASQUERADE\nCOMMIT' /etc/ufw/before.rules
        
        # Reload UFW
        ufw reload
    else
        # Configure iptables directly
        echo_message "UFW not found. Configuring iptables..."
        
        # Get the primary network interface
        PRIMARY_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
        
        # Allow OpenConnect port
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        iptables -A INPUT -p udp --dport 443 -j ACCEPT
        
        # Enable IP masquerading
        iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o $PRIMARY_INTERFACE -j MASQUERADE
        
        # Save the iptables rules
        if [ -d /etc/iptables ]; then
            iptables-save > /etc/iptables/rules.v4
        else
            echo_warning "Could not save iptables rules permanently. You may need to set them up again after reboot."
        fi
    fi
    
    echo_message "Network configuration completed"
}

# Function to create a new user
function create_user() {
    echo_message "Creating a new OpenConnect VPN user..."
    
    read -p "Enter username: " USERNAME
    
    # Check if ocpasswd exists
    if [ ! -f /etc/ocserv/ocpasswd ]; then
        touch /etc/ocserv/ocpasswd
        chmod 600 /etc/ocserv/ocpasswd
    fi
    
    # Create user
    echo_message "Creating user: $USERNAME"
    echo -n "Enter password: "
    ocpasswd -c /etc/ocserv/ocpasswd $USERNAME
    
    echo_message "User $USERNAME created successfully"
}

# Function to manage users
function user_management() {
    while true; do
        echo ""
        echo "===== USER MANAGEMENT ====="
        echo "1. Create a new user"
        echo "2. Delete a user"
        echo "3. List all users"
        echo "4. Lock a user"
        echo "5. Unlock a user"
        echo "6. Return to main menu"
        echo "=========================="
        
        read -p "Enter your choice [1-6]: " CHOICE
        
        case $CHOICE in
            1)
                create_user
                ;;
            2)
                read -p "Enter username to delete: " USERNAME
                ocpasswd -c /etc/ocserv/ocpasswd -d $USERNAME
                echo_message "User $USERNAME deleted"
                ;;
            3)
                echo_message "Current users:"
                if [ -f /etc/ocserv/ocpasswd ]; then
                    cat /etc/ocserv/ocpasswd | cut -d: -f1
                else
                    echo "No users found"
                fi
                ;;
            4)
                read -p "Enter username to lock: " USERNAME
                ocpasswd -c /etc/ocserv/ocpasswd -l $USERNAME
                echo_message "User $USERNAME locked"
                ;;
            5)
                read -p "Enter username to unlock: " USERNAME
                ocpasswd -c /etc/ocserv/ocpasswd -u $USERNAME
                echo_message "User $USERNAME unlocked"
                ;;
            6)
                return
                ;;
            *)
                echo_warning "Invalid option"
                ;;
        esac
    done
}

# Add a function to modify DNS settings
function modify_dns_settings() {
    echo_message "Modifying DNS Settings..."
    
    # Show current DNS settings
    echo -n "Current DNS settings: "
    grep "dns =" /etc/ocserv/ocserv.conf
    
    echo "1. Use Cloudflare DNS (1.1.1.1, 1.0.0.1)"
    echo "2. Use Google DNS (8.8.8.8, 8.8.4.4)"
    echo "3. Use Custom DNS"
    echo "4. Return to main menu"
    
    read -p "Select DNS option [1-4]: " DNS_OPTION
    
    case $DNS_OPTION in
        1)
            PRIMARY_DNS=$DEFAULT_PRIMARY_DNS
            SECONDARY_DNS=$DEFAULT_SECONDARY_DNS
            echo_message "Using Cloudflare DNS"
            ;;
        2)
            PRIMARY_DNS="8.8.8.8"
            SECONDARY_DNS="8.8.4.4"
            echo_message "Using Google DNS"
            ;;
        3)
            read -p "Enter primary DNS server: " PRIMARY_DNS
            read -p "Enter secondary DNS server (press Enter to skip): " SECONDARY_DNS
            PRIMARY_DNS=${PRIMARY_DNS:-$DEFAULT_PRIMARY_DNS}
            echo_message "Using custom DNS settings"
            ;;
        4)
            return
            ;;
        *)
            echo_warning "Invalid option"
            return
            ;;
    esac
    
    # Update DNS settings in the config file
    sed -i '/dns =.*/d' /etc/ocserv/ocserv.conf
    
    # Add the new DNS settings before the ping-leases line
    sed -i "/ping-leases/i dns = $PRIMARY_DNS" /etc/ocserv/ocserv.conf
    
    if [ ! -z "$SECONDARY_DNS" ]; then
        sed -i "/ping-leases/i dns = $SECONDARY_DNS" /etc/ocserv/ocserv.conf
    fi
    
    # Apply changes
    systemctl restart ocserv
    
    echo_message "DNS settings updated and applied"
}

# Function to install and configure the server
function install_server() {
    install_dependencies
    create_ssl_certificate
    configure_ocserv
    configure_network
    
    # Start and enable the service
    systemctl enable ocserv
    systemctl restart ocserv
    
    echo_message "Checking OpenConnect server status..."
    systemctl status ocserv
    
    # Create initial user
    echo_message "Creating initial VPN user..."
    create_user
    
    echo_message "OpenConnect VPN server has been successfully installed!"
    echo_message "Server is running on port 443 (TCP/UDP)"
    if [ "$CERT_TYPE" == "self-signed" ]; then
        echo_message "Note: You are using self-signed certificates. VPN clients will show security warnings."
        echo_message "You may need to distribute the CA certificate (/etc/ocserv/ssl/ca.pem) to clients."
    elif [ "$CERT_TYPE" == "letsencrypt" ]; then
        echo_message "You are using Let's Encrypt certificates which are trusted by browsers and clients."
        echo_message "Certificates will auto-renew via certbot timer."
    fi
    echo_message "You can connect using AnyConnect compatible clients like Cisco AnyConnect, openconnect, or GlobalProtect"
}

# Add certificate management option to main menu
function main_menu() {
    while true; do
        echo ""
        echo "====== OpenConnect VPN Server ======"
        echo "1. Install OpenConnect Server"
        echo "2. User Management"
        echo "3. View Server Status"
        echo "4. Restart Server"
        echo "5. Show Server Configuration"
        echo "6. Modify DNS Settings"
        echo "7. Certificate Management"
        echo "8. Exit"
        echo "==================================="
        
        read -p "Enter your choice [1-8]: " CHOICE
        
        case $CHOICE in
            1)
                install_server
                ;;
            2)
                user_management
                ;;
            3)
                systemctl status ocserv
                ;;
            4)
                systemctl restart ocserv
                echo_message "OpenConnect server restarted"
                ;;
            5)
                cat /etc/ocserv/ocserv.conf
                ;;
            6)
                modify_dns_settings
                ;;
            7)
                certificate_management
                ;;
            8)
                echo_message "Exiting..."
                exit 0
                ;;
            *)
                echo_warning "Invalid option"
                ;;
        esac
    done
}

# Add certificate management function
function certificate_management() {
    while true; do
        echo ""
        echo "===== CERTIFICATE MANAGEMENT ====="
        echo "1. Create new self-signed certificate"
        echo "2. Set up Let's Encrypt certificate"
        echo "3. Check certificate expiration"
        echo "4. Force Let's Encrypt renewal (if using Let's Encrypt)"
        echo "5. Return to main menu"
        echo "==================================="
        
        read -p "Enter your choice [1-5]: " CHOICE
        
        case $CHOICE in
            1)
                create_self_signed_certificate
                systemctl restart ocserv
                echo_message "New self-signed certificate installed and service restarted"
                ;;
            2)
                create_letsencrypt_certificate
                systemctl restart ocserv
                echo_message "Let's Encrypt certificate installed and service restarted"
                ;;
            3)
                echo_message "Certificate information:"
                openssl x509 -in /etc/ocserv/ssl/server-cert.pem -text -noout | grep -E 'Not Before|Not After|Subject:'
                ;;
            4)
                if [ -d /etc/letsencrypt/live/ocserv ]; then
                    echo_message "Forcing Let's Encrypt certificate renewal..."
                    certbot renew --force-renewal --cert-name ocserv
                    systemctl restart ocserv
                    echo_message "Certificate renewal attempted and service restarted"
                else
                    echo_warning "Let's Encrypt certificate not found. Install it first."
                fi
                ;;
            5)
                return
                ;;
            *)
                echo_warning "Invalid option"
                ;;
        esac
    done
}

# Start the main program
main_menu