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
        
        # Install iptables-persistent if not available
        if ! dpkg -l | grep -q iptables-persistent; then
            echo_message "Installing iptables-persistent package..."
            # Pre-answer the questions asked during installation
            echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
            echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
            apt-get install -y iptables-persistent
            
            # Save the rules
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6
        else
            # Save the rules if iptables-persistent is already installed
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6
        fi
        
        echo_message "iptables rules saved permanently"
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

# Function to troubleshoot connectivity issues
function troubleshoot_connectivity() {
    echo_message "VPN Connectivity Troubleshooting"
    echo ""
    echo "Checking VPN server configuration..."
    
    # Check if the server is running
    if ! systemctl is-active --quiet ocserv; then
        echo_warning "OpenConnect server is not running!"
        systemctl start ocserv
        echo_message "Started OpenConnect server."
    else
        echo_message "OpenConnect server is running."
    fi
    
    # Check routes
    echo_message "Checking routing configuration..."
    ROUTE_DEFAULT=$(grep -c "route = default" /etc/ocserv/ocserv.conf)
    if [ $ROUTE_DEFAULT -eq 0 ]; then
        echo_warning "Default route is missing in the configuration!"
        echo_message "Adding default route..."
        sed -i '/^no-route/i route = default' /etc/ocserv/ocserv.conf
        CHANGES_MADE=true
    else
        echo_message "Default route is correctly configured."
    fi
    
    # Check if IP forwarding is enabled
    echo_message "Checking IP forwarding..."
    IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
    if [ "$IP_FORWARD" != "1" ]; then
        echo_warning "IP forwarding is not enabled!"
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/60-custom.conf
        sysctl -p /etc/sysctl.d/60-custom.conf
        echo_message "IP forwarding has been enabled."
        CHANGES_MADE=true
    else
        echo_message "IP forwarding is correctly enabled."
    fi
    
    # Check NAT rules
    echo_message "Checking NAT configuration..."
    PRIMARY_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
    
    if command -v ufw > /dev/null && ufw status | grep -q active; then
        echo_message "Checking UFW masquerading rules..."
        UFW_NAT=$(grep -c "POSTROUTING -s 192.168.10.0/24" /etc/ufw/before.rules)
        if [ $UFW_NAT -eq 0 ]; then
            echo_warning "UFW NAT rules are missing!"
            sed -i '/^# End required lines/a\# NAT rules for OpenConnect VPN\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 192.168.10.0/24 -o '"$PRIMARY_INTERFACE"' -j MASQUERADE\nCOMMIT' /etc/ufw/before.rules
            ufw reload
            echo_message "UFW NAT rules have been added and UFW has been reloaded."
            CHANGES_MADE=true
        else
            echo_message "UFW NAT rules are correctly configured."
        fi
    else
        echo_message "Checking iptables masquerading rules..."
        IPTABLES_NAT=$(iptables -t nat -L POSTROUTING -v -n | grep -c "MASQUERADE.*192.168.10.0/24")
        if [ $IPTABLES_NAT -eq 0 ]; then
            echo_warning "iptables NAT rules are missing!"
            iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o $PRIMARY_INTERFACE -j MASQUERADE
            
            # Make sure iptables-persistent is installed and save the rules
            if ! dpkg -l | grep -q iptables-persistent; then
                echo_message "Installing iptables-persistent package..."
                echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
                echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
                apt-get install -y iptables-persistent
            fi
            
            # Save the rules
            iptables-save > /etc/iptables/rules.v4
            
            echo_message "iptables NAT rules have been added and saved."
            CHANGES_MADE=true
        else
            echo_message "iptables NAT rules are correctly configured."
        fi
    fi
    
    # Check DNS settings
    echo_message "Checking DNS configuration..."
    DNS_COUNT=$(grep -c "dns = " /etc/ocserv/ocserv.conf)
    if [ $DNS_COUNT -eq 0 ]; then
        echo_warning "No DNS servers configured!"
        sed -i '/^ipv4-netmask/a dns = 1.1.1.1\ndns = 1.0.0.1' /etc/ocserv/ocserv.conf
        echo_message "Added Cloudflare DNS servers to configuration."
        CHANGES_MADE=true
    else
        echo_message "DNS servers are configured: $(grep "dns = " /etc/ocserv/ocserv.conf | tr '\n' ' ')"
        
        # Ask if user wants to try different DNS servers
        echo ""
        echo "Would you like to try different DNS servers?"
        echo "1. Keep current DNS settings"
        echo "2. Use Cloudflare DNS (1.1.1.1, 1.0.0.1)"
        echo "3. Use Google DNS (8.8.8.8, 8.8.4.4)"
        echo "4. Use Quad9 DNS (9.9.9.9, 149.112.112.112)"
        echo "5. Use OpenDNS (208.67.222.222, 208.67.220.220)"
        
        read -p "Select DNS option [1-5]: " DNS_CHOICE
        
        case $DNS_CHOICE in
            1)
                echo_message "Keeping current DNS settings."
                ;;
            2)
                sed -i '/dns =.*/d' /etc/ocserv/ocserv.conf
                sed -i '/^ipv4-netmask/a dns = 1.1.1.1\ndns = 1.0.0.1' /etc/ocserv/ocserv.conf
                echo_message "Changed to Cloudflare DNS."
                CHANGES_MADE=true
                ;;
            3)
                sed -i '/dns =.*/d' /etc/ocserv/ocserv.conf
                sed -i '/^ipv4-netmask/a dns = 8.8.8.8\ndns = 8.8.4.4' /etc/ocserv/ocserv.conf
                echo_message "Changed to Google DNS."
                CHANGES_MADE=true
                ;;
            4)
                sed -i '/dns =.*/d' /etc/ocserv/ocserv.conf
                sed -i '/^ipv4-netmask/a dns = 9.9.9.9\ndns = 149.112.112.112' /etc/ocserv/ocserv.conf
                echo_message "Changed to Quad9 DNS."
                CHANGES_MADE=true
                ;;
            5)
                sed -i '/dns =.*/d' /etc/ocserv/ocserv.conf
                sed -i '/^ipv4-netmask/a dns = 208.67.222.222\ndns = 208.67.220.220' /etc/ocserv/ocserv.conf
                echo_message "Changed to OpenDNS."
                CHANGES_MADE=true
                ;;
            *)
                echo_warning "Invalid choice. Keeping current DNS settings."
                ;;
        esac
    fi
    
    # Check MTU settings
    echo_message "Checking MTU settings..."
    MTU_DISCOVERY=$(grep -c "try-mtu-discovery = true" /etc/ocserv/ocserv.conf)
    
    echo "Would you like to adjust the MTU value? Some networks require a lower MTU."
    echo "1. Keep current MTU settings"
    echo "2. Set a lower MTU value (1400)"
    echo "3. Set a very low MTU value (1300)"
    echo "4. Set custom MTU value"
    
    read -p "Select MTU option [1-4]: " MTU_CHOICE
    
    case $MTU_CHOICE in
        1)
            echo_message "Keeping current MTU settings."
            ;;
        2)
            if ! grep -q "^mtu " /etc/ocserv/ocserv.conf; then
                sed -i '/^try-mtu-discovery/a mtu = 1400' /etc/ocserv/ocserv.conf
            else
                sed -i 's/^mtu = .*/mtu = 1400/' /etc/ocserv/ocserv.conf
            fi
            echo_message "MTU set to 1400."
            CHANGES_MADE=true
            ;;
        3)
            if ! grep -q "^mtu " /etc/ocserv/ocserv.conf; then
                sed -i '/^try-mtu-discovery/a mtu = 1300' /etc/ocserv/ocserv.conf
            else
                sed -i 's/^mtu = .*/mtu = 1300/' /etc/ocserv/ocserv.conf
            fi
            echo_message "MTU set to 1300."
            CHANGES_MADE=true
            ;;
        4)
            read -p "Enter custom MTU value (recommended range 1200-1500): " CUSTOM_MTU
            if [[ "$CUSTOM_MTU" =~ ^[0-9]+$ ]] && [ $CUSTOM_MTU -ge 1200 ] && [ $CUSTOM_MTU -le 1500 ]; then
                if ! grep -q "^mtu " /etc/ocserv/ocserv.conf; then
                    sed -i '/^try-mtu-discovery/a mtu = '$CUSTOM_MTU /etc/ocserv/ocserv.conf
                else
                    sed -i 's/^mtu = .*/mtu = '$CUSTOM_MTU'/' /etc/ocserv/ocserv.conf
                fi
                echo_message "MTU set to $CUSTOM_MTU."
                CHANGES_MADE=true
            else
                echo_warning "Invalid MTU value. Must be between 1200-1500."
            fi
            ;;
        *)
            echo_warning "Invalid choice. Keeping current MTU settings."
            ;;
    esac
    
    # Apply changes if needed
    if [ "$CHANGES_MADE" = true ]; then
        echo_message "Applying changes and restarting OpenConnect server..."
        systemctl restart ocserv
        echo_message "OpenConnect server has been restarted with the new settings."
    else
        echo_message "No changes were needed to the configuration."
    fi
    
    # Provide client-side troubleshooting advice
    echo ""
    echo_message "Client-side Troubleshooting Tips:"
    echo "1. Make sure you're using the correct username and password"
    echo "2. If using AnyConnect, try enabling 'Allow local LAN access' in the client settings"
    echo "3. Check if your ISP or network blocks VPN connections"
    echo "4. Try using a different VPN client (OpenConnect, AnyConnect, etc.)"
    echo "5. If using macOS or iOS, check that you've trusted the server certificate"
    echo ""
    echo_message "Please disconnect and reconnect your VPN client to apply these changes."
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
        echo "8. Troubleshoot Connectivity Issues"
        echo "9. Exit"
        echo "==================================="
        
        read -p "Enter your choice [1-9]: " CHOICE
        
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
                troubleshoot_connectivity
                ;;
            9)
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