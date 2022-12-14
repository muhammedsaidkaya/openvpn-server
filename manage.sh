#!/bin/bash

OPENVPN_PATH="/etc/openvpn"
PASS="CA_PASSWORD"

function createDir() {
    mkdir -p ${OPENVPN_PATH}
}

function createEASYRSAPKI(){
    pushd ${OPENVPN_PATH}
        wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz -O - | tar -C /opt/ -zxf - && ln -sf /opt/EasyRSA-3.0.8/easyrsa /bin/easyrsa
        easyrsa init-pki
        EASYRSA_PASSIN="pass:$PASS" easyrsa build-server-full server nopass
    popd
}

function installPackages(){
    amazon-linux-extras install epel -y
    yum update -y 
    yum install -y openvpn iptables-services
}

function configureIPTables(){
    # ROUTE
    echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
    iptables -t nat -A POSTROUTING -s 0.0.0.0/0 -o eth0 -j MASQUERADE
}

function configureOpenVPN(){
    pushd ${OPENVPN_PATH}
    cat << EOF > server.conf
errors-to-stderr
dev tun0
tcp-nodelay
mode server
tls-server
local 0.0.0.0
port 443
proto tcp-server
topology subnet
push "topology subnet"
server 10.8.0.0 255.255.255.0
keepalive 10 600

push "route 0.0.0.0 192.0.0.0 net_gateway"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

ifconfig-pool-persist /etc/openvpn/ipp.txt

ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key /etc/openvpn/pki/private/server.key

tls-auth /etc/openvpn/ta.key 0 # for server
crl-verify /etc/openvpn/pki/crl.pem

tun-mtu 8192
fragment 0
mssfix 0

# taken from https://blog.securityevaluators.com/hardening-openvpn-in-2020-1672c3c4135a
user nobody
group nobody
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
dh none #disable static Diffie-Hellman parameters since we're using ECDHE
ecdh-curve secp384r1 # use the NSA-'s recommended curve

cipher AES-256-CBC
ncp-disable
auth SHA256
client-to-client
comp-lzo no
push "comp-lzo no"
verb 3
EOF
    popd
}

function setup(){
    createDir
    createEASYRSAPKI
    installPackages
    configureOpenVPN
    configureIPTables

    # Systemd Services
    service iptables save
    systemctl enable iptables
    systemctl restart iptables.service
    systemctl restart network.service
    systemctl -f enable openvpn@server.service
    systemctl restart openvpn@server.service
}

function exportClient(){
    NAME=$1
    PROTOCOL="tcp"
    PUBLIC_IP=$(curl -s ifconfig.me)

    CERTFILE=./pki/issued/$NAME.crt
    KEYFILE=./pki/private/$NAME.key

    CA=`cat ./pki/ca.crt`
    CERT=`cat $CERTFILE`
    KEY=`cat $KEYFILE`
    TLS=`cat ./ta.key`

    TCP_CONFIG=$(cat <<EOF
tls-client
dev tun
remote $PUBLIC_IP 443
allow-pull-fqdn
proto tcp-client
topology subnet
pull
resolv-retry infinite
nobind
persist-key
persist-tun
keepalive 10 120
remote-cert-tls server
cipher AES-256-CBC
compress lz4-v2
comp-lzo no
auth SHA256
auth-nocache
key-direction 1
auth-no-pass
EOF
)

    CONFIG=$TCP_CONFIG

    cat << EOF
$CONFIG
<ca>
$CA
</ca>
<cert>
$CERT
</cert>
<key>
$KEY
</key>
<tls-auth>
$TLS
</tls-auth>
EOF

}

function createVPNUser() {
    local client=$1
    local user_password=$2
    pushd ${OPENVPN_PATH}
        mkdir -p users
        export EASYRSA_PASSIN="pass:$PASS"
        printf "$user_password\n$user_password" | easyrsa build-client-full "${client}"
        echo "Client $client added."
        exportClient $client > users/$client.ovpn
    popd
}

function revokeVPNUser() {
    local client=$1
    pushd ${OPENVPN_PATH}
        easyrsa --batch revoke $client
        easyrsa gen-crl
        rm -f pki/reqs/$client.req*
        rm -f pki/private/$client.key*
        rm -f pki/issued/$client.crt*
        rm -f user/$client.ovpn
        # remove client from PKI index
        echo "$(grep -v "CN=${client}$" pki/index.txt)" >pki/index.txt
        echo "VPN access for $client is revoked"
    popd
}

function listVPNUsers() {
    cat /etc/openvpn/pki/index.txt | grep "^V" | grep -v "server_"
}

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
  -s | --setup)
    SETUP="true"
    shift
    ;;
  -a | --action)
    ACTION="$2"
    shift
    shift
    ;;
  -u | --user)
    VPN_USER="$2"
    shift
    shift
    ;;
  -p | --password)
    USER_PASSWORD="$2"
    shift
    shift
    ;;
  esac
done

if [[ "$SETUP" == "true" ]]; then
    setup
else
    if [[ "$ACTION" == "create" ]]; then
        if [[ -z $USER_PASSWORD || -z $VPN_USER ]]; then
        echo "USER_PASSWORD and VPN_USER are required."
        exit 1
        fi
        createVPNUser $VPN_USER $USER_PASSWORD
    fi

    if [[ "$ACTION" == "revoke" ]]; then
        if [[ -z $VPN_USER ]]; then
        echo "VPN_USER is required."
        exit 1
        fi
        revokeVPNUser $VPN_USER
    fi

    if [[ "$ACTION" == "status" ]]; then
        listVPNUsers
    fi
fi