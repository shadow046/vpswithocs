#!/bin/bash
#Initializing Var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com)
MYIP2="s/xxxxxxxxx/$MYIP/g"
# Detect public IPv4 address and pre-fill for the user
	apt install -y sudo
	IP=$(ip -4 addr ls $EXT_INT | head -2 | tail -1 | cut -d' ' -f6 | cut -d'/' -f1)
# If $IP is a private IP address, the server must be behind NAT
	if echo "$MYIP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		#IP=$(curl https://ipinfo.io/ip)
		MYIP=$(wget -qO- ipv4.icanhazip.com)

#echo ""
		#echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		#echo "We need it for the clients to connect to the server."
		#until [[ "$ENDPOINT" != "" ]]; do
		#	read -rp "Public IPv4 address or hostname: " -e ENDPOINT
		#done
	fi
	echo ""
	echo 'Your IP is '"$MYIP" '.. What port do you want OpenVPN to listen to?'
	echo "   1) Default: 1194"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ "$PORT_CHOICE" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
		1)
			PORT="1194"
		;;
		2)
			until [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
				read -rp "Custom port [1-65535]: " -e -i 1194 PORT
			done
		;;
		3)
			# Generate random number within private ports range
			PORT=$(shuf -i49152-65535 -n1)
			echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ "$PROTOCOL_CHOICE" =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 2 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
		1)
			PROTOCOL="udp"
		;;
		2)
			PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "What Privoxy port do you want?"
	echo "   1) Default: 8118"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ "$PORT_PRIVO" =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_PRIVO
	done
	case $PORT_PRIVO in
		1)
			PORTS="8118"
		;;
		2)
			until [[ "$PORTS" =~ ^[0-9]+$ ]] && [ "$PORTS" -ge 1 ] && [ "$PORTS" -le 65535 ]; do
				read -rp "Custom port [1-65535]: " -e -i 8118 PORTS
			done
		;;
		3)
			# Generate random number within private ports range
			PORTS=$(shuf -i49152-65535 -n1)
			echo "Random Port: $PORTS"
		;;
	esac
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi

#lets go to root directory 1st
cd

#set ipv6 to disable
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#Install wget curl iptables dnsutils openvpn screen whois ngrep unzip dnsutils dsniff privoxy lsb-release scrot nginx dropbear stunnel4 webmin and unrar
echo 'deb http://download.webmin.com/download/repository sarge contrib' >> /etc/apt/sources.list
echo 'deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib' >> /etc/apt/sources.list
wget http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
apt-get update;apt-get -y install wget curl iptables dnsutils openvpn screen privoxy whois lsb-release scrot dnsutils dsniff ngrep unzip webmin fail2ban stunnel4 unrar nginx dropbear;

# XML Parser
cd
apt-get -y --force-yes -f install libxml-parser-perl

# Set Local Time Manila
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime

# Local Configuration
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# Update
apt-get update

echo 'echo -e "\e[94m    #######################################       "' >> .bashrc
echo 'echo -e "\e[0m"'                                                    >> .bashrc
echo 'echo -e "\e[94m         AutoScriptVPS by  Shadow046              "' >> .bashrc
echo 'echo -e "\e[0m"'                                                    >> .bashrc
echo 'echo -e "\e[94m    #######################################       "' >> .bashrc
echo 'echo -e "\e[0m                                                   "' >> .bashrc


# Nginx Configuration
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/shadow046/vpswithocs/master/nginx.conf"
mkdir -p /home/panel/html
echo "<h1><center>AutoScriptVPS by Shadow046</center></h1>" > /home/panel/html/index.html
echo "<h3><center>For More Info Visit My <a href="https://github.com/shadow046">Github Repositories</a></center><h3>" >> /home/panel/html/index.html
wget -O /etc/nginx/conf.d/80.conf "https://raw.githubusercontent.com/shadow046/vpswithocs/master/80.conf"
service nginx restart

#Lets Install OpenVPN
apt-get -y install openvpn easy-rsa openssl iptables
cp -r /usr/share/easy-rsa/ /etc/openvpn
mkdir /etc/openvpn/easy-rsa/keys
sed -i 's|export KEY_COUNTRY="US"|export KEY_COUNTRY="PH"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_PROVINCE="CA"|export KEY_PROVINCE="Manila"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_CITY="SanFrancisco"|export KEY_CITY="Valenzuela"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_ORG="Fort-Funston"|export KEY_ORG="Shadow046"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_EMAIL="me@myhost.mydomain"|export KEY_EMAIL="emorej046@gmail.com"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_OU="MyOrganizationalUnit"|export KEY_OU="Shadow046"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_NAME="EasyRSA"|export KEY_NAME="Shadow046"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_OU=changeme|export KEY_OU=Shadow046|' /etc/openvpn/easy-rsa/vars

#Generate Diffie-Helman Pem
openssl dhparam -out /etc/openvpn/dh2048.pem 2048

#Copy server.crt server.key ca.crt to openvpn directory
wget -O /etc/openvpn/server.crt "https://raw.githubusercontent.com/shadow046/openvpndeb/master/server.crt"
wget -O /etc/openvpn/server.key "https://raw.githubusercontent.com/shadow046/openvpndeb/master/server.key"
wget -O /etc/openvpn/ca.crt "https://raw.githubusercontent.com/shadow046/openvpndeb/master/ca.crt"

# Setting Server
echo "port $PORT" > /etc/openvpn/server.conf
echo "proto $PROTOCOL" >> /etc/openvpn/server.conf
echo "dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
client-cert-not-required
username-as-common-name
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push \"redirect-gateway def1 bypass-dhcp\"
push \"dhcp-option DNS 8.8.8.8\"
push \"dhcp-option DNS 8.8.4.4\"
push \"route-method exe\"
push \"route-delay 2\"
socket-flags TCP_NODELAY
push \"socket-flags TCP_NODELAY\"
keepalive 10 120
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log openvpn.log
management "$MYIP" 7505
verb 3
ncp-disable
cipher AES-128-CBC" >> /etc/openvpn/server.conf

#Create Client ovpn
echo "client" > /etc/openvpn/client-template.txt
	if [[ "$PROTOCOL" = 'udp' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template.txt
	elif [[ "$PROTOCOL" = 'tcp' ]]; then
		echo "proto tcp" >> /etc/openvpn/client-template.txt
	fi
echo "remote $MYIP $PORT
dev tun
auth-user-pass
persist-key
persist-tun
pull
resolv-retry infinite
nobind
user nobody
group nogroup
comp-lzo
remote-cert-tls server
verb 3
mute 2
connect-retry 5 5
connect-retry-max 8080
mute-replay-warnings
redirect-gateway def1
script-security 2
cipher AES-128-CBC
setenv CLIENT_CERT 0
#uncomment below for windows 10
#setenv opt block-outside-dns # Prevent Windows 10 DNS leak" >> /etc/openvpn/client-template.txt
cp /etc/openvpn/client-template.txt /home/panel/html/SunTuConfig.ovpn
echo 'http-proxy' $MYIP $PORTS >> /home/panel/html/SunTuConfig.ovpn
echo 'http-proxy-option CUSTOM-HEADER ""' >> /home/panel/html/SunTuConfig.ovpn
echo 'http-proxy-option CUSTOM-HEADER "POST https://viber.com HTTP/1.1"' >> /home/panel/html/SunTuConfig.ovpn
echo 'http-proxy-option CUSTOM-HEADER "X-Forwarded-For: viber.com"' >> /home/panel/html/SunTuConfig.ovpn
echo '<ca>' >> /home/panel/html/SunTuConfig.ovpn
cat /etc/openvpn/ca.crt >> /home/panel/html/SunTuConfig.ovpn
echo '</ca>' >> /home/panel/html/SunTuConfig.ovpn

# Restart OpenVPN
/etc/init.d/openvpn restart
service openvpn start
service openvpn status
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
mkdir /etc/iptables
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" > /etc/iptables/add-openvpn-rules.sh
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT
" > /etc/iptables/rm-openvpn-rules.sh
  chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh
	ufw allow ssh
	ufw allow $PORT/tcp
	sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
	sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" > /etc/systemd/system/iptables-openvpn.service
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

# set ipv4 forward
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/20-openvpn.conf

# Install BadVPN
wget -O /usr/bin/badvpn-udpgw "https://github.com/shadow046/vpswithocs/raw/master/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://github.com/shadow046/vpswithocs/raw/master/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# SSH Configuration
sed -i 's@#Banner[[:space:]]none@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@PrintMotd[[:space:]]no@PrintMotd yes@g' /etc/ssh/sshd_config
sed -i 's@#PrintLastLog[[:space:]]yes@PrintLastLog no@g' /etc/ssh/sshd_config
sed -i 's@#Port[[:space:]]22@Port 22\nPort 225@g' /etc/ssh/sshd_config
sed -i 's@#AddressFamily[[:space:]]any@AddressFamily inet@g' /etc/ssh/sshd_config
sed -i 's@#ListenAddress[[:space:]]0@ListenAddress 0@g' /etc/ssh/sshd_config
service ssh restart

# Dropbear Configuration
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=550/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart

# Squid Configuration
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://raw.githubusercontent.com/shadow046/vpswithocs/master/squid.conf"
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

#Blocking
iptables -A INPUT -i eth0 -m state --state
iptables -A INPUT -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -j ACCEPT
iptables -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i eth0 -o tun+ -m state
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -A OUTPUT -o tun+ -j ACCEPT
iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A INPUT -m string --string "BitTorrent" --algo bm --to 65535 -j DROP
iptables -A INPUT -m string --string "BitTorrent protocol" --algo bm --to 65535 -j DROP
iptables -A INPUT -m string --string "peer_id=" --algo bm --to 65535 -j DROP
iptables -A INPUT -m string --string ".torrent" --algo bm --to 65535 -j DROP
iptables -A INPUT -m string --string "announce.php?passkey=" --algo bm --to 65535 -j DROP
iptables -A INPUT -m string --string "torrent" --algo bm --to 65535 -j DROP
iptables -A INPUT -m string --string "announce" --algo bm --to 65535 -j DROP
iptables -A INPUT -m string --string "info_hash" --algo bm --to 65535 -j DROP
iptables -A INPUT -m string --string "peer_id" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "BitTorrent" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "BitTorrent protocol" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "bittorrent-announce" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "announce.php?passkey=" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "find_node" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "info_hash" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "get_peers" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "announce" --algo kmp --to 65535 -j DROP
iptables -A INPUT -m string --string "announce_peers" --algo kmp --to 65535 -j DROP
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -I OUTPUT -p tcp --dport 1723 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -p tcp --dport 6881:6889 -j DROP
iptables -D FORWARD -m string --algo bm --string "BitTorrent" -j LOGDROP
iptables -D FORWARD -m string --algo bm --string "BitTorrent protocol" -j LOGDROP
iptables -D FORWARD -m string --algo bm --string "peer_id=" -j LOGDROP
iptables -D FORWARD -m string --algo bm --string ".torrent" -j LOGDROP
iptables -D FORWARD -m string --algo bm --string "announce.php?passkey=" -j LOGDROP
iptables -D FORWARD -m string --algo bm --string "torrent" -j LOGDROP
iptables -D FORWARD -m string --algo bm --string "announce" -j LOGDROP
iptables -D FORWARD -m string --algo bm --string "info_hash" -j LOGDROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j LOGDROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j LOGDROP
iptables -A FORWARD -p udp -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -p udp -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -p udp -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -p udp -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -p udp -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -p udp -m string --algo bm --string "torrent" -j DROP 
iptables -A FORWARD -p udp -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -p udp -m string --algo bm --string "info_hash" -j DROP 
iptables -A FORWARD -p udp -m string --algo bm --string "tracker" -j DROP 
iptables -A INPUT -p udp -m string --algo bm --string "BitTorrent" -j DROP 
iptables -A INPUT -p udp -m string --algo bm --string "BitTorrent protocol" -j DROP iptables -A INPUT -p udp -m string --algo bm --string "peer_id=" -j DROP 
iptables -A INPUT -p udp -m string --algo bm --string ".torrent" -j DROP 
iptables -A INPUT -p udp -m string --algo bm --string "announce.php?passkey=" -j DROP iptables -A INPUT -p udp -m string --algo bm --string "torrent" -j DROP 
iptables -A INPUT -p udp -m string --algo bm --string "announce" -j DROP 
iptables -A INPUT -p udp -m string --algo bm --string "info_hash" -j DROP 
iptables -A INPUT -p udp -m string --algo bm --string "tracker" -j DROP 
iptables -I INPUT -p udp -m string --algo bm --string "BitTorrent" -j DROP 
iptables -I INPUT -p udp -m string --algo bm --string "BitTorrent protocol" -j DROP iptables -I INPUT -p udp -m string --algo bm --string "peer_id=" -j DROP 
iptables -I INPUT -p udp -m string --algo bm --string ".torrent" -j DROP 
iptables -I INPUT -p udp -m string --algo bm --string "announce.php?passkey=" -j DROP iptables -I INPUT -p udp -m string --algo bm --string "torrent" -j DROP 
iptables -I INPUT -p udp -m string --algo bm --string "announce" -j DROP
iptables -I INPUT -p udp -m string --algo bm --string "info_hash" -j DROP 
iptables -I INPUT -p udp -m string --algo bm --string "tracker" -j DROP 
iptables -D INPUT -p udp -m string --algo bm --string "BitTorrent" -j DROP 
iptables -D INPUT -p udp -m string --algo bm --string "BitTorrent protocol" -j DROP iptables -D INPUT -p udp -m string --algo bm --string "peer_id=" -j DROP 
iptables -D INPUT -p udp -m string --algo bm --string ".torrent" -j DROP 
iptables -D INPUT -p udp -m string --algo bm --string "announce.php?passkey=" -j DROP iptables -D INPUT -p udp -m string --algo bm --string "torrent" -j DROP 
iptables -D INPUT -p udp -m string --algo bm --string "announce" -j DROP 
iptables -D INPUT -p udp -m string --algo bm --string "info_hash" -j DROP 
iptables -D INPUT -p udp -m string --algo bm --string "tracker" -j DROP 
iptables -I OUTPUT -p udp -m string --algo bm --string "BitTorrent" -j DROP 
iptables -I OUTPUT -p udp -m string --algo bm --string "BitTorrent protocol" -j DROP iptables -I OUTPUT -p udp -m string --algo bm --string "peer_id=" -j DROP 
iptables -I OUTPUT -p udp -m string --algo bm --string ".torrent" -j DROP 
iptables -I OUTPUT -p udp -m string --algo bm --string "announce.php?passkey=" -j DROP iptables -I OUTPUT -p udp -m string --algo bm --string "torrent" -j DROP 
iptables -I OUTPUT -p udp -m string --algo bm --string "announce" -j DROP 
iptables -I OUTPUT -p udp -m string --algo bm --string "info_hash" -j DROP 
iptables -I OUTPUT -p udp -m string --algo bm --string "tracker" -j DROP
iptables -D INPUT -m string --algo bm --string "BitTorrent" -j DROP 
iptables -D INPUT -m string --algo bm --string "BitTorrent protocol" -j DROP 
iptables -D INPUT -m string --algo bm --string "peer_id=" -j DROP
iptables -D INPUT -m string --algo bm --string ".torrent" -j DROP 
iptables -D INPUT -m string --algo bm --string "announce.php?passkey=" -j DROP 
iptables -D INPUT -m string --algo bm --string "torrent" -j DROP 
iptables -D INPUT -m string --algo bm --string "announce" -j DROP
iptables -D INPUT -m string --algo bm --string "info_hash" -j DROP
iptables -D INPUT -m string --algo bm --string "tracker" -j DROP 
iptables -D OUTPUT -m string --algo bm --string "BitTorrent" -j DROP
iptables -D OUTPUT -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -D OUTPUT -m string --algo bm --string "peer_id=" -j DROP
iptables -D OUTPUT -m string --algo bm --string ".torrent" -j DROP
iptables -D OUTPUT -m string --algo bm --string "announce.php?passkey=" -j DROP 
iptables -D OUTPUT -m string --algo bm --string "torrent" -j DROP
iptables -D OUTPUT -m string --algo bm --string "announce" -j DROP
iptables -D OUTPUT -m string --algo bm --string "info_hash" -j DROP
iptables -D OUTPUT -m string --algo bm --string "tracker" -j DROP 
iptables -D FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -D FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -D FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -D FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -D FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -D FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -D FORWARD -m string --algo bm --string "announce" -j DROP
iptables -D FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables -D FORWARD -m string --algo bm --string "tracker" -j DROP
iptables-save

# remove WebMin https
sed -i 's@ssl=1@ssl=0@g' /etc/webmin/miniserv.conf
service webmin restart

#Configure Stunnel
wget -O /etc/stunnel/stunnel.pem "https://raw.githubusercontent.com/shadow046/vpswithocs/master/stunnel.pem"
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
cat > /etc/stunnel/stunnel.conf <<-END
sslVersion = all
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no
[openssh]
accept = 444
connect = 127.0.0.1:225
[dropbear]
accept = 443
connect = 127.0.0.1:550
END
service stunnel4 restart

#restart fail2ban
service fail2ban restart

#configure ddos
wget "https://github.com/shadow046/vpswithocs/raw/master/ddos-deflate-master.zip"
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
rm -rf ddos-deflate-master.zip

#Banner
rm /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/shadow046/openvpndeb/master/bann3r"
wget -O /etc/motd "https://raw.githubusercontent.com/shadow046/openvpndeb/master/banner"
wget -O /etc/banner "https://raw.githubusercontent.com/shadow046/openvpndeb/master/banner"
service ssh restart
service dropbear restart

#Screenfetch
wget -O screenfetch "https://raw.githubusercontent.com/shadow046/openvpndeb/master/screenfetch"
chmod +x screenfetch

cd /usr/local/sbin
wget https://github.com/shadow046/vpswithocs/raw/master/menu.gz
tar -xzvf menu.gz
rm menu.gz
chmod +x /usr/local/sbin/*

#configure privoxy
rm -f /etc/privoxy/config
cat>>/etc/privoxy/config<<EOF
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:$PORTS
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 $MYIP
EOF

#restart all services
chown -R www-data:www-data /home/panel/html
service nginx start
service openvpn restart
service cron restart
service ssh restart
service dropbear restart
service squid3 restart
service webmin restart
service privoxy restart
rm -rf ~/.bash_history && history -c
