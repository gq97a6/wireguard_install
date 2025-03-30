#!/bin/bash

# DNS for client configuration (e.g. 8.8.8.8)
CLIENT_DNS=""

# Default endpoint for client configuration (e.g. your public IP address)
DEFAULT_ENDPOINT=""

# Directory where WireGuard configuration files are stored
DIR="/etc/wireguard"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

clear

# HELPER FUNCTIONS ------------------------------------------------------------------------------

function eraseLines() {
	for ((i=0; i<$1; i++)); do
    tput cuu1 # Move cursor up one line
    tput el # Clear the line
	done
}

# Function to check if all required packages (WireGuard, iptables, etc.) are installed
function checkPackages() {
	local ALL_INSTALLED=true

	check_package() {
		if dpkg -s $1 &> /dev/null; then
			echo "$1 package is installed"
		else
			echo "$1 package is NOT installed"
			ALL_INSTALLED=false
		fi
	}

	packages=("wireguard" "wireguard-tools" "iptables")

	for package in "${packages[@]}"; do
		check_package $package;
	done

	if $ALL_INSTALLED; then
		echo "All required packages are installed."
	else
		echo "Some required packages are missing."
		exit 0
	fi
}

# Function to check if a network address is valid
function isValidNetwork() {
  local network=$1
  
  # Regular expression to match a valid CIDR notation
  if [[ $network =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
    IFS='/' read -r ip mask <<< "$network"
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"

    # Check if each octet is in the range 0-255
    if [[ $i1 -le 255 && $i2 -le 255 && $i3 -le 255 && $i4 -le 255 ]]; then
      # Check if the IP is private
      if { [ "$i1" -eq 10 ] || 
           [ "$i1" -eq 172 ] && [ "$i2" -ge 16 ] && [ "$i2" -le 31 ] ||
           [ "$i1" -eq 192 ] && [ "$i2" -eq 168 ]; 
      }; then
        #Valid private network
        return 0
      else
        #Valid public network
        return 0
      fi
    else
      echo "Invalid network: $network (octets out of range)"
      return 1
    fi
  else
    echo "Invalid network format: $network"
    return 1
  fi
}

# Function to check if a WireGuard interface configuration file exists
function interfaceExists() {
	if [[ -f "$DIR/wg$1.conf" ]]; then
		return 0
	else
		return 1
	fi
}

#Function to extract and format the client addresses
function getClients() {
	grep '#!CLIENT-' "$DIR/wg$1.conf" 2> /dev/null | grep 'AllowedIPs' 2> /dev/null | \
	sed 's/AllowedIPs = \([0-9.\/]*\) #!CLIENT-\(.*\)/Client \2 allowed IPs: \1/' 2> /dev/null
}

# Function to retrieve the IP addresses of the current machine (useful for setting the endpoint)
function getEndpoints() {
	hostname -I
}

# Function to list all WireGuard interface indices (e.g. wg0, wg1) based on existing configuration files
function getInterfacesIndices() {
	ls $DIR/wg*.conf 2> /dev/null | sed -E 's/.*wg([0-9]+)\.conf/\1/' 2> /dev/null
}

function getInterfacePort() {
	grep "ListenPort =" "$DIR/wg$1.conf" | sed 's/ListenPort = //' 2> /dev/null
}

function getInterfaceAddress() {
	grep "Address =" "$DIR/wg$1.conf" | sed 's/Address = //' 2> /dev/null
}

# Function to check if a specific marker exists in the configuration file
function markerExists() {
	grep -q "$2$" "$DIR/wg$1.conf" 2> /dev/null
}

# Function to insert lines into a WireGuard configuration file based on a marker
function insertLines() {
	local LINES=("$@")
	local LINES_COUNT=${#LINES[@]}

	# Insert lines in reverse order after the specified marker
	for (( i=LINES_COUNT-1; i>=2; i-- )); do
		sed -i "/^#!$2$/a ${LINES[$i]}" "$DIR/wg$1.conf"
	done
}

# Function to remove lines marked with a specific marker from a WireGuard configuration file
function removeMarkedLines() {
	sed -i "/$2$/d" "$DIR/wg$1.conf" 2> /dev/null
}

# Function to create custom iptables chains for WireGuard traffic management
function addChains() {
	iptables -N WIREGUARD_INPUT
	iptables -N WIREGUARD_OUTPUT
	iptables -N WIREGUARD_FORWARD
	iptables -N WIREGUARD_POSTROUTING -t nat
	iptables -A INPUT -j WIREGUARD_INPUT
	iptables -A OUTPUT -j WIREGUARD_OUTPUT
	iptables -A FORWARD -j WIREGUARD_FORWARD
	iptables -A POSTROUTING -t nat -j WIREGUARD_POSTROUTING
}

# Function to remove custom iptables chains created for WireGuard
function removeChains() {
	iptables -D INPUT -j WIREGUARD_INPUT 2> /dev/null
	iptables -D OUTPUT -j WIREGUARD_OUTPUT 2> /dev/null
	iptables -D FORWARD -j WIREGUARD_FORWARD 2> /dev/null
	iptables -D POSTROUTING -t nat -j WIREGUARD_POSTROUTING 2> /dev/null
	iptables -F WIREGUARD_INPUT 2> /dev/null
	iptables -F WIREGUARD_OUTPUT 2> /dev/null
	iptables -F WIREGUARD_FORWARD 2> /dev/null
	iptables -F WIREGUARD_POSTROUTING -t nat 2> /dev/null
	iptables -X WIREGUARD_INPUT 2> /dev/null
	iptables -X WIREGUARD_OUTPUT 2> /dev/null
	iptables -X WIREGUARD_FORWARD 2> /dev/null
	iptables -X WIREGUARD_POSTROUTING -t nat 2> /dev/null
}

# Function to display the QR code of a client's configuration (useful for mobile clients)
function showCode() {

	CLIENT_NAME=""
	until [[ -n $CLIENT_NAME ]]; do
		read -rp "Client name: " CLIENT_NAME
	done
	echo ""

	qrencode -t ansiutf8 < $DIR/client_configs/$CLIENT_NAME.conf
}

# ASK POLICY FUNCTIONS ------------------------------------------------------------------------------

function askInput() { 
	echo -e "Specify policy regarding ${RED}INPUT${RESET} traffic on the wg$1 interface:"
	echo "   1) Rely on input chain policy"
	echo "   2) Accept only to wg$1 address"
	echo "   3) Accept to specific addresses"
	echo "   4) Accept all regardless of the target"
	echo ""
	echo "About this policy:"
	echo "- Affects the traffic that IS destinated to local interfaces on this machine"
	echo "- Affects the ability of clients to reach local interfaces on this machine"
	echo "- Affects the ability of clients to ping the wg$1 interface or other local interface"
	echo "- Affects the ability of clients to access services listening on the wg$1 interface or other local interface"
	echo "- Does NOT affect traffic forwarding"
}

function askForward() { 
	echo -e "Specify policy regarding ${RED}FORWARDING${RESET} traffic from the wg$1 interface:"
	echo "   1) Rely on forward chain policy"
	echo "   2) Accept only to wg$1"
	echo "   3) Accept to specific interfaces"
	echo "   4) Accept all regardless of the target"
	echo ""
	echo "About this policy:"
	echo "- Affects the traffic that is NOT destinated to local interfaces on this machine"
	echo "- Affects the ability of clients in wg$1 to reach other clients/devices"
	echo "- Does NOT affect the ability of clients to ping the wg$1 interface or other local interfaces"
	echo "- Does NOT affect the ability of clients to access services listening on the wg$1 interface or other local interfaces"
}

function askOutput() { 
	echo -e "Specify policy regarding ${RED}OUTPUT${RESET} traffic from the wg$1 interface:"
	echo "   1) Rely on output chain policy"
	echo "   2) Accept to specific addresses"
	echo "   3) Accept all regardless of the target"
	echo ""
	echo "About this policy:"
	echo "- Affects traffic generated by the wg$1 interface to external destinations"
}

# KEY PAIRS FUNCTIONS ------------------------------------------------------------------------------

# Function to generate a private and public key pair for WireGuard
function generatePair() {
	PRIVATE_KEY=$(wg genkey)
	PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)
}

# Function to create and store a key pair for a specific WireGuard interface
function createKeyPair() {
	generatePair

	if grep -q "^$1:" "$DIR/keys.txt"; then
		echo "Key pair for interface wg$1 already exists."
		exit 0;
	fi

	echo "$1:$PRIVATE_KEY:$PUBLIC_KEY" >> "$DIR/keys.txt"
}

# Function to remove a key pair for a specific WireGuard interface
function removeKeyPair() {
	if grep -q "^$1:" "$DIR/keys.txt"; then
		grep -v "^$1:" "$DIR/keys.txt" > "$DIR/keys.txt.tmp"
		mv "$DIR/keys.txt.tmp" $DIR/keys.txt
	else
		echo "Failed to remove interface wg$1 key pair."
		exit 0;
	fi
}

# Function to retrieve the private key of a specific WireGuard interface
function getPrivateKey() {
	if grep -q "^$1:" "$DIR/keys.txt"; then
		PRIVATE_KEY=$(grep "^$1:" "$DIR/keys.txt" | cut -d ':' -f2)
	else
		echo "Private key for interface wg$1 not found."
		exit 0;
	fi
}

# Function to retrieve the public key of a specific WireGuard interface
function getPublicKey() {
	if grep -q "^$1:" "$DIR/keys.txt"; then
		PUBLIC_KEY=$(grep "^$1:" "$DIR/keys.txt" | cut -d ':' -f3)
	else
		echo "Public key for interface wg$1 not found."
		exit 0;
	fi
}

# INTERFACE FUNCTIONS ------------------------------------------------------------------------------

# Function to manage (start, stop, restart) a WireGuard interface
function manageInterface() {
	local INTERFACE_INDEX=$2
	
	# Prompt the user to input the interface index if not provided
	if [[ -z $INTERFACE_INDEX ]]; then
		until interfaceExists $INTERFACE_INDEX; do
			read -rp "Interface index to $1: " INTERFACE_INDEX
		done

		local CONTINUE=""
		until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
			read -rp "Are you sure you want to $1 interface wg$INTERFACE_INDEX? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then exit 1; fi
	fi

	case $1 in
	RESTART)
		systemctl enable wg-quick@wg$INTERFACE_INDEX.service
		systemctl restart wg-quick@wg$INTERFACE_INDEX.service
		;;
	DISABLE)
		systemctl stop wg-quick@wg$INTERFACE_INDEX.service
		systemctl disable wg-quick@wg$INTERFACE_INDEX.service
		;;
	ENABLE)
		systemctl enable wg-quick@wg$INTERFACE_INDEX.service
		systemctl start wg-quick@wg$INTERFACE_INDEX.service
		;;
	esac
}

# Function to modify the rules and settings of an existing WireGuard interface
function modifyInterface() {
	local INTERFACE_INDEX=$1

	# Prompt the user to input the interface index if not provided
	until interfaceExists $INTERFACE_INDEX; do
		read -rp "Interface index to modify: " INTERFACE_INDEX
	done
	
	local INTERFACE_ADDRESS=$(getInterfaceAddress $INTERFACE_INDEX)

	if ! isValidNetwork $INTERFACE_ADDRESS; then 
		echo "Interface configuration contains invalid address."
		exit 0
	fi

	INTERFACE_ADDRESS=$(echo "$INTERFACE_ADDRESS" | sed 's/\/24/\/32/')

	echo ""

	ALLOW_INTERNET=""
	until [[ $ALLOW_INTERNET =~ ^[ynYN]$ ]]; do
		read -rp "Do you wish to allow $(echo -en ${RED}INTERNET${RESET}) access for clients in wg$INTERFACE_INDEX? [y/n]: " -e ALLOW_INTERNET
	done

	echo ""

	askInput $INTERFACE_INDEX
	echo ""
	local INPUT_POLICY=""
	while true; do
		read -rp "Select an option: " INPUT_POLICY
		if [[ $INPUT_POLICY == "3" ]]; then read -rp "List space-separated networks (eg. 10.0.0.0/24) (leave blank to abort): " INPUT_POLICY_NETWORKS;
		elif [[ $INPUT_POLICY =~ ^[0-9]+$ ]] && [[ $INPUT_POLICY -ge 1 ]] && [[ $INPUT_POLICY -le 4 ]]; then break; fi
		
		#Check if each network is valid
		VALID=true
		for NETWORK in $INPUT_POLICY_NETWORKS; do
			if ! isValidNetwork $NETWORK; then INPUT_POLICY_NETWORKS=""; local VALID=false; fi
		done

		if [[ -n $INPUT_POLICY_NETWORKS ]] && $VALID; then break;
		else local INPUT_POLICY=""; fi
	done

	echo ""

	askOutput $INTERFACE_INDEX
	echo ""
	local OUTPUT_POLICY=""
	while true; do
		read -rp "Select an option: " OUTPUT_POLICY
		if [[ $OUTPUT_POLICY == "2" ]]; then read -rp "List space-separated networks (eg. 10.0.0.0/24) (leave blank to abort): " OUTPUT_POLICY_NETWORKS;
		elif [[ $OUTPUT_POLICY =~ ^[0-9]+$ ]] && [[ $OUTPUT_POLICY -ge 1 ]] && [[ $OUTPUT_POLICY -le 4 ]]; then break; fi
		
		#Check if each network is valid
		VALID=true
		for NETWORK in $OUTPUT_POLICY_NETWORKS; do
			if ! isValidNetwork $NETWORK; then OUTPUT_POLICY_NETWORKS=""; local VALID=false; fi
		done

		if [[ -n $OUTPUT_POLICY_NETWORKS ]] && $VALID; then break;
		else local OUTPUT_POLICY=""; fi
	done

	echo ""
	
	askForward $INTERFACE_INDEX
	echo ""
	local FORWARD_POLICY=""
	while true; do
		read -rp "Select an option: " FORWARD_POLICY
		if [[ $FORWARD_POLICY == "3" ]]; then read -rp "List space-separated interfaces names (leave blank to abort): " FORWARD_POLICY_INTERFACES;
		elif [[ $FORWARD_POLICY =~ ^[0-9]+$ ]] && [[ $FORWARD_POLICY -ge 1 ]] && [[ $FORWARD_POLICY -le 4 ]]; then break; fi

		if [[ -n $FORWARD_POLICY_INTERFACES ]]; then break;
		else local FORWARD_POLICY=""; fi
	done

	echo ""
	
	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Before introducing new rules interface wg$INTERFACE_INDEX must be DISABLED. Proceed? [y/n]: " -e CONTINUE
	done
	if [[ $CONTINUE == "n" ]]; then exit 0; fi

	manageInterface DISABLE $INTERFACE_INDEX
	removeMarkedLines $INTERFACE_INDEX "#!RULE"

	local LINES_INTERNET=(
		"#Allow internet access #!RULE"
		"PostUp = iptables -A WIREGUARD_FORWARD -i wg$INTERFACE_INDEX -o eth0 -j ACCEPT #!RULE"
		"PostDown = iptables -D WIREGUARD_FORWARD -i wg$INTERFACE_INDEX -o eth0 -j ACCEPT #!RULE"
		"PostUp = iptables -A WIREGUARD_POSTROUTING -i wg$INTERFACE_INDEX -o eth0 -t nat -j MASQUERADE #!RULE"
		"PostDown = iptables -D WIREGUARD_POSTROUTING -i wg$INTERFACE_INDEX -o eth0 -t nat -j MASQUERADE #!RULE"
	)

	local LINES_INPUT_INTERNAL=(
		"#INPUT: Accepting only to wg$INTERFACE_INDEX address. #!RULE"
		"PostUp = iptables -A WIREGUARD_INPUT -i wg$INTERFACE_INDEX -d $INTERFACE_ADDRESS -j ACCEPT #!RULE"
		"PostDown = iptables -D WIREGUARD_INPUT -i wg$INTERFACE_INDEX -d $INTERFACE_ADDRESS -j ACCEPT #!RULE"
	)

	local LINES_INPUT_ALLOW_ALL=(
		"#INPUT: Accepting all regardless of the target. #!RULE"
		"PostUp = iptables -A WIREGUARD_INPUT -i wg$INTERFACE_INDEX -j ACCEPT #!RULE"
		"PostDown = iptables -D WIREGUARD_INPUT -i wg$INTERFACE_INDEX -j ACCEPT #!RULE"
	)

	local LINES_OUTPUT_ALLOW_ALL=(
		"#OUTPUT: Accepting all regardless of the target. #!RULE"
		"PostUp = iptables -A WIREGUARD_OUTPUT -o wg0 -j ACCEPT #!RULE"
		"PostDown = iptables -D WIREGUARD_OUTPUT -o wg0 -j ACCEPT #!RULE"
	)

	local LINES_FORWARD_INTERNAL=(
		"#FORWARD: Accepting only to wg$INTERFACE_INDEX. #!RULE"
		"PostUp = iptables -A WIREGUARD_FORWARD -i wg$INTERFACE_INDEX -o wg$INTERFACE_INDEX -j ACCEPT #!RULE"
		"PostDown = iptables -D WIREGUARD_FORWARD -i wg$INTERFACE_INDEX -o wg$INTERFACE_INDEX -j ACCEPT #!RULE"
	)

	local LINES_FORWARD_ALL=(
		"#FORWARD: Accepting all regardless of the target. #!RULE"
		"PostUp = iptables -A WIREGUARD_FORWARD -i wg$INTERFACE_INDEX -j ACCEPT #!RULE"
		"PostDown = iptables -D WIREGUARD_FORWARD -i wg$INTERFACE_INDEX -j ACCEPT #!RULE"
	)

	echo ""

	case $INPUT_POLICY in
	1)
		echo -e "${RED}INPUT:${GREEN} Relying on input chain policy."
		;; #---------------------------------------------------------
	2)
		insertLines $INTERFACE_INDEX IPTABLES "${LINES_INPUT_INTERNAL[@]}"
		echo -e "${RED}INPUT:${GREEN} Accepting only to wg$INTERFACE_INDEX address."
		;; #---------------------------------------------------------
	3)
		for NETWORK in $INPUT_POLICY_NETWORKS; do
			local LINES=(
				"#INPUT: Accepting to $NETWORK. #!RULE"
				"PostUp = iptables -A INPUT -i wg$INTERFACE_INDEX -d $NETWORK -j ACCEPT #!RULE"
				"PostDown = iptables -D INPUT -i wg$INTERFACE_INDEX -d $NETWORK -j ACCEPT #!RULE"
			)

			insertLines $INTERFACE_INDEX IPTABLES "${LINES[@]}"
			echo -e "${RED}INPUT:${GREEN} Accepting to $NETWORK."
		done
		;; #---------------------------------------------------------
	4)
		insertLines $INTERFACE_INDEX IPTABLES "${LINES_INPUT_ALLOW_ALL[@]}"
		echo -e "${RED}INPUT:${GREEN} Accepting all regardless of the target."
		;;
	esac

	echo ""

	case $OUTPUT_POLICY in
	1)
		echo -e "${RED}OUTPUT:${GREEN} Relying on output chain policy."
		;; #---------------------------------------------------------
	2)
		for NETWORK in $OUTPUT_POLICY_NETWORKS; do
			local LINES=(
				"#OUTPUT: Accepting only to $NETWORK. #!RULE"
				"PostUp = iptables -A OUTPUT -o wg$INTERFACE_INDEX -d $NETWORK -j ACCEPT #!RULE"
				"PostDown = iptables -D OUTPUT -o wg$INTERFACE_INDEX -d $NETWORK -j ACCEPT #!RULE"
			)

			insertLines $INTERFACE_INDEX IPTABLES "${LINES[@]}"
			echo -e "${RED}OUTPUT:${GREEN} Accepting to $NETWORK."
		done
		;; #---------------------------------------------------------
	3)
		insertLines $INTERFACE_INDEX IPTABLES "${LINES_OUTPUT_ALLOW_ALL[@]}"
		echo -e "${RED}OUTPUT:${GREEN} Accepting all regardless of the target."
		;; #---------------------------------------------------------
	esac

	echo ""

	case $FORWARD_POLICY in
	1)
		echo -e "${RED}FORWARD:${GREEN} Relying on forward chain policy."
		;; #---------------------------------------------------------
	2)
		insertLines $INTERFACE_INDEX IPTABLES "${LINES_FORWARD_INTERNAL[@]}"
		echo -e "${RED}FORWARD:${GREEN} Accepting only to wg$INTERFACE_INDEX."
		;; #---------------------------------------------------------
	3)
		for INTERFACE in $FORWARD_POLICY_INTERFACES; do
			local LINES=(
				"#FORWARD: Accepting to $INTERFACE interface. #!RULE"
				"PostUp = iptables -A FORWARD -i wg$INTERFACE_INDEX -o $INTERFACE -j ACCEPT #!RULE"
				"PostDown = iptables -D FORWARD -i wg$INTERFACE_INDEX -o $INTERFACE -j ACCEPT #!RULE"
			)

			insertLines $INTERFACE_INDEX IPTABLES "${LINES[@]}"
			echo -e "${RED}FORWARD:${GREEN} Accepting only to $INTERFACE interface."
		done
		;; #---------------------------------------------------------
	4)
		insertLines $INTERFACE_INDEX IPTABLES "${LINES_FORWARD_ALL[@]}"
		echo -e "${RED}FORWARD:${GREEN} Accepting all regardless of the target."
		;; #---------------------------------------------------------
	esac

	if [[ $ALLOW_INTERNET == "y" ]]; then 
		insertLines $INTERFACE_INDEX IPTABLES "${LINES_INTERNET[@]}"
		echo ""
		echo -e "${RED}INTERNET:${GREEN} Allowing internet access."
		echo -e "${RED}INTERNET: ${YELLOW}Remember to set ${BLUE}net.ipv4.ip_forward=1${YELLOW} in ${BLUE}/etc/sysctl.conf${RESET}"
		echo -e "${RED}INTERNET: ${YELLOW}Then ${BLUE}sudo sysctl -p${YELLOW} to apply changes.${RESET}"
	fi

	echo -e "${RESET}"

	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Do you want to enable wg$INTERFACE_INDEX interface with new configuration? [y/n]: " -e CONTINUE
	done
	if [[ $CONTINUE == "n" ]]; then exit 0; fi

	manageInterface ENABLE $INTERFACE_INDEX
}

# Function to remove a WireGuard interface
function removeInterface() {
	local INTERFACE_INDEX=$1

	# Prompt the user to input the interface index if not provided
	until interfaceExists $INTERFACE_INDEX; do
		read -rp "Interface index to remove: " INTERFACE_INDEX
	done
	echo ""

	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Are you sure you want to REMOVE interface wg$INTERFACE_INDEX? [y/n]: " -e CONTINUE
	done
	if [[ $CONTINUE == "n" ]]; then exit 0; fi

	removeKeyPair $INTERFACE_INDEX
	systemctl stop wg-quick@wg$INTERFACE_INDEX.service
	systemctl disable wg-quick@wg$INTERFACE_INDEX.service
	rm $DIR/wg$INTERFACE_INDEX.conf
}

# Function to add a new WireGuard interface
function addInterface() {

	# Prompt the user for the interface index and validate it
	INTERFACE_INDEX=""
	until [[ $INTERFACE_INDEX =~ ^[0-9]+$ ]] && [ "$INTERFACE_INDEX" -ge 0 ] && [ "$INTERFACE_INDEX" -le 100 ]; do
		read -rp "New interface index: " INTERFACE_INDEX
	done
	echo ""

	if interfaceExists $INTERFACE_INDEX; then
		echo "Interface wg$INTERFACE_INDEX already exists."
		exit 0;
	fi

	INTERFACE_PORT=""
	until [[ $INTERFACE_PORT =~ ^[0-9]+$ ]] && [ "$INTERFACE_PORT" -ge 1 ] && [ "$INTERFACE_PORT" -le 65535 ]; do
		read -rp "New interface port [1-65535]: " INTERFACE_PORT
	done
	echo ""

	read -rp "New interface address [e.g. 10.0.0.1/24]: " INTERFACE_ADDRESS
	until isValidNetwork $INTERFACE_ADDRESS; do
		read -rp "New interface address [e.g. 10.0.0.1/24]: " INTERFACE_ADDRESS
	done
	echo ""

	createKeyPair $INTERFACE_INDEX
	touch "$DIR/wg$INTERFACE_INDEX.conf"

	local LINES=(
		"# ============================================== #"
		"# DO NOT MODIFY OR REMOVE LINE MARKERS (!MARKER) #"
		"# ============================================== #"
		""
		"[Interface]"
		"Address = $INTERFACE_ADDRESS"
		"ListenPort = $INTERFACE_PORT"
		"PrivateKey = $PRIVATE_KEY"
		""
		"#!IPTABLES"
		"#Open port for this network"
		"PostUp = iptables -A WIREGUARD_INPUT -i eth0 -p udp --dport $INTERFACE_PORT -j ACCEPT"
		"PostDown = iptables -D WIREGUARD_INPUT -i eth0 -p udp --dport $INTERFACE_PORT -j ACCEPT"
		""
		"#!CLIENTS"
	)

	printf "%s\n" "${LINES[@]}" >> "$DIR/wg$INTERFACE_INDEX.conf"
	modifyInterface $INTERFACE_INDEX
}

# CLIENT FUNCTIONS ------------------------------------------------------------------------------

# Function to add a new client to a WireGuard interface
function addClient() {

	# Prompt the user to provide a valid interface index
	INTERFACE_INDEX=""
	until interfaceExists $INTERFACE_INDEX; do
		read -rp "Interface index to add client to: " INTERFACE_INDEX
	done
	echo ""

	# Define the server's public key, interface port, and network
	getPublicKey $INTERFACE_INDEX
	local SERVER_PUBLIC_KEY=$PUBLIC_KEY
	local INTERFACE_PORT=$(getInterfacePort $INTERFACE_INDEX)
	local INTERFACE_ADDRESS=$(getInterfaceAddress $INTERFACE_INDEX)

	echo "You are adding client for wg$INTERFACE_INDEX"
	echo "Interface address: $INTERFACE_ADDRESS"
	echo "Interface port: $INTERFACE_PORT"
	getClients 0
	echo ""
	
	CLIENT_NAME=""
	until [[ -n $CLIENT_NAME ]]; do
		read -rp "Set client name: " CLIENT_NAME
	done
	echo ""

	if [[ -f "$DIR/client_configs/$CLIENT_NAME.conf" ]]; then
		echo "Configuration for client $CLIENT_NAME already exists in: $DIR/client_configs"
		exit 0
	fi

	if markerExists $INTERFACE_INDEX "#!CLIENT-$CLIENT_NAME"; then
		echo "Interface wg$INTERFACE_INDEX already contains $CLIENT_NAME client."
		exit 0
	fi

	echo "Set client address."
	read -rp "Address = " CLIENT_ADDRESS
	until isValidNetwork $CLIENT_ADDRESS; do
		read -rp "Address = " CLIENT_ADDRESS
	done
	echo ""

	echo "Set to which networks client traffic should be routed."
	CLIENT_ROUTE=""
	until [[ -n $CLIENT_ROUTE ]]; do
		read -rp "AllowedIPs = " CLIENT_ROUTE
	done
	echo ""

	echo "Set which IP addresses client is allowed to have."
	CLIENT_ALLOWED=""
	until [[ -n $CLIENT_ALLOWED ]]; do
		read -rp "AllowedIPs = " CLIENT_ALLOWED
	done
	echo ""

	touch "$DIR/client_configs/$CLIENT_NAME.conf"
	
	generatePair
	local CLIENT_PRIVATE_KEY=$PRIVATE_KEY
	local CLIENT_PUBLIC_KEY=$PUBLIC_KEY

	local LINES=(
		"[Interface]"
		"PrivateKey = $CLIENT_PRIVATE_KEY"
		"Address = $CLIENT_ADDRESS"
		"DNS = $CLIENT_DNS"
		""
		"[Peer]"
		"PublicKey = $SERVER_PUBLIC_KEY"
		"AllowedIPs = $CLIENT_ROUTE"
		"Endpoint = $DEFAULT_ENDPOINT:$INTERFACE_PORT"
		"PersistentKeepalive = 25"
	)

	printf "%s\n" "${LINES[@]}" >> "$DIR/client_configs/$CLIENT_NAME.conf"

	local LINES=(
		"[Peer] #!CLIENT-$CLIENT_NAME"
		"PublicKey = $CLIENT_PUBLIC_KEY #!CLIENT-$CLIENT_NAME"
		"AllowedIPs = $CLIENT_ALLOWED #!CLIENT-$CLIENT_NAME"
	)

	insertLines $INTERFACE_INDEX CLIENTS "${LINES[@]}"
	echo "Client configuration saved to: $DIR/client_configs/$CLIENT_NAME.conf"

	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Do you want to restart wg$INTERFACE_INDEX interface to apply new configuration? [y/n]: " -e CONTINUE
	done
	echo ""

	if [[ $CONTINUE == "y" ]]; then
		manageInterface RESTART $INTERFACE_INDEX
	fi
}

# Function to remove a client from a WireGuard interface
function removeClient() {
	
	# Prompt the user to provide a valid interface index
	INTERFACE_INDEX=""
	until interfaceExists $INTERFACE_INDEX; do
		read -rp "Interface index to remove client from: " INTERFACE_INDEX
	done

	CLIENT_NAME=""
	until markerExists $INTERFACE_INDEX "#!CLIENT-$CLIENT_NAME"; do
		read -rp "Client name to remove (case sensitive): " CLIENT_NAME
	done

	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Are you sure you want to remove $CLIENT_NAME from wg$INTERFACE_INDEX? [y/n]: " -e CONTINUE
	done
	if [[ $CONTINUE == "n" ]]; then exit 0; fi

	removeMarkedLines $INTERFACE_INDEX "#!CLIENT-$CLIENT_NAME"
	rm "$DIR/client_configs/$CLIENT_NAME.conf" 2> /dev/null

	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Do you want to restart wg$INTERFACE_INDEX interface to apply new configuration? [y/n]: " -e CONTINUE
	done

	if [[ $CONTINUE == "y" ]]; then
		manageInterface RESTART $INTERFACE_INDEX
	fi
}

# Function to completely remove WireGuard and its configuration
function removeWireguard() {
	
	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Are you sure you want to REMOVE wireguard? [y/n]: " -e CONTINUE
	done
	if [[ $CONTINUE == "n" ]]; then exit 0; fi

	echo ""

	# Remove all WireGuard interfaces
	for INDEX in $(getInterfacesIndices); do
		removeInterface $INDEX
	done

	# Remove firewall rules and uninstall WireGuard packages
	removeChains
	apt -y remove wireguard 2> /dev/null
	apt -y remove wireguard-tools 2> /dev/null
	rm -r $DIR 2> /dev/null
}

# Function to install WireGuard and required packages
function installWireguard() {
	echo "This script requires the following packages to be installed:"
	echo "   - wireguard"
	echo "   - wireguard-tools"
	echo "   - iptables"
	echo "   - qrencode (optional for QR code generation)"
	echo ""
	echo "What do you want to do?"
	echo "   1) Install packages via apt and proceed"
	echo "   2) Proceed (packages already installed)"
	echo "   3) Cancel"

	local MENU_OPTION=""
	until [[ $MENU_OPTION =~ ^[0-9]+$ ]] && [ "$MENU_OPTION" -ge 1 ] && [ "$MENU_OPTION" -le 3 ]; do
		read -rp "Select an option: " MENU_OPTION
	done
	echo ""

	# Check if DNS and endpoint variables are set
	if [[ -z "$CLIENT_DNS" ]] || [[ -z "$DEFAULT_ENDPOINT" ]]; then
		echo "First edit lines below before running the script:"
		echo "CLIENT_DNS=\"\""
		echo "DEFAULT_ENDPOINT=\"\""
		exit 0
	fi

	if [[ $MENU_OPTION -eq 3 ]]; then
		exit 0;
	elif [[ $MENU_OPTION -eq 1 ]]; then
		apt update
		apt -y install wireguard
		apt -y install wireguard-tools
		apt -y install qrencode
		apt -y install iptables
	fi

	checkPackages
	mkdir $DIR/client_configs
	touch $DIR/keys.txt
	removeChains
	addChains

	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Do you want to add first interface? [y/n]: " -e CONTINUE
	done
	if [[ $CONTINUE == "n" ]]; then exit 0; fi
	
	echo ""

	addInterface

	local CONTINUE=""
	until [[ $CONTINUE =~ ^[ynYN]$ ]]; do
		read -rp "Do you want to add first client? [y/n]: " -e CONTINUE
	done
	if [[ $CONTINUE == "n" ]]; then exit 0; fi
	
	echo ""

	addClient
}

# Main menu function to handle user interaction
function mainMenu() {
	echo "What do you want to do?"
	echo "   11) Add new client"
	echo "   12) Remove client"
	echo "   13) Show QR code for client"
	echo "========================================"
	echo "   21) Add interface"
	echo "   22) Modify interface"
	echo "   23) Remove interface"
	echo "========================================"
	echo "   31) Disable interface"
	echo "   32) Enable interface"
	echo "   33) Restart interface"
	echo "========================================"
	echo "   41) Remove wireguard"
	echo "========================================"
	echo "   0) Exit"

	local MENU_OPTION=""
	until [[ $MENU_OPTION =~ ^[0-9]+$ ]] && [[ $MENU_OPTION -ge 1 ]] && [[ $MENU_OPTION -le 100 ]]; do
		read -rp "Select an option: " MENU_OPTION
	done
	clear

	case $MENU_OPTION in
		11) addClient ;;
		12) removeClient ;;
		13) showCode ;;
		21) addInterface ;;
		22) modifyInterface ;;
		23) removeInterface ;;
		31) manageInterface DISABLE ;;
		32) manageInterface ENABLE ;;
		33) manageInterface RESTART ;;
		41) removeWireguard ;;
		0) exit 0 ;;
	esac
}

if [[ -d "$DIR" ]]; then
	mainMenu
else
	installWireguard
	mainMenu
fi
