#!/bin/bash

# Hazel DDoS Mitigation basic configuration
# https://Pixiemines.com/


function Rootchekcer() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You have to run the script as root"
		exit 1
	fi
}

# this was forked from https://github.com/angristan
function OSVersionChecker() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "It appears that you are running an outdataed version of linux, Please update your OS"
		exit 1
	fi
}


function checkcer(){
Rootchekcer
OSVersionChecker
}


function PreApplying() {
echo "Hello and welcome to the MC basic firewall mitigation installer"
echo "This is suppsoed to be a configurable file that you set the paramaters as you like, most the configuration is mildy effective by default, it is exepected for the user to reconfigure the file"


# This checks the interface name 
	MAIN_INTERFACE="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${MAIN_PUB_INTERFACE} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${MAIN_INTERFACE}" main_pub_interface
	done

    UDP_usage=
    while true; do
    read -rp "Do you want UDP to be ON or OFF? (we recommend keeping it on in most cases as it may cause issues with contivity You also need UDP if your server supports Bedrock edition): " input
    if [[ "$UDP_STATE" == "ON" || "$UDP_STATE" == "OFF" ]]; then 
        break
    else
        echo "Invalid input. Please enter 'ON' or 'OFF'."
    fi
done


 if [[ "$UDP_STATE" == "OFF" ]]; then
    echo "Turning off UDP..."
    #  Here it executes the turn off comamand, if you wish to keep DNS on or anyother UDP port please add it in here(make sure its above the DROP). 
    iptables -A INPUT -p udp -j DROP
    iptables -A OUTPUT -p udp -j DROP
    echo "UDP has been turned off."
else
    echo "UDP remains on."
    fi

}

