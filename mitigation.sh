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
    # Command to turn off UDP
    echo "Turning off UDP..."
    #  Here it executes the turn off comamand, if you wish to keep DNS on or anyother UDP port please add it in here(make sure its above the DROP). 
    iptables -A INPUT -p udp -j DROP
    iptables -A OUTPUT -p udp -j DROP
    echo "UDP has been turned off."
else
    echo "UDP remains on."
    fi

}

function Applying(){

# Anti-DDoS Kernel Settings
sysctl_setting="

kernel.printk = 4 4 1 7
kernel.panic = 10
kernel.sysrq = 0
kernel.shmmax = 4294967296
kernel.shmall = 4194304
kernel.core_uses_pid = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
vm.swappiness = 20
vm.dirty_ratio = 80
vm.dirty_background_ratio = 5
fs.file-max = 2097152
net.core.netdev_max_backlog = 262144
net.core.rmem_default = 31457280
net.core.rmem_max = 67108864
net.core.wmem_default = 31457280
net.core.wmem_max = 67108864
net.core.somaxconn = 4096
net.core.optmem_max = 25165824
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
net.ipv4.neigh.default.gc_interval = 5
net.ipv4.neigh.default.gc_stale_time = 120
net.netfilter.nf_conntrack_max = 10000000
net.netfilter.nf_conntrack_buckets = 65536
net.netfilter.nf_conntrack_tcp_loose = 0
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 20
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 20
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.route.flush = 1
net.ipv4.route.max_size = 8048576
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.tcp_wmem = 4096 87380 33554432
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = 400000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.ipfrag_low_thresh = 196608
net.ipv4.ipfrag_high_thresh = 262144
net.ipv4.tcp_synproxy_enabled = 1
net.ipv4.icmp_ratelimit = 1000

"

# Check if the setting already exists in the file
if grep -q "^${sysctl_setting%%=*}" /etc/sysctl.conf; then
    # If it exists, replace the line
    sudo sed -i "s/^${sysctl_setting%%=*}.*/$sysctl_setting/" /etc/sysctl.conf
else
    echo "$sysctl_setting" | sudo tee -a /etc/sysctl.conf > /dev/null
fi

sudo sysctl -p



# extras

### 1: Drop invalid packets ### 
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -m conntrack --ctstate INVALID -j DROP  


### 2: Drop TCP packets that are new and are not SYN ### 
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp ! --syn -m conntrack --ctstate NEW -j DROP 

 
### 3: Drop SYN packets with suspicious MSS value ### 
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP  


### 4: Block packets with bogus TCP flags ### 
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp --tcp-flags FIN,ACK FIN -j DROP
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp --tcp-flags ACK,URG URG -j DROP
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp --tcp-flags ACK,PSH PSH -j DROP
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p tcp --tcp-flags ALL NONE -j DROP


### 6: Drop ICMP (you usually don't need this protocol) ### 
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -p icmp -j DROP  


### 7: Drop fragments in all chains ### 
/sbin/iptables -t mangle -A PREROUTING -i ${MAIN_INTERFACE} -f -j DROP  


### 8: Limit connections per source IP ### 
/sbin/iptables -A INPUT -p tcp -m connlimit --connlimit-above 111 -j REJECT --reject-with tcp-reset  


### 9: Limit RST packets ### 
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
/sbin/iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP  


### 10: Limit new TCP connections per second per source IP ### 

/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 
/sbin/iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP  
 
### SSH brute-force protection ###  test
/sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
/sbin/iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

## Drop spam packets on the mc server itself
iptables -A INPUT -p tcp --dport 25565 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 25565 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 10 -j DROP

#rate limit new connections to the server
iptables -A INPUT -p tcp --dport 25565 -m state --state NEW -m limit --limit 30/minute --limit-burst 10 -j ACCEPT
iptables -A INPUT -p tcp --dport 25565 -m state --state NEW -j DROP

## Drop SYN flood attacks
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A INPUT -p tcp --syn -j DROP

### Protection against port scanning ### 
/sbin/iptables -N port-scanning 
/sbin/iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
/sbin/iptables -A port-scanning -j DROP

## log and drop suspicious packets
iptables -A INPUT -p tcp --dport 25565 -m connlimit --connlimit-above 10 -j LOG --log-prefix "DDoS Attack: "
iptables -A INPUT -p tcp --dport 25565 -m connlimit --connlimit-above 10 -j DROP


sudo iptables-save > /etc/iptables/rules.v4
sudo apt-get install iptables-persistent


}