#!/bin/sh

main(){
    # Make sure other uci-default scripts have run
#    logger -t LibertyMESH -s  "Sleeping 10s to wait for other uci-default scripts to finish..."
#    sleep 10

    run_first
    conf_system
    set_root_passwd
    conf_wireless
    conf_cjdns
    conf_network
    conf_firewall
    conf_mwan3
    conf_knockd
    conf_dropbear
}

run_first(){
    # Make sure the cjdns configuration runs before the rest of this
    if [ -f /etc/uci-defaults/cjdns ]; then
	sh /etc/uci-defaults/cjdns
	if [ $? -eq 0 ]; then
	    rm /etc/uci-defaults/cjdns
	else
	    exit 252
	fi
    fi
}

conf_system(){
    # Configure system
    logger -t LibertyMESH -s  "Configuring system..."
    uci show system | grep LibertyMESH >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	    touch /etc/config/system
	    uci set system.@system[0].hostname="LibertyMESH"
	    uci commit system
    fi
}

set_root_passwd(){
    grep -v root /etc/passwd > /tmp/passwd                                         
    echo "root:x:0:0:root:/root:/bin/ash" > /etc/passwd
    cat /tmp/passwd >> /etc/passwd
    rm /tmp/passwd

    grep -v root /etc/shadow > /tmp/shadow
    echo "root:\$1\$9N.CFees\$dWw6eC3kSLlhpQs4whBQk.:16266:0:99999:7:::" > /etc/shadow
    cat /tmp/shadow >> /etc/shadow
    rm /tmp/shadow
}

conf_wireless(){
    # Configure wireless
    logger -t LibertyMESH -s  "Configuring wireless..."
    uci show wireless | grep LibertyMESH >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	if [ -f /etc/config/wireless ]; then
		cp /etc/config/wireless /etc/config/wireless.orig
		wifi detect > /etc/config/wireless
	fi

	#uci set wireless.radio0="wifi-device"
	#uci set wireless.radio0.type="mac80211"
	#uci set wireless.radio0.hwmode="11g"
	#uci set wireless.radio0.path="ssb0:3"
	uci set wireless.radio0.channel="1"
	#uci set wireless.radio0.txpower="20"
	#uci set wireless.radio0.country="00"
	#uci set wireless.radio0.disabled="1"

	uci set wireless.@wifi-iface[0]="wifi-iface"
	uci set wireless.@wifi-iface[0].device="radio0"
	uci set wireless.@wifi-iface[0].ssid="LibertyMESH"
	uci set wireless.@wifi-iface[0].network="mesh"
	uci set wireless.@wifi-iface[0].mode="adhoc"
	uci set wireless.@wifi-iface[0].bssid="02:FC:0D:DB:1A:DE"
	uci set wireless.@wifi-iface[0].encryption="none"

	uci commit wireless
    fi

    # Create script in /root that will enable radio easily
    if [ ! -f /root/enable_radio1.sh ]; then
	touch /root/enable_radio1.sh
	chmod +x /root/enable_radio1.sh
	cat <<'EOF' > /root/enable_radio1.sh
#!/bin/sh
uci set wireless.radio0.disabled="0"
uci commit wireless
wifi enabled
wifi
EOF
    fi
}

conf_cjdns(){
    # Configure cjdns
    logger -t LibertyMESH -s  "Configuring cjdns..."
    uci show cjdns | grep eth_interface >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	    touch /etc/config/cjdns
	    # Allow Auto-Peering on br-lan interface
	    uci add cjdns eth_interface
	    uci set cjdns.@eth_interface[-1]="eth_interface"
	    uci set cjdns.@eth_interface[-1].bind="br-lan"
	    uci set cjdns.@eth_interface[-1].beacon="2"

	    # Allow Auto-Peering on wlan0 interface
	    uci add cjdns eth_interface
	    uci set cjdns.@eth_interface[-1]="eth_interface"
	    uci set cjdns.@eth_interface[-1].bind="wlan0"
	    uci set cjdns.@eth_interface[-1].beacon="2"

	    # Setup UDP Peer
	    #uci set cjdns.@udp_peer[0]="udp_peer"
	    #uci set cjdns.@udp_peer[0].address=""
	    #uci set cjdns.@udp_peer[0].port=""
	    #uci set cjdns.@udp_peer[0].interface="1"
	    #uci set cjdns.@udp_peer[0].public_key=""
	    #uci set cjdns.@udp_peer[0].password=""

	    # Setup ipTunnel
	    #uci set cjdns.@iptunnel_outgoing[0]="iptunnel_outgoing"
	    #uci set cjdns.@iptunnel_outgoing[0].public_key=""

	    uci commit cjdns
    fi

    # Create script in /root to re-enable tun0 routes easily
    if [ ! -f /root/enable_tun_routes.sh ]; then
	touch /root/enable_tun_routes.sh
	chmod +x /root/enable_tun_routes.sh
	cat <<'EOF' > /root/enable_tun_routes.sh
#!/bin/sh

DEVICE=tun0
GW=`ifconfig $DEVICE  | grep "inet " | cut -d. -f1-3 | cut -d: -f2`.1

ip route add $GW dev $DEVICE metric 252
ip route add default via $GW dev $DEVICE metric 252

/etc/init.d/mwan3 restart
EOF

    fi

    # Interim script while debugging disappearing tun0 routes
    if [ ! -f /root/10-cjdns ]; then
	touch /root/10-cjdns
	chmod 664 /root/10-cjdns
	cat <<'EOF' > /root/10-cjdns
#!/bin/sh

[ mesh = "$INTERFACE" ] && {
    sleep 1
    GW=`ifconfig $DEVICE  | grep "inet " | cut -d. -f1-3 | cut -d: -f2`.1

    route add default gw $GW $DEVICE
    route add $GW dev $DEVICE
}
EOF

    fi

}

conf_network(){
    # Configure network
    logger -t LibertyMESH -s  "Configuring network..."
    uci show network | grep mesh >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	    touch /etc/config/network
	    # Set ULA Prefix to be similar to CJDNS Address
	    uci show network | grep globals >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		    uci add network globals
	    fi
	    uci show cjdns | grep ipv6 >/dev/null 2>&1
	    if [ $? -ne 0 ]; then
		    uci set network.@globals[0].ula_prefix="fd`uci get cjdns.cjdns.ipv6 | cut -b3-14`::/48"
	    fi

	    uci set network.lan.proto="static"
	    uci set network.lan.ipaddr="192.168.76.1"
	    uci set network.lan.netmask="255.255.255.0"
	    uci set network.lan.ip6assign="60"
	    
	    uci set network.wan.metric="0"

	    # Create tun0 interface for mesh
	    uci set network.mesh="interface"
	    uci set network.mesh.ifname="tun0"
	    uci set network.mesh.proto="static"
	    uci set network.mesh.ipaddr="192.168.252.1"
	    uci set network.mesh.netmask="255.255.255.0"
	    uci set network.mesh.gateway="192.168.252.1"
	    uci set network.mesh.metric="252"

	    # Combine the Gateway's ULA_Prefix with the last part of this node's CJDNS address
	    uci show cjdns | grep ipv6 >/dev/null 2>&1
	    if [ $? -ne 0 ] ; then
		    uci set network.mesh.ip6addr="`uci get network.@globals[0].ula_prefix | cut -d: -f1-3`:`uci get cjdns.cjdns.ipv6 | cut -d: -f4-8`"
	    fi

	    uci add network route
	    uci set network.@route[-1].interface="mesh"
	    uci set network.@route[-1].target="192.168.252.1"
	    uci set network.@route[-1].metric="252"

	    uci commit network
    fi

    if [ ! -f /root/refresh_ipv6_ula.sh ]; then
	touch /root/refresh_ipv6_ula.sh
	chmod +x /root/refresh_ipv6_ula.sh
	cat <<'EOF' > /root/refresh_ipv6_ula.sh
#!/bin/sh

uci set network.@globals[0].ula_prefix="fd`uci get cjdns.cjdns.ipv6 | cut -b3-14`::/48"
uci set network.mesh.ip6addr="`uci get network.@globals[0].ula_prefix | cut -d: -f1-3`:`uci get cjdns.cjdns.ipv6 | cut -d: -f4-8`"

uci commit network

# generate dummy cjdroute.conf for admin interface
cjdrouteconf get > /etc/cjdroute.conf

EOF
    fi
}

conf_firewall(){
    # Configure firewall
    logger -t LibertyMESH -s  "Configuring firewall..."
    uci show system | grep mesh >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	    touch /etc/config/firewall

	    uci add firewall zone
	    uci set firewall.@zone[-1].name="mesh"
	    uci set firewall.@zone[-1].network="mesh"
	    uci set firewall.@zone[-1].input="ACCEPT"
	    uci set firewall.@zone[-1].output="ACCEPT"
	    uci set firewall.@zone[-1].forward="ACCEPT"

	    uci add firewall forwarding
	    uci set firewall.@forwarding[-1].dest="wan"
	    uci set firewall.@forwarding[-1].src="mesh"

	    uci add firewall forwarding
	    uci set firewall.@forwarding[-1].dest="mesh"
	    uci set firewall.@forwarding[-1].src="lan"

	    uci commit firewall
    fi
}

conf_mwan3(){
    # Configure mwan3
    logger -t LibertyMESH -s  "Configuring mwan3..."
    uci show mwan3 | grep mesh >/dev/null 2>&1
    if [ $? -ne 0 ]; then
	    touch /etc/config/mwan3

	    # Replace wan2 with mesh throughout
	    sed -i 's/wan2/mesh/g' /etc/config/mwan3

	    uci set mwan3.wan.enabled="1"
	    uci set mwan3.mesh.enabled="1"

	    uci commit mwan3
    fi
}

conf_knockd(){
    # Configure knockd
    logger -t LibertyMESH -s  "Configuring knockd..."
    # Create init script for knockd
    if [ -f /usr/sbin/knockd ] && [ ! -f /etc/init.d/knockd ]; then
	touch /etc/init.d/knockd
	chmod 755 /etc/init.d/knockd
	cat <<'EOF' > /etc/init.d/knockd
#!/bin/sh /etc/rc.common

START=90
STOP=85

USE_PROCD=1
PROG=/usr/sbin/knockd
CONF=/etc/knockd.conf
IFACE=eth0.2

start_service()
{
	[ -f /etc/uci-defaults/knockd ] && ( . /etc/uci-defaults/knockd )
	procd_open_instance
	procd_set_param respawn
	procd_set_param command /bin/ash -c "$PROG -i $IFACE -c $CONF"
	procd_close_instance
}
stop_service()
{
	killall knockd
}
service_triggers()
{
	procd_add_reload_trigger "knockd"
}
EOF
    fi

    # Backup existing knockd.conf
    if [ -f /etc/knockd.conf ]; then
	    mv /etc/knockd.conf /etc/knockd.conf.orig
    fi

    # Create default knockd.conf
    if [ -f /usr/sbin/knockd ]; then
	touch /etc/knockd.conf
	cat <<'EOF' > /etc/knockd.conf
[options]
	logfile = /var/log/knockd.log
[startLUCI]
	sequence    = 252:udp,443:tcp,252:udp
	seq_timeout = 5
	command     = /etc/init.d/uhttpd restart
	tcpflags    = syn
[stopLUCI]
	sequence    = 252:udp,80:tcp,252:udp
	seq_timeout = 5
	command     = /etc/init.d/uhttpd stop
	tcpflags    = syn
[opencloseSSH]
	sequence        = 252:udp,22:tcp,252:udp
	seq_timeout     = 5
	start_command   = /usr/sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
	cmd_timeout     = 10
	stop_command    = /usr/sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
	tcpflags        = syn
EOF

	/etc/init.d/knockd restart
    fi
}

conf_dropbear() {
    # Configure dropbear
    logger -t LibertyMESH -s  "Configuring dropbear..."
    touch /etc/dropbear/authorized_keys
    chmod 600 /etc/dropbear/authorized_keys
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC/dChTKdN1FCPATQTqz3JH6Zy9Sw2YRcWjj5Y4yFp6clg9CwcFZITAYFrk8h5obInAVHUKZb0CxrTbnugyH/s9zV23x8DWKil/ZuHXGwhvsNAjeQlckAG4GIetMcvl1MLngE4Te4GUTYTphQAONP5tAjN0GDhkq7oPreWANEbMpCbyO/tJIQRrmaPaN1Xbl3HpQS/KSUUkce0PF5//bJ+q4MJuM8Cu2TxRrZ1NN1a7hOyl9Rq6JZ346swjQ35wN6ATvS8X8nnyRnUn96PIPlRaNHnUdyiRshThNJI5rE5Dc20iWxRoPaSPXAWI+OsYbm0/MrTrbZ1Hf7yMZ2I+FyMcg3oqPKyI5wJl1W+TO+b/usV5GCfI0Sg+B/tp8tn4danYEXOFnKpbZIiyA3nqpqR6r0P5txnkG3znAjL47AtcKY4Sj4pDH315xyg4zMrirj5qhGtb+O6TM+RAtd7+7wUXVOu8P2M6oUClOcnnSiZE9crpTNQbcjBZjq4BIl1guRC8Q98uXlZIWgj8lxAz9HHQoVcMw6KhxizkPty+Jy+VOGW1poK1+kZCf8GnJKFRit2Bzf8+/4fYuG1k17EvbR3mEMep851WBhW/NJvZAdxBIP4ruXo68cbbry6jovjRvCYj91eviLwE1jyUwQPRB8SX3RHyGQg01IzeYlazzEhR7Q==" >> /etc/dropbear/authorized_keys
}


main
exit 0
