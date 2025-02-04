#!/bin/sh

RET()
{
    echo -n "$1"
}

base64_enc()
{
    ## encode and unfold mutiple line
    local str="`echo -n "$1" | base64 | sed 's/ //g'`"
    RET "$str" | awk -v RS="" '{gsub("\n","");print}'
}

append_jsonstr()
{
	local cur_msg="$1"
	local new_msg="$1"
	local append_jsonstr="$2"

	if [ -n "$append_jsonstr" ]; then
		if [ -z "$cur_msg" ]; then
			new_msg="{$append_jsonstr}"
		else
			__final_ch() {
				local str="$@"
				local slen="${#str}"

				echo "$str" | cut -c "$slen"-"$slen"
			}

			local msg_prefix=""
			local final_ch=$(__final_ch "$cur_msg")

			if [ "$final_ch" = "," ]; then
				new_msg="${cur_msg}${append_jsonstr},"
			elif [ "$final_ch" = "}" ]; then
				new_msg="${cur_msg%\}*},${append_jsonstr}}"
			elif [ "$final_ch" = "\"" ]; then
				new_msg="${cur_msg},${append_jsonstr}"
			fi
		fi
	fi

	echo "$new_msg"
}

parse_width_from_mode()
{
	width=$(echo $1 | grep 160)
	if [ ! -z $width ]; then
		width="160MHz"
	else
		width=$(echo $1 | grep 80)
		if [ ! -z $width ]; then
			width="80MHz"
		else
			width=$(echo $1 | grep 40)
			if [ ! -z $width ]; then
				width="40MHz"
			else
				width="20MHz"
			fi
		fi
	fi
	
	RET "$width"
}

parse_phymode_from_mode()
{
	phymode=$(echo $1 | grep HE)
	if [ ! -z $phymode ]; then
		phymode="he"
	else
		phymode=$(echo $1 | grep AC)
		if [ ! -z $phymode ]; then
			phymode="vht"
		else
			phymode=$(echo $1 | grep NG)
			if [ ! -z $phymode ]; then
				phymode="ht"
			else
				phymode=$(echo $1 | grep NA)
				if [ ! -z $phymode ]; then
					phymode="ht"
				else
					phymode="basic"
				fi
			fi
		fi
	fi
	
	RET "$phymode"
}

whc_mode="$1"

ap_ifname_5g=$(uci -q get misc.wireless.ifname_5G)
ap_ifname_2g=$(uci -q get misc.wireless.ifname_2G)
iface_2g=$(uci show wireless | grep "ifname=\'$ap_ifname_2g\'" | awk -F"." '{print $2}')
iface_5g=$(uci show wireless | grep "ifname=\'$ap_ifname_5g\'" | awk -F"." '{print $2}')

disable_2g=$(uci -q get wireless.$iface_2g.disabled)
disable_5g=$(uci -q get wireless.$iface_5g.disabled)
[ -z "$disable_2g" ] && disable_2g=0
[ -z "$disable_5g" ] && disable_5g=0
jsonstr_2g=""
jsonstr_5g=""
jsonstr_5gh=""
jsonstr_game=""

lan_mac=`ifconfig br-lan |grep HWaddr | awk '{print $5}'`

if [ "$disable_2g" = "0" ]; then
	bssid_2g=`ifconfig "$ap_ifname_2g" |grep HWaddr | awk '{print $5}'`

	#get 2g ssid
	ssid_2g=$(uci -q get wireless.$iface_2g.ssid)

	#get 2g nss
	nss_2g=`iwpriv $ap_ifname_2g get_nss | awk -F '[:]' '{print $NF}' | sed 's/[ \t]*$//g'`

	#get 2g channel
	channel_2g="`iwlist $ap_ifname_2g channel | grep -Eo "\(Channel.*\)" | grep -Eo "[1-9]+"`"

	#get 2g width and phy mode
	mode="`iwpriv $ap_ifname_2g get_mode | awk -F '[:]' '{print $NF}'`"
	width_2g=$(parse_width_from_mode $mode)
	phymode_2g=$(parse_phymode_from_mode $mode)

	jsonstr_2g="\"bssid_2g\":\"$bssid_2g\",\"ssid_2g\":\"$(base64_enc "$ssid_2g")\",\"width_2g\":\"$width_2g\",\"channel_2g\":$channel_2g,\"nss_2g\":$nss_2g,\"phymode_2g\":\"$phymode_2g\""
fi

if [ "$disable_5g" = "0" ]; then
	bssid_5g=`ifconfig  "$ap_ifname_5g" |grep HWaddr | awk '{print $5}'`

	#get 5g ssid
	ssid_5g=$(uci -q get wireless.$iface_5g.ssid)

	#get 5g nss
	nss_5g=`iwpriv $ap_ifname_5g get_nss | awk -F '[:]' '{print $NF}' | sed 's/[ \t]*$//g'`

	#get 5g channel
	channel_5g="`iwlist $ap_ifname_5g channel | grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"

	#get 5g width and phy mode
	mode="`iwpriv $ap_ifname_5g get_mode | awk -F '[:]' '{print $NF}'`"
	width_5g=$(parse_width_from_mode $mode)
	phymode_5g=$(parse_phymode_from_mode $mode)

	jsonstr_5g="\"bssid_5g\":\"$bssid_5g\",\"ssid_5g\":\"$(base64_enc "$ssid_5g")\",\"width_5g\":\"$width_5g\",\"channel_5g\":$channel_5g,\"nss_5g\":$nss_5g,\"phymode_5g\":\"$phymode_5g\""
fi

is_tri_band_dev=$(mesh_cmd is_tri_band)
if [ "$is_tri_band_dev" = "1" ]; then
	ap_ifname_5gh=$(uci -q get misc.wireless.ifname_5GH)
	iface_5gh=$(uci show wireless | grep "ifname=\'$ap_ifname_5gh\'" | awk -F"." '{print $2}')

	ap_5gh_disabled=$(uci -q get wireless.$iface_5gh.disabled)
	[ -z "$ap_5gh_disabled" ] && ap_5gh_disabled=0
	if [ "$ap_5gh_disabled" = "0" ]; then

		bssid_5gh=`ifconfig  "$ap_ifname_5gh" |grep HWaddr | awk '{print $5}'`

		#get 5gh ssid
		ssid_5gh=$(uci -q get wireless.$iface_5gh.ssid)

		#get 5gh nss
		nss_5gh=`iwpriv $ap_ifname_5gh get_nss | awk -F '[:]' '{print $NF}' | sed 's/[ \t]*$//g'`

		#get 5gh channel
		channel_5gh="`iwlist $ap_ifname_5gh channel | grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"

		#get 5gh width and phy mode
		mode="`iwpriv $ap_ifname_5gh get_mode | awk -F '[:]' '{print $NF}'`"
		width_5gh=$(parse_width_from_mode $mode)
		phymode_5gh=$(parse_phymode_from_mode $mode)
		jsonstr_5gh="\"bssid_5gh\":\"$bssid_5gh\",\"ssid_5gh\":\"$(base64_enc "$ssid_5gh")\",\"width_5gh\":\"$width_5gh\",\"channel_5gh\":$channel_5gh,\"nss_5gh\":$nss_5gh,\"phymode_5gh\":\"$phymode_5gh\""
		jsonstr_game="\"bssid_game\":\"$bssid_5gh\",\"ssid_game\":\"$(base64_enc "$ssid_5gh")\",\"width_game\":\"$width_5gh\",\"channel_game\":$channel_5gh,\"nss_game\":$nss_5gh,\"phymode_game\":\"$phymode_5gh\""
	fi
fi

#get link type
link_type=$(topomon_action.sh current_status bh_type)

#get 5g backhaul
bh_band=$(mesh_cmd backhaul get band)
backhaul_ap_ifname_5g=$(uci -q get misc.backhauls.backhaul_${bh_band}_ap_iface)
backhaul_ap_bssid_5g=$(iwconfig "$backhaul_ap_ifname_5g" 2>>/dev/null| grep "Access Point" | awk '{print $6}')

#router_name
router_name=$(uci -q get xiaoqiang.common.ROUTER_NAME)
[ -z "$router_name" ] && router_name="default"

#support new topo
supp_new_topo=$(uci -q get misc.features.supportNewTopo)
[ -z "$supp_new_topo" ] && supp_new_topo=0

#support mlo
bh_mlo_support=$(mesh_cmd bh_mlo_support)

#get SNR //to do, get from driver
snr=0
uplink_mac=""
eth_link_rate=""

if [ "$whc_mode" == "CAP" ]; then
	uplink_mac=""
	snr=0
	eth_link_rate=""
	link_type="CAP"
elif [ "$link_type" = "wireless" ]; then
	backhaul_sta_ifname_5g=$(uci -q get misc.backhauls.backhaul_${bh_band}_sta_iface)
	uplink_mac=`iwconfig "$backhaul_sta_ifname_5g" 2>>/dev/null| grep "Access Point" | awk '{print $6}'`
	if [ -z "$uplink_mac" ] || [ "$bh_mlo_support" = "1" ]; then
		real_band=$(mesh_cmd backhaul get real_band)
		sta_iface=$(uci -q get wireless.bh_sta_$real_band.ifname)
		mesh_mld="$(cfg80211tool $sta_iface g_mesh_mld | sed -ne 's/.*g_mesh_mld:\(.*\),.*$/\1/p')"
		if [ -n "$mesh_mld" ] && [ "${mesh_mld##*@}" != "$mesh_mld" ]; then
			for ele in ${mesh_mld//,/ }; do
				if [ "${ele##*$bh_band@}" != "${ele}" ]; then
					uplink_mac="$(echo $ele | awk -F@ '{print $2}')"
				fi
			done
		fi
	fi
	[ -z "$uplink_mac" ] && echo "invalid uplink_mac"
elif [ "$link_type" = "wired" ]; then
	eth_link_rate=$(topomon_action.sh current_status eth_link_rate)
	uplink_mac=$(topomon_action.sh current_status uplink_mac)
else
	echo "invalid link_type $link_type"
fi

# translate uplink_mac to upcase to compat old cap
[ -n "$uplink_mac" ] && uplink_mac="$(echo $uplink_mac | tr '[a-z]' '[A-Z]')"

msg="{\
\"lan_mac\":\"$lan_mac\",\"link_type\":\"$link_type\",\"backhaul_ap_bssid_5g\":\"$backhaul_ap_bssid_5g\",\"uplink_mac\":\"$uplink_mac\",\
\"snr\":$snr,\"router_name\":\"$(base64_enc "$router_name")\",\"supp_new_topo\":$supp_new_topo,\"eth_link_rate\":\"$eth_link_rate\"\
}"

msg="$(append_jsonstr "$msg" "$jsonstr_2g")"
msg="$(append_jsonstr "$msg" "$jsonstr_5g")"
msg="$(append_jsonstr "$msg" "$jsonstr_5gh")"
msg="$(append_jsonstr "$msg" "$jsonstr_game")"
[ -n "$ap_mlo" ] && msg="$(append_jsonstr "$msg" "\"ap_mlo\":\"$ap_mlo\"")"

echo "$msg"
