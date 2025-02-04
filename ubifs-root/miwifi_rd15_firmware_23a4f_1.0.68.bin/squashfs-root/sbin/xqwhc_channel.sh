#!/bin/sh
# Copyright (C) 2020 Xiaomi

usage() {
        echo "$0 get_chan_2g"
		echo "$0 get_chan_5g"
		echo "$0 get_chan_5g_nbh"
		echo "$0 set_chan_2g XX"
		echo "$0 set_chan_5g XX"
		echo "$0 set_chan_5g_nbh XX"
        exit 1
}

xqwhc_lock="/var/run/xqwhc_wifi.lock"
trap "lock -u $xqwhc_lock; exit 1" INT TERM ABRT QUIT ALRM HUP;

mesh_version=$(uci -q get xiaoqiang.common.MESH_VERSION)
[ $mesh_version -gt 1 ] && {
    . /lib/mimesh/mimesh_public.sh
} || {
    . /lib/xqwhc/xqwhc_public.sh
}

# main backhaul band same as cap
main_bh_band=$(mesh_cmd backhaul get band)
main_bh_band_upcase=$(echo "$main_bh_band" | tr '[a-z]' '[A-Z]')

# current backhaul band used
real_bh_band=$(mesh_cmd backhaul get real_band)
real_bh_band_upcase=$(echo "$real_bh_band" | tr '[a-z]' '[A-Z]')

is_tri_band=$(mesh_cmd is_tri_band)

# non-backhaul band: 5G or 5GH
nbh_band=$(mesh_cmd nbh_band)
nbh_band_upcase=$(echo "$nbh_band" | tr '[a-z]' '[A-Z]')

set_chan() {
	local ifname=$1
	local target_chan=$2

	/sbin/wifi set_chan $ifname $target_chan 2>>/dev/null
	[ "$?" != "0" ] && iwconfig $ifname channel $target_chan
}

get_chan_2g() {
local ap_ifname_2g=$(uci -q get misc.wireless.ifname_2G)
local channel_2g="`iwlist $ap_ifname_2g channel 2>>/dev/null| grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"
[ -z "$channel_2g" ] && channel_2g=0
echo "$channel_2g"
}

get_chan_5g() {
local ap_ifname_5g=$(uci -q get misc.wireless.ifname_${main_bh_band_upcase})
local channel_5g="`iwlist $ap_ifname_5g channel 2>>/dev/null| grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"
if [ -z "$channel_5g" ]; then
	ap_ifname_5g=$(uci -q get misc.backhauls.backhaul_${main_bh_band}_ap_iface)
	channel_5g=$(iwlist $ap_ifname_5g channel 2>>/dev/null| grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+")
fi
[ -z "$channel_5g" ] && channel_5g=0
echo "$channel_5g"
}

get_chan_5g_nbh() {
local ap_ifname_5g_nbh=$(uci -q get misc.wireless.ifname_${nbh_band_upcase})
local channel_5g_nbh="`iwlist $ap_ifname_5g_nbh channel 2>>/dev/null| grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"
[ -z "$channel_5g_nbh" ] && channel_5g_nbh=0
echo "$channel_5g_nbh"
}

set_chan_2g() {
local channel=$1
local ap_ifname_2g=$(uci -q get misc.wireless.ifname_2G)
set_chan $ap_ifname_2g $channel
}

bh_band_changed() {
	local new_channel=$1
	local cap_type="$2"

	lock "$xqwhc_lock"
	local cur_bhap_ifname=$(uci -q get misc.backhauls.backhaul_${main_bh_band}_ap_iface)
	local current_channel="$(iwlist $cur_bhap_ifname channel 2>>/dev/null|grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+")"
	local bh_mlo_support=$(mesh_cmd bh_mlo_support)

	if [ "$is_tri_band" = "1" ] \
		&& [ "$new_channel" != "$current_channel" ]; then

		wifi_bh_change "$current_channel" "$new_channel" "band"
		bh_changed="$?"
		[ "$bh_changed" != "1" ] && lock -u "$xqwhc_lock" && return 1

		local new_bh_band=$(mesh_cmd backhaul get band)
		local new_bh_band_upcase=$(echo "$new_bh_band" | tr '[a-z]' '[A-Z]')
		local new_bhap_ifname=$(uci -q get misc.backhauls.backhaul_${new_bh_band}_ap_iface)
		local new_bhsta_ifname=$(uci -q get misc.backhauls.backhaul_${new_bh_band}_sta_iface)
		local new_bh_device=$(uci -q get misc.wireless.if_${new_bh_band_upcase})

		if [ "$cap_type" = "dual" ]; then
			if [ "$new_bh_band" = "5g" ]; then
				nbh_ap_chan=149
				nbh_ap_ifname=$(uci -q get misc.wireless.ifname_5GH)
			else
				nbh_ap_chan=36
				nbh_ap_ifname=$(uci -q get misc.wireless.ifname_5G)
			fi
			set_chan $nbh_ap_ifname $nbh_ap_chan

			# trigger topomon to update backhaul band
			mesh_cmd backhaul set real_band "$new_bh_band"
			ubus -t5 call topomon bh_band_update
		fi

		if [ "$bh_mlo_support" = "1" ]; then
			cfg80211tool $cur_bhap_ifname meshie_disab 1
			cfg80211tool $new_bhap_ifname meshie_disab 0
			lock -u "$xqwhc_lock"
			return 1
		fi

		if [ -n "$new_bhap_ifname" ] && [ -n "$new_bhsta_ifname" ]; then
			uci -q set wireless.bh_ap.ifname="$new_bhap_ifname"
			uci -q set wireless.bh_ap.device="$new_bh_device"
			uci -q set wireless.bh_sta.ifname="$new_bhsta_ifname"
			uci -q set wireless.bh_sta.device="$new_bh_device"
			uci commit wireless
			wifi update &

			lock -u "$xqwhc_lock"
			return 0
		fi
	fi
	lock -u "$xqwhc_lock"
	return 1
}

set_chan_5g() {
local new_channel=$1
local cap_type="$2"
local netmode=$(uci -q get xiaoqiang.common.NETMODE)
if [ "$netmode" = "whc_re" ]; then

	# check if bh_band changed, only update main_bh_band
	bh_band_changed "$new_channel" "$cap_type" && return

	bh_band=$(mesh_cmd backhaul get band)
	ap_ifname_5g=$(uci -q get misc.backhauls.backhaul_${bh_band}_ap_iface)
	local current_channel="`iwlist $ap_ifname_5g channel 2>>/dev/null| grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"
	local bit_rate=`iwinfo $ap_ifname_5g info | grep 'Bit Rate' | awk -F: '{print $2}' | awk '{gsub(/^\s+|\s+$/, "");print}'`

	if [ "$new_channel" != "$current_channel" -a "$bit_rate" != "unknown" ] ; then
		set_chan $ap_ifname_5g $new_channel
		sleep 1
		current_channel="`iwlist $ap_ifname_5g channel 2>>/dev/null| grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"
		if [ "$current_channel" != "$new_channel" ] ; then
			set_chan $ap_ifname_5g $current_channel
			sleep 1
			set_chan $ap_ifname_5g $new_channel
		fi
	fi
fi
}

set_chan_5g_nbh() {
local new_channel=$1
local netmode=$(uci -q get xiaoqiang.common.NETMODE)
if [ "$netmode" = "whc_re" ]; then
	local ap_ifname_5g_nbh=$(uci -q get misc.wireless.ifname_${nbh_band_upcase})
	local current_channel="`iwlist $ap_ifname_5g_nbh channel 2>>/dev/null| grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"
	local bit_rate=`iwinfo $ap_ifname_5g_nbh info | grep 'Bit Rate' | awk -F: '{print $2}' | awk '{gsub(/^\s+|\s+$/, "");print}'`
	if [ "$new_channel" != "$current_channel" -a "$bit_rate" != "unknown" ] ; then
		set_chan $ap_ifname_5g_nbh $new_channel
		sleep 1
		current_channel="`iwlist $ap_ifname_5g_nbh channel 2>>/dev/null| grep -Eo "\(Channel.*\)" | grep -Eo "[0-9]+"`"
		if [ "$current_channel" != "$new_channel" ] ; then
			set_chan $ap_ifname_5g_nbh $current_channel
			sleep 1
			set_chan $ap_ifname_5g_nbh $new_channel
		fi
	fi
fi
}

case "$1" in
	get_chan_2g)
	get_chan_2g
	;;
	get_chan_5g)
	get_chan_5g
	;;
	get_chan_5g_nbh)
	get_chan_5g_nbh
	;;
	set_chan_2g)
	set_chan_2g "$2"
	;;
	set_chan_5g)
	set_chan_5g "$2" "$3"
	;;
	set_chan_5g_nbh)
	set_chan_5g_nbh "$2"
	;;
	*)
	usage
	;;
esac
