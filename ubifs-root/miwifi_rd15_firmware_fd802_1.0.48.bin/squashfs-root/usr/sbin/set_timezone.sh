#!/bin/sh

COUNTRY_CODE="$1"

set_timezone_by_country() {
	local cc="$1"

	if [ -z "$cc" ]; then
		cc=$(getCountryCode)
	fi

	local tz=$(uci -q get country_mapping.$cc.timezone)
        [ -z "$tz" ] && return

	local tz_idx=$(uci -q get country_mapping.$cc.timezoneindex)

	echo $tz > /tmp/TZ

	uci set system.@system[0].timezone="$tz"
	uci set system.@system[0].timezoneindex="$tz_idx"
	uci commit system

	# apply timezone to kernel
	hwclock -u -t

	if [ -c "/dev/rtc0" ]; then
		local uptime=$(cat /proc/uptime | cut -d'.' -f1)
		[ "$uptime" -gt 100 ] && hwclock -w -u
	fi
}

set_timezone_by_country $COUNTRY_CODE