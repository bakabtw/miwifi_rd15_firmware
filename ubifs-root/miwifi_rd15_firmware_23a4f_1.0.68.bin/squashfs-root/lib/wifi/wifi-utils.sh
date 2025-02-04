#
# Copyright (c) 2023 Qualcomm Technologies, Inc.
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
#

. /lib/functions.sh

get_board_name()
{
	local board_name

	[ -f /tmp/sysinfo/board_name  ] && {
		board_name=ap$(cat /tmp/sysinfo/board_name | awk -F 'ap' '{print$2}')
	}
	echo "$board_name"
}

is_cert_enabled()
{
        local enable
        config_load sigma-dut
        config_get_bool enable global enable 0
        echo "$enable"
}

get_wpad_var_run()
{
	local board_name="$(get_board_name)"

	case "$board_name" in
	ap-sdxpinn*)
		# If certification is enabled, default to standard path;
		# default to ujail path, otherwise
		local cert_enabled="$(is_cert_enabled)"
		if [ "${cert_enabled}" -eq 0 ]; then
		        WPAD_VARRUN=/var/run/wpad
		else
			WPAD_VARRUN=/var/run
		fi
	;;
	*)
	        WPAD_VARRUN=/var/run
	;;
	esac

	echo "$WPAD_VARRUN"
}

get_ap_sdxpinn_ko_path()
{
	release=$(uname -r | awk -F '.' '{print $1,$2}' | tr ' ' '.')
	if [ -d /lib/modules/$release-debug ]; then
		echo "/lib/modules/$release-debug/extra"
	elif [ -d /lib/modules/$release-perf ]; then
		echo "/lib/modules/$release-perf/extra"
	else
		echo ""
	fi
}

add_ap_up_boot_kpi_marker()
{
	local device="$1"
	local BOOT_KPI_NODE=/sys/kernel/boot_kpi/kpi_values
	local board_name="$(get_board_name)"

	local kpi_marker

	case "$board_name" in
	ap-sdxpinn*)
	;;
	*)
		return
	;;
	esac

	kpi_marker="M - $device - enable beaconing"

	# Add marker only for the first AP beaconing for a $device
	cat "$BOOT_KPI_NODE" | grep "$kpi_marker" 2>&1 > /dev/null
	if [ $? -eq 0 ]; then
		return
	fi

	echo -n "$kpi_marker" >> $BOOT_KPI_NODE
}

get_ap_sdxpinn_bridge_interface()
{
	local net_cfg="$1"
	local board_name=$(get_board_name)
	local bridge_tmp bridge

	case "$board_name" in
	ap-sdxpinn*)
	;;
	*)
		return
	;;
	esac

	bridge_tmp="$(bridge_interface "$net_cfg")"
	bridge_tmp=$(echo $bridge_tmp | sed 's/\n/ /g')
	bridge=$(echo "$bridge_tmp" | awk -F '{' '{print $1}')
	echo "$bridge"
}
