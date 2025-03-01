#!/bin/sh
#
# Copyright (c) 2015, 2020, The Linux Foundation. All rights reserved.
# Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.

# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

. /lib/functions.sh

enable_smp_affinity_wigig() {
	# This function supports up to 2 wil6210 devices.
	wil6210_tx0=`grep -E -m1 'wil6210_tx' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	wil6210_rx0=`grep -E -m1 'wil6210_rx' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	wil6210_tx1=`grep -E -m2 'wil6210_tx' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	wil6210_rx1=`grep -E -m2 'wil6210_rx' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`

	# Enable smp_affinity for wil6210 devices
	[ -n "$wil6210_tx0" ] && echo 8 > /proc/irq/$wil6210_tx0/smp_affinity
	[ -n "$wil6210_rx0" ] && echo 4 > /proc/irq/$wil6210_rx0/smp_affinity
	[ -n "$wil6210_tx1" ] && echo 8 > /proc/irq/$wil6210_tx1/smp_affinity
	[ -n "$wil6210_rx1" ] && echo 4 > /proc/irq/$wil6210_rx1/smp_affinity

	# Adjust nss_queue handler affinity to avoid contention with wil6210_tx handler for EDMG
	[ -n "$wil6210_tx0" ] && [ -n "$wil6210_rx0" ] && {
		nssq0_set1=`grep -E -m1 'nss_queue0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		nssq3_set1=`grep -E -m1 'nss_queue3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		nssq0_set2=`grep -E -m2 'nss_queue0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`

		irq3_set1=`cat /proc/irq/$nssq3_set1/smp_affinity`
		if [ $irq3_set1 -eq 8 ] ; then
			echo 4 > /proc/irq/$nssq3_set1/smp_affinity
		fi

		irq0_set1=`cat /proc/irq/$nssq0_set1/smp_affinity`
		irq0_set2=`cat /proc/irq/$nssq0_set2/smp_affinity`
		if [ "$irq0_set1" == "f" ] && [ "$irq0_set2" == "f" ] ; then
			echo e > /proc/irq/$nssq0_set2/smp_affinity
		fi
	}
}

enable_smp_affinity_wifi() {
	irq_wifi0=`grep -E -m1 'ath10k' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	irq_wifi1=`grep -E -m2 'ath10k' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`

	# Enable smp_affinity for ath10k driver
	if [ -n "$irq_wifi0" ]; then
		board=ap$(echo $(board_name) | awk -F 'ap' '{print$2}')

		case "$board" in
			ap-dk0*)
				echo 4 > /proc/irq/$irq_wifi0/smp_affinity
				[ -n "$irq_wifi1" ] && {
				echo 8 > /proc/irq/$irq_wifi1/smp_affinity
				}
			;;
			ap148*)
				echo 2 > /proc/irq/$irq_wifi0/smp_affinity
			;;
		esac
	else
	# Enable smp_affinity for qca-wifi driver
		board=ap$(echo $(board_name) | awk -F 'ap' '{print$2}')
		device="$1"
		hwcaps=$(cat /sys/class/net/$device/hwcaps)


		[ -n "$device" ] && {
			case "$board" in
				ap-dk0*)
					if [ $device == "wifi2" ]; then
						irq_affinity_num=`grep -E -m3 'wlan' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
					elif [ $device == "wifi1" ];then
						irq_affinity_num=`grep -E -m2 'wlan' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
					else
						irq_affinity_num=`grep -E -m1 'wlan' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
					fi
				;;
				*)
					if [ $device == "wifi2" ]; then
						irq_affinity_num=`grep -E -m3 'wlan' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
					elif [ $device == "wifi1" ];then
						irq_affinity_num=`grep -E -m2 'wlan' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
					else
						irq_affinity_num=`grep -E -m1 'wlan' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
					fi
				esac
		}

		case "${hwcaps}" in
			*11an/ac)
				smp_affinity=2
			;;
			*)
				smp_affinity=4
		esac

		case "$board" in
			ap-dk0*)
			if [ $device == "wifi2" ]; then
				# Assign core 3 for wifi2. For ap-dkXX,wifi2 is always the third radio
				smp_affinity=8
			fi
			;;
		esac

		[ -n "$irq_affinity_num" ] && echo $smp_affinity > /proc/irq/$irq_affinity_num/smp_affinity
	fi

	# Enable smp_affinity for Lithium

	#Flipping arrangement for HK14 boards as reo2host-destination-ring1 5G data needs to go to core 1 for better throughput
	[ -f /tmp/sysinfo/board_name ] && {
		board=ap$(cat /tmp/sysinfo/board_name | awk -F 'ap' '{print$2}')
	}

	case "$board" in
		ap-hk14*)
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
		ap-hk01-c6*)
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
		*)
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	esac

	case "$board" in
			#Maple uses only two cores. Update smp affinity for maple boards to two cores.
		ap-mp*)
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity

			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity

			irq_affinity_num=`grep -E -m1 'ppdu-end-interrupts-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-status-ring-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-destination-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'host2rxdma-monitor-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

		ap-hk01-c6*)
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity

			irq_affinity_num=`grep -E -m1 'ppdu-end-interrupts-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-status-ring-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-destination-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'host2rxdma-monitor-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

			#Keep smp affinity for other Lithium chips across all 4 cores.
		*)
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'reo2host-destination-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'wbm2host-tx-completions-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity

			irq_affinity_num=`grep -E -m1 'ppdu-end-interrupts-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-status-ring-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-destination-mac1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'host2rxdma-monitor-ring1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	esac

	irq_affinity_num=`grep -E -m1 'ppdu-end-interrupts-mac2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-status-ring-mac2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-destination-mac2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'host2rxdma-monitor-ring2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

	irq_affinity_num=`grep -E -m1 'ppdu-end-interrupts-mac3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-status-ring-mac3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'rxdma2host-monitor-destination-mac3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'host2rxdma-monitor-ring3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity

	# Enable smp affinity for PCIE attach
	case "$board" in
			#Maple uses only two cores.
			#Update smp affinity of pine and spruce PCI interrupts on maple boards to two cores.
		ap-mp*)
			#pci 0
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity

			#pci 1
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

		ap-hk01-c6*)
			#pci 0
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
		ap-al02-c20)
			#pci0
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

			#pci1
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
		ap-al02-c16)
			#pci0
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

			#pci1
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

			#Keep smp affinity for pine with HK and CYP boards across all 4 cores.
		*)
			#pci 0
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity

			#pci 1
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
			irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
			[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	esac
	[ -f /tmp/sysinfo/board_name ] && {
		board=ap$(cat /tmp/sysinfo/board_name | awk -F 'ap' '{print$2}')
	}
	case "$board" in
	ap-al02-c1 | ap-al01-c1)
		irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	*)
		irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	esac

	#pci 2
	irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity

	[ -f /tmp/sysinfo/board_name ] && {
		board=ap$(cat /tmp/sysinfo/board_name | awk -F 'ap' '{print$2}')
	}
	case "$board" in
	ap-al02-c4 | ap-al02-c9 | ap-al02-c16 | ap-al05 | ap-al06)
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

	ap-al02-c20)
		#pci2
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

	*)
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	esac

	#pci 3
	irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
	irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_7' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
	[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity

	[ -f /tmp/sysinfo/board_name ] && {
		board=ap$(cat /tmp/sysinfo/board_name | awk -F 'ap' '{print$2}')
	}
	case "$board" in
	ap-al02-c4 | ap-al02-c9 | ap-al02-c16 | ap-al05 | ap-al06)
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

	ap-al02-c20)
		#pci2
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_4' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_5' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_6' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

	*)
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_0' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_1' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_2' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 8 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	esac

	# Enable smp_affinity for Monitor mode
	[ -f /tmp/sysinfo/board_name ] && {
                board=ap$(cat /tmp/sysinfo/board_name | awk -F 'ap' '{print$2}')
        }
	case "$board" in
	ap-al02-c4 | ap-al02-c9 | ap-al05 | ap-al06)
		#smp affinity for Rx monitor mode
		irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_8' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_8' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_8' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

		#smp affinity for Tx monitor mode
		irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_9' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_9' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_9' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

	ap-al02-c16)
		#smp affinity for Rx monitor mode
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_8' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_8' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity

		#smp affinity for Tx monitor mode
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_9' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_9' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;

	ap-al02-c20)
		irq_affinity_num=`grep -E -m1 'pci0_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 1 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 2 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_3' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	*)
	esac

	# Map RX error interrupts to CPU2
	[ -f /tmp/sysinfo/board_name ] && {
                board=ap$(cat /tmp/sysinfo/board_name | awk -F 'ap' '{print$2}')
        }
	case "$board" in
	ap-al02-c4 | ap-al02-c9 | ap-al02-c16 | ap-al05 | ap-al06)
		#smp affinity for Rx release ring
		irq_affinity_num=`grep -E -m1 'pci1_wlan_grp_dp_11' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci2_wlan_grp_dp_11' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		irq_affinity_num=`grep -E -m1 'pci3_wlan_grp_dp_11' /proc/interrupts | cut -d ':' -f 1 | tail -n1 | tr -d ' '`
		[ -n "$irq_affinity_num" ] && echo 4 > /proc/irq/$irq_affinity_num/smp_affinity
		;;
	*)
	esac

}
