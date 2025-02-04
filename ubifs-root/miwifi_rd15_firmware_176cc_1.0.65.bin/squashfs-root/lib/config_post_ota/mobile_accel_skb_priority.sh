#!/bin/ash

if [ ! -n "$(uci -q get misc.mobile_accel)" ]; then
	uci set misc.mobile_accel=misc
	uci set misc.mobile_accel.use_skb_priority='1'
	uci commit misc
fi
