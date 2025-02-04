#!/bin/sh
###
# @Copyright (C), 2020-2022, Xiaomi CO., Ltd.:
# @Description: Used to configure ACL rules for the specified port
# @Author: Lin Hongqing
# @Date: 2022-09-28 10:00:07
# @Email: linhongqing@xiaomi.com
# @LastEditTime: 2022-09-28 14:22:02
# @LastEditors: Lin Hongqing
# @History: first version
###

readonly PSUCI="port_service"
readonly LOCK_FILE="/var/lock/game_port.lock"

log() {
	logger -t "game_port" -p $1 "$2"
}

# set port as game port
# game port will has the highest priority
port_set_highest_pri() {
	local port=$1
	[ -z "${port}" ] && {
		log err "port_set_highest_pri: port is empty"
	}

	[ "$port" -gt 3 ] && return

	log info "set port $port as game port"

	local phy_id=$(port_map config get $port phy_id)
	switch_ctl phy "$phy_id" game set

	log info "set port $port as game port finish"
}

start() {
	local game_port game_phy_id
	local flag_enable=$(uci -q get "${PSUCI}".game.enable)

	log info "start game port, en:${flag_enable}"

	[ "${flag_enable}" = "1" ] && {
		game_port=$(uci -q get "${PSUCI}".game.ports)
		port_set_highest_pri "${game_port}"
	} || {
		# cleanup game port
		uci batch <<-EOF
			set "$PSUCI".game.ports=""
			commit "$PSUCI"
		EOF
		switch_ctl phy game disable
	}
}

stop() {
	switch_ctl phy game disable
}

# use lock to block concurrent access
trap "lock -u $LOCK_FILE" EXIT
lock $LOCK_FILE

# main
case "$1" in
start)
	# start game service
	start
	;;
stop)
	# stop game service
	stop
	;;
restart)
	# restart game service
	stop
	start
	;;
*)
	echo "Usage: $0 {start|stop|restart}"
	exit 1
	;;
esac
