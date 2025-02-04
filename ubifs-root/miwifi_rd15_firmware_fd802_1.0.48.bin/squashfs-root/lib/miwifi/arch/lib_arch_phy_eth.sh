#!/bin/sh

#LAN1 is a 2.5G phy and not a switch port
PHY_ATTR_PATH="/sys/module/yt_phy_module/port_status/port0/"
__is_phy_port() {
    [ "$1" = "4" ] && return 0
    return 1
}

__phy_port_restart() {
    echo "0" > $PHY_ATTR_PATH/power
    echo "1" > $PHY_ATTR_PATH/power
}

arch_phy_eth_port_restart() {
    local port="$1"
    local speed=""

    if __is_phy_port "$port"; then
        __phy_port_restart
    else
        local phy_id=$(port_map config get $port phy_id)
        speed=$(switch_ctl phy "$phy_id" autoNeg get| cut -d ':' -f 3 | xargs)
        switch_ctl phy "$phy_id" autoNeg set "$speed"
    fi

    return 0
}

arch_phy_eth_port_mode_set() {
    local port="$1"
    local speed="$2"

    if __is_phy_port "$port"; then
        if [ "$speed" = "0" ]; then
            echo 1 > $PHY_ATTR_PATH/10_autoNeg
            echo 1 > $PHY_ATTR_PATH/100_autoNeg
            echo 1 > $PHY_ATTR_PATH/1000_autoNeg
            echo 1 > $PHY_ATTR_PATH/2500_autoNeg
        else
            echo 0 > $PHY_ATTR_PATH/10_autoNeg
            echo 0 > $PHY_ATTR_PATH/100_autoNeg
            echo 0 > $PHY_ATTR_PATH/1000_autoNeg
            echo 0 > $PHY_ATTR_PATH/2500_autoNeg
            echo 1 > $PHY_ATTR_PATH/${speed}_autoNeg
        fi
        __phy_port_restart
    else
        local phy_id=$(port_map config get $port phy_id)
        switch_ctl phy "$phy_id" autoNeg set "$speed"
    fi

    return 0
}

arch_phy_eth_port_mode_get() {
    local port="$1"
    local speed=""

    if __is_phy_port "$port"; then
        local autoNeg_10=$(cat $PHY_ATTR_PATH/10_autoNeg)
        local autoNeg_100=$(cat $PHY_ATTR_PATH/100_autoNeg)
        local autoNeg_1000=$(cat $PHY_ATTR_PATH/1000_autoNeg)
        local autoNeg_2500=$(cat $PHY_ATTR_PATH/2500_autoNeg)
        if [ "$autoNeg_1000" = "1" -a "$autoNeg_2500" = "1" ]; then
            speed="0" #Auto Negotiate
        else
            if [ "$autoNeg_2500" = "1" ]; then
                speed="2500"
            elif [ "$autoNeg_1000" = "1" ]; then
                speed="1000"
            elif [ "$autoNeg_100" = "1" ]; then
                speed="100"
            elif [ "$autoNeg_10" = "1" ]; then
                speed="10"
            fi
        fi
    else
        local phy_id=$(port_map config get $port phy_id)
        speed=$(switch_ctl phy "$phy_id" autoNeg get| cut -d ':' -f 3 | xargs)
    fi

    echo "$speed"
    return 0
}

arch_phy_eth_port_link_status() {
    local port="$1"
    local status=""

    if __is_phy_port "$port"; then
        status=$(cat $PHY_ATTR_PATH/speed | awk '{print $1}' | cut -d ':' -f 2)
    else
        local phy_id=$(port_map config get $port phy_id)
        status=$(swconfig dev switch1 port "$phy_id" get link | cut -d ' ' -f 2 | cut -d ':' -f 2)
    fi

    [ -n "$status" ] && echo "$status"
}

arch_phy_eth_port_link_speed() {
    local port="$1"
    local speed=""

    if __is_phy_port "$port"; then
        speed=$(cat $PHY_ATTR_PATH/speed | awk '{print $2}' | cut -d ':' -f 2)
    else
        local phy_id=$(port_map config get $port phy_id)
        speed=$(swconfig dev switch1 port "$phy_id" get link | cut -d " " -f 3 | tr -cd "\[0-9\]")
    fi

    [ -z "$speed" ] && echo "0" || echo "$speed"
}

arch_phy_eth_port_link_duplex() {
    local port="$1"
    local duplex=""

    if __is_phy_port "$port"; then
        duplex=$(cat $PHY_ATTR_PATH/speed | awk '{print $3}')
    else
        local phy_id=$(port_map config get $port phy_id)
        duplex=$(swconfig dev switch1 port "$phy_id" get link | grep duplex | cut -d " " -f 4 | cut -d '-' -f 1)
    fi

    [ -n "$duplex" ] && echo "$duplex"
}

arch_phy_eth_port_mib_info() {
    local port="$1"
    local que="$2"
    local res=""

    local phy_id=$(port_map config get $port phy_id)
    que=$(echo "$que" | awk '{print toupper($0)}')

    res=$(swconfig dev switch1 port "$phy_id" get mib | grep "$que" | awk -F ':' '{print $2}' | xargs)
    echo "$res"
}

arch_phy_eth_port_power_on() {
    local port="$1"

    if __is_phy_port "$port"; then
        echo "1" > $PHY_ATTR_PATH/power
    else
        local phy_id=$(port_map config get $port phy_id)
        switch_ctl phy "$phy_id" power 1
    fi

    return 0
}

arch_phy_eth_port_power_off() {
    local port="$1"

    if __is_phy_port "$port"; then
        echo "0" > $PHY_ATTR_PATH/power
    else
        local phy_id=$(port_map config get $port phy_id)
        switch_ctl phy "$phy_id" power 0
    fi
    return 0
}
