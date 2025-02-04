#!/bin/ash

/usr/sbin/xqled link_down >/dev/null 2>&1
echo "link_down" > /var/run/light.status