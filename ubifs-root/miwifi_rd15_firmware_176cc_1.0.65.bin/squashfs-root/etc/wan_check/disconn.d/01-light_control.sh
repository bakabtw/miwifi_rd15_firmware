#!/bin/ash

/usr/sbin/xqled internet_fail >/dev/null 2>&1
echo "internet_fail" > /var/run/light.status