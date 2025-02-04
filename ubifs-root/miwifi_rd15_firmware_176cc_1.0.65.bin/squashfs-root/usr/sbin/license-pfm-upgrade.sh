#!/bin/sh
#
#  Copyright (c) 2022 Qualcomm Technologies, Inc.
#
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
#
. /lib/functions.sh

licensepath="$1"
upgrade_mode="$2"
temp="/tmp"
license="/license"

upgrade_partition()
{
	local mtdblock=$(find_mtd_part 0:LICENSE)

	if [ -z "$mtdblock" ]; then
		# read from mmc
		mtdblock=$(find_mmc_part 0:LICENSE)
	fi

	if [ -z "$mtdblock" ]; then
		echo "No License partition in device to upgrade" > /dev/console
		exit 1;
	fi

	printf "Copying license files to ${temp}/license/..\n"

	rm -rf ${temp}/license
	mkdir -p ${temp}/license

	#Copying license files from license partition
	if [ "$upgrade_mode" == "ADD" ]; then

		rm -rf ${temp}/license_part
		mkdir -p ${temp}/license_part
		rm -f ${temp}/license.tar.gz

		dd if=${mtdblock} of=${temp}/license.tar.gz bs=2K conv=sync
		tar -xzf ${temp}/license.tar.gz -C ${temp}/license_part/.

		cp ${temp}/license_part/* ${temp}/license/.
	fi

	#Copying user given license files
	cp ${licensepath}/*.pfm ${temp}/license/.

	printf "Preparing License tar file..\n"

	rm -f ${temp}/license.tar.gz

	cd ${temp}/license/
	tar -czf ${temp}/license.tar.gz ./*
	cd -

	printf "Writing to flash..\n"

	dd if=${temp}/license.tar.gz of=${mtdblock}

	rm -rf $temp/license $temp/license_part
	rm -f ${temp}/license.tar.gz

}


if [ -z "$licensepath" ]; then
	echo "Error: License path is empty"
	echo "Usages: Please run as below command:"
	echo "license-pfm-upgarde.sh <path_to_license_files> <ADD/UPGRADE>"
	echo "Default mode is ADD, use UPGRADE to replace entire license partition"
	exit 1;
fi

files=$(ls $licensepath/*.pfm | wc -l)

if [ $files -eq 0 ]; then
	echo "No license files in given directory $licensepath"
	exit 1;
fi

if [ "$upgrade_mode" != "UPGRADE" ]; then
        upgrade_mode="ADD"
fi

echo "Upgrade license files to partition" > /dev/console
upgrade_partition

printf " PFM license upgrade done! \n"
