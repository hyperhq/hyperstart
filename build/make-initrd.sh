#!/bin/bash

rm -rf root
mkdir root

cp ../src/init ./root

ldd ./root/init | while read line
do
	arr=(${line// / })

	for lib in ${arr[@]}
	do
		if [ "${lib:0:1}" = "/" ]; then
			dir=root`dirname $lib`
			mkdir -p "${dir}"
			cp -f $lib $dir
		fi
	done
done
cd ./root && find . | cpio -H newc -o | gzip -9 > ../hyper-initrd.img


if [ "$1" != "cbfs" ]; then
	exit 0
fi

cd ../

echo "build cbfs"
rm -rf .cbfs
rm -rf cbfs.rom

mkdir .cbfs
dd if=/dev/zero of=.cbfs/boot.bin bs=4096 count=1
cbfstool .cbfs/cbfs.rom create -s 4096k -B .cbfs/boot.bin -m x86  0x1000
cbfstool .cbfs/cbfs.rom add -f kernel -n vmlinuz -t raw
cbfstool .cbfs/cbfs.rom add -f hyper-initrd.img -n initrd -t raw
cp .cbfs/cbfs.rom ./
rm -rf .cbfs
