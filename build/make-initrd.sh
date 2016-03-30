#!/bin/bash

rm -rf root
mkdir root

cp ../src/init ./root
cp busybox ./root

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

if [ "$1"x = "vbox"x ]; then
	echo "build initrd for vbox"
	cp ./vbox/driver/* ./root
fi

cd ./root && find . | cpio -H newc -o | gzip -9 > ../hyper-initrd.img

cd ../
rm -rf ./root

if [ "$1"x = "cbfs"x ]; then
	echo "build cbfs"
	rm -rf .cbfs
	rm -rf cbfs.rom

	mkdir .cbfs
	dd if=/dev/zero of=.cbfs/boot.bin bs=4096 count=1
	cbfstool .cbfs/cbfs.rom create -s 8128k -B .cbfs/boot.bin -m x86  0x1000
	cbfstool .cbfs/cbfs.rom add -f kernel -n vmlinuz -t raw
	cbfstool .cbfs/cbfs.rom add -f hyper-initrd.img -n initrd -t raw
	echo 'console=ttyS0 panic=1 no_timer_check' > .cbfs/cmdline
	cbfstool .cbfs/cbfs.rom add -f .cbfs/cmdline -n cmdline -t raw
	cp .cbfs/cbfs.rom ./
	rm -rf .cbfs
	exit 0
fi

if [ "$1"x = "vbox"x ]; then
	mkdir tmp
	mkdir -p tmp/images
	mkdir -p tmp/kernel
	mkdir -p tmp/isolinux

	cd tmp
	cp ../vbox/kernel ./kernel/
	cp ../hyper-initrd.img ./images/initrd.img
	cp ../vbox/isolinux/isolinux.bin ./isolinux/
	cp ../vbox/isolinux/ldlinux.c32 ./isolinux/

cat > isolinux/syslinux.cfg <<EOF
DEFAULT linux
LABEL linux
  SAY Now booting the kernel from SYSLINUX...
  KERNEL /kernel/kernel
  APPEND initrd=/images/initrd.img
EOF

	cd ../

	mkisofs -o hyper-vbox-boot.iso -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table tmp 

	rm -fr tmp
fi
