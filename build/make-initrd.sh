#!/bin/bash

rm -rf /tmp/hyperstart-rootfs
mkdir -p /tmp/hyperstart-rootfs/lib \
	  /tmp/hyperstart-rootfs/lib64 \
	  /tmp/hyperstart-rootfs/lib/modules

mkdir -m 0755 -p /tmp/hyperstart-rootfs/dev \
	  /tmp/hyperstart-rootfs/sys \
	  /tmp/hyperstart-rootfs/sbin \
	  /tmp/hyperstart-rootfs/bin \
	  /tmp/hyperstart-rootfs/proc

cp ../src/hyperstart /tmp/hyperstart-rootfs/init
cp busybox /tmp/hyperstart-rootfs/sbin/
cp iptables /tmp/hyperstart-rootfs/sbin/
cp ipvsadm /tmp/hyperstart-rootfs/sbin/
cp socat /tmp/hyperstart-rootfs/sbin/
cp mount.nfs /tmp/hyperstart-rootfs/sbin/mount.nfs4

if [ "$INCLUDE_KMODULES"x == "1"x ]; then
	if [ "$1"x = "aarch64"x ]; then
		echo "build hyperstart for aarch64"
		tar -xf modules_aarch64.tar -C \
			/tmp/hyperstart-rootfs/lib/modules
	else
		tar -xf modules.tar -C /tmp/hyperstart-rootfs/lib/modules
	fi
fi

# create symlinks to busybox and iptables
BUSYBOX_BINARIES=(/bin/sh /bin/tar /bin/hwclock /sbin/modprobe /sbin/depmod)
for bin in ${BUSYBOX_BINARIES[@]}
do
	mkdir -p /tmp/hyperstart-rootfs/`dirname ${bin}`
	ln -sf /sbin/busybox /tmp/hyperstart-rootfs/${bin}
done
IPTABLES_BINARIES=(/sbin/iptables-restore /sbin/iptables-save)
for bin in ${IPTABLES_BINARIES[@]}
do
	mkdir -p /tmp/hyperstart-rootfs/`dirname ${bin}`
	ln -sf /sbin/iptables /tmp/hyperstart-rootfs/${bin}
done

LDD_BINARIES=(/init /sbin/ipvsadm /sbin/iptables)
for bin in ${LDD_BINARIES[@]}
do
    ldd /tmp/hyperstart-rootfs/${bin} | while read line
    do
	    arr=(${line// / })

	    for lib in ${arr[@]}
	    do
		    if [ "${lib:0:1}" = "/" ]; then
			    dir=/tmp/hyperstart-rootfs`dirname $lib`
			    mkdir -p "${dir}"
			    cp -f $lib $dir
		    fi
	    done
    done
done

( cd /tmp/hyperstart-rootfs && find . | cpio -H newc -o | gzip -9 ) > ./hyper-initrd.img

rm -rf /tmp/hyperstart-rootfs

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
