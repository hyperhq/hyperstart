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

ARCHPATH=arch/$(uname -m)
cp $ARCHPATH/binary/busybox /tmp/hyperstart-rootfs/sbin/
cp $ARCHPATH/binary/iptables /tmp/hyperstart-rootfs/sbin/
cp $ARCHPATH/binary/ipvsadm /tmp/hyperstart-rootfs/sbin/
cp $ARCHPATH/binary/socat /tmp/hyperstart-rootfs/sbin/
cp $ARCHPATH/binary/mount.nfs /tmp/hyperstart-rootfs/sbin/mount.nfs4

# on ppc64le the RTAS binaries are required for NIC hot plugging
if [ -e $ARCHPATH/binary/rtas.tar ]; then
       tar -xf $ARCHPATH/binary/rtas.tar -C /tmp/hyperstart-rootfs/
       mkdir -p /tmp/hyperstart-rootfs/var/lock
       mkdir -p /tmp/hyperstart-rootfs/var/log
       touch  /tmp/hyperstart-rootfs/var/log/messages
       touch  /tmp/hyperstart-rootfs/var/log/platform
fi


if [ "$INCLUDE_KMODULES"x == "1"x ] && [ -e $ARCHPATH/modules.tar ]; then
	tar -xf $ARCHPATH/modules.tar -C /tmp/hyperstart-rootfs/lib/modules
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
	cbfstool .cbfs/cbfs.rom add -f $ARCHPATH/kernel -n vmlinuz -t raw
	cbfstool .cbfs/cbfs.rom add -f hyper-initrd.img -n initrd -t raw
	echo 'console=ttyS0 panic=1 no_timer_check' > .cbfs/cmdline
	cbfstool .cbfs/cbfs.rom add -f .cbfs/cmdline -n cmdline -t raw
	cp .cbfs/cbfs.rom ./
	rm -rf .cbfs
	exit 0
fi
