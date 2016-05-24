all-local: initrd

if WITH_VBOX
initrd-local:
	bash ./make-initrd.sh vbox
else
initrd-local:
	bash ./make-initrd.sh
endif

cbfs-local:
	bash ./make-initrd.sh cbfs

kernel-local:
	bash ./make-kernel.sh
