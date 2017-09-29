all-local: initrd

if WITH_KMODULES
export INCLUDE_KMODULES=1
endif

if WITH_AARCH64
initrd-local:
	bash ./make-initrd.sh aarch64
else
initrd-local:
	bash ./make-initrd.sh
endif

cbfs-local:
	bash ./make-initrd.sh cbfs

kernel-local:
	hyperctl build -t hyperstart-dev:latest .
	hyperctl run --rm hyperstart-dev:latest cat /root/build/result/kernel >kernel.new && mv -f kernel.new kernel
	hyperctl run --rm hyperstart-dev:latest cat /root/build/result/modules.tar >modules.tar
	mv kernel_config kernel_config.old
	hyperctl run --rm hyperstart-dev:latest cat /root/build/result/kernel_config >kernel_config
