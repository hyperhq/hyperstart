all-local: initrd

if WITH_KMODULES
export INCLUDE_KMODULES=1
endif

if WITH_AARCH64
ARCHPATH=arch/aarch64
initrd-local:
	bash ./make-initrd.sh aarch64
else
ARCHPATH=arch/x86_64
initrd-local:
	bash ./make-initrd.sh
endif

cbfs-local:
	bash ./make-initrd.sh cbfs

kernel-local:
	cp $(ARCHPATH)/kernel_config ./kernel_config
	hyperctl build -t hyperstart-dev:latest .
	hyperctl run --rm hyperstart-dev:latest cat /root/build/result/kernel >kernel.new && mv -f kernel.new $(ARCHPATH)/kernel
	hyperctl run --rm hyperstart-dev:latest cat /root/build/result/modules.tar > $(ARCHPATH)/modules.tar
	mv $(ARCHPATH)/kernel_config $(ARCHPATH)/kernel_config.old
	hyperctl run --rm hyperstart-dev:latest cat /root/build/result/kernel_config > $(ARCHPATH)/kernel_config
	rm ./kernel_config
