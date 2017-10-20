AUTOMAKE_OPTIONS = -Wno-portability
SHELL=/bin/bash
ARCH=$(shell uname -m)
ARCHPATH=arch/$(ARCH)

all-local: initrd

if WITH_KMODULES
export INCLUDE_KMODULES=1
endif

initrd-local:
	bash ./make-initrd.sh

cbfs-local:
	bash ./make-initrd.sh cbfs

kernel-local:
	cp $(ARCHPATH)/kernel_config ./kernel_config
	cp Dockerfile.$(ARCH) Dockerfile
	hyperctl build -t hyperstart-dev-$(ARCH):latest -f Dockerfile .
	hyperctl run --rm hyperstart-dev-$(ARCH):latest cat /root/build/result/kernel >kernel.new && mv -f kernel.new $(ARCHPATH)/kernel
	hyperctl run --rm hyperstart-dev-$(ARCH):latest cat /root/build/result/modules.tar > $(ARCHPATH)/modules.tar
	mv $(ARCHPATH)/kernel_config $(ARCHPATH)/kernel_config.old
	hyperctl run --rm hyperstart-dev-$(ARCH):latest cat /root/build/result/kernel_config > $(ARCHPATH)/kernel_config
	rm ./kernel_config
