SUBDIRS=src build

initrd-local:
	@echo finish make initrd
cbfs-local:
	@echo finish make cbfs
kernel-local:
	@echo finish make kernel

if SYSTEMD
SYSTEMD_SYS_UNITdir = @SYSTEMD_SYSTEMUNIT@
SYSTEMD_SYS_UNIT_DATA = data/hyperstart.service
endif
