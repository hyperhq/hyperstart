#ifndef _CONTAINER_H_
#define _CONTAINER_H_

#include "exec.h"

struct env {
	char	*env;
	char	*value;
};

struct volume {
	char	*device;
	char	*scsiaddr;
	char	*mountpoint;
	char	*fstype;
	int	readonly;
	int	docker;
};

struct fsmap {
	char	*source;
	char	*path;
	int	readonly;
	int	docker;
};

struct sysctl {
	char	*path;
	char	*value;
};

struct hyper_container {
	char			*id;
	char			*rootfs;
	char			*image;
	char			*scsiaddr;
	char			*fstype;
	struct volume		*vols;
	struct env		*envs;
	struct fsmap		*maps;
	struct sysctl		*sys;
	int			vols_num;
	int			envs_num;
	int			maps_num;
	int			sys_num;
	int			ns;
	int			initialize;
	uint32_t		code;
	struct list_head	list;
	struct hyper_exec	exec;
};

struct hyper_pod;

int hyper_start_container(struct hyper_container *container,
			  int utsns, int ipcns, struct hyper_pod *pod);
struct hyper_container *hyper_find_container(struct hyper_pod *pod, char *id);
void hyper_cleanup_container(struct hyper_container *container);
void hyper_cleanup_containers(struct hyper_pod *pod);
void hyper_free_container(struct hyper_container *c);

#endif
