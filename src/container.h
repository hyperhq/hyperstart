#ifndef _CONTAINER_H_
#define _CONTAINER_H_

#include "exec.h"

struct env {
	char	*env;
	char	*value;
};

struct volume {
	char	*device;
	char	*mountpoint;
	char	*fstype;
	int	readonly;
};

struct fsmap {
	char	*source;
	char	*path;
	int	readonly;
};

struct hyper_container {
	char			*id;
	char			*rootfs;
	char			*image;
	char			*workdir;
	char			*fstype;
	struct volume		*vols;
	struct env		*envs;
	struct fsmap		*maps;
	int			vols_num;
	int			envs_num;
	int			maps_num;
	uint32_t		code;
	struct hyper_exec	exec;
};

struct hyper_pod;

int hyper_start_container(struct hyper_container *container,
			  int pidns, int utsns, int ipcns);
struct hyper_container *hyper_find_container(struct hyper_pod *pod, char *id);
//int hyper_restart_containers(struct hyper_pod *pod);
void hyper_cleanup_container(struct hyper_pod *pod);

#endif
