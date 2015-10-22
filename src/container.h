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

struct sysctl {
	char	*path;
	char	*value;
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
	struct sysctl		*sys;
	int			vols_num;
	int			envs_num;
	int			maps_num;
	int			sys_num;
	int			ns;
	uint32_t		code;
	struct hyper_exec	exec;
};

struct hyper_pod;

int hyper_start_container(struct hyper_container *container,
			  int utsns, int ipcns, struct hyper_pod *pod);
struct hyper_container *hyper_find_container(struct hyper_pod *pod, char *id);
void hyper_cleanup_container(struct hyper_pod *pod);

#endif
