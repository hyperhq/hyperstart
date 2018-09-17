#ifndef _PORT_MAPPING_H_
#define _PORT_MAPPING_H_

#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/types.h>

struct ipt_rule {
	char *table;
	char *op;
	char *chain;
	char *rule;
};

struct hyper_pod;
struct hyper_container;
int hyper_setup_portmapping(struct hyper_pod *pod);
int hyper_setup_container_portmapping(struct hyper_container *c, struct hyper_pod *pod);
void hyper_cleanup_portmapping(struct hyper_pod *pod);
void hyper_cleanup_container_portmapping(struct hyper_container *c, struct hyper_pod *pod);

#endif
