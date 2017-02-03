#ifndef _ITERATORS_H
#define _ITERATORS_H

#include <stdio.h>

/**
 * Detailed information about available controller.
 */
struct controller_data {
	/** Controller name. */
	char name[FILENAME_MAX];
	/**
	 * Hierarchy ID. Controllers with the same hierarchy ID
	 * are mounted together as one hierarchy. Controllers with
	 * ID 0 are not currently mounted anywhere.
	 */
	int hierarchy;
	/** Number of groups. */
	int num_cgroups;
	/** Enabled flag. */
	int enabled;
};

/**
 * Read the first of controllers from /proc/cgroups.
 * @param handle Handle to be used for iteration.
 * @param info The structure which will be filled with controller data.
 */
int cgroup_get_all_controller_begin(void **handle,
	struct controller_data *info);
/**
 * Read next controllers from /proc/cgroups.
 * @param handle Handle to be used for iteration.
 * @param info The structure which will be filled with controller data.
 */
int cgroup_get_all_controller_next(void **handle, struct controller_data *info);

/**
 * Release the iterator
 */
int cgroup_get_all_controller_end(void **handle);

#endif /* _ITERATORS_H */
