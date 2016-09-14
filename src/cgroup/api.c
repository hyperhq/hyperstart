/*
 * libcgroup api functions which hyperstart would like to depend on without
 * pulling in all of hyperstart.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "error.h"
#include "iterators.h"

const char const *cgroup_strerror_codes[] = {
	"Cgroup is not compiled in",
	"Cgroup is not mounted",
	"Cgroup does not exist",
	"Cgroup has not been created",
	"Cgroup one of the needed subsystems is not mounted",
	"Cgroup, request came in from non owner",
	"Cgroup controllers are bound to different mount points",
	"Cgroup, operation not allowed",
	"Cgroup value set exceeds maximum",
	"Cgroup controller already exists",
	"Cgroup value already exists",
	"Cgroup invalid operation",
	"Cgroup, creation of controller failed",
	"Cgroup operation failed",
	"Cgroup not initialized",
	"Cgroup, requested group parameter does not exist",
	"Cgroup generic error",
	"Cgroup values are not equal",
	"Cgroup controllers are different",
	"Cgroup parsing failed",
	"Cgroup, rules file does not exist",
	"Cgroup mounting failed",
	"End of File or iterator",
	"Failed to parse config file",
	"Have multiple paths for the same namespace",
	"Controller in namespace does not exist",
	"Either mount or namespace keyword has to be specified in the configuration file",
	"This kernel does not support this feature",
	"Value setting does not succeed",
	"Failed to remove a non-empty group",
};

/*
 * The errno which happend the last time (have to be thread specific)
 */
//__thread int last_errno;
int last_errno;	// Not thread specific because hyperstart is single-threaded.

#define MAXLEN 256

/* the value have to be thread specific */
//static __thread char errtext[MAXLEN];
static char errtext[MAXLEN];

int cgroup_get_all_controller_next(void **handle, struct controller_data *info)
{
	FILE *proc_cgroup = (FILE *) *handle;
	int err = 0;
	int hierarchy, num_cgroups, enabled;
	char subsys_name[FILENAME_MAX];

	if (!proc_cgroup)
		return ECGINVAL;

	if (!info)
		return ECGINVAL;

	err = fscanf(proc_cgroup, "%s %d %d %d\n", subsys_name,
			&hierarchy, &num_cgroups, &enabled);

	if (err != 4)
		return ECGEOF;

	strncpy(info->name, subsys_name, FILENAME_MAX);
	info->name[FILENAME_MAX-1] = '\0';
	info->hierarchy = hierarchy;
	info->num_cgroups = num_cgroups;
	info->enabled = enabled;

	return 0;
}

int cgroup_get_all_controller_begin(void **handle, struct controller_data *info)
{
	FILE *proc_cgroup = NULL;
	char buf[FILENAME_MAX];
	int ret;

	if (!info)
		return ECGINVAL;

	proc_cgroup = fopen("/proc/cgroups", "re");
	if (!proc_cgroup) {
		last_errno = errno;
		return ECGOTHER;
	}

	if (!fgets(buf, FILENAME_MAX, proc_cgroup)) {
		last_errno = errno;
		fclose(proc_cgroup);
		*handle = NULL;
		return ECGOTHER;
	}
	*handle = proc_cgroup;

	ret = cgroup_get_all_controller_next(handle, info);
	if (ret != 0) {
		fclose(proc_cgroup);
		*handle = NULL;
	}
	return ret;
}

int cgroup_get_all_controller_end(void **handle)
{
	FILE *proc_cgroup = (FILE *) *handle;

	if (!proc_cgroup)
		return ECGINVAL;

	fclose(proc_cgroup);
	*handle = NULL;

	return 0;
}

const char *cgroup_strerror(int code)
{
	if (code == ECGOTHER)
		return strerror_r(cgroup_get_last_errno(), errtext, MAXLEN);

	return cgroup_strerror_codes[code % ECGROUPNOTCOMPILED];
}

/**
 * Return last errno, which caused ECGOTHER error.
 */
int cgroup_get_last_errno(void)
{
    return last_errno;
}
