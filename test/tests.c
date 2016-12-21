#include <sys/types.h>

#include <stdlib.h>
#include "tinytest.h"

extern struct testcase_t tc_blackbox[];

struct testgroup_t groups[] = {
	{"blackbox/", tc_blackbox},
	END_OF_GROUPS
};

int
main(int argc, const char *argv[])
{

	return tinytest_main(argc, argv, groups);
}
