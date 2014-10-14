#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <err.h>

#include "priv.h"

void linux_drop_privs(uid_t uid)
{
	cap_t caps = cap_init();
	int num = 2;

	cap_value_t capList[] = { CAP_NET_ADMIN, CAP_SETUID };

	cap_set_flag(caps, CAP_EFFECTIVE, num, capList, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, num, capList, CAP_SET);
        cap_set_flag(caps, CAP_PERMITTED, num, capList, CAP_SET);

	if (cap_set_proc(caps))
		err(1, "cap_set_flag()");

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0))
		err(1, "prctl()");

	cap_free(caps);

	if (setuid(uid) < 0)
		err(1, "setuid(%ld)", (long) uid);

	caps = cap_init();
	num  = 1;

	cap_set_flag(caps, CAP_EFFECTIVE, num, capList, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, num, capList, CAP_SET);
        cap_set_flag(caps, CAP_PERMITTED, num, capList, CAP_SET);

	if (cap_set_proc(caps))
		err(1, "cap_set_proc()");	

	cap_free(caps);

	/* XXX this really sucks.  The guy can screw with our net =( */
}
