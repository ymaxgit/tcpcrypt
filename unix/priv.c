#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>
#include <errno.h>

#include "priv.h"

void drop_privs(const char *dir, const char *name)
{
	struct passwd *pwd = NULL;
	uid_t uid = (uid_t)(-1);
	gid_t gid;

	if (name) {
		errno = 0;
		pwd = getpwnam(name);
		if (pwd == NULL)
			(errno ? err : errx)(1, "Can't find user '%s'", name);
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;

		if (setgid(gid) < 0)
			err(1, "setgid(%ld)", (long) gid);

		if (initgroups(name, gid) < 0)
			err(1, "initgroups(\"%s\", %ld)",
			    name, (long) gid);
	}

	if (dir) {
		if (chroot(dir) < 0)
			err(1, "Could not chroot to %s", dir);
		if (chdir("/") < 0)
			err(1, "Could not chdir to root of jail");
	}

	if (name) {
#if defined(__linux__)
		linux_drop_privs(uid);
#else
		if (setuid(uid) != 0)
			err(1, "setuid(%ld)", (long) uid);
#endif
	}
}
