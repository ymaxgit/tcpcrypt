#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/time.h>
#include <stdarg.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <openssl/err.h>

#include "tcpcrypt_divert.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "profile.h"
#include "test.h"
#include "crypto.h"

int _s;

void open_raw()
{       
        int one = 1;

        _s= socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (_s == -1)
                err(1, "socket()");

        if (setsockopt(_s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))
	    == -1)
                err(1, "IP_HDRINCL");
}

void divert_inject(void *data, int len)
{
        int rc;
        struct ip *ip = data;
        struct tcphdr *tcp = (struct tcphdr*) ((char*) ip + (ip->ip_hl << 2));
        struct sockaddr_in s_in;

	if (_s == 0)
		open_raw();

        s_in.sin_family = PF_INET;
        s_in.sin_addr   = ip->ip_dst;
        s_in.sin_port   = tcp->th_dport;

#if defined(__FreeBSD__) || defined(__DARWIN_UNIX03)
	#define HO_LEN
#endif
#ifdef HO_LEN
	ip->ip_len = ntohs(ip->ip_len);
#endif

        rc = sendto(_s, data, len, 0, (struct sockaddr*) &s_in,
		    sizeof(s_in));
        if (rc == -1)
                err(1, "sendto(raw)");

        if (rc != len)
                errx(1, "wrote %d/%d", rc, len);

#ifdef HO_LEN
	ip->ip_len = htons(ip->ip_len);
#endif
}

void divert_cycle(void)
{
}

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

	if (dir)
		xprintf(XP_DEFAULT, "Changed filesystem root to %s\n", dir);
	else
		xprintf(XP_ALWAYS, "WARNING: Did not chroot()\n");

	if (name)
		xprintf(XP_DEFAULT, "Changed to user '%s' (%ld)\n",
			name, (long) uid);
	else
		xprintf(XP_ALWAYS, "WARNING: Retaining root privileges!\n");
}
