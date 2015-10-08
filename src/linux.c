#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>

#undef _POSIX_SOURCE    

#include "tcpcrypt_divert.h"
#include "tcpcryptd.h"

static struct nfq_handle    *_h;
static struct nfq_q_handle  *_q;
static unsigned int	    _mark;
static int		    _conntrack[2];

static int packet_input(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              		struct nfq_data *nfa, void *data)
{
	divert_cb cb = (divert_cb) data;
	char *d;
	int len;
	int rc;
	unsigned int id;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	struct ip *ip;
	int flags = 0;
	struct timeval tv;
	int rlen = 0;
	void *rdata = NULL;

	len = nfq_get_payload(nfa, &d);
	if (len < 0)
		err(1, "nfq_get_payload()");

	if (nfq_get_indev(nfa))
		flags |= DF_IN;

	if (nfq_get_timestamp(nfa, &tv) == 0)
		set_time(&tv);
	else {
		static int warn = 0;

		if (!warn && !_conf.cf_disable_timers)
			xprintf(XP_ALWAYS, "No timestamp provided in packet"
			                   " - expect low performance due to"
					   " calls to gettimeofday\n");
		warn = 1;	
	}

	rc = cb(d, len, flags);

	id = ntohl(ph->packet_id);

	switch (rc) {
	case DIVERT_MODIFY:
		ip    = (struct ip*) d;
		rlen  = ntohs(ip->ip_len);
		rdata = d;
		/* fallthrough */
	case DIVERT_ACCEPT:
		if (_mark) {
			unsigned int mark = 0;

			assert((mark & _mark) == 0);
			nfq_set_verdict_mark(qh, id, NF_REPEAT,
					     htonl(_mark | mark),
					     rlen, rdata);
		} else
			nfq_set_verdict(qh, id, NF_ACCEPT, rlen, rdata);
		break;

	case DIVERT_DROP:
		nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		break;

	default:
		printf("Unknown verdict %d\n", rc);
		abort();
	}

	return 0;
}

/* IPC because we drop privs later on */
static void conntrack_open(void)
{
	int pid;

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, _conntrack) == -1)
		err(1, "socketpair()");

	if ((pid = fork()) == -1)
		err(1, "fork()");

	if (pid != 0) {
		close(_conntrack[1]);
		/* parent - keep working */
		return;
	}

	/* child */
	close(_conntrack[0]);

	/* for now */
	close(0);
	close(1);
	close(2);

	while (1) {
		unsigned char x;
		int rc;
		struct msghdr mh;
		int fd;
		char buf[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr *cm;
		int *fdp;
		struct iovec iov;

		if ((rc = read(_conntrack[1], &x, 1)) <= 0)
			break;

		if ((fd = open("/proc/net/nf_conntrack", O_RDONLY)) == -1)
			err(1, "open(conntrack)");

		memset(&mh, 0, sizeof(mh));
		mh.msg_control    = buf;
		mh.msg_controllen = sizeof(buf);

		cm = CMSG_FIRSTHDR(&mh);
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type  = SCM_RIGHTS;
		cm->cmsg_len   = CMSG_LEN(sizeof(fd));

		fdp  = (int *) CMSG_DATA(cm);
		*fdp = fd;

		iov.iov_base = &x;
		iov.iov_len  = sizeof(x);

		mh.msg_controllen = cm->cmsg_len;
		mh.msg_iov        = &iov;
		mh.msg_iovlen     = 1;

		if (sendmsg(_conntrack[1], &mh, 0) == -1)
			err(1, "sendmsg()");

		close(fd);
	}

	exit(0);
}

static int linux_open(int port, divert_cb cb)
{
	unsigned int bufsize = 1024 * 1024 * 1;
	unsigned int rc;
	char *m;
	int fd, flags;

        _h = nfq_open();
        if (!_h)
                err(1, "nfq_open()");

	rc = nfnl_rcvbufsiz(nfq_nfnlh(_h), bufsize);
	if (rc != bufsize)
		xprintf(XP_DEBUG, "Buffer size %u wanted %u\n", rc, bufsize);

	/* reset in case of previous crash */
	if (nfq_unbind_pf(_h, AF_INET) < 0)
		err(1, "nfq_unbind_pf()");

        if (nfq_bind_pf(_h, AF_INET) < 0)
                err(1, "nfq_bind_pf()");

        _q = nfq_create_queue(_h, port, packet_input, cb);
        if (!_q)
                err(1, "nfq_create_queue()");

        if (nfq_set_mode(_q, NFQNL_COPY_PACKET, 0xffff) < 0)
                err(1, "nfq_set_mode()");

	if (nfq_set_queue_maxlen(_q, 10000) < 0)
		err(1, "nfq_set_queue_maxlen()");

       	xprintf(XP_DEFAULT,
		"Divert packets using iptables -j NFQUEUE --queue-num %d\n",
                port);

	m = driver_param(0);
	if (m) {
		_mark = strtoul(m, NULL, 16);
		xprintf(XP_DEFAULT, "Also, add -m mark --mark 0x0/0x%x\n",
			_mark);
	}

	fd = nfq_fd(_h);

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		err(1, "fcntl()");

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "fcntl()");

	raw_open();

	conntrack_open();

	return fd;
}

static void linux_close(void)
{
        if (_q)
                nfq_destroy_queue(_q);

        if (_h)
                nfq_close(_h);
}

static void linux_next_packet(int s)
{
	char buf[2048];
	int rc;

	rc = read(s, buf, sizeof(buf));
	if (rc == -1) {
		if (errno == ENOBUFS) {
			printf("FUCK - we're dropping packets\n");
			return;
		}

		err(1, "read(divert) %d", errno);
	}

	if (rc == 0)
		errx(1, "EOF");

	nfq_handle_packet(_h, buf, rc);
}

static int linux_orig_dest(struct sockaddr_in *to, struct ip *ip, int *flags)
{
	int fd, *fdp;
	struct msghdr mh;
	char buf[4096 * 5];
	struct cmsghdr *cm;
	unsigned char x = 'a';
	struct iovec iov;
	int rc;
	char match[128];
	char match2[128];
	char *found = NULL;
	char *p, *p2;
	struct tcphdr *tcp = (struct tcphdr*) ((unsigned long) ip
					       + ip->ip_hl * 4);

	assert(sizeof(buf) >= CMSG_SPACE(sizeof(fd)));

	iov.iov_base = &x;
	iov.iov_len  = 1;

	if (write(_conntrack[0], &x, sizeof(x)) != 1)
		err(1, "write()");

	memset(&mh, 0, sizeof(mh));
	mh.msg_control    = buf;
	mh.msg_controllen = sizeof(buf);
	mh.msg_iov        = &iov;
	mh.msg_iovlen     = 1;

	if (recvmsg(_conntrack[0], &mh, 0) == -1)
		err(1, "recvmsg()");

	cm = CMSG_FIRSTHDR(&mh);
	assert(cm);
	assert(cm->cmsg_level == SOL_SOCKET);
	assert(cm->cmsg_type  == SCM_RIGHTS);
	assert(cm->cmsg_len   == CMSG_LEN(sizeof(fd)));

	fdp = (int*) CMSG_DATA(cm);
	fd  = *fdp;

	snprintf(match, sizeof(match), " src=%s dst=",
		 inet_ntoa(ip->ip_src));

	snprintf(match2, sizeof(match2), "sport=%d dport=",
		 ntohs(tcp->th_sport));

	/* XXX make parsing more precise and robust */

	/* XXX read and glue whole thing - incorrect code */
	while ((rc = read(fd, buf, sizeof(buf) - 1)) > 0) {
		p = buf;

		buf[rc] = 0;

		if (rc == sizeof(buf) - 1)
			xprintf(XP_ALWAYS, "CODEME\n");

		while (*p) {
			char *line = p = strstr(p, match);
			if (!p)
				break;

			p2 = strchr(p, '\n');
			if (!p2)
				break;

			*p2++ = 0;
			p = p2;

			if ((p2 = strstr(line, match2)) == NULL)
				continue;

			found = line;
			break;
		}

		if (found)
			break;
	}

	if (rc == -1)
		err(1, "read()");

	close(fd);

	if (!found)
		return -1;

	assert(found >= buf);

	/* XXX */
	found -= 8;
	if (found < buf)
		return -1;

	if (strstr(found, "SYN_SENT"))
		*flags = 0;
	else if (strstr(found, "SYN_RECV"))
		*flags = DF_IN;
	else
		assert(!"dunno man");

	p = strstr(found, "dst=");
	assert(p);
	p += 4;

	p2 = strchr(p, ' ');
	assert(p2);
	*p2++ = 0;

	if (inet_aton(p, &to->sin_addr) == 0)
		errx(1, "inet_aton()");

	p = strstr(p2, "dport=");
	assert(p);
	p += 6;

	p2 = strstr(p, " ");
	assert(p2);
	*p2++ = 0;

	to->sin_port = htons(atoi(p));

	return 0;
}

struct divert *divert_get(void)
{
	static struct divert _divert_linux = {
		.open		= linux_open,
		.next_packet	= linux_next_packet,
		.close		= linux_close,
		.inject		= raw_inject,
		.orig_dest	= linux_orig_dest,
	};

	if (_conf.cf_rdr)
		_divert_linux.inject = divert_inject_pcap;

	return &_divert_linux;
}
