#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/time.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <openssl/err.h>

#include "shared/socket_address.h"
#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt_divert.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "priv.h"
#include "profile.h"
#include "test.h"
#include "crypto.h"
#include "tcpcrypt_strings.h"
#include "config.h"
#include "util.h"

#define ARRAY_SIZE(n)	(sizeof(n) / sizeof(*n))
#define MAX_TIMERS 1024

struct conf _conf;
struct divert *_divert;

struct backlog_ctl {
	struct backlog_ctl	*bc_next;
	struct socket_address	bc_sa;
	struct tcpcrypt_ctl	bc_ctl;
};

struct timer {
	struct timeval	t_time;
	timer_cb	t_cb;
	void		*t_arg;
	struct timer	*t_next;
	struct timer	*t_prev;
	int		t_id;
};

struct network_test {
	int			nt_port;
	int			nt_proto;
	int			nt_req;
	int			nt_s;
	int			nt_state;
	int			nt_err;
	int			nt_last_state;
	int			nt_flags;
	int			nt_crypt;
	time_t			nt_start;
	struct tcpcrypt_ctl	nt_ctl;
	struct network_test	*nt_next;
};

static struct state {
	struct backlog_ctl	s_backlog_ctl;
	int			s_ctl;
	struct socket_address	s_ctl_addr;
	int			s_raw;
	struct timer		s_timers;
	struct timer		*s_timer_map[MAX_TIMERS];
	struct timer		s_timer_free;
	struct timeval		s_now;
	int			s_divert;
	int			s_time_set;
	packet_hook		s_post_packet_hook;
	packet_hook		s_pre_packet_hook;
	struct network_test	s_network_tests;
	void			*s_nt_timer;
	struct in_addr		s_nt_ip;
} _state;

static struct fd _fds;

typedef void (*test_cb)(void);

struct test {
        test_cb t_cb;
        char    *t_desc;
};

static struct test _tests[] = {
	{ test_sym_throughput, "Symmetric cipher throughput" },
	{ test_mac_throughput, "Symmetric MAC throughput" },
	{ test_dropper,	       "Packet dropper" },
};

static void ensure_socket_address_unlinked(struct socket_address *sa)
{
	const char *path;

	if (socket_address_is_null(sa))
		return;

	if ((path = socket_address_pathname(sa)) != NULL) {
		if (unlink(path) != 0) {
			if (errno != ENOENT)
				warn("unlink(%s)", path);
		}
	}
}

static void cleanup()
{
	_divert->close();

	if (_state.s_ctl > 0)
		close(_state.s_ctl);

	if (_state.s_raw > 0)
		close(_state.s_raw);

	profile_end();
}

static void sig(int num)
{
	printf("\n");

	cleanup();
	exit(0);
}

void set_time(struct timeval *tv)
{
	_state.s_now	  = *tv;
	_state.s_time_set = 1;
}

static struct timeval *get_time(void)
{
	if (!_state.s_time_set) {
		struct timeval tv;

		gettimeofday(&tv, NULL);
		set_time(&tv);
	}

	return &_state.s_now;
}

static void alloc_timers()
{
	int i;
	struct timer *t;

	for (i = 0; i < MAX_TIMERS; i++) {
		t = xmalloc(sizeof(*t));
		memset(t, 0, sizeof(*t));
		t->t_id = i;
		_state.s_timer_map[i] = t;

		t->t_next = _state.s_timer_free.t_next;
		_state.s_timer_free.t_next = t;
	}
}

void *add_timer(unsigned int usec, timer_cb cb, void *arg)
{
	struct timer *t, *prev, *cur;
	int sec;

	if (_conf.cf_disable_timers)
		return (void*) 0x666;

	if (!_state.s_timer_map[0])
		alloc_timers();

	t = _state.s_timer_free.t_next;
	assert(t);
	_state.s_timer_free.t_next = t->t_next;
	t->t_next = NULL;

	t->t_time = *(get_time());
	t->t_time.tv_sec  += usec / (1000 * 1000);
	t->t_time.tv_usec += usec % (1000 * 1000);

	sec = t->t_time.tv_usec / (1000 * 1000);
	if (sec) {
		t->t_time.tv_sec  += sec;
		t->t_time.tv_usec  = t->t_time.tv_usec % (1000 * 1000);
	}

	t->t_cb   = cb;
	t->t_arg  = arg;

	prev = &_state.s_timers;
	cur  = prev->t_next;

	while (cur) {
		if (time_diff(&t->t_time, &cur->t_time) >= 0) {
			t->t_next   = cur;
			cur->t_prev = t;
			break;
		}

		prev = cur;
		cur  = cur->t_next;
	}

	prev->t_next = t;
	t->t_prev    = prev;

	if (!t->t_next)
		_state.s_timers.t_prev = t;

	return t;
}

void clear_timer(void *timer)
{
	struct timer *prev = &_state.s_timers;
	struct timer *t    = prev->t_next;

	if (_conf.cf_disable_timers)
		return;

	while (t) {
		if (t == timer) {
			prev->t_next = t->t_next;

			t->t_next = _state.s_timer_free.t_next;
			_state.s_timer_free.t_next = t;
			return;
		}

		prev = t;
		t    = t->t_next;
	}

	assert(!"Timer not found");
}

static int packet_handler(void *packet, int len, int flags)
{
	int rc;

	/* XXX implement as pre packet hook */
	if (_conf.cf_accept)
		return DIVERT_ACCEPT;
	else if (_conf.cf_modify)
		return DIVERT_MODIFY;

	if (_state.s_pre_packet_hook) {
		rc = _state.s_pre_packet_hook(-1, packet, len, flags);

		if (rc != -1)
			return rc;
	}

	rc = tcpcrypt_packet(packet, len, flags);

	if (_state.s_post_packet_hook)
		return _state.s_post_packet_hook(rc, packet, len, flags);

	return rc;
}

void set_packet_hook(int post, packet_hook p)
{
	if (post)
		_state.s_post_packet_hook = p;
	else
		_state.s_pre_packet_hook  = p;
}

static void backlog_ctl(struct tcpcrypt_ctl *c, struct socket_address *sa)
{
	struct backlog_ctl *b;

	b = xmalloc(sizeof(*b) + c->tcc_dlen);
	memset(b, 0, sizeof(*b));

	memcpy(&b->bc_sa, sa, sizeof(*sa));
	memcpy(&b->bc_ctl, c, sizeof(*c));
	memcpy(b->bc_ctl.tcc_data, c->tcc_data, c->tcc_dlen);

	b->bc_next = _state.s_backlog_ctl.bc_next;
	_state.s_backlog_ctl.bc_next = b;
}

static int do_handle_ctl(struct tcpcrypt_ctl *c, struct socket_address *sa)
{
	int l, rc;

	if (c->tcc_flags & TCC_SET)
		c->tcc_err = tcpcryptd_setsockopt(c, c->tcc_opt, c->tcc_data,
					 	  c->tcc_dlen);
	else
		c->tcc_err = tcpcryptd_getsockopt(c, c->tcc_opt, c->tcc_data,
						  &c->tcc_dlen);

	/* we can either have client retry, or we queue things up.  The latter
	 * is more efficient but more painful to implement.  I'll go for the
	 * latter anyway, i'm sure nobody will mind (I'm the one coding after
	 * all).
	 */
	if (c->tcc_err == EBUSY)
		return 0;

	l = sizeof(*c) + c->tcc_dlen;
	rc = sendto(_state.s_ctl, (void*) c, l, 0, &sa->addr.sa, sa->addr_len);

	if (rc == -1)
		err(1, "sendto()");

	if (rc != l)
		errx(1, "short write");

	return 1;
}

static void backlog_ctl_process(void)
{
	struct backlog_ctl *prev = &_state.s_backlog_ctl;
	struct backlog_ctl *b = prev->bc_next;

	while (b) {
		if (do_handle_ctl(&b->bc_ctl, &b->bc_sa)) {
			struct backlog_ctl *next = b->bc_next;

			prev->bc_next = next;
			free(b);
			b = next;
		} else {
			prev = b;
			b = b->bc_next;
		}
	}
}

static void handle_ctl(int ctl)
{
	unsigned char buf[4096];
	struct tcpcrypt_ctl *c = (struct tcpcrypt_ctl*) buf;
	int rc;
	struct socket_address sa = SOCKET_ADDRESS_ANY;

	rc = recvfrom(ctl, (void*) buf, sizeof(buf), 0, &sa.addr.sa, &sa.addr_len);
	if (rc == -1)
		err(1, "read(ctl)");

	if (rc == 0)
		errx(1, "EOF");

	if (rc < sizeof(*c)) {
		xprintf(XP_ALWAYS, "fsadlfijasldkjf\n");
		return;
	}

	if (c->tcc_dlen + sizeof(*c) != rc) {
		xprintf(XP_ALWAYS, "bad len\n");
		return;
	}

	if (!do_handle_ctl(c, &sa))
		backlog_ctl(c, &sa);
}

static void dispatch_timers(void)
{
	struct timer *head = &_state.s_timers;
	struct timer *t;
	struct timer tmp;

	while ((t = head->t_next)) {
		if (time_diff(&t->t_time, get_time()) < 0)
			break;

		/* timers can add timers so lets fixup linked list first */
		tmp = *t;

		clear_timer(t);

		tmp.t_cb(tmp.t_arg);
	}
}

static void add_test(int port, int proto, int req)
{
	struct network_test *t = xmalloc(sizeof(*t));
	struct network_test *cur = &_state.s_network_tests;

	memset(t, 0, sizeof(*t));

	t->nt_port  = port;
	t->nt_proto = proto;
	t->nt_req   = req;

	while (cur->nt_next)
		cur = cur->nt_next;

	cur->nt_next = t;
}

static void test_port(int port)
{
	add_test(port, TEST_TCP, 0);
	add_test(port, TEST_TCP, 1);
	add_test(port, TEST_CRYPT, 2);
}

static void prepare_ctl(struct network_test *nt)
{
	struct sockaddr_in s_in;
	struct tcpcrypt_ctl *ctl = &nt->nt_ctl;
	int s = nt->nt_s;
	socklen_t sl = sizeof(s_in);

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family      = AF_INET;
	s_in.sin_addr.s_addr = INADDR_ANY;
	s_in.sin_port        = htons(0);

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	if (getsockname(s, (struct sockaddr*) &s_in, &sl) == -1)
		err(1, "getsockname()");

	ctl->tcc_src   = s_in.sin_addr;
	ctl->tcc_sport = s_in.sin_port;
}

#ifdef __WIN32__
static void set_nonblocking(int s)
{
	u_long mode = 1;

	ioctlsocket(s, FIONBIO, &mode);
}
#else
static void set_nonblocking(int s)
{
	int flags;

	if ((flags = fcntl(s, F_GETFL, 0)) == -1)
		err(1, "fcntl()");

	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "fcntl()");
}
#endif

static void test_connect(struct network_test *t)
{
	int s;
	struct sockaddr_in s_in;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket()");

	t->nt_s = s;

	prepare_ctl(t);

	if (t->nt_proto == TEST_TCP) {
		int off = 0;

		if (tcpcryptd_setsockopt(&t->nt_ctl, TCP_CRYPT_ENABLE, &off,
					 sizeof(off)) == -1)
			errx(1, "tcpcryptd_setsockopt()");
	} else {
		int one = 1;
		assert(t->nt_proto == TEST_CRYPT);
		if (tcpcryptd_setsockopt(&t->nt_ctl, TCP_CRYPT_NOCACHE, &one,
					 sizeof(one)) == -1)
			errx(1, "tcpcryptd_setsockopt()");
	}

	set_nonblocking(s);

	memset(&s_in, 0, sizeof(s_in));

	s_in.sin_family      = AF_INET;
	s_in.sin_port        = htons(t->nt_port);
	s_in.sin_addr        = _state.s_nt_ip;

	if (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1) {
#ifdef __WIN32__
		if (WSAGetLastError() != WSAEWOULDBLOCK)
#else
		if (errno != EINPROGRESS)
#endif
			err(1, "connect()");
	}

	t->nt_ctl.tcc_dst   = s_in.sin_addr;
	t->nt_ctl.tcc_dport = s_in.sin_port;

	t->nt_state = TEST_STATE_CONNECTING;
	t->nt_start = time(NULL);
}

static void test_finish(struct network_test *t, int rc)
{
	t->nt_last_state = t->nt_state;
	t->nt_err        = rc;
	t->nt_state      = TEST_STATE_DONE;

	close(t->nt_s);

	printf("Test result: " \
	       "port %d crypt %d req %d state %d err %d flags %d\n",
	       t->nt_port,
	       t->nt_proto == TEST_CRYPT ? 1 : 0,
	       t->nt_req,
	       t->nt_last_state,
	       t->nt_err,
	       t->nt_flags);
}

static void test_success(struct network_test *t)
{
	t->nt_state = TEST_SUCCESS;
	test_finish(t, 0);
}

static void test_connecting(struct network_test *t)
{
	int s = t->nt_s;
	struct timeval tv;
	fd_set fds;
	int rc;
	socklen_t sz = sizeof(rc);
	char *buf = NULL;
	unsigned char sid[1024];
	unsigned int sidlen = sizeof(sid);
	struct sockaddr_in s_in;
	socklen_t sl = sizeof(s_in);

	tv.tv_sec  = 0;
	tv.tv_usec = 0;

	FD_ZERO(&fds);
	FD_SET(s, &fds);

	if (select(s + 1, NULL, &fds, NULL, &tv) == -1)
		err(1, "select()");

	if (!FD_ISSET(s, &fds))
		return;

	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &rc, &sz) == -1)
		err(1, "getsockopt()");

	if (rc != 0) {
		test_finish(t, rc);
		return;
	}

	if (getsockname(s, (struct sockaddr*) &s_in, &sl) == -1)
		err(1, "getsockname()");

	t->nt_ctl.tcc_src = s_in.sin_addr;

	rc = tcpcryptd_getsockopt(&t->nt_ctl, TCP_CRYPT_SESSID, sid, &sidlen);

	if (rc == EBUSY)
		return;

	t->nt_crypt = rc != -1;

	assert(t->nt_req < (sizeof(REQS) / sizeof(*REQS)));
	buf = REQS[t->nt_req];

	if (send(s, buf, strlen(buf), 0) != strlen(buf))
		err(1, "send()");

	t->nt_state = TEST_STATE_REQ_SENT;
}

static void test_req_sent(struct network_test *t)
{
	int s = t->nt_s;
	fd_set fds;
	struct timeval tv;
	char buf[1024];
	int rc;

	FD_ZERO(&fds);
	FD_SET(s, &fds);

	tv.tv_sec  = 0;
	tv.tv_usec = 0;

	if (select(s + 1, &fds, NULL, NULL, &tv) == -1)
		err(1, "select()");

	if (!FD_ISSET(s, &fds))
		return;

	rc = recv(s, buf, sizeof(buf) - 1, 0);
	if (rc == -1) {
		test_finish(t, errno);
		return;
	}

	if (rc == 0) {
		test_finish(t, TEST_ERR_DISCONNECT);
		return;
	}

	buf[rc] = 0;

	if (strncmp(buf, TEST_REPLY, strlen(TEST_REPLY)) != 0) {
		test_finish(t, TEST_ERR_BADINPUT);
		return;
	}

	t->nt_flags = atoi(&buf[rc - 1]);

	if (t->nt_proto == TEST_TCP && t->nt_crypt == 1) {
		test_finish(t, TEST_ERR_UNEXPECTED_CRYPT);
		return;
	}

	if (t->nt_proto == TEST_CRYPT && t->nt_crypt != 1) {
		test_finish(t, TEST_ERR_NO_CRYPT);
		return;
	}

	test_success(t);
}

static void run_network_test(struct network_test *t)
{
	if (t->nt_start && (time(NULL) - t->nt_start) > 5) {
		test_finish(t, TEST_ERR_TIMEOUT);
		return;
	}

	switch (t->nt_state) {
	case TEST_STATE_START:
		test_connect(t);
		break;

	case TEST_STATE_CONNECTING:
		test_connecting(t);
		break;

	case TEST_STATE_REQ_SENT:
		test_req_sent(t);
		break;
	}
}

static int resolve_server(void)
{
	struct hostent *he = gethostbyname(_conf.cf_test_server);
	struct in_addr **addr;

	_state.s_nt_ip.s_addr = INADDR_ANY;

	if (!he)
		return 0;

	addr = (struct in_addr**) he->h_addr_list;

	if (!addr[0])
		return 0;

	_state.s_nt_ip = *addr[0];

	return 1;
}

static void test_network(void)
{
	resolve_server();

	if (_state.s_nt_ip.s_addr == INADDR_ANY) {
		xprintf(XP_ALWAYS, "Won't test network - can't resolve %s\n",
			_conf.cf_test_server);
		return;
	}

	xprintf(XP_ALWAYS, "Testing network via %s\n",
		inet_ntoa(_state.s_nt_ip));

	test_port(80);
	test_port(7777);
}

static void retest_network(void* ignored)
{
	_conf.cf_disable = 0;
	test_network();
}

static void test_results(void)
{
	struct network_test *t = _state.s_network_tests.nt_next;
	int tot = 0;
	int fail = 0;

	xprintf(XP_ALWAYS, "Tests done!");

	while (t) {
		tot++;

		if (t->nt_last_state != TEST_SUCCESS) {
			fail++;
			xprintf(XP_ALWAYS, " %d", tot);
		}

		t = t->nt_next;
	}

	if (fail) {
		unsigned long mins = 30;
		unsigned long timeout = 1000 * 1000 * 60 * mins;

		xprintf(XP_ALWAYS, " failed [%d/%d]!\n", fail, tot);

		t = _state.s_network_tests.nt_next;
		if (t->nt_last_state == TEST_SUCCESS) {
			xprintf(XP_ALWAYS,
			        "Disabling tcpcrypt for %lu minutes\n", mins);

			_conf.cf_disable = 1;
			_state.s_nt_timer = add_timer(timeout, retest_network,
					  	      NULL);
		}
	} else {
		xprintf(XP_ALWAYS, " All passed\n");
		/* XXX retest later? */
	}
}

static int run_network_tests(void)
{
	struct network_test *t = _state.s_network_tests.nt_next;

	while (t) {
		if (t->nt_state != TEST_STATE_DONE) {
			run_network_test(t);
			return 1;
		}

		t = t->nt_next;
	}

	t = _state.s_network_tests.nt_next;
	if (t) {
		test_results();

		while (t) {
			struct network_test *next = t->nt_next;
			free(t);
			t = next;
		}

		_state.s_network_tests.nt_next = NULL;
	}

	return 0;
}

static void do_cycle(void)
{
	fd_set rd, wr;
	int max = 0;
	struct timer *t;
	struct timeval tv, *tvp = NULL;
	int testing = 0;
	struct fd *fd = &_fds;

	testing = run_network_tests();

	FD_ZERO(&rd);
	FD_ZERO(&wr);

        /* prepare select */
        while (fd->fd_next) {
                struct fd *next = fd->fd_next;

                /* unlink dead sockets */
                if (next->fd_state == FD_DEAD) {
			fd->fd_next = next->fd_next;
                        free(next);
                        continue;
                }

                fd = next;

                switch (fd->fd_state) {
		case FD_IDLE:
			continue;

                case FD_WRITE:
                        FD_SET(fd->fd_fd, &wr);
                        break;

                case FD_READ:
                        FD_SET(fd->fd_fd, &rd);
                        break;
                }

                max = fd->fd_fd > max ? fd->fd_fd : max;
        }

	t = _state.s_timers.t_next;

	if (t) {
		int diff = time_diff(get_time(), &t->t_time);

		assert(diff > 0);
		tv.tv_sec  = diff / (1000 * 1000);
		tv.tv_usec = diff % (1000 * 1000);
		tvp = &tv;
	} else
		tvp = NULL;

	_state.s_time_set = 0;

	if (testing && !tvp) {
		tv.tv_sec = 0;
		tv.tv_usec = 1000;
		tvp = &tv;
	}

	if (select(max + 1, &rd, &wr, NULL, tvp) == -1) {
		if (errno == EINTR)
			return;

		err(1, "select()");
	}

	fd = &_fds;

	while ((fd = fd->fd_next)) {
		if (fd->fd_state == FD_READ && FD_ISSET(fd->fd_fd, &rd))
			fd->fd_cb(fd);

		if (fd->fd_state == FD_WRITE && FD_ISSET(fd->fd_fd, &wr))
			fd->fd_cb(fd);
	}

	dispatch_timers();

	if (_divert->cycle)
		_divert->cycle();
}

static void do_test(void)
{
	struct test *t;

	if (_conf.cf_test < 0 
	    || _conf.cf_test >= sizeof(_tests) / sizeof(*_tests))
		errx(1, "Test %d out of range", _conf.cf_test);

	t = &_tests[_conf.cf_test];

	printf("Running test %d: %s\n", _conf.cf_test, t->t_desc);
	t->t_cb();
	printf("Test done\n");
}

static int bind_control_socket(struct socket_address *sa, const char *descr)
{
	int r, s;
	static const int error_len = 1000;
	char error[error_len];
	mode_t mask;
	const char *path;

	r = resolve_socket_address_local(_conf.cf_ctl, sa, error, error_len);
	if (r != 0)
		errx(1, "interpreting socket address '%s': %s", descr, error);
	{
		char name[1000];
		socket_address_pretty(name, 1000, sa);
		xprintf(XP_DEFAULT, "Opening control socket at %s\n", name);
	}

	if ((s = socket(sa->addr.sa.sa_family, SOCK_DGRAM, 0)) <= 0)
		err(1, "socket()");

	ensure_socket_address_unlinked(sa);
	mask = umask(0);
	if (bind(s, &sa->addr.sa, sa->addr_len) != 0)
		err(1, "bind()");
	umask(mask);

	/* in case of old systems where bind() ignores the umask: */
	if ((path = socket_address_pathname(sa)) != NULL) {
		if (chmod(path, 0777) != 0)
			warnx("Setting permissions on control socket");
	}

	return s;
}

void _drop_privs(const char *dir, const char *name) {
	xprintf(XP_DEFAULT, "Attempting to drop privileges with chroot=%s and user=%s\n",
		dir ? dir : "(NONE)", name ? name : "(NONE)");
	drop_privs(dir, name);
}

struct fd *add_fd(int f, fd_cb cb)
{
	struct fd *fd = xmalloc(sizeof(*fd));

	memset(fd, 0, sizeof(*fd));

	fd->fd_fd    = f;
	fd->fd_cb    = cb;
	fd->fd_state = FD_READ;
	fd->fd_next  = _fds.fd_next;
	_fds.fd_next = fd;

	return fd;
}

static void process_divert(struct fd *fd)
{
	_divert->next_packet(fd->fd_fd);
	backlog_ctl_process();
}

static void process_ctl(struct fd *fd)
{
	handle_ctl(fd->fd_fd);
}

void tcpcryptd(void)
{
	_divert = divert_get();
	assert(_divert);

	_state.s_divert = _divert->open(_conf.cf_divert, packet_handler);

	_state.s_ctl = bind_control_socket(&_state.s_ctl_addr, _conf.cf_ctl);

	_drop_privs(_conf.cf_jail_dir, _conf.cf_jail_user);

	printf("Running\n");

	if (!_conf.cf_disable && !_conf.cf_disable_network_test)
		test_network();

	add_fd(_state.s_divert, process_divert);
	add_fd(_state.s_ctl, process_ctl);

	while (1)
		do_cycle();
}

static void do_set_preference(int id, int type)
{
	if (!id)
		return;

	assert(!"implement");
}

static void setup_tcpcrypt(void)
{
	struct cipher_list *c;

	/* set cipher preference */
	do_set_preference(_conf.cf_cipher, TYPE_SYM);

	/* add ciphers */
	c = crypt_cipher_list();

	while (c) {
		tcpcrypt_register_cipher(c);

		c = c->c_next;
	}

	/* setup */
	tcpcrypt_init();
}

static void pwn(void)
{
	printf("Initializing...\n");
	setup_tcpcrypt();

	if (_conf.cf_test != -1)
		do_test();
	else
		tcpcryptd();
}

void xprintf(int level, char *fmt, ...)
{
	va_list ap;

	if (_conf.cf_verbose < level)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

void hexdump(void *x, int len)
{
	uint8_t *p = x;
	int did = 0;
	int level = XP_ALWAYS;

	xprintf(level, "Dumping %d bytes\n", len);
	while (len--) {
		xprintf(level, "%.2X ", *p++);

		if (++did == 16) {
			if (len)
				xprintf(level, "\n");

			did = 0;
		}
	}

	xprintf(level, "\n");
}

void errssl(int x, char *fmt, ...)
{       
        va_list ap;

        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);

        printf(": %s\n", ERR_error_string(ERR_get_error(), NULL));
        exit(1);
}

static void add_param(struct params *p, char *optarg)
{
	if (p->p_paramc >= ARRAY_SIZE(p->p_params))
		errx(1, "too many parameters\n");

	p->p_params[p->p_paramc++] = optarg;
}

static char *get_param(struct params *p, int idx)
{
	if (idx >= p->p_paramc)
		return NULL;

	return p->p_params[idx];
}

uint64_t xbe64toh(uint64_t x)
{       
        return ntohl(x); /* XXX */
}

uint64_t xhtobe64(uint64_t x)
{       
        return htonl(x); /* XXX */
}

char *driver_param(int idx)
{
	return get_param(&_conf.cf_divert_params, idx);
}

char *test_param(int idx)
{
	return get_param(&_conf.cf_test_params, idx);
}

static void usage(char *prog)
{
	int i;

	printf("Usage: %s <opt>\n"
	       "-h\thelp (or --help)\n"
	       "-p\t<divert port> (default: %d)\n"
	       "-v\tverbose\n"
	       "-d\tdisable\n"
	       "-c\tno cache\n"
	       "-a\tdivert accept (NOP)\n"
	       "-m\tdivert modify (NOP)\n"
	       "-u\t<local control socket> (default: " TCPCRYPTD_CONTROL_SOCKET ")\n"
	       "-n\tno crypto\n"
	       "-P\tprofile\n"
	       "-S\tprofile time source (0 TSC, 1 gettimeofday)\n"
	       "-t\t<test>\n"
	       "-T\t<test param>\n"
	       "-D\tdebug\n"
	       "-x\t<divert driver param>\n"
	       "-N\trun as nat / middlebox\n"
	       "-C\t<preferred cipher>\n"
	       "-M\t<preferred MAC>\n"
	       "-r\t<random device>\n"
	       "-R\tRSA client hack\n"
	       "-i\tdisable timers\n"
	       "-f\tdisable network test\n"
	       "-s\t<network test server> (default: " TCPCRYPTD_TEST_SERVER ")\n"
	       "-V\tshow version (or --version)\n"
	       "-U\t<jail username> (default: " TCPCRYPTD_JAIL_USER ")\n"
	       "-J\t<jail directory> (default: " TCPCRYPTD_JAIL_DIR ")\n"
	       "-e\tredirect\n"
	       , prog, TCPCRYPTD_DIVERT_PORT);

	printf("\nTests:\n");
	for (i = 0; i < sizeof(_tests) / sizeof(*_tests); i++)
		printf("%d) %s\n", i, _tests[i].t_desc);
}

int main(int argc, char *argv[])
{
	int ch;

#ifdef __WIN32__
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(1,1), &wsadata) == SOCKET_ERROR)
		errx(1, "WSAStartup()");
#endif

	_conf.cf_divert	     = TCPCRYPTD_DIVERT_PORT;
	_conf.cf_ctl  	     = TCPCRYPTD_CONTROL_SOCKET;
	_conf.cf_test 	     = -1;
	_conf.cf_test_server = TCPCRYPTD_TEST_SERVER;
	_conf.cf_jail_dir    = TCPCRYPTD_JAIL_DIR;
	_conf.cf_jail_user   = TCPCRYPTD_JAIL_USER;

	if (argc == 2 && argv[1][0] == '-' && argv[1][1] == '-') {
		if (strcmp(argv[1], "--help") == 0) {
			usage(argv[0]);
			exit(0);
		} else if (strcmp(argv[1], "--version") == 0) {
			printf("tcpcrypt version %s\n", TCPCRYPT_VERSION);
			exit(0);
		} else {
			usage(argv[0]);
			exit(1);
		}			
	}

	while ((ch = getopt(argc, argv, "hp:vdu:camnPt:T:S:Dx:NC:M:r:Rifs:VU:J:e"))
	       != -1) {
		switch (ch) {
		case 'e':
			_conf.cf_rdr = 1;
			break;

		case 'i':
			_conf.cf_disable_timers = 1;
			break;

		case 'r':
			_conf.cf_random_path = optarg;
			break;

		case 'R':
			_conf.cf_rsa_client_hack = 1;
			break;

		case 'M':
			_conf.cf_mac = atoi(optarg);
			break;

		case 'C':
			_conf.cf_cipher = atoi(optarg);
			break;

		case 'N':
			_conf.cf_nat = 1;
			break;

		case 'D':
			_conf.cf_debug = 1;
			break;

		case 'S':
			profile_setopt(PROFILE_TIME_SOURCE, atoi(optarg));
			break;

		case 'x':
			add_param(&_conf.cf_divert_params, optarg);
			break;

		case 'T':
			add_param(&_conf.cf_test_params, optarg);
			break;

		case 't':
			_conf.cf_test = atoi(optarg);
			break;

		case 'P':
			_conf.cf_profile++;
			break;

		case 'n':
			_conf.cf_dummy = 1;
			break;

		case 'a':
			_conf.cf_accept = 1;
			break;

		case 'm':
			_conf.cf_modify = 1;
			break;

		case 'c':
			_conf.cf_nocache = 1;
			break;

		case 'u':
			_conf.cf_ctl = optarg;
			break;

		case 'd':
			_conf.cf_disable = 1;
			break;

		case 'p':
			_conf.cf_divert = atoi(optarg);
			break;

		case 'v':
			_conf.cf_verbose++;
			break;

		case 'V':
			printf("tcpcrypt version %s\n", TCPCRYPT_VERSION);
			exit(0);

		case 'f':
			_conf.cf_disable_network_test = 1;
			break;

		case 's':
			_conf.cf_test_server = optarg;
			break;

		case 'U':
			_conf.cf_jail_user = optarg;
			break;

		case 'J':
			_conf.cf_jail_dir = optarg;
			break;

		case 'h':
			usage(argv[0]);
			exit(0);
			break;

		default:
			usage(argv[0]);
			exit(1);
			break;
		}
	}

	resolve_server();

	if (signal(SIGINT, sig) == SIG_ERR)
		err(1, "signal(SIGINT)");

	if (signal(SIGTERM, sig) == SIG_ERR)
		err(1, "signal(SIGTERM)");
#ifndef __WIN32__
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		err(1, "signal(SIGPIPE)");
#endif
	profile_setopt(PROFILE_DISCARD, 3);
	profile_setopt(PROFILE_ENABLE, _conf.cf_profile);

	pwn();
	cleanup();

	exit(0);
}
