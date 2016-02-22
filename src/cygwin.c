#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include "inc.h"
#include "tcpcrypt_divert.h"
#include "tcpcryptd.h"
#include "tcpcrypt.h"
#include "checksum.h"
#include "util.h"

#include <windivert.h>

#define MAC_SIZE 14

static int	  _s;
static divert_cb _cb;

struct packet {
	unsigned char p_buf[2048];
	int	      p_len;
	struct packet *p_next;
} _outbound;

enum {
	STATE_NONE = 0,
	STATE_REDIRECT,
	STATE_HANDSHAKE,
	STATE_CONNECTED
};

#define CONN_TIMEOUT 15

static struct conmap {
	struct sockaddr_in	src;
	struct sockaddr_in	dst;
	int			state;
	time_t			dead;
	struct conmap		*next;
} _cons;

static struct in_addr _local_ip;

extern int do_divert_open(void);
extern int do_divert_read(int s, void *buf, int len);
extern int do_divert_write(int s, void *buf, int len);
extern void do_divert_close(int s);

static int divert_open(int port, divert_cb cb)
{
	int s;
	struct sockaddr_in s_in;
	socklen_t len = sizeof(s_in);

	_s  = do_divert_open();
	_cb = cb;

	/* figure out local IP */
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket()");

	memset(&s_in, 0, sizeof(&s_in));
	s_in.sin_family      = PF_INET;
	s_in.sin_addr.s_addr = inet_addr("8.8.8.8");
	s_in.sin_port        = htons(666);

	if (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "connect()");

	if (getsockname(s, (struct sockaddr*) &s_in, &len) == -1)
		err(1, "getsockname()");

	_local_ip.s_addr = s_in.sin_addr.s_addr;

	xprintf(XP_ALWAYS, "Local IP is %s\n", inet_ntoa(_local_ip));

	close(s);

	return _s;
}

static void divert_close(void)
{
	do_divert_close(_s);
}

static void do_redirect(struct conmap *c,
			struct ip *ip, struct tcphdr *tcp,
			struct in_addr *fromip, uint32_t toip,
			uint16_t *fromport, uint16_t toport)
{
#if 0
	xprintf(XP_NOISY, "rdr %s:%d->",
		inet_ntoa(*fromip), ntohs(*fromport));
#endif
	fromip->s_addr = toip;
	*fromport      = htons(toport);

	checksum_packet(NULL, ip, tcp);
#if 0
	xprintf(XP_NOISY,"%s:%d\n",
		inet_ntoa(*fromip), ntohs(*fromport));
#endif

	if (tcp->th_flags & (TH_RST | TH_FIN)) {
		c->dead = time(NULL);
	}
}

static struct conmap *find_conmap_prev(int sport)
{
	struct conmap *c = &_cons;

	while (c->next) {
		if (c->next->src.sin_port == sport)
			return c;

		c = c->next;
	}

	return NULL;
}

static struct conmap *find_conmap(int sport)
{
	struct conmap *c = find_conmap_prev(sport);

	if (!c)
		return NULL;

	return c->next;
}

static struct conmap *redirect(struct ip *ip, int len, int flags)
{
	struct tcphdr *tcp = get_tcp(ip);

	if (ntohs(tcp->th_dport) == 80) {
		struct conmap *c = find_conmap(tcp->th_sport);

		if (!c && (tcp->th_flags == TH_SYN)) {
			c = xmalloc(sizeof(*c));
			memset(c, 0, sizeof(*c));

			c->src.sin_port = tcp->th_sport;
			c->state        = STATE_REDIRECT;

			c->next     = _cons.next;
			_cons.next  = c;
		}

		/* not redirecting */
		if (!c)
			return NULL;

		/* don't redirect outbound handshake but divert it */
		if (c->state == STATE_HANDSHAKE)
			return c;

		if (c->state != STATE_REDIRECT)
			return NULL;

		if (tcp->th_flags == TH_SYN)
			c->dead = 0;

		c->dst.sin_addr.s_addr = ip->ip_dst.s_addr;

		do_redirect(c, ip, tcp,
			    &ip->ip_dst, _local_ip.s_addr,
			    &tcp->th_dport, REDIRECT_PORT);

	} else if (ntohs(tcp->th_sport) == REDIRECT_PORT) {
		struct conmap *c = find_conmap(tcp->th_dport);

		if (!c || c->state != STATE_REDIRECT)
			return NULL;

		do_redirect(c, ip, tcp,
			    &ip->ip_src, c->dst.sin_addr.s_addr,
			    &tcp->th_sport, 80);
	}

	return NULL;
}

static void print_con(void)
{
	struct conmap *c = &_cons;

	printf("Dumping con\n");

	while ((c = c->next)) {
		printf("con %s:%d ", 
		       inet_ntoa(c->src.sin_addr),
		       ntohs(c->src.sin_port));

		printf("->%s:%d %d [dead %u]\n", 
		       inet_ntoa(c->dst.sin_addr),
		       ntohs(c->dst.sin_port),
		       c->state,
		       c->dead);
	}
}

static void kill_dead(void)
{
	time_t now = time(NULL);
	struct conmap *prev = &_cons, *cur;

	while ((cur = prev->next)) {
		if (cur->dead && (now - cur->dead) >= CONN_TIMEOUT) {
			prev->next = cur->next;
			free(cur);
			continue;
		}

		prev = cur;
	}
}

static int firewall_divert(struct ip *ip, int len, int flags)
{
	struct tcphdr *tcp = get_tcp(ip);
	struct conmap *c;

	kill_dead();
//	print_con();

	c = redirect(ip, len, flags);

	/* don't firewall our injections */
	if (ip->ip_tos == INJECT_TOS) {
		ip->ip_tos = 0;
		checksum_ip(ip);
		return 0;
	}

	/* stuff we didn't redirect, so it's going to the outside world */
	if (c) {
		/* divert syns */
		if (tcp->th_flags == TH_SYN)
			c->state = STATE_HANDSHAKE;

		/* XXX assume it's ACK of 3 way handshake.  Won't work with
		 * retransmits */
		if (!(tcp->th_flags & TH_SYN)) {
			if (c->state == STATE_HANDSHAKE) {
//				c->state = STATE_CONNECTED;
				return 1;
			}
		}
	}

	/* divert handshake */
	if (tcp->th_flags & TH_SYN)
		return 1;

	return 0;
}

static void do_divert_next_packet(unsigned char *buf, int rc)
{
	int verdict = DIVERT_MODIFY;
	int flags = 0;
	struct ip *iph = (struct ip*) &buf[MAC_SIZE];
	int len;
	PDIVERT_ADDRESS addr = (PDIVERT_ADDRESS)buf;

	if (rc < MAC_SIZE)
		errx(1, "short read %d", rc);

	if (addr->Direction == WINDIVERT_DIRECTION_INBOUND)
		flags |= DF_IN;

	// XXX ethernet padding on short packets?  (46 byte minimum)
	len = rc - MAC_SIZE;
	if (len > ntohs(iph->ip_len)) {
		xprintf(XP_ALWAYS, "Trimming from %d to %d\n",
			len, ntohs(iph->ip_len));

		len = ntohs(iph->ip_len);
	}

	if (firewall_divert(iph, len, flags))
		verdict = _cb(iph, len, flags);

	switch (verdict) {
	case DIVERT_MODIFY:
		rc = ntohs(iph->ip_len) + MAC_SIZE;
		/* fallthrough */
	case DIVERT_ACCEPT:
		flags = do_divert_write(_s, buf, rc);
		if (flags == -1)
			err(1, "write()");

		if (flags != rc)
			errx(1, "wrote %d/%d", flags, rc);
		break;

	case DIVERT_DROP:
		break;

	default:
		abort();
		break;
	}
}

static void divert_next_packet(int s)
{
	unsigned char buf[2048];
	int rc;

	rc = do_divert_read(_s, buf, sizeof(buf));
	if (rc == -1)
		err(1, "read()");

	if (rc == 0)
		errx(1, "EOF");

	do_divert_next_packet(buf, rc);
}

static void divert_inject(void *data, int len)
{
	struct packet *p, *p2;
	struct ip *ip;

	p = malloc(sizeof(*p));
	if (!p)
		err(1, "malloc()");

	memset(p, 0, sizeof(*p));

	// XXX: for divert, we can just zero the ethhdr, which contains the
	//      DIVERT_ADDRESS.  A zeroed address usually gives the desired
	//      result.

	/* payload */
	p->p_len = len + MAC_SIZE;

	if (p->p_len > sizeof(p->p_buf))
		errx(1, "too big (divert_inject)");

	memcpy(&p->p_buf[MAC_SIZE], data, len);

	/* Keep TOS signaling consistent */
	ip = (struct ip*) &p->p_buf[MAC_SIZE];
	ip->ip_tos = INJECT_TOS;
	checksum_ip(ip);

	/* add to list */
	p2 = &_outbound;

	if (p2->p_next)
		p2 = p2->p_next;

	p2->p_next = p;
}

static void divert_cycle(void)
{
	struct packet *p = _outbound.p_next;

	while (p) {
		struct packet *next = p->p_next;

		do_divert_next_packet(p->p_buf, p->p_len);

		free(p);

		p = next;
	}

	_outbound.p_next = NULL;
}

static int divert_orig_dest(struct sockaddr_in *out, struct ip *ip, int *flags)
{
	struct tcphdr *tcp = get_tcp(ip);
	struct conmap *c = find_conmap(tcp->th_sport);

	if (!c || c->state != STATE_REDIRECT)
		return -1;

	memset(out, 0, sizeof(*out));

	out->sin_family      = PF_INET;
	out->sin_addr.s_addr = c->dst.sin_addr.s_addr;
	out->sin_port        = htons(80);

	return 0;
}

void win_dont_rdr(int s)
{
	struct sockaddr_in s_in;
	struct conmap *c;
	socklen_t len = sizeof(s_in);

	if (getsockname(s, (struct sockaddr*) &s_in, &len) == -1)
		err(1, "getsockname()");

	c = find_conmap(s_in.sin_port);
	if (c) {
		printf("XXX TODO\n");
		return;
	}

	c = xmalloc(sizeof(*c));
	memset(c, 0, sizeof(*c));

	c->src.sin_port = s_in.sin_port;
	c->state        = STATE_HANDSHAKE;

	c->next      = _cons.next;
	_cons.next = c;

	xprintf(XP_NOISY, "No RDR on %d\n", ntohs(c->src.sin_port));
}

void win_handshake_complete(int s)
{
	struct sockaddr_in s_in;
	struct conmap *c, *con;
	socklen_t len = sizeof(s_in);

	if (getsockname(s, (struct sockaddr*) &s_in, &len) == -1)
		err(1, "getsockname()");

	if (!(c = find_conmap_prev(s_in.sin_port))) {
		printf("XXX TODO 222\n");
		return;
	}
	con = c->next;

	if (con->state != STATE_HANDSHAKE) {
		printf("DDDD TODO\n");
		return;
	}

	c->next = con->next;
	free(con);
}

uint32_t win_local_ip(void)
{
	return _local_ip.s_addr;
}

struct divert *divert_get(void)
{
        static struct divert _divert_win = {
                .open           = divert_open,
                .next_packet    = divert_next_packet,
                .close          = divert_close,
                .inject         = divert_inject,
		.cycle		= divert_cycle,
		.orig_dest      = divert_orig_dest,
        };

        return &_divert_win;
}
