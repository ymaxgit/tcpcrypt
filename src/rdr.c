/*
 * General strategy:
 *
 * a) Use firewall redirect to change TCP payload - like a transparent proxy.
 *
 * b) Use firewall to edit SYN packets.  Redirect them to a blackhole, snoop
 *    them, and reinject a modified version
 *
 * c) Delay SYN/SYN-ACKs of firewall redirect so that connection doesn't succeed
 *    if other end sends us RST.  (Instead of us accepting and closing the
 *    connection.)
 *
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <pcap/pcap.h>

#define REDIRECT_PORT 65530

extern int pcap_set_want_pktap(pcap_t *, int);

struct sock;
typedef void (*sock_handler)(struct sock *s);

struct tcp_ph {
        struct in_addr  ph_src;
        struct in_addr  ph_dst;
        uint8_t         ph_zero;
        uint8_t         ph_proto;
        uint16_t        ph_len;
};

/* from tcpdump */
typedef struct pktap_header {
        uint32_t        pkt_len;        /* length of pktap header */
        uint32_t        pkt_rectype;    /* type of record */
        uint32_t        pkt_dlt;        /* DLT type of this packet */
        char            pkt_ifname[24]; /* interface name */
        uint32_t        pkt_flags;
        uint32_t        pkt_pfamily;    /* "protocol family" */
        uint32_t        pkt_llhdrlen;   /* link-layer header length? */
        uint32_t        pkt_lltrlrlen;  /* link-layer trailer length? */
        uint32_t        pkt_pid;        /* process ID */
        char            pkt_cmdname[20]; /* command name */
        uint32_t        pkt_svc_class;  /* "service class" */
        uint16_t        pkt_iftype;     /* "interface type" */
        uint16_t        pkt_ifunit;     /* unit number of interface? */
        uint32_t        pkt_epid;       /* "effective process ID" */
        char            pkt_ecmdname[20]; /* "effective command name" */
} pktap_header_t;

enum {
	STATE_IDLE = 0,
	STATE_CONNECT,
	STATE_READY,
	STATE_DEAD
};

static struct sock {
	int			s;
	sock_handler		handler;
	struct sockaddr_in	from;
	struct sockaddr_in	to;
	int			state;
	struct sock		*peer;
	pcap_t			*pcap;
	unsigned char		buf[2048];
	int			len;
	int			local;
	int			need_eno_ack;
	struct sock		*next;
} socks_;

static int outs_;
static pcap_t *outp_;

static void *xmalloc(size_t len)
{
	void *x = malloc(len);

	if (!x)
		err(1, "malloc()");

	memset(x, 0, len);

	return x;
}

static struct sock *add_sock(int s, sock_handler handler)
{
	struct sock *sock = xmalloc(sizeof(*sock));

	sock->s       = s;
	sock->handler = handler;
	sock->next    = socks_.next;
	sock->state   = STATE_READY;
	socks_.next   = sock;

	return sock;
}

static void kill_sock(struct sock *sock)
{
	if (sock->peer) {
		assert(sock->peer->peer == sock);
		sock->peer->peer = NULL;
		kill_sock(sock->peer);
	}

	close(sock->s);
	sock->state = STATE_DEAD;
}

static void proxy_connection(struct sock *sock)
{
	unsigned char buf[4096];
	int rc;

	if ((rc = read(sock->s, buf, sizeof(buf))) <= 0) {
		kill_sock(sock);
		return;
	}

	printf("PROXY read %d\n", rc);

	/* XXX assuming non-blocking write */
	if (write(sock->peer->s, buf, rc) != rc) {
		kill_sock(sock);
		return;
	}
}

static void local_handler(struct sock *sock)
{
	proxy_connection(sock);
}

#if 0
static int get_dest_pf(struct sock *sock)
{
	char buf[1024];
	FILE *f;
	int rc;
	char *p;

	snprintf(buf, sizeof(buf),
		 "sudo pfctl -ss 2> /dev/null"
		 "| grep ESTABLISHED:ESTABLISHED"
		 "| grep '<- %s:%d'"
		 "| awk -F '<- ' '{print $2}'",
		 inet_ntoa(sock->from.sin_addr), ntohs(sock->from.sin_port));

	if (!(f = popen(buf, "r")))
		err(1, "popen()");

	rc = fread(buf, 1, sizeof(buf) - 1, f);

	pclose(f);

	if (rc <= 1)
		return -1;

	buf[rc - 1] = 0;

	if (!(p = strchr(buf, ':')))
		return -1;

	*p++ = 0;

	if (!inet_aton(buf, &sock->to.sin_addr))
		return -1;

	if ((sock->to.sin_port = htons(atoi(p))) == 0)
		return -1;

	sock->to.sin_family = PF_INET;

	return 0;
}
#endif

struct tcphdr *get_tcp(struct ip *ip)
{
	return (struct tcphdr*) ((unsigned long) ip + ip->ip_hl * 4);
}

static char *ip_tuple(struct ip *ip)
{
	static char crap[1024];
	char ipaddr[17];
	struct tcphdr *tcp = get_tcp(ip);

	snprintf(ipaddr, sizeof(ipaddr), "%s", inet_ntoa(ip->ip_src));

	snprintf(crap, sizeof(crap), "%s:%d -> %s:%d",
		 ipaddr, ntohs(tcp->th_sport),
		 inet_ntoa(ip->ip_dst),
		 ntohs(tcp->th_dport));

	return crap;
}

static void inject(struct ip *ip, struct tcphdr *tcp)
{
	int rc;
	int len = ntohs(ip->ip_len);
	struct sockaddr_in s_in;

	ip->ip_len = ntohs(ip->ip_len);
	ip->ip_off = ntohs(ip->ip_off);
	ip->ip_tos = 0x22;
	ip->ip_id = htons(666);

	memset(&s_in, 0, sizeof(s_in));

	s_in.sin_family      = PF_INET;
	s_in.sin_port        = ntohs(tcp->th_dport);
	s_in.sin_addr.s_addr = ip->ip_dst.s_addr;

	printf("INJECTING %s\n", ip_tuple(ip));

	rc = sendto(outs_, ip, len, 0, (struct sockaddr*) &s_in, sizeof(s_in));

	if (rc != len)
		err(1, "sendto()");
}

static void inject_ip(struct ip *ip)
{
	return inject(ip, get_tcp(ip));
}


static unsigned short in_cksum(struct tcp_ph *ph, unsigned short *ptr,
                               int nbytes, int s)
{
  register long sum;
  u_short oddbyte; 
  register u_short answer;
 
  sum = s;
 
  if (ph) {
        unsigned short *p = (unsigned short*) ph;
        int i;

        for (i = 0; i < sizeof(*ph) >> 1; i++)
                sum += *p++;
  }
 
  while (nbytes > 1)
    {
      sum += *ptr++;
      nbytes -= 2; 
    }
 
  if (nbytes == 1)
    { 
      oddbyte = 0;
      *((u_char *) & oddbyte) = *(u_char *) ptr;
      sum += oddbyte;
    }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

static void checksum_ip(struct ip *ip)
{
        ip->ip_sum = 0;
        ip->ip_sum = in_cksum(NULL, (unsigned short*) ip, sizeof(*ip), 0);
}

static void checksum_tcp(struct ip *ip, struct tcphdr *tcp, int sum)
{
        struct tcp_ph ph;
        int len;

        len = ntohs(ip->ip_len) - (ip->ip_hl << 2);

        ph.ph_src   = ip->ip_src;
        ph.ph_dst   = ip->ip_dst;
        ph.ph_zero  = 0;
        ph.ph_proto = ip->ip_p;
        ph.ph_len   = htons(len);

        if (sum != 0)
                len = tcp->th_off << 2;

        tcp->th_sum = 0;
        tcp->th_sum = in_cksum(&ph, (unsigned short*) tcp, len, sum);
}

static void checksum_packet(struct ip *ip)
{
	checksum_ip(ip);
	checksum_tcp(ip, get_tcp(ip), 0);
}

static void send_rst(struct sock *sock)
{
	struct ip *ip = (struct ip*) sock->buf;
	struct tcphdr *tcp = (struct tcphdr*) get_tcp(ip);
	struct in_addr addr;
	int port;

	addr.s_addr = ip->ip_src.s_addr;
	ip->ip_src.s_addr = ip->ip_dst.s_addr;
	ip->ip_dst.s_addr = addr.s_addr;

	port = tcp->th_sport;
	tcp->th_sport = tcp->th_dport;
	tcp->th_dport = port;

	tcp->th_flags = TH_RST | TH_ACK;
	tcp->th_ack   = htonl(ntohl(tcp->th_seq) + 1);
	tcp->th_seq   = htonl(0);

	checksum_ip(ip);
	checksum_tcp(ip, tcp, 0);	
printf("SENDING RST\n");
	inject(ip, tcp);
}

static void check_connect(struct sock *sock)
{
	int e;
	socklen_t len = sizeof(e);
        int tos = 0;

	if (getsockopt(sock->s, SOL_SOCKET, SO_ERROR, &e, &len) == -1) {
		perror("getsockopt()");
		kill_sock(sock);
		return;
	}

	if (e != 0) {
		if (e == ECONNREFUSED)
			send_rst(sock);

		kill_sock(sock);
		return;
	}

	/* XXX we should set this only when we receive traffic from other end.
	 * Else our pakcet might have been lost and retransmitted without ENO
	 */
        if (setsockopt(sock->s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) {
            perror("getsockopt(IP_TOS)");
            kill_sock(sock);
            return;
        }

	printf("I CONNECTED BRO\n");

	sock->state = STATE_IDLE;

	/* inject the local SYN so that user connects to proxy */
	if (sock->local) {
		/* we need to manually redirect... */
		struct ip *ip = (struct ip*) sock->buf;
		struct tcphdr *tcp = get_tcp(ip);

		ip->ip_dst.s_addr = inet_addr("127.0.0.1");
		tcp->th_dport = htons(REDIRECT_PORT);
		checksum_packet(ip);
	}

	inject_ip((struct ip*) sock->buf);
}

static void remote_handler(struct sock *sock)
{
	if (sock->state == STATE_CONNECT) {
		check_connect(sock);
		return;
	}

	proxy_connection(sock);
}

static void print_sock(struct sock *s)
{
	printf("SOCK %s:%d",
	       inet_ntoa(s->from.sin_addr), ntohs(s->from.sin_port));

	printf(" -> %s:%d sock %d state %d local %d\n",
	       inet_ntoa(s->to.sin_addr), ntohs(s->to.sin_port),
	       s->s, s->state, s->local);
}

static void dump_socks(void)
{
	struct sock *s = &socks_;

	printf("Starting dump socks\n");

	while ((s = s->next))
		print_sock(s);

	printf("====================\n");
}

static void redirect_listen_handler(struct sock *sock)
{
	struct sock *s = &socks_;
	struct sockaddr_in s_in;
	socklen_t len = sizeof(s_in);

	/* Accept redirected connection */
	int dude = accept(sock->s, (struct sockaddr*) &s_in, &len);

	printf("REDIRECT connection from %s:%d\n",
	       inet_ntoa(s_in.sin_addr), ntohs(s_in.sin_port));

	dump_socks();

	if (dude == -1) {
		printf("accept() failed\n");
		return;
	}

	/* try to find him */
	while ((s = s->next)) {
		if (s->peer && s->peer->from.sin_port == s_in.sin_port
		    && s->peer->from.sin_addr.s_addr == s_in.sin_addr.s_addr)
			break;
	}

	if (!s) {
		printf("Couldn't find dude\n");
		close(dude);
		return;
	}

	s = s->peer;

	/* setup socket */
	s->s        = dude;
	s->handler  = local_handler;
	s->state    = STATE_READY;

	if (s->peer->state == STATE_IDLE)
		s->peer->state = STATE_READY;

	printf("Connection %s:%d",
	       inet_ntoa(s->from.sin_addr), ntohs(s->from.sin_port));

	printf(" -> %s:%d\n",
	       inet_ntoa(s->to.sin_addr), ntohs(s->to.sin_port));
}

#if 0
static void hexdump(void *x, int len)
{
	unsigned char *a = x;

	while (len--)
		printf("%.2x ", *a++);

	printf("\n");
}
#endif

static void add_connection(struct ip *ip, struct tcphdr *tcp, int local)
{
	struct sockaddr_in from, to;
	int s, flags, rc;
	struct sock *sock, *peer;
	socklen_t len;
        int tos = IPTOS_RELIABILITY;

	/* figure out where connection is going to */
	memset(&to, 0, sizeof(to));
	memset(&from, 0, sizeof(from));

	from.sin_family = to.sin_family = PF_INET;

	from.sin_port        = tcp->th_sport;
	from.sin_addr.s_addr = ip->ip_src.s_addr;

	to.sin_port	     = tcp->th_dport;
	to.sin_addr.s_addr   = ip->ip_dst.s_addr;

	/* connect to destination */
	if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		err(1, "socket()");

	sock = add_sock(s, remote_handler);
	sock->state = STATE_CONNECT;

	memcpy(&sock->to, &to, sizeof(to));

	/* XXX bypass firewall */
	if (local) {
		sock->to.sin_addr.s_addr = inet_addr("127.0.0.1");
		sock->local = 1;
	}

	if ((flags = fcntl(s, F_GETFL)) == -1)
		err(1, "fcntl()");

	flags |= O_NONBLOCK;

	if (fcntl(s, F_SETFL, flags) == -1)
		err(1, "fcntl()");

        if (setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1)
            err(1, "setsockopt()");

	sock->need_eno_ack = 1;

	rc = connect(s, (struct sockaddr*) &sock->to, sizeof(sock->to));
	if (rc == -1 && errno != EINPROGRESS)
		kill_sock(sock);

	len = sizeof(sock->from);

	if (getsockname(s, (struct sockaddr*) &sock->from, &len) == -1)
		err(1, "getsockname()");

	printf("Adding a connection %s:%d",
	       inet_ntoa(sock->from.sin_addr), ntohs(sock->from.sin_port));

	printf("-> %s:%d\n",
	       inet_ntoa(sock->to.sin_addr), ntohs(sock->to.sin_port));

	/* save SYN to replay once connection is successful */
	len = ntohs(ip->ip_len);
	assert(len < sizeof(sock->buf));

	memcpy(sock->buf, ip, len);
	sock->len = len;

	/* create placeholder peer */
	peer = xmalloc(sizeof(*peer));

	memcpy(&peer->to, &to, sizeof(peer->to));
	memcpy(&peer->from, &from, sizeof(peer->from));

	peer->s     = -1;
	peer->state = STATE_IDLE;
	peer->local = sock->local;

	peer->peer  = sock;
	sock->peer  = peer;
	peer->next  = socks_.next;
	socks_.next = peer;
}

static void modify_syn(struct sock *s, struct ip *ip, struct tcphdr *tcp)
{
	/* Already done */
	if (ip->ip_tos == 0x22)
		return;

	printf("MODIFY SYN\n");

	inject(ip, tcp);
}

static void send_syn_ack(struct sock *s, struct ip *ip, struct tcphdr *tcp)
{
	unsigned char buf[2049];
	int len = ntohs(ip->ip_len);

	printf("Sending SYN ACK\n");

	assert(len < sizeof(buf));

	memcpy(buf, ip, len);

	ip  = (struct ip *) buf;
	tcp = get_tcp(ip);

	ip->ip_src.s_addr = s->to.sin_addr.s_addr;
	tcp->th_sport     = s->to.sin_port;

	checksum_packet(ip);

	inject_ip(ip);
}

static void handle_syn_ack(struct ip *ip, struct tcphdr *tcp)
{
	struct sock *s = &socks_;

	/* need to add eno option to outgoing syn ack */
	while ((s = s->next)) {
		if (ntohs(tcp->th_sport) == REDIRECT_PORT
		    && ip->ip_src.s_addr == inet_addr("127.0.0.1")
		    && ip->ip_dst.s_addr == s->from.sin_addr.s_addr
		    && tcp->th_dport     == s->from.sin_port) {
			send_syn_ack(s, ip, tcp);
			return;
		}
	}
}

static struct sock *get_sock(struct ip *ip, struct tcphdr *tcp)
{
	struct sock *s = &socks_;

	while ((s = s->next)) {
		if (s->to.sin_addr.s_addr == ip->ip_dst.s_addr
		    && s->to.sin_port == tcp->th_dport
		    && s->from.sin_addr.s_addr == ip->ip_src.s_addr
		    && s->from.sin_port == tcp->th_sport)
			return s;
	}

	return NULL;
}

static void handle_syn(struct ip *ip, struct tcphdr *tcp)
{
	struct sock *s;

	/* our injection */
	if (ip->ip_tos == 0x22)
		return;

	/* our own connections */
	if (ip->ip_dst.s_addr == inet_addr("127.0.0.1")
	    && ip->ip_dst.s_addr == ip->ip_src.s_addr)
		return;

	/* Inbound - check if:
	 *
	 * 1. We're getting a retransmitted SYN and we're already connecting.
	 *
	 * 2. We sent out the SYN (proxy connection).
	 *
	 */
	if ((s = get_sock(ip, tcp))) {
		/* SYN we generated that we gotta modify */
		if (s->state == STATE_CONNECT)
			modify_syn(s, ip, tcp);

		/* Kernel sending more SYNs on ongoing connection */
		return;
	}

	/* must be new connection */
	int local = 0;

	/* XXX */
	if (ip->ip_dst.s_addr == inet_addr("172.16.9.1"))
		local = 1;
	else
		local = 0;

	add_connection(ip, tcp, local);
	dump_socks();
}

static void handle_ack(struct ip *ip, struct tcphdr *tcp)
{
	struct sock *s = get_sock(ip, tcp);

	if (!s || !s->need_eno_ack)
		return;

	printf("HANDLE ACK\n");

	/* XXX delay this until we know that ACK made it */
	s->need_eno_ack = 0;

	inject_ip(ip);
}

static void pcap_in_handler(struct sock *pcap)
{
	struct pcap_pkthdr h;
	struct pktap_header *pktap;
	unsigned char *data;
	int len;
	int ll;
	struct ip *ip;
	struct tcphdr *tcp;

	if ((data = (void*) pcap_next(pcap->pcap, &h)) == NULL)
		errx(1, "pcap_next()");

	if (h.caplen != h.len) {
		printf("Short pcap %d %d\n", h.caplen, h.len);
		return;
	}

	len = h.caplen;

	pktap = (struct pktap_header *) data;
	if (len < sizeof(*pktap))
		goto __bad_packet;

	ll = pktap->pkt_len + pktap->pkt_llhdrlen;

	if (len < ll)
		goto __bad_packet;

	/* This seems to be the redirected packet to the loopback - an extra
	 * copy
	 */
	if (strcmp(pktap->pkt_ifname, "lo0") == 0 && pktap->pkt_pid == -1)
		return;

	data += ll;
	len  -= ll;

//	hexdump(data, len);

	/* find SYN */
	ip = (struct ip*) data;
	if (len < sizeof(*ip))
		goto __bad_packet;

	if (ip->ip_p != IPPROTO_TCP)
		return;

	tcp = (struct tcphdr*) (((unsigned long) ip) + ip->ip_hl * 4);
	if (len < (unsigned long) (tcp + 1) - (unsigned long) ip)
		goto __bad_packet;

	if (tcp->th_flags & TH_SYN) {
		printf("PCAP packet %s:%d",
		       inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));

		printf(" -> %s:%d [%s%s]\n",
		       inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport),
		       tcp->th_flags & TH_SYN ? "S" : "",
		       tcp->th_flags & TH_ACK ? "A" : "");
	}

	if (tcp->th_flags == TH_SYN)
		handle_syn(ip, tcp);

	if (tcp->th_flags == (TH_SYN | TH_ACK))
		handle_syn_ack(ip, tcp);

	if (tcp->th_flags == TH_ACK)
		handle_ack(ip, tcp);

	return;
__bad_packet:
	printf("Bad packet\n");
	return;
}

static void setup_pcap(void)
{
	char buf[PCAP_ERRBUF_SIZE];
	pcap_t *p;
	int fd;
	struct sock *s;

	p = pcap_create("any", buf);

	if (!p)
		errx(1, "pcap_open_live(): %s", buf);

//	pcap_set_want_pktap(p, 1);
	pcap_set_snaplen(p, 2048);
	pcap_set_timeout(p, 1);
	pcap_activate(p);

	if (pcap_set_datalink(p, DLT_PKTAP) == -1) {
		pcap_perror(p, "pcap_set_datalink()");
		exit(1);
	}

	if ((fd = pcap_get_selectable_fd(p)) == -1)
		errx(1, "pcap_get_selectable_fd()");

	s = add_sock(fd, pcap_in_handler);
	s->pcap = p;
}

static void setup_raw_sock(void)
{
	int s;
	int one = 1;
	char buf[PCAP_ERRBUF_SIZE];
	pcap_t *p = pcap_open_live("en0", BUFSIZ, 1, 1000, buf);

	if (!p) {
		errx(1, "pcap_open_live()");
	}

	outp_ = p;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		err(1, "socket()");

	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1)
		err(1, "setsockopt(IP_HDRINCL)");

	outs_ = s;
}

static void setup_redirect(void)
{
	int s, one = 1;
	struct sockaddr_in s_in;

	if (setgid(503) == -1)
		err(1, "setgid()");

	setup_pcap();
	setup_raw_sock();

	if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		err(1, "socket()");

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		err(1, "setsockopt()");

	memset(&s_in, 0, sizeof(s_in));

	s_in.sin_family      = PF_INET;
	s_in.sin_port        = htons(REDIRECT_PORT);
	s_in.sin_addr.s_addr = INADDR_ANY;

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	if (listen(s, 5) == -1)
		err(1, "listen()");

	add_sock(s, redirect_listen_handler);

	if (setuid(502) == -1)
		err(1, "setuid()");
}

static void work(void)
{
	int max = 0;
	fd_set fds;
	fd_set wfds;
	struct sock *s = &socks_;

	FD_ZERO(&fds);
	FD_ZERO(&wfds);

	/* prepare select */
	while (s->next) {
		struct sock *next = s->next;

		/* unlink dead sockets */
		if (next->state == STATE_DEAD) {
			s->next = next->next;
			free(next);
			continue;
		}

		s = next;

		switch (s->state) {
		case STATE_IDLE:
			continue;

		case STATE_CONNECT:
			FD_SET(s->s, &wfds);
			break;

		case STATE_READY:
			FD_SET(s->s, &fds);
			break;
		}

		max = s->s > max ? s->s : max;
	}

	/* select */
	if (select(max + 1, &fds, &wfds, NULL, NULL) == -1)
		err(1, "select()");

	/* process socks */
	s = &socks_;

	while ((s = s->next)) {
		if (s->state != STATE_CONNECT && s->state != STATE_READY)
			continue;

		if (FD_ISSET(s->s, &fds) || FD_ISSET(s->s, &wfds))
			s->handler(s);
	}
}

int main(int argc, char *argv[])
{
	setup_redirect();

	while (1)
		work();

	exit(0);
}
