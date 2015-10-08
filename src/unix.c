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
#include <pcap.h>

#include "tcpcrypt_divert.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "profile.h"
#include "test.h"
#include "crypto.h"
#include "checksum.h"

#define INJECT_TOS 0x22

extern int pcap_set_want_pktap(pcap_t *, int);

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

static divert_cb _cb;
static int _s;
static pcap_t *_pcap;

void raw_open(void)
{       
        int one = 1;

        _s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (_s == -1)
                err(1, "socket()");

        if (setsockopt(_s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one))
	    == -1)
                err(1, "IP_HDRINCL");
}

void raw_inject(void *data, int len)
{
        int rc;
        struct ip *ip = data;
        struct tcphdr *tcp = (struct tcphdr*) ((char*) ip + (ip->ip_hl << 2));
        struct sockaddr_in s_in;

	memset(&s_in, 0, sizeof(s_in));

        s_in.sin_family = PF_INET;
        s_in.sin_addr   = ip->ip_dst;
        s_in.sin_port   = tcp->th_dport;

#if defined(__FreeBSD__)
#include <osreldate.h>
#if __FreeBSD_version < 1000022
       #define HO_LEN
#endif
#endif
#ifdef __DARWIN_UNIX03
	#define HO_LEN
#endif
#ifdef HO_LEN
	ip->ip_len = ntohs(ip->ip_len);
	ip->ip_off = ntohs(ip->ip_off);
#endif

        rc = sendto(_s, data, len, 0, (struct sockaddr*) &s_in,
		    sizeof(s_in));
        if (rc == -1)
                err(1, "sendto(raw)");

        if (rc != len)
                errx(1, "wrote %d/%d", rc, len);

#ifdef HO_LEN
	ip->ip_len = htons(ip->ip_len);
	ip->ip_off = htons(ip->ip_off);
#endif
}

void divert_cycle(void)
{
}

void divert_inject(void *data, int len)
{
	raw_inject(data, len);
}

void divert_next_packet_pcap(int s)
{
	struct pcap_pkthdr h;
	struct pktap_header *pktap;
	unsigned char *data;
	int len, ll, rc;
	struct ip *ip;
	unsigned char copy[4096];

	if ((data = (void*) pcap_next(_pcap, &h)) == NULL)
		errx(1, "pcap_next()");

	if (h.caplen != h.len) {
		xprintf(XP_ALWAYS, "Short pcap %d %d\n", h.caplen, h.len);
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

	if (len < sizeof(*ip))
		goto __bad_packet;

	ip = (struct ip*) data;

	/* Don't listen to our own injections */
	if (ip->ip_tos == INJECT_TOS)
		return;

	assert(len < sizeof(copy));
	memcpy(copy, data, len);
	data = copy;

	rc = _cb(data, len, pktap->pkt_flags & 1);

	switch (rc) {
	case DIVERT_DROP:
	case DIVERT_ACCEPT:
		break;

	case DIVERT_MODIFY:
		ip = (struct ip*) data;
		divert_inject(data, ntohs(ip->ip_len));
		break;
	}

	return;
__bad_packet:
	xprintf(XP_ALWAYS, "Bad packet\n");
	return;
}

void divert_inject_pcap(void *data, int len)
{
	struct ip *ip = data;
	uint8_t tos = ip->ip_tos;
	uint16_t sum = ip->ip_sum;

	/* annotate packets so firewall lets them through */
	ip->ip_tos = INJECT_TOS;
	checksum_ip(ip);

	raw_inject(data, len);

	ip->ip_tos = tos;
	ip->ip_sum = sum;
}

int divert_open_pcap(int port, divert_cb cb)
{
	char buf[PCAP_ERRBUF_SIZE];
	pcap_t *p;
	int fd;

	p = pcap_create("any", buf);

	if (!p)
		errx(1, "pcap_create(): %s", buf);

#ifdef __DARWIN_UNIX03
	pcap_set_want_pktap(p, 1);
#endif
	pcap_set_snaplen(p, 2048);
	pcap_set_timeout(p, 1);
	pcap_activate(p);

#ifdef __DARWIN_UNIX03
	if (pcap_set_datalink(p, DLT_PKTAP) == -1) {
		pcap_perror(p, "pcap_set_datalink()");
		exit(1);
	}
#endif

	if ((fd = pcap_get_selectable_fd(p)) == -1)
		errx(1, "pcap_get_selectable_fd()");

	_pcap = p;
	_cb   = cb;

	raw_open();

	xprintf(XP_ALWAYS, "Blackhole handshake and rdr using pf\n");

	return fd;
}

void divert_close_pcap(void)
{
	pcap_close(_pcap);
}
