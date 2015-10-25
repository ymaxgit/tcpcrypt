#include <stdint.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/ip.h>

#include "tcpcrypt_divert.h"
#include "tcpcryptd.h"
#include "tcpcrypt.h"
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

static pcap_t *_pcap;
static divert_cb _cb;

void divert_next_packet(int s)
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

void divert_inject(void *data, int len)
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

int divert_open(int port, divert_cb cb)
{
	char buf[PCAP_ERRBUF_SIZE];
	pcap_t *p;
	int fd;

	p = pcap_create("any", buf);

	if (!p)
		errx(1, "pcap_create(): %s", buf);

	pcap_set_want_pktap(p, 1);
	pcap_set_snaplen(p, 2048);
	pcap_set_timeout(p, 1);
	pcap_activate(p);

	if (pcap_set_datalink(p, DLT_PKTAP) == -1) {
		pcap_perror(p, "pcap_set_datalink()");
		exit(1);
	}

	if ((fd = pcap_get_selectable_fd(p)) == -1)
		errx(1, "pcap_get_selectable_fd()");

	_pcap = p;
	_cb   = cb;

	open_raw();

	xprintf(XP_ALWAYS, "Blackhole handshake and rdr using pf\n");

	return fd;
}

void divert_close(void)
{
	pcap_close(_pcap);
}
