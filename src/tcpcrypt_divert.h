#ifndef __TCPCRYPT_DIVERT_H__
#define __TCPCRYPT_DIVERT_H__

#define INJECT_TOS 0x22

enum {
	DIVERT_ACCEPT = 0,
	DIVERT_DROP,
	DIVERT_MODIFY,
};

#define DF_IN	0x1

typedef int (*divert_cb)(void *data, int len, int flags);

struct divert {
	int  (*open)(int port, divert_cb cb);
	void (*next_packet)(int s);
	void (*close)(void);
	void (*inject)(void *data, int len);
	void (*cycle)(void);
	int  (*orig_dest)(struct sockaddr_in *out, struct ip *ip, int *flags);
};

extern struct divert *divert_get(void);
extern struct divert *_divert;

extern void raw_inject(void *data, int len);
extern void raw_open(void);
extern struct divert *divert_get_pcap(void);

extern void win_dont_rdr(int s);
extern uint32_t win_local_ip(void);
extern void win_handshake_complete(int s);

#endif /* __TCPCRYPT_DIVERT_H__ */
