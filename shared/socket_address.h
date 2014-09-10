#ifndef __TCPCRYPT_SOCKET_ADDRESS_H__
#define __TCPCRYPT_SOCKET_ADDRESS_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

union sockaddr_any {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_un un;
};

struct socket_address {
	socklen_t addr_len;
	union sockaddr_any addr;
};

#define SOCKET_ADDRESS_NULL { 0, {} }

#define SOCKET_ADDRESS_ANY { (socklen_t) sizeof(union sockaddr_any), {} }

extern int socket_address_is_null(struct socket_address *sa);

void socket_address_clear(struct socket_address *sa);

extern int socket_address_pretty(char *name, size_t size,
				 struct socket_address *sa);

extern int resolve_socket_address_local(const char *descr,
					struct socket_address *sa,
					char *error, int error_len);

#endif /* __TCPCRYPT_SOCKET_ADDRESS_H__ */
