#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "socket_address.h"

int socket_address_is_null(const struct socket_address *sa)
{
	return sa->addr_len == 0;
}

void socket_address_clear(struct socket_address *sa)
{
	sa->addr_len = 0;
}

int socket_address_pretty(char *name, size_t size, const struct socket_address *sa)
{
	size_t n = 0;

	if (sa->addr_len == 0) {
		n = snprintf(name, size, "<null socket address>");
	}
	else {
		switch (sa->addr.sa.sa_family) {
		case AF_UNIX:
		{
			size_t path_len = sa->addr_len - sizeof(sa_family_t) - 1;
			if (path_len == 0) {
				n = snprintf(name, size, "<unnamed unix socket>");
			}
			else if (sa->addr.un.sun_path[0] == '\0') {
				n = snprintf(name, size, "<abstract unix socket>");
			}
			else {
				n = path_len;
				if (n > size)
					n = size;
				strncpy(name, sa->addr.un.sun_path, n);
				if (n < size)
					name[n++] = '\0';
			}
			break;
		}
		case AF_INET:
			n = snprintf(name, size, "%s:%d",
				     inet_ntoa(sa->addr.in.sin_addr),
				     (int) ntohs(sa->addr.in.sin_port));
			break;
		default:
			n = snprintf(name, size, "<unknown socket type>");
		}
	}

	return n;
}

const char *socket_address_pathname(const struct socket_address *sa)
{
	if (socket_address_is_null(sa))
		return NULL;

	if (sa->addr.sa.sa_family == AF_UNIX
	    && sa->addr_len > 0
	    && sa->addr.un.sun_path[0] == '/')
		return sa->addr.un.sun_path;

	return NULL;
}

int resolve_socket_address_local(const char *descr, struct socket_address *sa,
				 char *error, int error_len)
{
#define errx(...) \
	{ \
		if (error) \
			snprintf(error, error_len, __VA_ARGS__); \
		return -1; \
	}
#define err(...) \
	{ \
		if (error) { \
			int n = snprintf(error, error_len, __VA_ARGS__); \
			n += snprintf(error + n, error_len - n, ": "); \
			strerror_r(errno, error + n, error_len - n); \
		} \
		return -1; \
	}\
			
		
	if (descr == NULL || descr[0] == '\0')
		errx("empty description");

#if 0
	/* not tested */

	/* file descriptor */
	if (descr[0] == '&') {
		int s, r;
		const char *fd_str = &descr[1];

		s = atoi(fd_str);
		if (s <= 0)
			errx("couldn't parse file-descriptor number from '%s'",
			     fd_str);

		r = getsockname(s, &sa->addr.sa, &sa->addr_len);
		if (r != 0)
			err("getsockname");
		return 0;
	}
#endif

	/* path to a unix-domain socket */
	if (descr[0] == '/') {
		size_t path_len;
		struct sockaddr_un *sun = &sa->addr.un;

		path_len = strlen(descr);
		if (path_len + 1 > sizeof(sun->sun_path))
			errx("unix-domain path too long");
		memset(sun, 0, sizeof(*sun));
		sun->sun_family = AF_UNIX;
		memcpy(&sun->sun_path, descr, path_len);

		sa->addr_len = offsetof(struct sockaddr_un, sun_path)
			       + path_len + 1;
		return 0;
	}

	/* abstract unix-domain socket (linux) */
	if (descr[0] == '@') {
		const char *name;
		size_t len;
		struct sockaddr_un *sun = &sa->addr.un;

		name = &descr[1];
		/* include trailing null for readability */
		len = strlen(name) + 1;

		if (len + 1 > sizeof(sun->sun_path))
			errx("unix-domain path too long");
		memset(sun, 0, sizeof(*sun));
		sun->sun_family = AF_UNIX;
		sun->sun_path[0] = '\0';
		memcpy(&sun->sun_path[1], name, len);

		/* length includes leading null, the text, and trailing null */
		sa->addr_len = offsetof(struct sockaddr_un, sun_path)
			       + 1 + len + 1;
		return 0;
	}

	/* port number at localhost */
	if (descr[0] == ':') {
	        unsigned long port;
		const char *port_str = &descr[1];
		char *d = NULL;
		
		errno = 0;
		port = strtoul(port_str, &d, 10);
		if (d && *d == '\0' && !errno && port == (uint16_t) port)
		{
			struct sockaddr_in *sin = &sa->addr.in;

			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = inet_addr("127.0.0.1");
			sin->sin_port = htons((uint16_t) port);

			sa->addr_len = sizeof(*sin);
			return 0;
		}
		else {
			errx("couldn't parse port number from '%s'", port_str);
		}
	}

	errx("couldn't understand socket description");
	return -1;
}
