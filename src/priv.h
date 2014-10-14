#ifndef __TCPCRYPT_PRIV_H__
#define __TCPCRYPT_PRIV_H__

extern void drop_privs(const char *dir, const char *name);
extern void linux_drop_privs(uid_t uid);

#endif
