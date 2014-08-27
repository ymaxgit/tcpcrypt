% tcpcryptd(8)
% 

# NAME

__tcpcryptd__ - Implement the tcpcrypt protocol by transparently modifying network I/O 

# SYNOPSIS

__tcpcryptd__ [_options_]

# OPTIONS

A list of all options is produced by:

> __tcpcryptd -h__

# DESCRIPTION

The __tcpcryptd__ daemon transforms TCP segments received from a kernel
"divert" port (configurable with __-p__ _port_) in order to implement
"opportunistic encryption" via the _tcpcrypt_ protocol: for peers that
support the protocol (signalled by a TCP option in the SYN packet),
ephemeral keys are exchanged and used to encrypt and protect the integrity
of connection data.  (The protocol provides integrity for parts of the TCP
header as well.)  When a peer does not signal support for _tcpcrypt_ in the
connection handshake, the daemon will pass the remainder of the
connection unperturbed (and thus unprotected).

Application software need not be modified to take advantage of this
facility, which provides confidentiality in the face of passive network
attackers (those who cannot modify network data in transit).  But in order
to protect communications from active attackers, connections must be
authenticated as described below.

Configuration of packet diversion rules allows the system administrator to
control which TCP connections are protected by __tcpcryptd__.

## Authentication

The _tcpcrypt_ protocol does not itself protect communications against "active
attackers", that is, those who are able to modify network packets in transit.
Such an attacker may perform a "man in the middle" (MITM) attack that allows
her to behave as the endpoint of the encrypted connection and thus compromise
its intended confidentiality.

However, applications aware of _tcpcrypt_ may authenticate the connection in
whatever manner they choose, aided by an identifier for the connection that is
derived from the protocol and made available by __tcpcryptd__:

A _session id_ is derived from the ephemeral keys used to encrypt each
connection protected by _tcpcrypt_.  This identifier is (probabalistically)
unique over all connections, is not secret, and may be extracted by
applications via a user library.  Session ids for all active connections may
also be listed with the netstat-like utility __tcnetstat__(8).

Applications may use the _tcpcrypt_ session id to authenticate the
connection in arbitrary ways.  For example, they may bind it together with
a shared secret such as a password, sign it with a public key, use a voice
connection to speak a fingerprint of it, or simply record it for later
confirmation.

# SEE ALSO

__tcnetstat__(8), [http://tcpcrypt.org/](http://tcpcrypt.org/)

