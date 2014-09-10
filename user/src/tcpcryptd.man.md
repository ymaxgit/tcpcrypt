% tcpcryptd(8)
% 

# NAME

__tcpcryptd__ - Implement the tcpcrypt protocol by transparently modifying network I/O 

# SYNOPSIS

__tcpcryptd__ [_options_]

# OPTIONS

A list of all options is produced by:

> __tcpcryptd -h__

Configuration of packet-diversion rules allows the system administrator to
control which TCP connections are protected by __tcpcryptd__.
The daemon receives packets for transformation via a "divert port",
configurable with __-p__ _port_.

The daemon communicates with user programs via a "control socket", configurable
with __-u__ _socket_address_.  If _socket_address_ begins with "/", it is
interpreted as a filesystem path pointing to a unix-domain socket; if it is
of the form ":_port_", it is interpreted as the internet address localhost:_port_.

Verbosity may be increased with multiple __-v__ options.

A "phone-home" test will be performed at daemon startup to confirm end-to-end
functionality of the implementation (by default, with the authors' server), but
may be redirected to another test-server with __-s__ _hostname_ or disabled
completely with __-f__.



# DESCRIPTION

The __tcpcryptd__ daemon transforms TCP segments via a kernel "divert" port in
order to implement "opportunistic encryption" according to the _tcpcrypt_
protocol.

For a peer that signals in the connection handshake that it has support for the
_tcpcrypt_ protocol, ephemeral keys are exchanged and used to protect the
confidentiality and integrity of the connection's application data.  (The
protocol protects the integrity of parts of the TCP header as well.)  When a
peer does not indicate support for the protocol, the daemon will pass the
remainder of the connection unperturbed (and thus unprotected).

Application software need not be modified to take advantage of this facility,
which provides confidentiality in the face of passive network attackers (those
who cannot modify network data in transit).  But in order to protect
communication from active attackers, the application must intentionally
authenticate the connection as described below.

## Authentication

The _tcpcrypt_ protocol does not itself protect communications against "active
attackers", that is, those who are able to modify network packets in transit.
Such an attacker may perform a "man in the middle" attack that allows
her to behave as the endpoint of the encrypted connection and thus compromise
its security.

However, applications aware of _tcpcrypt_ may authenticate the connection in
whatever manner they choose, aided by an identifier for the connection that is
derived from the protocol and made available by __tcpcryptd__:

A _session id_ is derived from the ephemeral keys used to encrypt each
connection protected by _tcpcrypt_.  This identifier is (probabalistically)
unique over all connections, is not secret, and may be extracted by
applications via the user library __libtcpcrypt__.  Session ids for all active
connections may also be listed with the netstat-like utility __tcnetstat__(8).

Connection peers may ensure they are communicating securely with each other
(enjoying confidentiality and integrity in the face of active network
attackers) by confirming that the _tcpcrypt_ session ids derived at each end
are identical.  For example, they may bind the session id together with a
shared secret such as a password, sign it with public keys, use a voice
connection to speak a fingerprint of it, or simply record it for later
confirmation.

# SEE ALSO

__tcnetstat__(8), [http://tcpcrypt.org/](http://tcpcrypt.org/)

