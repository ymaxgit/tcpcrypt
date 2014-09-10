% tcnetstat(8)
% 

# NAME

__tcnetstat__ - Print information about network connections protected by tcpcrypt

# SYNOPSIS

__tcnetstat__

# DESCRIPTION

The __tcnetstat__ utility prints the _session id_ of each TCP connection that
is currently being protected by the _tcpcrypt_ protocol.

# OPTIONS

Where the _tcpcrypt_ protocol is implemented by the __tcpcryptd__ daemon,
this utility communicates with the daemon via a "control socket", configurable
with __-u__ _socket_address_.  If _socket_address_ begins with "/", it is
interpreted as a filesystem path pointing to a unix-domain socket; if it is
of the form ":_port_", it is interpreted as the internet address localhost:_port_.

# SEE ALSO

__tcpcryptd__(8), [http://tcpcrypt.org/](http://tcpcrypt.org/)

