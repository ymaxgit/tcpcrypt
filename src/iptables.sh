#!/bin/sh

# determine which operation is requested (Append or Delete)
if [ "$1" = "start" -o -z "$1" ]; then
    # during startup, bail early if any of these commands fails
    set -e
    OP="-A"
elif [ "$1" = "stop" -o "$1" = "-f" ] ; then
    OP="-D"
else
    echo "Expected \"start\" or \"stop\" as first argument" >&2
    exit 1
fi

# determine which ports should be tcpcrypt-enabled
if [ -z "$ONLY_PORTS" -a -z "$OMIT_PORTS" ] ; then
    echo "Expected either OMIT_PORTS or ONLY_PORTS environment variables to be set" >&2
    exit 1
fi
if [ -n "$ONLY_PORTS" -a -n "$OMIT_PORTS" ] ; then
    echo "Expected only one of OMIT_PORTS or ONLY_PORTS environment variables to be set" >&2
    exit 1
fi
if [ -n "$OMIT_PORTS" ] ; then
    PORT_TEST=!
    PORTS="$OMIT_PORTS"
fi
if [ -n "$ONLY_PORTS" ] ; then
    PORT_TEST=
    PORTS="$ONLY_PORTS"
fi

# more necessary configuration
if [ -z "$DAEMON_USER" ] ; then
    echo "Expected DAEMON_USER environment variable to be set" >&2
    exit 1
fi
if [ -z "$DIVERT_PORT" ] ; then
    echo "Expected DIVERT_PORT environment variable to be set" >&2
    exit 1
fi

# some shorthand to make rules more concise
from_enabled_port="-m multiport $PORT_TEST --source-ports $PORTS"
to_enabled_port="-m multiport $PORT_TEST --destination-ports $PORTS"
NFQUEUE="NFQUEUE --queue-num $DIVERT_PORT"
REDIRECT_PORT="65530"
REDIRECT="REDIRECT --to-port $REDIRECT_PORT"
INJECT_TOS="0x22"
HANDSHAKE_TOS="0x04"

filter="$ECHO iptables -t filter $OP"

# Injection from daemon: Accept
$filter INPUT -i lo -p tcp --dport $REDIRECT_PORT \
              -m tos --tos $INJECT_TOS \
  -j ACCEPT

# SYN redirected to daemon:
#   Queue for daemon to initiate proxy connection with original destination
$filter INPUT -p tcp \! -s 127.0.0.1 --dport $REDIRECT_PORT --tcp-flags ALL SYN \
  -j $NFQUEUE

# SYN+ACK on proxy connection:
#   Queue for daemon to complete original handshake
$filter INPUT -p tcp $from_enabled_port --tcp-flags ALL SYN,ACK \
  -j $NFQUEUE


# Handshake packet of proxy connection from daemon:
#   Queue for daemon to set tcp options via DIVERT_MODIFY
$filter OUTPUT -p tcp $to_enabled_port \
               -m tos --tos $HANDSHAKE_TOS \
               -m owner --uid-owner $DAEMON_USER \
  -j $NFQUEUE

# SYN+ACK on redirected connection:
#   Queue for daemon to delay handshake until proxy connection succeeds
$filter OUTPUT -p tcp --sport $REDIRECT_PORT --tcp-flags ALL SYN,ACK \
  -j $NFQUEUE


nat="$ECHO iptables -t nat $OP"

# Inbound connection for enabled ports:
#   Redirect to daemon (at localhost:$REDIRECT_PORT) for encryption
#
# (The nat module will now translate addresses in both directions,
#  for the lifetime of this connection.)
$nat PREROUTING -p tcp $to_enabled_port \
  -j $REDIRECT


# Proxy connection from daemon to enabled port: Accept
$nat OUTPUT -p tcp $to_enabled_port \
            -m owner --uid-owner $DAEMON_USER \
  -j ACCEPT

# Outbound connections to enabled ports on remote hosts:
#   Redirect to daemon (at localhost port $REDIRECT_PORT) for encryption
#
# (The nat module will now translate addresses in both directions,
#  for the lifetime of this connection.)
$nat OUTPUT \! -o lo -p tcp $to_enabled_port \
  -j $REDIRECT


mangle="$ECHO iptables -t mangle $OP"

# Packets leaving the machine with bookkeeping mark: Remove mark
$mangle POSTROUTING -m tos --tos $HANDSHAKE_TOS \
  -j TOS --set-tos 0x00
