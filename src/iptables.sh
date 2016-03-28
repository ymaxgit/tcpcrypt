#!/bin/sh

PR=80
from_enabled_port="--sport $PR"
to_enabled_port="--dport $PR"

NFQUEUE="NFQUEUE --queue-num 666"
RDR="65530"
DAEMON_UID="tcpcryptd"
INJECT_TOS="0x22"
HANDSHAKE_TOS="0x04"

OP="-A"
if [ "$1" = "-f" ] ; then
	OP="-D"
fi


filter="iptables -t filter $OP"

# Injection from daemon: Accept
$filter INPUT -i lo -p tcp --dport $RDR \
              -m tos --tos $INJECT_TOS \
  -j ACCEPT

# SYN redirected to daemon:
#   Queue for daemon to initiate proxy connection with original destination
$filter INPUT -p tcp \! -s 127.0.0.1 --dport $RDR --tcp-flags ALL SYN \
  -j $NFQUEUE

# SYN+ACK on proxy connection:
#   Queue for daemon to complete original handshake
$filter INPUT -p tcp $from_enabled_port --tcp-flags ALL SYN,ACK \
  -j $NFQUEUE


# Handshake packet of proxy connection from daemon:
#   Queue for daemon to set tcp options via DIVERT_MODIFY
$filter OUTPUT -p tcp $to_enabled_port \
               -m tos --tos $HANDSHAKE_TOS \
               -m owner --uid-owner $DAEMON_UID \
  -j $NFQUEUE

# SYN+ACK on redirected connection:
#   Queue for daemon to delay handshake until proxy connection succeeds
$filter OUTPUT -p tcp --sport $RDR --tcp-flags ALL SYN,ACK \
  -j $NFQUEUE


nat="iptables -t nat $OP"

# Inbound connection for enabled ports:
#   Redirect to daemon (at localhost:$RDR) for encryption
#
# (The nat module will now translate addresses in both directions,
#  for the lifetime of this connection.)
$nat PREROUTING -p tcp $to_enabled_port \
  -j REDIRECT --to-port $RDR


# Proxy connection from daemon to enabled port: Accept
$nat OUTPUT -p tcp $to_enabled_port \
            -m owner --uid-owner $DAEMON_UID \
  -j ACCEPT

# Outbound connections to enabled ports on remote hosts:
#   Redirect to daemon (at localhost port $RDR) for encryption
#
# (The nat module will now translate addresses in both directions,
#  for the lifetime of this connection.)
$nat OUTPUT \! -o lo -p tcp $to_enabled_port \
  -j REDIRECT --to-port $RDR


mangle="iptables -t mangle $OP"

# Packets leaving the machine with bookkeeping mark: Remove mark
$mangle POSTROUTING -m tos --tos $HANDSHAKE_TOS \
  -j TOS --set-tos 0x00
