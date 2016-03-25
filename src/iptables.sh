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

# injection from daemon: accept
$filter INPUT -i lo -p tcp --dport $RDR \
              -m tos --tos $INJECT_TOS \
  -j ACCEPT

# SYN redirected to daemon:
#   queue for daemon to initiate proxy connection with original destination
$filter INPUT -p tcp \! -s 127.0.0.1 --dport $RDR --tcp-flags ALL SYN \
  -j $NFQUEUE

# SYN+ACK on proxy connection:
#   queue for daemon to complete original handshake
$filter INPUT -p tcp $from_enabled_port --tcp-flags ALL SYN,ACK \
  -j $NFQUEUE


# handshake packet of proxy connection from daemon:
#   queue for daemon to set tcp options via DIVERT_MODIFY
$filter OUTPUT -p tcp $to_enabled_port \
               -m tos --tos $HANDSHAKE_TOS \
               -m owner --uid-owner $DAEMON_UID \
  -j $NFQUEUE

# SYN+ACK for redirected connection:
#   queue for daemon to delay handshake until proxy connection succeeds
$filter OUTPUT -p tcp --sport $RDR --tcp-flags ALL SYN,ACK \
  -j $NFQUEUE


nat="iptables -t nat $OP"

# inbound connection for enabled ports:
#   redirect to daemon for encryption
# (the nat module handles port-mapping in both directions)
$nat PREROUTING -p tcp $to_enabled_port \
  -j REDIRECT --to-port $RDR


# proxy connection from daemon to enabled port: accept
$nat OUTPUT -p tcp $to_enabled_port \
            -m owner --uid-owner $DAEMON_UID \
  -j ACCEPT

# outbound connections to enabled ports on remote hosts:
#   redirect to daemon for encryption
# (the nat module handles port-mapping in both directions)
$nat OUTPUT \! -o lo -p tcp $to_enabled_port \
  -j REDIRECT --to-port $RDR


mangle="iptables -t mangle $OP"

# packets leaving the machine with bookkeeping mark: remove mark
$mangle POSTROUTING -m tos --tos $HANDSHAKE_TOS \
  -j TOS --set-tos 0x00
