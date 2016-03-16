#!/bin/sh

PR=80

OP="-A"

if [ "$1" = "-f" ] ; then
	OP="-D"
fi

iptables $OP INPUT -i lo -p tcp --dport 65530 -m tos --tos 0x22 -j ACCEPT

iptables $OP INPUT -p tcp \! -s 127.0.0.1 --dport 65530 --tcp-flags ALL SYN \
	-j NFQUEUE --queue-num 666

iptables $OP INPUT -p tcp --sport $PR --tcp-flags ALL SYN,ACK \
	-j NFQUEUE --queue-num 666


iptables $OP OUTPUT -p tcp --dport $PR -m tos --tos 0x4 \
	-m owner --uid-owner tcpcryptd -j NFQUEUE --queue-num 666

iptables $OP OUTPUT -p tcp --sport 65530 --tcp-flags ALL SYN,ACK \
	-j NFQUEUE --queue-num 666


iptables -t nat $OP PREROUTING -p tcp --dport $PR -j REDIRECT --to-port 65530


iptables -t nat $OP OUTPUT -p tcp --dport $PR -m owner --uid-owner tcpcryptd \
	-j ACCEPT

iptables -t nat $OP OUTPUT -p tcp \! -o lo --dport $PR \
	-j REDIRECT --to-port 65530

###### clean up all ths tos tricks we've been doing
iptables -t mangle $OP POSTROUTING -m tos --tos 0x04 -j TOS --set-tos 0x00
