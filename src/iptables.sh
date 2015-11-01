#!/bin/sh

PR=80

iptables -A INPUT -i lo -p tcp --dport 65530 -m tos --tos 0x22 -j ACCEPT

iptables -A INPUT -p tcp --dport 65530 --tcp-flags ALL SYN \
	-j NFQUEUE --queue-num 666

iptables -A INPUT -p tcp -d 127.0.0.1 --dport 65530 --tcp-flags ALL SYN \
	-j NFQUEUE --queue-num 666

iptables -A INPUT -p tcp --sport $PR --tcp-flags ALL SYN,ACK \
	-j NFQUEUE --queue-num 666


iptables -A OUTPUT -p tcp --dport $PR -m tos --tos 0x4 \
	-m owner --uid-owner tcpcryptd -j NFQUEUE --queue-num 666

iptables -A OUTPUT -p tcp --sport 65530 --tcp-flags ALL SYN,ACK \
	-j NFQUEUE --queue-num 666


iptables -t nat -A PREROUTING -p tcp --dport $PR -j REDIRECT --to-port 65530


iptables -t nat -A OUTPUT -p tcp --dport $PR -m owner --uid-owner tcpcryptd \
	-j ACCEPT

iptables -t nat -A OUTPUT -p tcp --dport $PR -j REDIRECT --to-port 65530

###### clean up all ths tos tricks we've been doing
iptables -t mangle -A POSTROUTING -m tos --tos 0x04 -j TOS --set-tos 0x00
