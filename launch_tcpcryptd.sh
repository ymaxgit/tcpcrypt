#!/bin/sh

BASE=`dirname $0`
TCPCRYPTD=$BASE/src/tcpcryptd
DIVERT_PORT=666
PIDFILE=/var/run/tcpcrypt.pid
JAIL_DIR=/var/run/tcpcryptd
JAIL_USER=tcpcryptd

OSNAME=`uname -s`

if [ "$OSNAME" = "Linux" ]
then
    # set either ONLY_PORTS or OMIT_PORTS, in a manner acceptable to the
    # "multiport" extension.  see iptables-extensions(8)

    # ONLY_PORTS="80,7777"

    # exclude already-encrypted services:
    OMIT_PORTS="22,261,443,563,614,636,684,695,989,990,992:995"
else
    # for ipfw users:
    PORT=${1:-80}
    PORT2=${2:-7777}
fi

start_tcpcryptd() {
    LD_LIBRARY_PATH=lib/ $TCPCRYPTD \
        -U $JAIL_USER \
        -J $JAIL_DIR \
        -p $DIVERT_PORT \
	-e \
	-f \
        $OPTS &
    echo $! > $PIDFILE
    wait $!
}

init_jail() {
    if [ ! -d "$JAIL_DIR" ]
    then
        echo "Creating jail directory $JAIL_DIR"
        (umask 077 && mkdir $JAIL_DIR)
    fi

    id $JAIL_USER >/dev/null 2>&1
    if [ $? -ne 0 ]
    then
        echo "Creating user and group '$JAIL_USER'"
        useradd -s /nonexistent -d /nonexistent -M -U $JAIL_USER
    fi
}

ee() {
    echo $*
    eval $*
}

set_iptables() {
    $BASE/src/iptables.sh
}

unset_iptables() {
    echo Removing iptables rules and quitting tcpcryptd...

    $BASE/src/iptables.sh -f

    exit
}

bsd_set_ipfw() {
    echo Tcpcrypting port 80 and 7777...
    ipfw 02 add divert $DIVERT_PORT tcp from any to any $PORT
    ipfw 03 add divert $DIVERT_PORT tcp from any $PORT to any
    ipfw 04 add divert $DIVERT_PORT tcp from any to any $PORT2
    ipfw 05 add divert $DIVERT_PORT tcp from any $PORT2 to any
}

bsd_unset_ipfw() {
    echo Removing ipfw rules and quitting tcpcryptd...
    ipfw delete 02 03 04 05
    exit
}

win_start_tcpcryptd() {
    MAC_ADDR=`ipconfig /all | grep 'Physical Address'| head -n 1 | sed 's/\s*Physical Address\(\. \)*: \(.*\)/\2/' | sed 's/-/:/g'`
    echo Using MAC address $MAC_ADDR...
    LD_LIBRARY_PATH=lib/ $TCPCRYPTD $OPTS -p $DIVERT_PORT -x $MAC_ADDR &
    echo $! > $PIDFILE
    wait $!    
}

check_root() {
    if [ `whoami` != "root" ]
    then
        echo "must be root"
        exit 1
    fi
}

check_ssh() {
    if [ -n "$SSH_CONNECTION" ]
    then
        read -p 'Command may disrupt existing ssh connections. Proceed? [y/N] ' C
        if [ "$C" != "y" ]
        then
            exit 1
        fi
    fi
}

check_existing_tcpcryptd() {
    P=`ps axo pid,comm | grep tcpcryptd`
    if [ $? -eq 0 ]
    then
        read -p "tcpcryptd already running with pid $P. Proceed? [y/N] " C
        if [ "$C" != "y" ]
        then
            exit 1
        fi
    fi
}


#check_ssh

case "$OSNAME" in
    Linux)
        check_existing_tcpcryptd
        check_root
        init_jail
        set_iptables
        trap unset_iptables 2 # trap SIGINT to remove iptables rules before exit
        start_tcpcryptd
        unset_iptables
        ;;
    FreeBSD|Darwin)
        check_existing_tcpcryptd
        check_root
        init_jail
        bsd_set_ipfw
        trap bsd_unset_ipfw 2
        start_tcpcryptd
        bsd_unset_ipfw
        ;;
    [Cc][Yy][Gg][Ww][Ii][Nn]*)
        win_start_tcpcryptd
        ;;
esac

