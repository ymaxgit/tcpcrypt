Tcpcrypt netstat
================

The `util/tcnetstat` program lists active tcpcrypt connections and their
session IDs.

With two HTTP connections open, the output looks like:

    $ test/tcnetstat -N
    Using 1 implementation
    Local address		Foreign address		SID
    128.12.13.14:59539   	171.66.3.211:80      	E0C4FA717D0B3C51E4E2A8EC70CA34ADFC91A260
    128.12.13.14:59540   	171.66.3.211:80      	EA22A7B8A9994AB151A865C5F5AC1309DD674D6C

There is currently a limit of approximately 100 active connections that can be
displayed by tcnetstat. This will be fixed soon and does not affect tcpcryptd.

