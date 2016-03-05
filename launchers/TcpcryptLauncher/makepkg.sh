#!/bin/sh

DIR=$1

pkgbuild --root $DIR --identifier org.tcpcrypt.TcpcryptLauncher \
	--version 0.4 --install-location /Applications  tcpcrypt.pkg

productsign --sign 'Developer ID Installer' tcpcrypt.pkg tcpcrypt-signed.pkg
spctl --asses --type install tcpcrypt-signed.pkg
mv tcpcrypt-signed.pkg tcpcrypt.pkg
