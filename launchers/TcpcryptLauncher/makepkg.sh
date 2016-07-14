#!/bin/bash

DIR=$1

VER=$(awk -F , '/AC_INIT/ {print $2}' ../../configure.ac | tr -d '[] ')

echo Version $VER

pkgbuild --root $DIR --identifier org.tcpcrypt.TcpcryptLauncher \
	--version $VER --install-location /Applications  tcpcrypt.pkg

productsign --sign 'Developer ID Installer' tcpcrypt.pkg tcpcrypt-signed.pkg
spctl --asses --type install tcpcrypt-signed.pkg
mv tcpcrypt-signed.pkg tcpcrypt.pkg
