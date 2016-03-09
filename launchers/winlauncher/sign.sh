#!/bin/bash

sign() {
	echo Signing $1
	osslsigncode sign \
	 -pkcs12 cert.p12 \
	 -askpass \
	 -h sha1 \
	 -n tcpcrypt \
	 -i http://tcpcrypt.org/ \
	 -t http://timestamp.verisign.com/scripts/timstamp.dll \
	 -in $1 -out $1-signed
	mv $1-signed $1
}

BINS=(tcpcrypt.exe ../../src/.libs/tcpcryptd.exe ../../util/.libs/tcnetstat.exe)
for i in ${BINS[@]} ; do
	sign $i
done

make tcpcrypt.msi

sign tcpcrypt.msi
