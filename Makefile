# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

CC=clang
CFLAGS=-I/usr/include/nss3/ -I/usr/include/nspr4/ -Wall -g
LDFLAGS=-lnss3 -lnspr4 -lsmime3

default: nss-extract-symkey nss-import-symkey

nss-extract-symkey: nss-extract-symkey.c
	$(CC) -o nss-extract-symkey nss-extract-symkey.c $(CFLAGS) $(LDFLAGS)

nss-import-symkey: nss-import-symkey.c
	$(CC) -o nss-import-symkey nss-import-symkey.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -f nss-extract-symkey nss-import-symkey
