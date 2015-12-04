#!/bin/sh

if test -z "${OPENBSD_SOURCE}"; then
    echo Set the OPENBSD_SOURCE environment variable and try again
    exit 1
fi

cp ${OPENBSD_SOURCE}/include/blf.h .
cp ${OPENBSD_SOURCE}/include/sha2.h .

cp ${OPENBSD_SOURCE}/lib/libc/crypt/blowfish.c .
cp ${OPENBSD_SOURCE}/lib/libc/hash/sha2.c .
cp ${OPENBSD_SOURCE}/lib/libc/net/base64.c .
cp ${OPENBSD_SOURCE}/lib/libc/string/explicit_bzero.c .
cp ${OPENBSD_SOURCE}/lib/libc/string/timingsafe_bcmp.c .

cp ${OPENBSD_SOURCE}/lib/libutil/bcrypt_pbkdf.c .

patch -p1 < portability.patch
