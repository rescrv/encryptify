AM_MAKEFLAGS = --no-print-directory

EXTRA_DIST =
EXTRA_DIST += README
EXTRA_DIST += update.sh
EXTRA_DIST += portability.patch

bin_PROGRAMS = encryptify
dist_man_MANS = encryptify.1

noinst_HEADERS =
noinst_HEADERS += tweetnacl.h
noinst_HEADERS += blf.h
noinst_HEADERS += sha2.h

encryptify_SOURCES =
encryptify_SOURCES += base64.c
encryptify_SOURCES += tweetnacl.c
encryptify_SOURCES += bcrypt_pbkdf.c
encryptify_SOURCES += blowfish.c
encryptify_SOURCES += encryptify.c
encryptify_SOURCES += explicit_bzero.c
encryptify_SOURCES += sha2.c
encryptify_SOURCES += timingsafe_bcmp.c
encryptify_LDADD = ${BSDLIB}
