/* Code modified from signify in OpenBSD.  Relevant license text: */
/* $OpenBSD: signify.c,v 1.100 2015/01/16 06:16:12 tedu Exp $ */
/*
 * Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <resolv.h>

#include <limits.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <bsd/string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <unistd.h>
#include <bsd/readpassphrase.h>
#include <bsd/libutil.h>
#include <sha2.h>

#include "tweetnacl.h"

#define SECRETBYTES  crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
#define PUBLICBYTES  crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
#define NONCEBYTES   crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
#define ZEROBYTES    crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
#define BOXZEROBYTES crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES

#define SYM_NONCEBYTES crypto_stream_salsa20_NONCEBYTES
#define SYM_KEYBYTES crypto_stream_salsa20_KEYBYTES
#if SYM_NONCEBYTES < 8
#error need more nonce
#endif

#define PKALG "Ed"
#define KDFALG "BK"
#define KEYNUMLEN 8

#define KALG "Sa"

#define COMMENTHDR "untrusted comment: "
#define COMMENTHDRLEN 19
#define COMMENTMAXLEN 1024

struct enckey {
    uint8_t pkalg[2];
    uint8_t kdfalg[2];
    uint32_t kdfrounds;
    uint8_t salt[16];
    uint8_t checksum[8];
    uint8_t keynum[KEYNUMLEN];
    uint8_t seckey[SECRETBYTES];
};

struct pubkey {
    uint8_t pkalg[2];
    uint8_t keynum[KEYNUMLEN];
    uint8_t pubkey[PUBLICBYTES];
};

extern char *__progname;

static void
usage(const char *error)
{
    if (error)
        fprintf(stderr, "%s\n", error);
    fprintf(stderr, "usage:"
        "\t%1$s -G [-n] [-c comment] -p pubkey -s seckey\n"
        "\t%1$s -E -p pubkey [file ...]\n"
        "\t%1$s -D [-q] -s seckey [file ...]\n",
        __progname);
    exit(1);
}

static int
xopen(const char *fname, int oflags, mode_t mode)
{
    struct stat sb;
    int fd;

    if (strcmp(fname, "-") == 0) {
        if ((oflags & O_WRONLY))
            fd = dup(STDOUT_FILENO);
        else
            fd = dup(STDIN_FILENO);
        if (fd == -1)
            err(1, "dup failed");
    } else {
        fd = open(fname, oflags, mode);
        if (fd == -1)
            err(1, "can't open %s for %s", fname,
                (oflags & O_WRONLY) ? "writing" : "reading");
    }
    if (fstat(fd, &sb) == -1 || S_ISDIR(sb.st_mode))
        errx(1, "not a valid file: %s", fname);
    return fd;
}

static size_t
parseb64file(const char *filename, char *b64, void *buf, size_t buflen,
    char *comment)
{
    char *commentend, *b64end;

    commentend = strchr(b64, '\n');
    if (!commentend || commentend - b64 <= COMMENTHDRLEN ||
        memcmp(b64, COMMENTHDR, COMMENTHDRLEN) != 0)
        errx(1, "invalid comment in %s; must start with '%s'",
            filename, COMMENTHDR);
    *commentend = '\0';
    if (comment) {
        if (strlcpy(comment, b64 + COMMENTHDRLEN,
            COMMENTMAXLEN) >= COMMENTMAXLEN)
            errx(1, "comment too long");
    }
    if (!(b64end = strchr(commentend + 1, '\n')))
        errx(1, "missing new line after base64 in %s", filename);
    *b64end = '\0';
    if (b64_pton(commentend + 1, buf, buflen) != buflen)
        errx(1, "invalid base64 encoding in %s", filename);
    if (memcmp(buf, PKALG, 2) != 0)
        errx(1, "unsupported file %s", filename);
    return b64end - b64 + 1;
}

static void
readb64file(const char *filename, void *buf, size_t buflen, char *comment)
{
    char b64[2048];
    int rv, fd;

    fd = xopen(filename, O_RDONLY | O_NOFOLLOW, 0);
    if ((rv = read(fd, b64, sizeof(b64) - 1)) == -1)
        err(1, "read from %s", filename);
    b64[rv] = '\0';
    parseb64file(filename, b64, buf, buflen, comment);
    explicit_bzero(b64, sizeof(b64));
    close(fd);
}

static void
writeall(int fd, const void *buf, size_t buflen, const char *filename)
{
    ssize_t x;

    while (buflen != 0) {
        if ((x = write(fd, buf, buflen)) == -1)
            err(1, "write to %s", filename);
        buflen -= x;
        buf = (char *)buf + x;
    }
}

static void
writeb64file(const char *filename, const char *comment, const void *buf,
    size_t buflen, const void *msg, size_t msglen, int oflags, mode_t mode)
{
    char header[1024];
    char b64[1024];
    int fd, rv, nr;

    fd = xopen(filename, O_CREAT|oflags|O_NOFOLLOW|O_WRONLY, mode);
    if ((nr = snprintf(header, sizeof(header), "%s%s\n",
        COMMENTHDR, comment)) == -1 || nr >= sizeof(header))
        errx(1, "comment too long");
    writeall(fd, header, strlen(header), filename);
    if ((rv = b64_ntop(buf, buflen, b64, sizeof(b64))) == -1)
        errx(1, "base64 encode failed");
    b64[rv++] = '\n';
    writeall(fd, b64, rv, filename);
    explicit_bzero(b64, sizeof(b64));
    if (msg)
        writeall(fd, msg, msglen, filename);
    close(fd);
}

static void
kdf(uint8_t *salt, size_t saltlen, int rounds, int allowstdin, int confirm,
    uint8_t *key, size_t keylen)
{
    char pass[1024];
    int rppflags = RPP_ECHO_OFF;

    if (rounds == 0) {
        memset(key, 0, keylen);
        return;
    }

    if (allowstdin && !isatty(STDIN_FILENO))
        rppflags |= RPP_STDIN;
    if (!readpassphrase("passphrase: ", pass, sizeof(pass), rppflags))
        errx(1, "unable to read passphrase");
    if (strlen(pass) == 0)
        errx(1, "please provide a password");
    if (confirm && !(rppflags & RPP_STDIN)) {
        char pass2[1024];
        if (!readpassphrase("confirm passphrase: ", pass2,
            sizeof(pass2), rppflags))
            errx(1, "unable to read passphrase");
        if (strcmp(pass, pass2) != 0)
            errx(1, "passwords don't match");
        explicit_bzero(pass2, sizeof(pass2));
    }
    if (bcrypt_pbkdf(pass, strlen(pass), salt, saltlen, key,
        keylen, rounds) == -1)
        errx(1, "bcrypt pbkdf");
    explicit_bzero(pass, sizeof(pass));
}

static void
generate(const char *pubkeyfile, const char *seckeyfile, int rounds,
    const char *comment)
{
    uint8_t digest[SHA512_DIGEST_LENGTH];
    struct pubkey pubkey;
    struct enckey enckey;
    uint8_t xorkey[sizeof(enckey.seckey)];
    uint8_t keynum[KEYNUMLEN];
    char commentbuf[COMMENTMAXLEN];
    SHA2_CTX ctx;
    int i, nr;

    crypto_box_curve25519xsalsa20poly1305_keypair(pubkey.pubkey, enckey.seckey);
    arc4random_buf(keynum, sizeof(keynum));

    SHA512Init(&ctx);
    SHA512Update(&ctx, enckey.seckey, sizeof(enckey.seckey));
    SHA512Final(digest, &ctx);

    memcpy(enckey.pkalg, PKALG, 2);
    memcpy(enckey.kdfalg, KDFALG, 2);
    enckey.kdfrounds = htonl(rounds);
    memcpy(enckey.keynum, keynum, KEYNUMLEN);
    arc4random_buf(enckey.salt, sizeof(enckey.salt));
    kdf(enckey.salt, sizeof(enckey.salt), rounds, 1, 1, xorkey, sizeof(xorkey));
    memcpy(enckey.checksum, digest, sizeof(enckey.checksum));
    for (i = 0; i < sizeof(enckey.seckey); i++)
        enckey.seckey[i] ^= xorkey[i];
    explicit_bzero(digest, sizeof(digest));
    explicit_bzero(xorkey, sizeof(xorkey));

    if ((nr = snprintf(commentbuf, sizeof(commentbuf), "%s secret key",
        comment)) == -1 || nr >= sizeof(commentbuf))
        errx(1, "comment too long");
    writeb64file(seckeyfile, commentbuf, &enckey,
        sizeof(enckey), NULL, 0, O_EXCL, 0600);
    explicit_bzero(&enckey, sizeof(enckey));

    memcpy(pubkey.pkalg, PKALG, 2);
    memcpy(pubkey.keynum, keynum, KEYNUMLEN);
    if ((nr = snprintf(commentbuf, sizeof(commentbuf), "%s public key",
        comment)) == -1 || nr >= sizeof(commentbuf))
        errx(1, "comment too long");
    writeb64file(pubkeyfile, commentbuf, &pubkey,
        sizeof(pubkey), NULL, 0, O_EXCL, 0666);
}

static void
readpubkey(const char *pubkeyfile, struct pubkey *pubkey,
    const char *sigcomment)
{
    readb64file(pubkeyfile, pubkey, sizeof(*pubkey), NULL);
}

static ssize_t
xread(int fd, unsigned char* buf, size_t nbytes)
{
    size_t rem = nbytes;
    ssize_t amt = 0;

    while (rem > 0) {
        if ((amt = read(fd, buf, rem)) < 0) {
            if (rem == nbytes) {
                return -1;
            } else {
                break;
            }
        } else if (amt == 0) {
            break;
        }
        rem -= amt;
        buf += amt;
    }
    return nbytes - rem;
}

ssize_t
xwrite(int fd, const unsigned char *buf, size_t nbytes)
{
    size_t rem = nbytes;
    ssize_t amt = 0;

    while (rem > 0) {
        if ((amt = write(fd, buf, rem)) < 0) {
            if (rem == nbytes) {
                return -1;
            } else {
                break;
            }
        } else if (amt == 0) {
            break;
        }
        rem -= amt;
        buf += amt;
    }

    return nbytes - rem;
}

#define BLOCK_SIZE (1U << 18)
#if ZEROBYTES > BOXZEROBYTES
#define PAD ZEROBYTES
#define DIFF (ZEROBYTES - BOXZEROBYTES)
#else
#error assumption violated
#endif

struct singlekey {
    uint8_t kalg[2];
    uint8_t key[SYM_KEYBYTES];
};

static void
write_encrypted_buffer(int fd, struct pubkey* key, unsigned char* pbuf, unsigned char* cbuf, size_t sz)
{
    unsigned char pk[SECRETBYTES];
    unsigned char sk[SECRETBYTES];
    crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk);
    unsigned char nonce[NONCEBYTES];
    arc4random_buf(nonce, sizeof(nonce));
    explicit_bzero(pbuf, ZEROBYTES);
    crypto_box_curve25519xsalsa20poly1305(cbuf, pbuf, PAD + sz, nonce, key->pubkey, sk);
    explicit_bzero(sk, sizeof(sk));
    xwrite(fd, pk, sizeof(pk));
    xwrite(fd, nonce, sizeof(nonce));
    xwrite(fd, cbuf + BOXZEROBYTES, sz + DIFF);
    explicit_bzero(nonce, sizeof(nonce));
    explicit_bzero(pbuf, PAD + sz);
    explicit_bzero(cbuf, PAD + sz);
    explicit_bzero(pk, sizeof(pk));
}

static void
read_encrypted_buffer(int fd, struct enckey* key, unsigned char* cbuf, unsigned char* pbuf, size_t sz)
{
    unsigned char pk[SECRETBYTES];
    unsigned char nonce[NONCEBYTES];
    explicit_bzero(pk, sizeof(pk));
    explicit_bzero(nonce, sizeof(nonce));
    explicit_bzero(cbuf, PAD + sz);
    explicit_bzero(pbuf, PAD + sz);
    xread(fd, pk, sizeof(pk));
    xread(fd, nonce, sizeof(nonce));
    xread(fd, cbuf + BOXZEROBYTES, sz + DIFF);
    if (crypto_box_curve25519xsalsa20poly1305_open(pbuf, cbuf, PAD + sz, nonce, pk, key->seckey) < 0)
        errx(1, "could not decrypt file");
    explicit_bzero(nonce, sizeof(nonce));
    explicit_bzero(cbuf, BOXZEROBYTES + sz);
}

static void
write_encrypted_symmetric_key(int fd, struct pubkey* key, struct singlekey* sym)
{
    unsigned char pbuf[PAD + sizeof(struct singlekey)];
    unsigned char cbuf[PAD + sizeof(struct singlekey)];
    memmove(pbuf + ZEROBYTES, sym, sizeof(struct singlekey));
    write_encrypted_buffer(fd, key, pbuf, cbuf, sizeof(struct singlekey));
}

static void
read_encrypted_symmetric_key(int fd, struct enckey* key, struct singlekey* sym)
{
    unsigned char cbuf[PAD + sizeof(struct singlekey)];
    unsigned char pbuf[PAD + sizeof(struct singlekey)];
    read_encrypted_buffer(fd, key, cbuf, pbuf, sizeof(struct singlekey));
    memmove(sym, pbuf + ZEROBYTES, sizeof(struct singlekey));
    explicit_bzero(pbuf, sizeof(pbuf));
}

static void
write_encrypted_digest(int fd, struct pubkey* key, const unsigned char* digest)
{
    unsigned char pbuf[PAD + SHA512_DIGEST_LENGTH];
    unsigned char cbuf[PAD + SHA512_DIGEST_LENGTH];
    memmove(pbuf + ZEROBYTES, digest, SHA512_DIGEST_LENGTH);
    write_encrypted_buffer(fd, key, pbuf, cbuf, SHA512_DIGEST_LENGTH);
}

static void
encode_nonce(unsigned long long n, unsigned char nonce[SYM_NONCEBYTES])
{
    explicit_bzero(nonce, SYM_NONCEBYTES);

    for (unsigned i = 0; i < SYM_NONCEBYTES; ++i)
    {
        nonce[i] = n & 0xffu;
        n >>= 8;
    }
}

static void
encrypt(const char* keyfile, const char* plaintext, const char* ciphertext)
{
    struct pubkey pubkey;
    struct singlekey key;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    unsigned char nonce[SYM_NONCEBYTES];
    unsigned char pbuf[BLOCK_SIZE];
    unsigned char cbuf[BLOCK_SIZE];
    readpubkey(keyfile, &pubkey, NULL);
    memmove(key.kalg, KALG, 2);
    arc4random_buf(key.key, sizeof(key.key));
    int pfd = xopen(plaintext, O_RDONLY, 0600);
    int cfd = xopen(ciphertext, O_WRONLY|O_CREAT|O_EXCL, 0600);
    write_encrypted_symmetric_key(cfd, &pubkey, &key);
    unsigned long long x = 0;

    SHA2_CTX ctx;
    SHA512Init(&ctx);

    while (1) {
        ++x;
        encode_nonce(x, nonce);
        explicit_bzero(pbuf, sizeof(pbuf));
        explicit_bzero(cbuf, sizeof(cbuf));
        ssize_t amt = xread(pfd, pbuf, BLOCK_SIZE);
        if (amt == 0)
            break;
        SHA512Update(&ctx, pbuf, amt);
        crypto_stream_salsa20_xor(cbuf, pbuf, amt, nonce, key.key);
        xwrite(cfd, cbuf, amt);
    }

    SHA512Final(digest, &ctx);
    write_encrypted_digest(cfd, &pubkey, digest);
    explicit_bzero(&pubkey, sizeof(pubkey));
    explicit_bzero(&key, sizeof(key));
    explicit_bzero(nonce, sizeof(nonce));
    explicit_bzero(pbuf, sizeof(pbuf));
    explicit_bzero(cbuf, sizeof(cbuf));
    close(pfd);
    close(cfd);
}

#define FOOTER (PUBLICBYTES + NONCEBYTES + DIFF + SHA512_DIGEST_LENGTH)

static void
check_digest(struct enckey* key, const unsigned char* digest, const unsigned char* footer)
{
    unsigned char pk[PUBLICBYTES];
    unsigned char nonce[NONCEBYTES];
    unsigned char cbuf[PAD + SHA512_DIGEST_LENGTH];
    unsigned char pbuf[PAD + SHA512_DIGEST_LENGTH];
    memmove(pk, footer, PUBLICBYTES);
    memmove(nonce, footer + PUBLICBYTES, NONCEBYTES);
    memmove(cbuf + BOXZEROBYTES, footer + PUBLICBYTES + NONCEBYTES, SHA512_DIGEST_LENGTH + DIFF);
    explicit_bzero(pbuf, ZEROBYTES);
    if (crypto_box_curve25519xsalsa20poly1305_open(pbuf, cbuf, PAD + SHA512_DIGEST_LENGTH, nonce, pk, key->seckey) < 0)
        errx(1, "could not decrypt file");
    explicit_bzero(nonce, sizeof(nonce));
    explicit_bzero(cbuf, sizeof(cbuf));
    explicit_bzero(pbuf, sizeof(pbuf));
}

static void
decrypt(const char* keyfile, const char* ciphertext, const char* plaintext)
{
    struct enckey enckey;
    struct singlekey key;
    uint8_t xorkey[sizeof(enckey.seckey)];
    uint8_t digest[SHA512_DIGEST_LENGTH];
    unsigned char nonce[SYM_NONCEBYTES];
    unsigned char cbuf[BLOCK_SIZE + FOOTER];
    unsigned char pbuf[BLOCK_SIZE];
    size_t cbuf_sz = 0;
    ssize_t amt;
    off_t total = 0;
    int i, rounds, nr;
    SHA2_CTX ctx;

    readb64file(keyfile, &enckey, sizeof(enckey), NULL);

    if (memcmp(enckey.kdfalg, KDFALG, 2) != 0)
        errx(1, "unsupported KDF");
    rounds = ntohl(enckey.kdfrounds);
    kdf(enckey.salt, sizeof(enckey.salt), rounds, strcmp(ciphertext, "-") != 0,
        0, xorkey, sizeof(xorkey));
    for (i = 0; i < sizeof(enckey.seckey); i++)
        enckey.seckey[i] ^= xorkey[i];
    explicit_bzero(xorkey, sizeof(xorkey));
    SHA512Init(&ctx);
    SHA512Update(&ctx, enckey.seckey, sizeof(enckey.seckey));
    SHA512Final(digest, &ctx);
    if (memcmp(enckey.checksum, digest, sizeof(enckey.checksum)) != 0)
        errx(1, "incorrect passphrase");
    explicit_bzero(digest, sizeof(digest));
    int cfd = xopen(ciphertext, O_RDONLY, 0600);
    int pfd = xopen(plaintext, O_WRONLY|O_CREAT|O_EXCL, 0600);
    read_encrypted_symmetric_key(cfd, &enckey, &key);
    unsigned long long x = 0;

    SHA512Init(&ctx);

    while (1) {
        explicit_bzero(pbuf, sizeof(pbuf));
        amt = xread(cfd, cbuf + cbuf_sz, sizeof(cbuf) - cbuf_sz);
        if (amt == 0)
            break;
        cbuf_sz += amt;
        if (cbuf_sz < FOOTER)
            errx(1, "could not decrypt file");
        if (cbuf_sz == FOOTER)
            break;
        ++x;
        encode_nonce(x, nonce);
        const size_t sz = cbuf_sz - FOOTER;
        crypto_stream_salsa20_xor(pbuf, cbuf, sz, nonce, key.key);
        SHA512Update(&ctx, pbuf, sz);
        xwrite(pfd, pbuf, sz);
        cbuf_sz -= sz;
        memmove(cbuf, cbuf + sz, cbuf_sz);
    }

    assert(cbuf_sz == FOOTER);
    SHA512Final(digest, &ctx);
    check_digest(&enckey, digest, cbuf);
}

static void
encryptfile(const char* keyfile, const char* plaintext)
{
    int nr;
    char buf[PATH_MAX];

    if ((nr = snprintf(buf, sizeof(buf), "%s.enc", plaintext)) == -1 ||
            nr >= sizeof(buf))
        errx(1, "path too long");
    encrypt(keyfile, plaintext, buf);
}

static void
decryptfile(const char* keyfile, const char* ciphertext)
{
    int nr;
    char buf[PATH_MAX];
    if (strlcpy(buf, ciphertext, sizeof(buf)) >= sizeof(buf))
        errx(1, "path too long");
    if (strcmp(buf + strlen(buf) - 4, ".enc") != 0)
        errx(1, "cannot handle path %s", ciphertext);
    buf[strlen(buf) - 4] = 0;
    decrypt(keyfile, ciphertext, buf);
}

int
main(int argc, char **argv)
{
    const char *pubkeyfile = NULL, *seckeyfile = NULL;
    const char *comment = "encryptify";
    int ch, rounds;
    int embedded = 0;
    int quiet = 0;
    enum {
        NONE,
        GENERATE,
        ENCRYPT,
        DECRYPT
    } verb = NONE;

    rounds = 42;

    while ((ch = getopt(argc, argv, "GEDc:np:qs:")) != -1) {
        switch (ch) {
        case 'G':
            if (verb)
                usage(NULL);
            verb = GENERATE;
            break;
        case 'E':
            if (verb)
                usage(NULL);
            verb = ENCRYPT;
            break;
        case 'D':
            if (verb)
                usage(NULL);
            verb = DECRYPT;
            break;
        case 'c':
            comment = optarg;
            break;
        case 'n':
            rounds = 0;
            break;
        case 'p':
            pubkeyfile = optarg;
            break;
        case 'q':
            quiet = 1;
            break;
        case 's':
            seckeyfile = optarg;
            break;
        default:
            usage(NULL);
            break;
        }
    }
    argc -= optind;
    argv += optind;

    if (!verb)
        usage("must specify an action");

    if (verb == GENERATE) {
        if (!pubkeyfile || !seckeyfile)
            usage("must specify pubkey and seckey");
        generate(pubkeyfile, seckeyfile, rounds, comment);
        return 0;
    }

    if (verb == ENCRYPT) {
        if (!pubkeyfile)
            usage("must specify pubkey");
        if (argc == 0) {
            encrypt(pubkeyfile, "-", "-");
        } else {
            for (int i = 0; i < argc; ++i) {
                encryptfile(pubkeyfile, argv[i]);
            }
        }
    } else {
        if (!seckeyfile)
            usage("must specify seckey");
        if (argc == 0) {
            decrypt(seckeyfile, "-", "-");
        } else {
            for (int i = 0; i < argc; ++i) {
                decryptfile(seckeyfile, argv[i]);
            }
        }
    }

    return 0;
}
