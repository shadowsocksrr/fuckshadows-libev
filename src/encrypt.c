/*
 * encrypt.c - Manage the global encryptor
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

// TODO: enlarge buffer to hold tag
#include <stdint.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/version.h>
#define CIPHER_UNSUPPORTED "unsupported"

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

#endif

#include <sodium.h>

#ifndef __MINGW32__
#include <arpa/inet.h>
#endif

#include "cache.h"
#include "encrypt.h"
#include "utils.h"

/*
 *
 * TCP and UDP
 * +----------+
 * | Payload  |
 * +----------+
 * | Variable |
 * +----------+
 *
 * Cipher Text (Payload)
 * +--------+-------+----------+
 * | NONCE  |  TAG  |  DATA    |
 * +--------+-------+----------+
 * | Fixed  | Fixed | Variable |
 * +--------+-------+----------+
 *
 * NONCE and TAG are the max length
 * of available methods. (12 + 16)
 *
 */

/* several global vars
 *
 *
 */
static uint8_t enc_key[MAX_KEY_LENGTH];
static int enc_key_len;
static int enc_iv_len;
static int enc_tag_len;
static int enc_method;

static struct cache *iv_cache;

#ifdef DEBUG
static void
dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", (uint8_t)text[i]);
    printf("\n");
}

#endif

static const char *supported_ciphers[CIPHER_NUM] = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-poly1305-ietf",
#ifdef FS_HAVE_XCHACHA20IETF
    "xchacha20-poly1305-ietf"
#endif
};

/*
 * use mbed TLS cipher wrapper to unify handling
 */
#ifdef USE_CRYPTO_MBEDTLS
static const char *supported_ciphers_mbedtls[CIPHER_NUM] = {
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
#ifdef FS_HAVE_XCHACHA20IETF
    CIPHER_UNSUPPORTED
#endif
};
#endif

static const int supported_ciphers_iv_size[CIPHER_NUM] = {
    12, 12, 12, 8, 12,
#ifdef FS_HAVE_XCHACHA20IETF
    24
#endif
};

static const int supported_ciphers_key_size[CIPHER_NUM] = {
    16, 24, 32, 32, 32,
#ifdef FS_HAVE_XCHACHA20IETF
    32
#endif
};

static const int supported_ciphers_tag_size[CIPHER_NUM] = {
    16, 16, 16, 16, 16,
#ifdef FS_HAVE_XCHACHA20IETF
    16
#endif
};

int
balloc(buffer_t *ptr, size_t capacity)
{
    sodium_memzero(ptr, sizeof(buffer_t));
    ptr->data     = ss_malloc(capacity);
    ptr->capacity = capacity;
    return capacity;
}

int
brealloc(buffer_t *ptr, size_t len, size_t capacity)
{
    if (ptr == NULL)
        return -1;
    size_t real_capacity = max(len, capacity);
    if (ptr->capacity < real_capacity) {
        ptr->data     = ss_realloc(ptr->data, real_capacity);
        ptr->capacity = real_capacity;
    }
    return real_capacity;
}

void
bfree(buffer_t *ptr)
{
    if (ptr == NULL)
        return;
    ptr->idx      = 0;
    ptr->len      = 0;
    ptr->capacity = 0;
    if (ptr->data != NULL) {
        ss_free(ptr->data);
    }
}

int
enc_get_iv_len()
{
    return enc_iv_len;
}

int
enc_get_tag_len()
{
    return enc_tag_len;
}

int
cipher_iv_size(const cipher_t *cipher)
{
#if defined(USE_CRYPTO_MBEDTLS)
    if (cipher == NULL) {
        return 0;
    }
    return cipher->info->iv_size;
#endif
}

int
cipher_key_size(const cipher_t *cipher)
{
#if defined(USE_CRYPTO_MBEDTLS)
    if (cipher == NULL) {
        return 0;
    }
    /* From Version 1.2.7 released 2013-04-13 Default Blowfish keysize is now 128-bits */
    return cipher->info->key_bitlen / 8;
#endif
}

/*
 * TODO: convert to Argon2 password hashing
 *
 */
int
derive_key(const cipher_t *cipher,
           const uint8_t *pass,
           uint8_t *key)
{
    if (pass == NULL) {
        LOGE("derive_key(): password is empty");
        return 0;
    }
    int key_size    = cipher_key_size(cipher);
    size_t pass_len = strlen((const char *)pass);
    int ret         = crypto_generichash(key, key_size,
                                         pass, pass_len,
                                         NULL, 0);
    if (ret != 0) {
        LOGE("derive_key(): failed to generic hash");
        return 0;
    }
    return key_size;
}

int
rand_bytes(void *output, int len)
{
    randombytes_buf(output, len);
    // always return success
    return 0;
}

/* nsec: always NULL
 * npub: nonce
 */
int
sodium_aead_encrypt(unsigned char *c,
                    unsigned char *mac,
                    unsigned long long *maclen_p,
                    const unsigned char *m,
                    unsigned long long mlen,
                    const unsigned char *ad,
                    unsigned long long adlen,
                    const unsigned char *nsec,
                    const unsigned char *npub,
                    const unsigned char *k,
                    int method)
{
    switch (method) {
    case CHACHA20POLY1305:
        return crypto_aead_chacha20poly1305_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k);
    case CHACHA20POLY1305IETF:
        return crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k);
#ifdef FS_HAVE_XCHACHA20IETF
    case XCHACHA20POLY1305IETF:
        return crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k);
#endif
    }
    // We should not reach here.
    return -2;
}

int
sodium_aead_decrypt(unsigned char *m,
                    unsigned char *nsec,
                    const unsigned char *c,
                    unsigned long long clen,
                    const unsigned char *mac,
                    const unsigned char *ad,
                    unsigned long long adlen,
                    const unsigned char *npub,
                    const unsigned char *k,
                    int method)
{
    switch (method) {
    case CHACHA20POLY1305:
        return crypto_aead_chacha20poly1305_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k);
    case CHACHA20POLY1305IETF:
        return crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k);
#ifdef FS_HAVE_XCHACHA20IETF
    case XCHACHA20POLY1305IETF:
        return crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k);
#endif
    }
    // We should not reach here.
    return -2;
}

/*
 * get basic cipher info structure
 * it's a wrapper offered by crypto library
 */
const cipher_kt_t *
get_cipher_type(int method)
{
    if (method < AES128GCM || method >= CIPHER_NUM) {
        LOGE("get_cipher_type(): Illegal method");
        return NULL;
    }

    /* cipher that don't use mbed TLS, just return */
    if (method >= CHACHA20POLY1305) {
        return NULL;
    }

    const char *ciphername = supported_ciphers[method];
#if defined(USE_CRYPTO_MBEDTLS)
    const char *mbedtlsname = supported_ciphers_mbedtls[method];
    if (strcmp(mbedtlsname, CIPHER_UNSUPPORTED) == 0) {
        LOGE("Cipher %s currently is not supported by mbed TLS library",
             ciphername);
        return NULL;
    }
    return mbedtls_cipher_info_from_string(mbedtlsname);
#endif
}

void
cipher_context_init(cipher_ctx_t *ctx, int method, int enc)
{
    if (method < AES128GCM || method >= CIPHER_NUM) {
        LOGE("cipher_context_init(): Illegal method");
        return;
    }

    if (method >= CHACHA20POLY1305) {
        enc_iv_len = supported_ciphers_iv_size[method];
        return;
    }

    const char *ciphername = supported_ciphers[method];

    const cipher_kt_t *cipher = get_cipher_type(method);

#if defined(USE_CRYPTO_MBEDTLS)
    ctx->evp = ss_malloc(sizeof(cipher_evp_t));
    memset(ctx->evp, 0, sizeof(cipher_evp_t));
    cipher_evp_t *evp = ctx->evp;

    if (cipher == NULL) {
        LOGE("Cipher %s not found in mbed TLS library", ciphername);
        FATAL("Cannot initialize mbed TLS cipher");
    }
    mbedtls_cipher_init(evp);
    if (mbedtls_cipher_setup(evp, cipher) != 0) {
        FATAL("Cannot initialize mbed TLS cipher context");
    }
    if (mbedtls_cipher_setkey(evp, enc_key, enc_key_len * 8, enc) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher key");
    }

#ifdef DEBUG
    dump("KEY", (char *)enc_key, enc_key_len);
#endif

#endif
}

void
cipher_context_set_iv(cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len,
                      int enc)
{
    if (iv == NULL) {
        LOGE("cipher_context_set_iv(): IV is null");
        return;
    }

    if (!enc) {
        memcpy(ctx->iv, iv, iv_len);
    }

    if (enc_method >= CHACHA20POLY1305) {
        return;
    }

    cipher_evp_t *evp = ctx->evp;
    if (evp == NULL) {
        LOGE("cipher_context_set_iv(): Cipher context is null");
        return;
    }
#if defined(USE_CRYPTO_MBEDTLS)

    if (mbedtls_cipher_set_iv(evp, iv, iv_len) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher IV");
    }
    if (mbedtls_cipher_reset(evp) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot finish preparation of mbed TLS cipher context");
    }
#endif

#ifdef DEBUG
    dump("IV", (char *)iv, iv_len);
#endif
}

static int
cipher_context_update(cipher_ctx_t *ctx, uint8_t *output, size_t *olen,
                      const uint8_t *input, size_t ilen)
{
    cipher_evp_t *evp = ctx->evp;
#if defined(USE_CRYPTO_MBEDTLS)
    return !mbedtls_cipher_update(evp, (const uint8_t *)input, ilen,
                                  (uint8_t *)output, olen);
#endif
}

void
cipher_context_release(cipher_ctx_t *ctx)
{
    if (enc_method >= CHACHA20POLY1305) {
        return;
    }

#if defined(USE_CRYPTO_MBEDTLS)
    mbedtls_cipher_free(ctx->evp);
    ss_free(ctx->evp);
#endif
}

int
ss_encrypt_all(buffer_t *plain, int method, size_t capacity)
{
    cipher_ctx_t evp;
    cipher_context_init(&evp, method, 1);

    size_t iv_len = enc_iv_len;
    int err       = 1;

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, iv_len + plain->len, capacity);
    buffer_t *cipher = &tmp;
    cipher->len = plain->len;

    uint8_t iv[MAX_IV_LENGTH];

    rand_bytes(iv, iv_len);
    cipher_context_set_iv(&evp, iv, iv_len, 1);
    memcpy(cipher->data, iv, iv_len);

    if (method >= CHACHA20POLY1305) {
        /* do what we want directly */
    } else {
        err = cipher_context_update(&evp, (uint8_t *)(cipher->data + iv_len),
                                    &cipher->len, (const uint8_t *)plain->data,
                                    plain->len);
    }

    if (!err) {
        bfree(plain);
        cipher_context_release(&evp);
        return -1;
    }

#ifdef DEBUG
    dump("PLAIN", plain->data, plain->len);
    dump("CIPHER", cipher->data + iv_len, cipher->len);
#endif

    cipher_context_release(&evp);

    brealloc(plain, iv_len + cipher->len, capacity);
    memcpy(plain->data, cipher->data, iv_len + cipher->len);
    plain->len = iv_len + cipher->len;

    return 0;
}

int
ss_encrypt(buffer_t *plain, enc_ctx_t *ctx, size_t capacity)
{
    static buffer_t tmp = { 0, 0, 0, NULL };

    int err       = 1;
    size_t iv_len = 0;
    if (!ctx->init) {
        iv_len = enc_iv_len;
    }

    brealloc(&tmp, iv_len + plain->len, capacity);
    buffer_t *cipher = &tmp;
    cipher->len = plain->len;

    if (!ctx->init) {
        cipher_context_set_iv(&ctx->evp, ctx->evp.iv, iv_len, 1);
        memcpy(cipher->data, ctx->evp.iv, iv_len);
        ctx->init = 1;
    }
    if (enc_method >= CHACHA20POLY1305) {
        /* do what we want directly */
    } else {
        err =
            cipher_context_update(&ctx->evp,
                                  (uint8_t *)(cipher->data + iv_len),
                                  &cipher->len, (const uint8_t *)plain->data,
                                  plain->len);
    }
    if (!err) {
        return -1;
    }

#ifdef DEBUG
    dump("PLAIN", plain->data, plain->len);
    dump("CIPHER", cipher->data + iv_len, cipher->len);
#endif

    brealloc(plain, iv_len + cipher->len, capacity);
    memcpy(plain->data, cipher->data, iv_len + cipher->len);
    plain->len = iv_len + cipher->len;

    return 0;
}

int
ss_decrypt_all(buffer_t *cipher, int method, size_t capacity)
{
    size_t iv_len = enc_iv_len;
    int ret       = 1;

    if (cipher->len <= iv_len) {
        return -1;
    }

    cipher_ctx_t evp;
    cipher_context_init(&evp, method, 0);

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, cipher->len, capacity);
    buffer_t *plain = &tmp;
    plain->len = cipher->len - iv_len;

    uint8_t iv[MAX_IV_LENGTH];
    memcpy(iv, cipher->data, iv_len);
    cipher_context_set_iv(&evp, iv, iv_len, 0);

    if (enc_method >= CHACHA20POLY1305) {
        /* do what we want directly */
    } else {
        ret = cipher_context_update(&evp, (uint8_t *)plain->data, &plain->len,
                                    (const uint8_t *)(cipher->data + iv_len),
                                    cipher->len - iv_len);
    }

    if (!ret) {
        bfree(cipher);
        cipher_context_release(&evp);
        return -1;
    }

#ifdef DEBUG
    dump("PLAIN", plain->data, plain->len);
    dump("CIPHER", cipher->data + iv_len, cipher->len - iv_len);
#endif

    cipher_context_release(&evp);

    brealloc(cipher, plain->len, capacity);
    memcpy(cipher->data, plain->data, plain->len);
    cipher->len = plain->len;

    return 0;
}

int
ss_decrypt(buffer_t *cipher, enc_ctx_t *ctx, size_t capacity)
{
    static buffer_t tmp = { 0, 0, 0, NULL };

    size_t iv_len = 0;
    int err       = 1;

    brealloc(&tmp, cipher->len, capacity);
    buffer_t *plain = &tmp;
    plain->len = cipher->len;

    if (!ctx->init) {
        uint8_t iv[MAX_IV_LENGTH];
        iv_len      = enc_iv_len;
        plain->len -= iv_len;

        memcpy(iv, cipher->data, iv_len);
        cipher_context_set_iv(&ctx->evp, iv, iv_len, 0);
        ctx->init = 1;

        if (cache_key_exist(iv_cache, (char *)iv, iv_len)) {
            bfree(cipher);
            return -1;
        } else {
            cache_insert(iv_cache, (char *)iv, iv_len, NULL);
        }
    }

    if (enc_method >= CHACHA20POLY1305) {
        /* do what we want directly */
    } else {
        err = cipher_context_update(&ctx->evp, (uint8_t *)plain->data, &plain->len,
                                    (const uint8_t *)(cipher->data + iv_len),
                                    cipher->len - iv_len);
    }

    if (!err) {
        bfree(cipher);
        return -1;
    }

#ifdef DEBUG
    dump("PLAIN", plain->data, plain->len);
    dump("CIPHER", cipher->data + iv_len, cipher->len - iv_len);
#endif

    brealloc(cipher, plain->len, capacity);
    memcpy(cipher->data, plain->data, plain->len);
    cipher->len = plain->len;

    return 0;
}

void
enc_ctx_init(int method, enc_ctx_t *ctx, int enc)
{
    sodium_memzero(ctx, sizeof(enc_ctx_t));
    cipher_context_init(&ctx->evp, method, enc);

    if (enc) {
        rand_bytes(ctx->evp.iv, enc_iv_len);
    }
}

/*
 * initialize encryption key based on password
 * inputed by user
 */
void
enc_key_init(int method, const char *pass)
{
    if (method < AES128GCM || method >= CIPHER_NUM) {
        LOGE("enc_key_init(): Illegal method");
        return;
    }

    cipher_kt_t cipher_info;

    cipher_t cipher;
    memset(&cipher, 0, sizeof(cipher_t));

    if (method >= CHACHA20POLY1305) {
        /*
         * fake cipher context info
         * since they don't really need it
         * just to keep things consistent
         */
#if defined(USE_CRYPTO_MBEDTLS)
        cipher.info             = &cipher_info;
        cipher.info->base       = NULL;
        cipher.info->key_bitlen = supported_ciphers_key_size[method] * 8;
        cipher.info->iv_size    = supported_ciphers_iv_size[method];
#endif
    } else {
        cipher.info = (cipher_kt_t *)get_cipher_type(method);
    }

    if (cipher.info == NULL && cipher.key_len == 0) {
        do {
            LOGE("Cipher %s not found in crypto library", supported_ciphers[method]);
            FATAL("Cannot initialize cipher");
        } while (0);
    }

    /* we should derive key here instead just use md5 */
    enc_key_len = derive_key(&cipher, (const uint8_t *)pass, enc_key);

    if (enc_key_len == 0) {
        FATAL("Cannot generate key and IV");
    }

    enc_iv_len  = cipher_iv_size(&cipher);
    enc_tag_len = supported_ciphers_tag_size[method];
    enc_method  = method;
}

/*
 * TODO: do we really need additional data input by user?
 * determine the encryption method to be used
 */
int
enc_init(const char *pass, const char *method)
{
    int m = AES128GCM;
    if (method != NULL) {
        /* check method validity */
        for (m = AES128GCM; m < CIPHER_NUM; m++)
            if (strcmp(method, supported_ciphers[m]) == 0) {
                break;
            }
        if (m >= CIPHER_NUM) {
            LOGE("Invalid cipher name: %s, use aes-256-gcm instead", method);
            m = AES256GCM;
        }
    }

    // Initialize sodium for random generator
    if (sodium_init() == -1) {
        FATAL("Failed to initialize sodium");
    }

    // Initialize IV cache
    cache_create(&iv_cache, 1024, NULL);

    enc_key_init(m, pass);
    return m;
}
