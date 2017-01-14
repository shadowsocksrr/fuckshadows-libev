/*
 * encrypt.h - Define the enryptor's interface
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

#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#ifndef __MINGW32__
#include <sys/socket.h>
#else

#ifdef max
#undef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifdef min
#undef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#if defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/cipher.h>

/* TODO: replace with gcm cipher context type */
typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_cipher_context_t cipher_evp_t;

/* The length of MAC tag
 * libsodium only outputs exactly *_ABYTES
 * while mbedtls can choose variable length
 * thus, we choose the larger one in case
 * auth failed due to truncated tag
 */
#define MAX_TAG_LENGTH 16U

/* In general, most of them are 32U, we make it a little larger */
#define MAX_KEY_LENGTH 64U

/* In general, max IV len is 16U */
#define MAX_IV_LENGTH MBEDTLS_MAX_IV_LENGTH

#endif

#define SODIUM_BLOCK_SIZE   64
#define ADDRTYPE_MASK 0xF

/* to be determined */
#define AEAD_BYTES 10U
#define CHUNKLEN_BYTES 2U
#define AUTH_BYTES (AEAD_BYTES + CHUNKLEN_BYTES)

typedef struct {
    cipher_evp_t *evp;
    uint8_t iv[MAX_IV_LENGTH];
} cipher_ctx_t;

typedef struct {
    cipher_kt_t *info;
    size_t iv_len;
    size_t key_len;
} cipher_t;

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define CIPHER_NUM          7

/* now focus on chacha20-poly1305 */
#define NONE                    (-1)
#define AES128GCM               0
#define AES192GCM               1
#define AES256GCM               2
/*
 * methods above requires gcm context
 * methods below doesn't require it,
 * then we need to fake one
 */
#define CHACHA20POLY1305        3
#define CHACHA20POLY1305IETF    4
#define XCHACHA20POLY1305       5
#define XCHACHA20POLY1305IETF   6

typedef struct buffer {
    size_t idx;
    size_t len;
    size_t capacity;
    char   *data;
} buffer_t;

typedef struct chunk {
    uint32_t idx;
    uint32_t len;
    uint32_t counter;
    buffer_t *buf;
} chunk_t;

typedef struct enc_ctx {
    uint8_t init;
    uint64_t counter;
    cipher_ctx_t evp;
} enc_ctx_t;

int ss_encrypt_all(buffer_t *plaintext, int method, int auth, size_t capacity);
int ss_decrypt_all(buffer_t *ciphertext, int method, int auth, size_t capacity);
int ss_encrypt(buffer_t *plaintext, enc_ctx_t *ctx, size_t capacity);
int ss_decrypt(buffer_t *ciphertext, enc_ctx_t *ctx, size_t capacity);

void enc_ctx_init(int method, enc_ctx_t *ctx, int enc);
int enc_init(const char *pass, const char *method);
int enc_get_iv_len(void);
void cipher_context_release(cipher_ctx_t *evp);
unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);

int ss_onetimeauth(buffer_t *buf, uint8_t *iv, size_t capacity);
int ss_onetimeauth_verify(buffer_t *buf, uint8_t *iv);

int ss_check_hash(buffer_t *buf, chunk_t *chunk, enc_ctx_t *ctx, size_t capacity);
int ss_gen_hash(buffer_t *buf, uint32_t *counter, enc_ctx_t *ctx, size_t capacity);

int balloc(buffer_t *ptr, size_t capacity);
int brealloc(buffer_t *ptr, size_t len, size_t capacity);
void bfree(buffer_t *ptr);

int rand_bytes(void *output, int len);

#endif // _ENCRYPT_H
