/*
 * Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef OWSYNC_CRYPTO_H
#define OWSYNC_CRYPTO_H

#include "common.h"

#ifdef ENABLE_ENCRYPTION

#include <openssl/evp.h>

/* AES-256-GCM encryption context for message-level encryption */
typedef struct {
    uint8_t key[AES_KEY_SIZE];  /* 256-bit key derived from hex PSK */
    EVP_CIPHER_CTX *ctx;        /* OpenSSL cipher context (reusable) */
} security_context_t;

/* Create context from 64-char hex key. Returns NULL on invalid key. */
security_context_t *security_context_new(const char *key_hex);

/* Free context and securely clear key material */
void security_context_free(security_context_t *ctx);

/*
 * Encrypt plaintext using AES-256-GCM.
 * Output format: [12-byte nonce][ciphertext][16-byte auth tag]
 * Caller must free *ciphertext.
 */
int security_encrypt(security_context_t *ctx, const uint8_t *plaintext,
                     size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len);

/*
 * Decrypt and authenticate ciphertext.
 * Returns OWSYNC_ERROR_CRYPTO on authentication failure.
 * Caller must free *plaintext.
 */
int security_decrypt(security_context_t *ctx, const uint8_t *ciphertext,
                     size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len);

/* Generate 256-bit random key, returns 64-char hex string */
char *security_generate_key(void);

#endif

#endif
