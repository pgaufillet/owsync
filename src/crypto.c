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
#include "crypto.h"

#ifdef ENABLE_ENCRYPTION

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/*
 * Create AES-256-GCM encryption context from hex-encoded key.
 * Key must be exactly 64 hex characters (256 bits).
 */
security_context_t *security_context_new(const char *key_hex) {
    if (!key_hex) return NULL;

    /* Decode hex key to binary */
    size_t key_len = 0;
    uint8_t *key_bytes = hex_decode(key_hex, &key_len);
    if (!key_bytes || key_len != AES_KEY_SIZE) {
        free(key_bytes);
        return NULL;
    }

    security_context_t *ctx = malloc(sizeof(security_context_t));
    if (!ctx) {
        free(key_bytes);
        return NULL;
    }

    memcpy(ctx->key, key_bytes, AES_KEY_SIZE);
    free(key_bytes);

    /* Create reusable OpenSSL cipher context */
    ctx->ctx = EVP_CIPHER_CTX_new();
    if (!ctx->ctx) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

/* Free context and securely clear key from memory */
void security_context_free(security_context_t *ctx) {
    if (!ctx) return;
    if (ctx->ctx) {
        EVP_CIPHER_CTX_free(ctx->ctx);
    }
    /* Secure clear prevents key recovery from memory dumps */
    explicit_bzero(ctx->key, AES_KEY_SIZE);
    free(ctx);
}

/*
 * Encrypt plaintext using AES-256-GCM.
 *
 * Output format: [12-byte nonce][ciphertext][16-byte auth tag]
 *
 * Nonce is generated randomly for each message (safe for GCM with 96-bit nonce).
 * Auth tag provides integrity/authenticity verification.
 */
int security_encrypt(security_context_t *ctx, const uint8_t *plaintext,
                     size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len) {
    if (!ctx || !plaintext || !ciphertext || !ciphertext_len) {
        return OWSYNC_ERROR;
    }

    /* Generate random 96-bit nonce */
    uint8_t nonce[AES_NONCE_SIZE];
    if (RAND_bytes(nonce, AES_NONCE_SIZE) != 1) {
        return OWSYNC_ERROR_CRYPTO;
    }

    /* Overflow check for output buffer size */
    if (plaintext_len > SIZE_MAX - EVP_MAX_BLOCK_LENGTH - 16 - AES_NONCE_SIZE) {
        return OWSYNC_ERROR_CRYPTO;
    }

    size_t max_output_len = plaintext_len + EVP_MAX_BLOCK_LENGTH + 16;
    if (max_output_len > MAX_MESSAGE_SIZE) {
        return OWSYNC_ERROR_CRYPTO;
    }

    /* Allocate output: nonce + ciphertext + tag */
    uint8_t *output = malloc(AES_NONCE_SIZE + max_output_len);
    if (!output) {
        return OWSYNC_ERROR_MEMORY;
    }

    /* Prepend nonce to output */
    memcpy(output, nonce, AES_NONCE_SIZE);

    if (EVP_EncryptInit_ex(ctx->ctx, EVP_aes_256_gcm(), NULL, ctx->key, nonce) != 1) {
        free(output);
        return OWSYNC_ERROR_CRYPTO;
    }

    int len = 0;
    if (EVP_EncryptUpdate(ctx->ctx, output + AES_NONCE_SIZE, &len, plaintext, plaintext_len) != 1) {
        free(output);
        return OWSYNC_ERROR_CRYPTO;
    }
    int total_len = len;

    if (EVP_EncryptFinal_ex(ctx->ctx, output + AES_NONCE_SIZE + len, &len) != 1) {
        free(output);
        return OWSYNC_ERROR_CRYPTO;
    }
    total_len += len;

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        free(output);
        return OWSYNC_ERROR_CRYPTO;
    }
    memcpy(output + AES_NONCE_SIZE + total_len, tag, 16);
    total_len += 16;

    *ciphertext = output;
    *ciphertext_len = AES_NONCE_SIZE + total_len;

    return OWSYNC_OK;
}

/*
 * Decrypt and authenticate ciphertext using AES-256-GCM.
 *
 * Input format: [12-byte nonce][ciphertext][16-byte auth tag]
 *
 * Returns OWSYNC_ERROR_CRYPTO if:
 *   - Message too short (missing nonce or tag)
 *   - Authentication tag verification fails (tampering detected)
 */
int security_decrypt(security_context_t *ctx, const uint8_t *ciphertext,
                     size_t ciphertext_len, uint8_t **plaintext, size_t *plaintext_len) {
    if (!ctx || !ciphertext || !plaintext || !plaintext_len) {
        return OWSYNC_ERROR;
    }

    /* Minimum size: nonce (12) + tag (16) = 28 bytes */
    if (ciphertext_len < AES_NONCE_SIZE + 16) {
        return OWSYNC_ERROR_CRYPTO;
    }

    /* Parse wire format: [nonce][encrypted_data][tag] */
    const uint8_t *nonce = ciphertext;
    const uint8_t *encrypted_data = ciphertext + AES_NONCE_SIZE;
    size_t encrypted_len = ciphertext_len - AES_NONCE_SIZE - 16;
    const uint8_t *tag = ciphertext + ciphertext_len - 16;

    uint8_t *output = malloc(encrypted_len + EVP_MAX_BLOCK_LENGTH);
    if (!output) {
        return OWSYNC_ERROR_MEMORY;
    }

    if (EVP_DecryptInit_ex(ctx->ctx, EVP_aes_256_gcm(), NULL, ctx->key, nonce) != 1) {
        free(output);
        return OWSYNC_ERROR_CRYPTO;
    }

    int len = 0;
    if (EVP_DecryptUpdate(ctx->ctx, output, &len, encrypted_data, encrypted_len) != 1) {
        free(output);
        return OWSYNC_ERROR_CRYPTO;
    }
    int total_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
        free(output);
        return OWSYNC_ERROR_CRYPTO;
    }

    if (EVP_DecryptFinal_ex(ctx->ctx, output + len, &len) != 1) {
        free(output);
        return OWSYNC_ERROR_CRYPTO;
    }
    total_len += len;

    *plaintext = output;
    *plaintext_len = total_len;

    return OWSYNC_OK;
}

/* Generate cryptographically secure random 256-bit key */
char *security_generate_key(void) {
    uint8_t key[AES_KEY_SIZE];
    if (RAND_bytes(key, AES_KEY_SIZE) != 1) {
        return NULL;
    }
    return hex_encode(key, AES_KEY_SIZE);  /* Returns 64-char hex string */
}

#endif
