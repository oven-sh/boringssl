// Copyright 2021 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/blake2.h>

#include <assert.h>

#include <iterator>

#include "../internal.h"

using namespace bssl;

// https://tools.ietf.org/html/rfc7693#section-2.6
static const uint64_t kIV[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179),
};

// https://tools.ietf.org/html/rfc7693#section-2.7
static const uint8_t kSigma[10 * 16] = {
    // clang-format off
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    // clang-format on
};

// https://tools.ietf.org/html/rfc7693#section-3.1
static void blake2b_mix(uint64_t v[16], int a, int b, int c, int d, uint64_t x,
                        uint64_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = CRYPTO_rotr_u64(v[d] ^ v[a], 32);
  v[c] = v[c] + v[d];
  v[b] = CRYPTO_rotr_u64(v[b] ^ v[c], 24);
  v[a] = v[a] + v[b] + y;
  v[d] = CRYPTO_rotr_u64(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = CRYPTO_rotr_u64(v[b] ^ v[c], 63);
}

static uint64_t blake2b_load(const uint8_t block[BLAKE2B_CBLOCK], size_t i) {
  return CRYPTO_load_u64_le(block + 8 * i);
}

static void blake2b_transform(BLAKE2B_CTX *b2b,
                              const uint8_t block[BLAKE2B_CBLOCK],
                              size_t num_bytes, int is_final_block) {
  // https://tools.ietf.org/html/rfc7693#section-3.2
  uint64_t v[16];
  static_assert(sizeof(v) == sizeof(b2b->h) + sizeof(kIV));
  OPENSSL_memcpy(v, b2b->h, sizeof(b2b->h));
  OPENSSL_memcpy(&v[8], kIV, sizeof(kIV));

  b2b->t_low += num_bytes;
  if (b2b->t_low < num_bytes) {
    b2b->t_high++;
  }
  v[12] ^= b2b->t_low;
  v[13] ^= b2b->t_high;

  if (is_final_block) {
    v[14] = ~v[14];
  }

  for (int round = 0; round < 12; round++) {
    const uint8_t *const s = &kSigma[16 * (round % 10)];
    blake2b_mix(v, 0, 4, 8, 12, blake2b_load(block, s[0]),
                blake2b_load(block, s[1]));
    blake2b_mix(v, 1, 5, 9, 13, blake2b_load(block, s[2]),
                blake2b_load(block, s[3]));
    blake2b_mix(v, 2, 6, 10, 14, blake2b_load(block, s[4]),
                blake2b_load(block, s[5]));
    blake2b_mix(v, 3, 7, 11, 15, blake2b_load(block, s[6]),
                blake2b_load(block, s[7]));
    blake2b_mix(v, 0, 5, 10, 15, blake2b_load(block, s[8]),
                blake2b_load(block, s[9]));
    blake2b_mix(v, 1, 6, 11, 12, blake2b_load(block, s[10]),
                blake2b_load(block, s[11]));
    blake2b_mix(v, 2, 7, 8, 13, blake2b_load(block, s[12]),
                blake2b_load(block, s[13]));
    blake2b_mix(v, 3, 4, 9, 14, blake2b_load(block, s[14]),
                blake2b_load(block, s[15]));
  }

  for (size_t i = 0; i < std::size(b2b->h); i++) {
    b2b->h[i] ^= v[i];
    b2b->h[i] ^= v[i + 8];
  }
}

void BLAKE2B256_Init(BLAKE2B_CTX *b2b) {
  OPENSSL_memset(b2b, 0, sizeof(BLAKE2B_CTX));

  static_assert(sizeof(kIV) == sizeof(b2b->h));
  OPENSSL_memcpy(&b2b->h, kIV, sizeof(kIV));

  // https://tools.ietf.org/html/rfc7693#section-2.5
  b2b->h[0] ^= 0x01010000 | BLAKE2B256_DIGEST_LENGTH;
}

void BLAKE2B256_Update(BLAKE2B_CTX *b2b, const void *in_data, size_t len) {
  if (len == 0) {
    // Work around a C language bug. See https://crbug.com/1019588.
    return;
  }

  const uint8_t *data = reinterpret_cast<const uint8_t *>(in_data);
  size_t todo = sizeof(b2b->block) - b2b->block_used;
  if (todo > len) {
    todo = len;
  }
  OPENSSL_memcpy(&b2b->block[b2b->block_used], data, todo);
  b2b->block_used += todo;
  data += todo;
  len -= todo;

  if (!len) {
    return;
  }

  // More input remains therefore we must have filled `b2b->block`.
  assert(b2b->block_used == BLAKE2B_CBLOCK);
  blake2b_transform(b2b, b2b->block, BLAKE2B_CBLOCK,
                    /*is_final_block=*/0);
  b2b->block_used = 0;

  while (len > BLAKE2B_CBLOCK) {
    blake2b_transform(b2b, data, BLAKE2B_CBLOCK, /*is_final_block=*/0);
    data += BLAKE2B_CBLOCK;
    len -= BLAKE2B_CBLOCK;
  }

  OPENSSL_memcpy(b2b->block, data, len);
  b2b->block_used = len;
}

void BLAKE2B256_Final(uint8_t out[BLAKE2B256_DIGEST_LENGTH], BLAKE2B_CTX *b2b) {
  OPENSSL_memset(&b2b->block[b2b->block_used], 0,
                 sizeof(b2b->block) - b2b->block_used);
  blake2b_transform(b2b, b2b->block, b2b->block_used,
                    /*is_final_block=*/1);
  static_assert(BLAKE2B256_DIGEST_LENGTH <= sizeof(b2b->h));
  memcpy(out, b2b->h, BLAKE2B256_DIGEST_LENGTH);
}

void BLAKE2B256(const uint8_t *data, size_t len,
                uint8_t out[BLAKE2B256_DIGEST_LENGTH]) {
  BLAKE2B_CTX ctx;
  BLAKE2B256_Init(&ctx);
  BLAKE2B256_Update(&ctx, data, len);
  BLAKE2B256_Final(out, &ctx);
}


void BLAKE2B512_Init(BLAKE2B_CTX *b2b) {
  OPENSSL_memset(b2b, 0, sizeof(BLAKE2B_CTX));

  static_assert(sizeof(kIV) == sizeof(b2b->h), "");
  OPENSSL_memcpy(&b2b->h, kIV, sizeof(kIV));

  // https://tools.ietf.org/html/rfc7693#section-2.5
  b2b->h[0] ^= 0x01010000 | BLAKE2B512_DIGEST_LENGTH;
}

void BLAKE2B512_Update(BLAKE2B_CTX *b2b, const void *in_data, size_t len) {
  const uint8_t *data = reinterpret_cast<const uint8_t *>(in_data);
  size_t todo = sizeof(b2b->block) - b2b->block_used;
  if (todo > len) {
    todo = len;
  }
  OPENSSL_memcpy(&b2b->block[b2b->block_used], data, todo);
  b2b->block_used += todo;
  data += todo;
  len -= todo;

  if (!len) {
    return;
  }

  // More input remains therefore we must have filled |b2b->block|.
  assert(b2b->block_used == BLAKE2B_CBLOCK);
  blake2b_transform(b2b, b2b->block, BLAKE2B_CBLOCK,
                    /*is_final_block=*/0);
  b2b->block_used = 0;

  while (len > BLAKE2B_CBLOCK) {
    blake2b_transform(b2b, data, BLAKE2B_CBLOCK, /*is_final_block=*/0);
    data += BLAKE2B_CBLOCK;
    len -= BLAKE2B_CBLOCK;
  }

  OPENSSL_memcpy(b2b->block, data, len);
  b2b->block_used = len;
}

void BLAKE2B512_Final(uint8_t out[BLAKE2B512_DIGEST_LENGTH], BLAKE2B_CTX *b2b) {
  OPENSSL_memset(&b2b->block[b2b->block_used], 0,
                 sizeof(b2b->block) - b2b->block_used);
  blake2b_transform(b2b, b2b->block, b2b->block_used,
                    /*is_final_block=*/1);
  static_assert(BLAKE2B512_DIGEST_LENGTH <= sizeof(b2b->h), "");
  memcpy(out, b2b->h, BLAKE2B512_DIGEST_LENGTH);
}

void BLAKE2B512(const uint8_t *data, size_t len,
                uint8_t out[BLAKE2B512_DIGEST_LENGTH]) {
  BLAKE2B_CTX ctx;
  BLAKE2B512_Init(&ctx);
  BLAKE2B512_Update(&ctx, data, len);
  BLAKE2B512_Final(out, &ctx);
}


// BLAKE2s. BLAKE2s is the 32-bit-word variant of BLAKE2b: SHA-256's IV, ten
// rounds instead of twelve, a 64-byte block, and rotation constants
// (16, 12, 8, 7). The message schedule (kSigma) is shared with BLAKE2b.

// https://tools.ietf.org/html/rfc7693#section-2.6
static const uint32_t kIVS[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// https://tools.ietf.org/html/rfc7693#section-3.1
static void blake2s_mix(uint32_t v[16], int a, int b, int c, int d, uint32_t x,
                        uint32_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = CRYPTO_rotr_u32(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = CRYPTO_rotr_u32(v[b] ^ v[c], 12);
  v[a] = v[a] + v[b] + y;
  v[d] = CRYPTO_rotr_u32(v[d] ^ v[a], 8);
  v[c] = v[c] + v[d];
  v[b] = CRYPTO_rotr_u32(v[b] ^ v[c], 7);
}

static uint32_t blake2s_load(const uint8_t block[BLAKE2S_CBLOCK], size_t i) {
  return CRYPTO_load_u32_le(block + 4 * i);
}

static void blake2s_transform(BLAKE2S_CTX *b2s,
                              const uint8_t block[BLAKE2S_CBLOCK],
                              size_t num_bytes, int is_final_block) {
  // https://tools.ietf.org/html/rfc7693#section-3.2
  uint32_t v[16];
  static_assert(sizeof(v) == sizeof(b2s->h) + sizeof(kIVS));
  OPENSSL_memcpy(v, b2s->h, sizeof(b2s->h));
  OPENSSL_memcpy(&v[8], kIVS, sizeof(kIVS));

  b2s->t_low += num_bytes;
  if (b2s->t_low < num_bytes) {
    b2s->t_high++;
  }
  v[12] ^= b2s->t_low;
  v[13] ^= b2s->t_high;

  if (is_final_block) {
    v[14] = ~v[14];
  }

  for (int round = 0; round < 10; round++) {
    const uint8_t *const s = &kSigma[16 * (round % 10)];
    blake2s_mix(v, 0, 4, 8, 12, blake2s_load(block, s[0]),
                blake2s_load(block, s[1]));
    blake2s_mix(v, 1, 5, 9, 13, blake2s_load(block, s[2]),
                blake2s_load(block, s[3]));
    blake2s_mix(v, 2, 6, 10, 14, blake2s_load(block, s[4]),
                blake2s_load(block, s[5]));
    blake2s_mix(v, 3, 7, 11, 15, blake2s_load(block, s[6]),
                blake2s_load(block, s[7]));
    blake2s_mix(v, 0, 5, 10, 15, blake2s_load(block, s[8]),
                blake2s_load(block, s[9]));
    blake2s_mix(v, 1, 6, 11, 12, blake2s_load(block, s[10]),
                blake2s_load(block, s[11]));
    blake2s_mix(v, 2, 7, 8, 13, blake2s_load(block, s[12]),
                blake2s_load(block, s[13]));
    blake2s_mix(v, 3, 4, 9, 14, blake2s_load(block, s[14]),
                blake2s_load(block, s[15]));
  }

  for (size_t i = 0; i < std::size(b2s->h); i++) {
    b2s->h[i] ^= v[i];
    b2s->h[i] ^= v[i + 8];
  }
}

void BLAKE2S256_Init(BLAKE2S_CTX *b2s) {
  OPENSSL_memset(b2s, 0, sizeof(BLAKE2S_CTX));

  static_assert(sizeof(kIVS) == sizeof(b2s->h));
  OPENSSL_memcpy(&b2s->h, kIVS, sizeof(kIVS));

  // https://tools.ietf.org/html/rfc7693#section-2.5
  b2s->h[0] ^= 0x01010000 | BLAKE2S256_DIGEST_LENGTH;
}

void BLAKE2S256_Update(BLAKE2S_CTX *b2s, const void *in_data, size_t len) {
  if (len == 0) {
    // Work around a C language bug. See https://crbug.com/1019588.
    return;
  }

  const uint8_t *data = reinterpret_cast<const uint8_t *>(in_data);
  size_t todo = sizeof(b2s->block) - b2s->block_used;
  if (todo > len) {
    todo = len;
  }
  OPENSSL_memcpy(&b2s->block[b2s->block_used], data, todo);
  b2s->block_used += todo;
  data += todo;
  len -= todo;

  if (!len) {
    return;
  }

  // More input remains therefore we must have filled `b2s->block`.
  assert(b2s->block_used == BLAKE2S_CBLOCK);
  blake2s_transform(b2s, b2s->block, BLAKE2S_CBLOCK,
                    /*is_final_block=*/0);
  b2s->block_used = 0;

  while (len > BLAKE2S_CBLOCK) {
    blake2s_transform(b2s, data, BLAKE2S_CBLOCK, /*is_final_block=*/0);
    data += BLAKE2S_CBLOCK;
    len -= BLAKE2S_CBLOCK;
  }

  OPENSSL_memcpy(b2s->block, data, len);
  b2s->block_used = len;
}

void BLAKE2S256_Final(uint8_t out[BLAKE2S256_DIGEST_LENGTH], BLAKE2S_CTX *b2s) {
  OPENSSL_memset(&b2s->block[b2s->block_used], 0,
                 sizeof(b2s->block) - b2s->block_used);
  blake2s_transform(b2s, b2s->block, b2s->block_used,
                    /*is_final_block=*/1);
  static_assert(BLAKE2S256_DIGEST_LENGTH == sizeof(b2s->h));
  for (size_t i = 0; i < std::size(b2s->h); i++) {
    CRYPTO_store_u32_le(out + 4 * i, b2s->h[i]);
  }
}

void BLAKE2S256(const uint8_t *data, size_t len,
                uint8_t out[BLAKE2S256_DIGEST_LENGTH]) {
  BLAKE2S_CTX ctx;
  BLAKE2S256_Init(&ctx);
  BLAKE2S256_Update(&ctx, data, len);
  BLAKE2S256_Final(out, &ctx);
}
