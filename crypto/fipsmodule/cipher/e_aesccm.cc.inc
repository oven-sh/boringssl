// Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
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

#include <openssl/aead.h>

#include <assert.h>

#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/span.h>

#include "../aes/internal.h"
#include "../delocate.h"
#include "../service_indicator/internal.h"
#include "internal.h"


using namespace bssl;

struct ccm128_context {
  block128_f block;
  ctr128_f ctr;
  unsigned M, L;
};

struct ccm128_state {
  alignas(16) uint8_t nonce[16];
  alignas(16) uint8_t cmac[16];
};

static int CRYPTO_ccm128_init(struct ccm128_context *ctx, const AES_KEY *key,
                              block128_f block, ctr128_f ctr, unsigned M,
                              unsigned L) {
  if (M < 4 || M > 16 || (M & 1) != 0 || L < 2 || L > 8) {
    return 0;
  }
  ctx->block = block;
  ctx->ctr = ctr;
  ctx->M = M;
  ctx->L = L;
  return 1;
}

static size_t CRYPTO_ccm128_max_input(const struct ccm128_context *ctx) {
  return ctx->L >= sizeof(size_t) ? SIZE_MAX
                                  : (((size_t)1) << (ctx->L * 8)) - 1;
}

static int ccm128_init_state(const struct ccm128_context *ctx,
                             struct ccm128_state *state, const AES_KEY *key,
                             Span<const uint8_t> nonce,
                             Span<const CRYPTO_IVEC> aadvecs,
                             size_t plaintext_len) {
  const block128_f block = ctx->block;
  const unsigned M = ctx->M;
  const unsigned L = ctx->L;

  // `L` determines the expected `nonce_len` and the limit for `plaintext_len`.
  if (plaintext_len > CRYPTO_ccm128_max_input(ctx)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }
  if (nonce.size() != 15 - L) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  // Assemble the first block for computing the MAC.
  OPENSSL_memset(state, 0, sizeof(*state));
  state->nonce[0] = (uint8_t)((L - 1) | ((M - 2) / 2) << 3);
  size_t aad_len = bssl::iovec::TotalLength(aadvecs);
  if (aad_len != 0) {
    state->nonce[0] |= 0x40;  // Set AAD Flag
  }
  OPENSSL_memcpy(&state->nonce[1], nonce.data(), nonce.size());
  for (unsigned i = 0; i < L; i++) {
    state->nonce[15 - i] = (uint8_t)(plaintext_len >> (8 * i));
  }

  (*block)(state->nonce, state->cmac, key);
  size_t blocks = 1;

  if (aad_len != 0) {
    unsigned i;
    // Cast to u64 to avoid the compiler complaining about invalid shifts.
    uint64_t aad_len_u64 = aad_len;
    if (aad_len_u64 < 0x10000 - 0x100) {
      state->cmac[0] ^= (uint8_t)(aad_len_u64 >> 8);
      state->cmac[1] ^= (uint8_t)aad_len_u64;
      i = 2;
    } else if (aad_len_u64 <= 0xffffffff) {
      state->cmac[0] ^= 0xff;
      state->cmac[1] ^= 0xfe;
      state->cmac[2] ^= (uint8_t)(aad_len_u64 >> 24);
      state->cmac[3] ^= (uint8_t)(aad_len_u64 >> 16);
      state->cmac[4] ^= (uint8_t)(aad_len_u64 >> 8);
      state->cmac[5] ^= (uint8_t)aad_len_u64;
      i = 6;
    } else {
      state->cmac[0] ^= 0xff;
      state->cmac[1] ^= 0xff;
      state->cmac[2] ^= (uint8_t)(aad_len_u64 >> 56);
      state->cmac[3] ^= (uint8_t)(aad_len_u64 >> 48);
      state->cmac[4] ^= (uint8_t)(aad_len_u64 >> 40);
      state->cmac[5] ^= (uint8_t)(aad_len_u64 >> 32);
      state->cmac[6] ^= (uint8_t)(aad_len_u64 >> 24);
      state->cmac[7] ^= (uint8_t)(aad_len_u64 >> 16);
      state->cmac[8] ^= (uint8_t)(aad_len_u64 >> 8);
      state->cmac[9] ^= (uint8_t)aad_len_u64;
      i = 10;
    }

    while (!aadvecs.empty() && aadvecs.front().len == 0) {
      aadvecs = aadvecs.subspan(1);
    }
    size_t offset = 0;
    while (!aadvecs.empty()) {
      for (; i < 16 && !aadvecs.empty(); i++) {
        state->cmac[i] ^= aadvecs.front().in[offset];
        ++offset;
        if (offset >= aadvecs.front().len) {
          aadvecs = aadvecs.subspan(1);
          while (!aadvecs.empty() && aadvecs.front().len == 0) {
            aadvecs = aadvecs.subspan(1);
          }
          offset = 0;
        }
      }
      (*block)(state->cmac, state->cmac, key);
      blocks++;
      i = 0;
    }
  }

  // Per RFC 3610, section 2.6, the total number of block cipher operations done
  // must not exceed 2^61. There are two block cipher operations remaining per
  // message block, plus one block at the end to encrypt the MAC.
  size_t remaining_blocks = 2 * ((plaintext_len + 15) / 16) + 1;
  if (plaintext_len + 15 < plaintext_len ||
      remaining_blocks + blocks < blocks ||
      (uint64_t)remaining_blocks + blocks > UINT64_C(1) << 61) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  // Assemble the first block for encrypting and decrypting. The bottom `L`
  // bytes are replaced with a counter and all bit the encoding of `L` is
  // cleared in the first byte.
  state->nonce[0] &= 7;
  return 1;
}

static int ccm128_encrypt(const struct ccm128_context *ctx,
                          struct ccm128_state *state, const AES_KEY *key,
                          Span<const CRYPTO_IOVEC> iovecs) {
  // The counter for encryption begins at one.
  for (unsigned i = 0; i < ctx->L; i++) {
    state->nonce[15 - i] = 0;
  }
  state->nonce[15] = 1;

  uint8_t partial_buf[16];
  unsigned num = 0;
  for (const CRYPTO_IOVEC &iovec : iovecs) {
    CRYPTO_ctr128_encrypt_ctr32(iovec.in, iovec.out, iovec.len, key,
                                state->nonce, partial_buf, &num, ctx->ctr);
  }
  return 1;
}

static int ccm128_compute_mac(const struct ccm128_context *ctx,
                              struct ccm128_state *state, const AES_KEY *key,
                              Span<uint8_t> out_tag,
                              Span<const CRYPTO_IOVEC> iovecs, bool encrypt) {
  block128_f block = ctx->block;
  if (out_tag.size() != ctx->M) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  auto update_mac = [&](const uint8_t *in, size_t len) {
    while (len >= 16) {
      CRYPTO_xor16(state->cmac, state->cmac, in);
      (*block)(state->cmac, state->cmac, key);
      in += 16;
      len -= 16;
    }
    if (len != 0) {
      for (size_t i = 0; i < len; i++) {
        state->cmac[i] ^= in[i];
      }
      (*block)(state->cmac, state->cmac, key);
    }
    return true;
  };

  // Incorporate the plaintext into the MAC.
  if (encrypt) {
    bssl::iovec::ForEachBlockRange<16>(iovecs, update_mac, update_mac);
  } else {
    bssl::iovec::ForEachOutBlockRange<16>(iovecs, update_mac, update_mac);
  }

  // Encrypt the MAC with counter zero.
  for (unsigned i = 0; i < ctx->L; i++) {
    state->nonce[15 - i] = 0;
  }
  alignas(16) uint8_t tmp[16];
  (*block)(state->nonce, tmp, key);
  CRYPTO_xor16(state->cmac, state->cmac, tmp);

  CopySpan(Span(state->cmac).first(out_tag.size()), out_tag);
  return 1;
}

static int CRYPTO_ccm128_encrypt(const struct ccm128_context *ctx,
                                 const AES_KEY *key,
                                 Span<const CRYPTO_IOVEC> iovecs,
                                 Span<uint8_t> out_tag,
                                 Span<const uint8_t> nonce,
                                 Span<const CRYPTO_IVEC> aadvecs) {
  struct ccm128_state state;
  return ccm128_init_state(ctx, &state, key, nonce, aadvecs,
                           bssl::iovec::TotalLength(iovecs)) &&
         ccm128_compute_mac(ctx, &state, key, out_tag, iovecs,
                            /*encrypt=*/true) &&
         ccm128_encrypt(ctx, &state, key, iovecs);
}

static int CRYPTO_ccm128_decrypt(const struct ccm128_context *ctx,
                                 const AES_KEY *key,
                                 Span<const CRYPTO_IOVEC> iovecs,
                                 Span<uint8_t> out_tag,
                                 Span<const uint8_t> nonce,
                                 Span<const CRYPTO_IVEC> aadvecs) {
  struct ccm128_state state;
  return ccm128_init_state(ctx, &state, key, nonce, aadvecs,
                           bssl::iovec::TotalLength(iovecs)) &&
         ccm128_encrypt(ctx, &state, key, iovecs) &&
         ccm128_compute_mac(ctx, &state, key, out_tag, iovecs,
                            /*encrypt=*/false);
}

#define EVP_AEAD_AES_CCM_MAX_TAG_LEN 16

namespace {
struct aead_aes_ccm_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  struct ccm128_context ccm;
};
}  // namespace

static_assert(sizeof(((EVP_AEAD_CTX *)nullptr)->state) >=
                  sizeof(struct aead_aes_ccm_ctx),
              "AEAD state is too small");
static_assert(alignof(union evp_aead_ctx_st_state) >=
                  alignof(struct aead_aes_ccm_ctx),
              "AEAD state has insufficient alignment");

static int aead_aes_ccm_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                             size_t key_len, size_t tag_len, unsigned M,
                             unsigned L) {
  assert(M == EVP_AEAD_max_overhead(ctx->aead));
  assert(M == EVP_AEAD_max_tag_len(ctx->aead));
  assert(15 - L == EVP_AEAD_nonce_length(ctx->aead));

  if (key_len != EVP_AEAD_key_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
    return 0;  // EVP_AEAD_CTX_init should catch this.
  }

  if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH) {
    tag_len = M;
  }

  if (tag_len != M) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  struct aead_aes_ccm_ctx *ccm_ctx = (struct aead_aes_ccm_ctx *)&ctx->state;

  block128_f block;
  ctr128_f ctr =
      aes_ctr_set_key(&ccm_ctx->ks.ks, nullptr, &block, key, key_len);
  ctx->tag_len = tag_len;
  if (!CRYPTO_ccm128_init(&ccm_ctx->ccm, &ccm_ctx->ks.ks, block, ctr, M, L)) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  return 1;
}

static void aead_aes_ccm_cleanup(EVP_AEAD_CTX *ctx) {}

static int aead_aes_ccm_sealv(const EVP_AEAD_CTX *ctx,
                              Span<const CRYPTO_IOVEC> iovecs,
                              Span<uint8_t> out_tag, size_t *out_tag_len,
                              Span<const uint8_t> nonce,
                              Span<const CRYPTO_IVEC> aadvecs) {
  const struct aead_aes_ccm_ctx *ccm_ctx =
      (struct aead_aes_ccm_ctx *)&ctx->state;

  if (bssl::iovec::TotalLength(iovecs) >
      CRYPTO_ccm128_max_input(&ccm_ctx->ccm)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (out_tag.size() < ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce.size() != EVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (!CRYPTO_ccm128_encrypt(&ccm_ctx->ccm, &ccm_ctx->ks.ks, iovecs,
                             out_tag.first(ctx->tag_len), nonce, aadvecs)) {
    return 0;
  }

  *out_tag_len = ctx->tag_len;
  AEAD_CCM_verify_service_indicator(ctx);
  return 1;
}

static int aead_aes_ccm_openv_detached(const EVP_AEAD_CTX *ctx,
                                       Span<const CRYPTO_IOVEC> iovecs,
                                       Span<const uint8_t> nonce,
                                       Span<const uint8_t> in_tag,
                                       Span<const CRYPTO_IVEC> aadvecs) {
  const struct aead_aes_ccm_ctx *ccm_ctx =
      (struct aead_aes_ccm_ctx *)&ctx->state;

  if (bssl::iovec::TotalLength(iovecs) >
      CRYPTO_ccm128_max_input(&ccm_ctx->ccm)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (nonce.size() != EVP_AEAD_nonce_length(ctx->aead)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
    return 0;
  }

  if (in_tag.size() != ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  uint8_t tag[EVP_AEAD_AES_CCM_MAX_TAG_LEN];
  if (!CRYPTO_ccm128_decrypt(&ccm_ctx->ccm, &ccm_ctx->ks.ks, iovecs,
                             Span(tag).first(ctx->tag_len), nonce, aadvecs)) {
    return 0;
  }

  if (CRYPTO_memcmp(tag, in_tag.data(), ctx->tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  AEAD_CCM_verify_service_indicator(ctx);
  return 1;
}

static int aead_aes_ccm_bluetooth_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                       size_t key_len, size_t tag_len) {
  return aead_aes_ccm_init(ctx, key, key_len, tag_len, 4, 2);
}

DEFINE_METHOD_FUNCTION(EVP_AEAD, EVP_aead_aes_128_ccm_bluetooth) {
  memset(out, 0, sizeof(EVP_AEAD));

  out->key_len = 16;
  out->nonce_len = 13;
  out->overhead = 4;
  out->max_tag_len = 4;

  out->init = aead_aes_ccm_bluetooth_init;
  out->cleanup = aead_aes_ccm_cleanup;
  out->sealv = aead_aes_ccm_sealv;
  out->openv_detached = aead_aes_ccm_openv_detached;
}

static int aead_aes_ccm_bluetooth_8_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                         size_t key_len, size_t tag_len) {
  return aead_aes_ccm_init(ctx, key, key_len, tag_len, 8, 2);
}

DEFINE_METHOD_FUNCTION(EVP_AEAD, EVP_aead_aes_128_ccm_bluetooth_8) {
  memset(out, 0, sizeof(EVP_AEAD));

  out->key_len = 16;
  out->nonce_len = 13;
  out->overhead = 8;
  out->max_tag_len = 8;

  out->init = aead_aes_ccm_bluetooth_8_init;
  out->cleanup = aead_aes_ccm_cleanup;
  out->sealv = aead_aes_ccm_sealv;
  out->openv_detached = aead_aes_ccm_openv_detached;
}

static int aead_aes_ccm_matter_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                    size_t key_len, size_t tag_len) {
  return aead_aes_ccm_init(ctx, key, key_len, tag_len, 16, 2);
}

DEFINE_METHOD_FUNCTION(EVP_AEAD, EVP_aead_aes_128_ccm_matter) {
  memset(out, 0, sizeof(EVP_AEAD));

  out->key_len = 16;
  out->nonce_len = 13;
  out->overhead = 16;
  out->max_tag_len = 16;

  out->init = aead_aes_ccm_matter_init;
  out->cleanup = aead_aes_ccm_cleanup;
  out->sealv = aead_aes_ccm_sealv;
  out->openv_detached = aead_aes_ccm_openv_detached;
}

namespace {
struct evp_aes_ccm_ctx {
  AES_KEY ks;
  struct ccm128_context ccm;
  unsigned M;
  unsigned L;
  uint8_t iv[16];
  uint8_t tag[16];
  uint8_t *aad;
  size_t aad_len;
  size_t aad_cap;
  size_t msg_len;
  int key_set;
  int iv_set;
  int len_set;
  int tag_set;
  int data_processed;
};
}  // namespace

static int evp_aes_ccm_reserve_aad(struct evp_aes_ccm_ctx *cctx, size_t append_len) {
  if (append_len == 0) {
    return 1;
  }
  if (cctx->aad_len > SIZE_MAX - append_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }
  size_t needed = cctx->aad_len + append_len;
  if (needed <= cctx->aad_cap) {
    return 1;
  }

  size_t new_cap = cctx->aad_cap ? cctx->aad_cap : 64;
  while (new_cap < needed) {
    if (new_cap > SIZE_MAX / 2) {
      new_cap = needed;
      break;
    }
    new_cap *= 2;
  }

  uint8_t *next = reinterpret_cast<uint8_t *>(OPENSSL_realloc(cctx->aad, new_cap));
  if (next == nullptr) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  cctx->aad = next;
  cctx->aad_cap = new_cap;
  return 1;
}

static int evp_aes_ccm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
  auto *cctx = reinterpret_cast<evp_aes_ccm_ctx *>(ctx->cipher_data);
  switch (type) {
    case EVP_CTRL_INIT:
      cctx->key_set = 0;
      cctx->iv_set = 0;
      cctx->L = 3;
      cctx->M = 12;
      cctx->tag_set = 0;
      cctx->len_set = 0;
      cctx->data_processed = 0;
      cctx->aad = nullptr;
      cctx->aad_len = 0;
      cctx->aad_cap = 0;
      cctx->msg_len = 0;
      return 1;
    case EVP_CTRL_GET_IVLEN:
      *reinterpret_cast<int *>(ptr) = static_cast<int>(15 - cctx->L);
      return 1;
    case EVP_CTRL_AEAD_SET_IVLEN:
      arg = 15 - arg;
      if (arg < 2 || arg > 8) {
        return 0;
      }
      cctx->L = static_cast<unsigned>(arg);
      return 1;
    case EVP_CTRL_AEAD_SET_TAG:
      if ((arg & 1) || arg < 4 || arg > 16) {
        return 0;
      }
      if (EVP_CIPHER_CTX_encrypting(ctx) && ptr != nullptr) {
        return 0;
      }
      cctx->M = static_cast<unsigned>(arg);
      if (ptr != nullptr) {
        cctx->tag_set = 1;
        CopySpan(Span(reinterpret_cast<const uint8_t *>(ptr), cctx->M), Span(cctx->tag).first(cctx->M));
      }
      return 1;
    case EVP_CTRL_AEAD_GET_TAG:
      if (!EVP_CIPHER_CTX_encrypting(ctx) || !cctx->tag_set) {
        return 0;
      }
      if (arg < 0 || static_cast<unsigned>(arg) > cctx->M) {
        return 0;
      }
      CopySpan(Span(cctx->tag).first(static_cast<size_t>(arg)),
               Span(reinterpret_cast<uint8_t *>(ptr), static_cast<size_t>(arg)));
      cctx->tag_set = 0;
      cctx->iv_set = 0;
      cctx->len_set = 0;
      cctx->data_processed = 0;
      cctx->aad_len = 0;
      return 1;
    case EVP_CTRL_COPY: {
      auto *src = reinterpret_cast<evp_aes_ccm_ctx *>(ctx->cipher_data);
      auto *dst = reinterpret_cast<evp_aes_ccm_ctx *>(ptr);
      if (src->aad != nullptr && src->aad_cap > 0) {
        dst->aad = reinterpret_cast<uint8_t *>(OPENSSL_memdup(src->aad, src->aad_cap));
        if (dst->aad == nullptr) {
          return 0;
        }
      }
      return 1;
    }
    default:
      return -1;
  }
}

static int evp_aes_ccm_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key, const uint8_t *iv, int /*enc*/) {
  auto *cctx = reinterpret_cast<evp_aes_ccm_ctx *>(ctx->cipher_data);
  if (key != nullptr) {
    block128_f block;
    ctr128_f ctr = aes_ctr_set_key(&cctx->ks, nullptr, &block, key, EVP_CIPHER_CTX_key_length(ctx));
    if (!CRYPTO_ccm128_init(&cctx->ccm, &cctx->ks, block, ctr, cctx->M, cctx->L)) {
      OPENSSL_PUT_ERROR(CIPHER, ERR_R_INTERNAL_ERROR);
      return 0;
    }
    cctx->key_set = 1;
    cctx->len_set = 0;
    cctx->tag_set = 0;
    cctx->data_processed = 0;
    cctx->aad_len = 0;
  }
  if (iv != nullptr) {
    OPENSSL_memcpy(cctx->iv, iv, 15 - cctx->L);
    cctx->iv_set = 1;
  }
  return 1;
}

static int evp_aes_ccm_update_aad(EVP_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len) {
  auto *cctx = reinterpret_cast<evp_aes_ccm_ctx *>(ctx->cipher_data);
  if (!cctx->key_set || !cctx->iv_set || cctx->data_processed) {
    return 0;
  }
  // Plaintext length for CCM is passed as update_aad(nullptr, len) before AAD; see
  // EVP_EncryptUpdate when |EVP_CIPH_FLAG_CUSTOM_CIPHER| and out==nullptr.
  if (in == nullptr) {
    if (in_len == 0) {
      return 1;
    }
    if (cctx->len_set) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
      return 0;
    }
    cctx->msg_len = in_len;
    cctx->len_set = 1;
    return 1;
  }
  if (!cctx->len_set) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
    return 0;
  }
  if (!evp_aes_ccm_reserve_aad(cctx, in_len)) {
    return 0;
  }
  OPENSSL_memcpy(cctx->aad + cctx->aad_len, in, in_len);
  cctx->aad_len += in_len;
  return 1;
}

static int evp_aes_ccm_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in, size_t in_len) {
  auto *cctx = reinterpret_cast<evp_aes_ccm_ctx *>(ctx->cipher_data);
  if (!cctx->key_set || !cctx->iv_set) {
    return 0;
  }

  if (out == nullptr) {
    if (in == nullptr) {
      cctx->msg_len = in_len;
      cctx->len_set = 1;
      return 1;
    }
    return evp_aes_ccm_update_aad(ctx, in, in_len);
  }

  if (!cctx->len_set) {
    cctx->msg_len = in_len;
    cctx->len_set = 1;
  }
  if (cctx->msg_len != in_len || cctx->data_processed) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
    return 0;
  }

  CRYPTO_IOVEC iovec = {.out = out, .in = in, .len = in_len};
  CRYPTO_IVEC aadvec = {.in = cctx->aad, .len = cctx->aad_len};
  auto aadvecs = cctx->aad_len ? Span(&aadvec, 1) : Span<const CRYPTO_IVEC>();
  bool ok = false;

  if (EVP_CIPHER_CTX_encrypting(ctx)) {
    ok = CRYPTO_ccm128_encrypt(&cctx->ccm, &cctx->ks, Span(&iovec, 1), Span(cctx->tag).first(cctx->M),
                               Span(cctx->iv).first(15 - cctx->L), aadvecs);
    if (ok) cctx->tag_set = 1;
  } else {
    if (!cctx->tag_set) {
      OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
      return 0;
    }
    uint8_t computed_tag[16];
    ok = CRYPTO_ccm128_decrypt(&cctx->ccm, &cctx->ks, Span(&iovec, 1), Span(computed_tag).first(cctx->M),
                               Span(cctx->iv).first(15 - cctx->L), aadvecs) &&
         CRYPTO_memcmp(computed_tag, cctx->tag, cctx->M) == 0;
    if (!ok) OPENSSL_cleanse(out, in_len);
    cctx->tag_set = 0;
  }

  cctx->data_processed = 1;
  cctx->aad_len = 0;
  return ok ? 1 : 0;
}

static int evp_aes_ccm_cipher_final(EVP_CIPHER_CTX *ctx) {
  auto *cctx = reinterpret_cast<evp_aes_ccm_ctx *>(ctx->cipher_data);
  cctx->iv_set = 0;
  cctx->len_set = 0;
  cctx->data_processed = 0;
  cctx->aad_len = 0;
  return 1;
}

static void evp_aes_ccm_cleanup(EVP_CIPHER_CTX *ctx) {
  auto *cctx = reinterpret_cast<evp_aes_ccm_ctx *>(ctx->cipher_data);
  OPENSSL_cleanse(&cctx->ks, sizeof(cctx->ks));
  OPENSSL_cleanse(cctx->tag, sizeof(cctx->tag));
  OPENSSL_cleanse(cctx->iv, sizeof(cctx->iv));
  OPENSSL_free(cctx->aad);
  cctx->aad = nullptr;
  cctx->aad_len = 0;
  cctx->aad_cap = 0;
}

#define EVP_AES_CCM_COMMON_FLAGS (EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_FLAG_AEAD_CIPHER)

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_aes_128_ccm) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_aes_128_ccm;
  out->block_size = 1;
  out->key_len = 16;
  out->iv_len = 12;
  out->ctx_size = sizeof(evp_aes_ccm_ctx);
  out->flags = EVP_AES_CCM_COMMON_FLAGS;
  out->init = evp_aes_ccm_init_key;
  out->cipher_update = evp_aes_ccm_cipher_update;
  out->cipher_final = evp_aes_ccm_cipher_final;
  out->update_aad = evp_aes_ccm_update_aad;
  out->cleanup = evp_aes_ccm_cleanup;
  out->ctrl = evp_aes_ccm_ctrl;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_aes_192_ccm) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_aes_192_ccm;
  out->block_size = 1;
  out->key_len = 24;
  out->iv_len = 12;
  out->ctx_size = sizeof(evp_aes_ccm_ctx);
  out->flags = EVP_AES_CCM_COMMON_FLAGS;
  out->init = evp_aes_ccm_init_key;
  out->cipher_update = evp_aes_ccm_cipher_update;
  out->cipher_final = evp_aes_ccm_cipher_final;
  out->update_aad = evp_aes_ccm_update_aad;
  out->cleanup = evp_aes_ccm_cleanup;
  out->ctrl = evp_aes_ccm_ctrl;
}

DEFINE_METHOD_FUNCTION(EVP_CIPHER, EVP_aes_256_ccm) {
  memset(out, 0, sizeof(EVP_CIPHER));
  out->nid = NID_aes_256_ccm;
  out->block_size = 1;
  out->key_len = 32;
  out->iv_len = 12;
  out->ctx_size = sizeof(evp_aes_ccm_ctx);
  out->flags = EVP_AES_CCM_COMMON_FLAGS;
  out->init = evp_aes_ccm_init_key;
  out->cipher_update = evp_aes_ccm_cipher_update;
  out->cipher_final = evp_aes_ccm_cipher_final;
  out->update_aad = evp_aes_ccm_update_aad;
  out->cleanup = evp_aes_ccm_cleanup;
  out->ctrl = evp_aes_ccm_ctrl;
}
