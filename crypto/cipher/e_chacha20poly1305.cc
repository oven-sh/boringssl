// Copyright 2014 The BoringSSL Authors
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
#include <string.h>

#include <openssl/chacha.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/poly1305.h>
#include <openssl/span.h>

#include "../chacha/internal.h"
#include "../fipsmodule/cipher/internal.h"
#include "../internal.h"
#include "internal.h"

using namespace bssl;

struct aead_chacha20_poly1305_ctx {
  uint8_t key[32];
};

static_assert(sizeof(((EVP_AEAD_CTX *)nullptr)->state) >=
                  sizeof(struct aead_chacha20_poly1305_ctx),
              "AEAD state is too small");
static_assert(alignof(union evp_aead_ctx_st_state) >=
                  alignof(struct aead_chacha20_poly1305_ctx),
              "AEAD state has insufficient alignment");

static int aead_chacha20_poly1305_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                       size_t key_len, size_t tag_len) {
  struct aead_chacha20_poly1305_ctx *c20_ctx =
      (struct aead_chacha20_poly1305_ctx *)&ctx->state;

  if (tag_len == 0) {
    tag_len = POLY1305_TAG_LEN;
  }

  if (tag_len > POLY1305_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (key_len != sizeof(c20_ctx->key)) {
    return 0;  // internal error - EVP_AEAD_CTX_init should catch this.
  }

  OPENSSL_memcpy(c20_ctx->key, key, key_len);
  ctx->tag_len = tag_len;

  return 1;
}

static void aead_chacha20_poly1305_cleanup(EVP_AEAD_CTX *ctx) {}

static void poly1305_update_length(poly1305_state *poly1305,
                                   uint64_t data_len) {
  uint8_t length_bytes[8];

  for (unsigned i = 0; i < sizeof(length_bytes); i++) {
    length_bytes[i] = data_len;
    data_len >>= 8;
  }

  CRYPTO_poly1305_update(poly1305, length_bytes, sizeof(length_bytes));
}

// calc_tag_pre prepares filling `tag` with the authentication tag for the given
// inputs.
static size_t calc_tag_pre(poly1305_state *ctx, const uint8_t key[32],
                           const uint8_t nonce[12],
                           Span<const CRYPTO_IVEC> aadvecs) {
  alignas(16) uint8_t poly1305_key[32];
  OPENSSL_memset(poly1305_key, 0, sizeof(poly1305_key));
  CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key), key, nonce,
                   0);

  static const uint8_t padding[16] = {0};  // Padding is all zeros.
  CRYPTO_poly1305_init(ctx, poly1305_key);
  size_t ad_len = 0;
  for (const CRYPTO_IVEC &aadvec : aadvecs) {
    CRYPTO_poly1305_update(ctx, aadvec.in, aadvec.len);
    ad_len += aadvec.len;
  }
  if (ad_len % 16 != 0) {
    CRYPTO_poly1305_update(ctx, padding, sizeof(padding) - (ad_len % 16));
  }
  return ad_len;
}

static void calc_tag_post(poly1305_state *ctx, uint8_t tag[POLY1305_TAG_LEN],
                          size_t ciphertext_total, size_t ad_len) {
  static const uint8_t padding[16] = {0};  // Padding is all zeros.
  if (ciphertext_total % 16 != 0) {
    CRYPTO_poly1305_update(ctx, padding,
                           sizeof(padding) - (ciphertext_total % 16));
  }
  poly1305_update_length(ctx, ad_len);
  poly1305_update_length(ctx, ciphertext_total);
  CRYPTO_poly1305_finish(ctx, tag);
}

static int chacha20_poly1305_sealv(const uint8_t *key,
                                   Span<const CRYPTO_IOVEC> iovecs,
                                   Span<uint8_t> out_tag, size_t *out_tag_len,
                                   Span<const uint8_t> nonce,
                                   Span<const CRYPTO_IVEC> aadvecs,
                                   size_t tag_len) {
  if (out_tag.size() < tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }
  if (nonce.size() != 12) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_NONCE_SIZE);
    return 0;
  }

  // `CRYPTO_chacha_20` uses a 32-bit block counter. Therefore we disallow
  // individual operations that work on more than 256GB at a time.
  // `in_len_64` is needed because, on 32-bit platforms, size_t is only
  // 32-bits and this produces a warning because it's always false.
  // Casting to uint64_t inside the conditional is not sufficient to stop
  // the warning.
  const uint64_t in_len_64 = bssl::iovec::TotalLength(iovecs);
  if (in_len_64 >= (UINT64_C(1) << 32) * 64 - 64) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  union chacha20_poly1305_seal_data data;
  if (chacha20_poly1305_asm_capable() && iovecs.size() <= 2 &&
      aadvecs.size() <= 1) {
    OPENSSL_memcpy(data.in.key, key, 32);
    data.in.counter = 0;
    CopySpan(nonce, data.in.nonce);
    if (iovecs.size() >= 2) {
      // `chacha20_poly1305_seal` only supports one extra input and expects it
      // to have been encrypted ahead of time. (Historically it was only used
      // for very short inputs.)
      constexpr size_t kChaChaBlockSize = 64;
      uint32_t block_counter =
          (uint32_t)(1 + (iovecs[0].len / kChaChaBlockSize));
      size_t offset = iovecs[0].len % kChaChaBlockSize;
      size_t done = 0;
      if (offset != 0) {
        uint8_t block[kChaChaBlockSize];
        memset(block, 0, sizeof(block));
        CRYPTO_chacha_20(block, block, sizeof(block), key, nonce.data(),
                         block_counter);
        for (size_t i = offset; i < sizeof(block) && done < iovecs[1].len;
             i++, done++) {
          iovecs[1].out[done] = iovecs[1].in[done] ^ block[i];
        }
        ++block_counter;
      }
      if (done < iovecs[1].len) {
        CRYPTO_chacha_20(iovecs[1].out + done, iovecs[1].in + done,
                         iovecs[1].len - done, key, nonce.data(),
                         block_counter);
      }
      // TODO(crbug.com/473454967): Support more than 1 extra ciphertext.
      data.in.extra_ciphertext = iovecs[1].out;
      data.in.extra_ciphertext_len = iovecs[1].len;
    } else {
      data.in.extra_ciphertext = nullptr;
      data.in.extra_ciphertext_len = 0;
    }
    chacha20_poly1305_seal(iovecs.size() >= 1 ? iovecs[0].out : nullptr,
                           iovecs.size() >= 1 ? iovecs[0].in : nullptr,
                           iovecs.size() >= 1 ? iovecs[0].len : 0,
                           aadvecs.size() >= 1 ? aadvecs[0].in : nullptr,
                           aadvecs.size() >= 1 ? aadvecs[0].len : 0, &data);
  } else {
    poly1305_state ctx;
    size_t ad_len = calc_tag_pre(&ctx, key, nonce.data(), aadvecs);

    size_t ciphertext_total = 0;
    size_t block = 1;
    bssl::iovec::ForEachBlockRange<64, /*WriteOut=*/true>(
        iovecs,
        [&](const uint8_t *in, uint8_t *out, size_t len) {
          // TODO(crbug.com/473454967): Maybe just provide asm version of this?
          // Here, len is always a multiple of 64.
          CRYPTO_chacha_20(out, in, len, key, nonce.data(), block);
          CRYPTO_poly1305_update(&ctx, out, len);
          ciphertext_total += len;
          block += len / 64;
          return true;
        },
        [&](const uint8_t *in, uint8_t *out, size_t len) {
          // Here, len may be anything. If an asm version can't handle that,
          // it will be worth splitting off multiples of 64 here.
          CRYPTO_chacha_20(out, in, len, key, nonce.data(), block);
          CRYPTO_poly1305_update(&ctx, out, len);
          ciphertext_total += len;
          return true;
        });

    calc_tag_post(&ctx, data.out.tag, ciphertext_total, ad_len);
  }

  CopyToPrefix(Span(data.out.tag).first(tag_len), out_tag);
  *out_tag_len = tag_len;
  return 1;
}

static int aead_chacha20_poly1305_sealv(const EVP_AEAD_CTX *ctx,
                                        Span<const CRYPTO_IOVEC> iovecs,
                                        Span<uint8_t> out_tag,
                                        size_t *out_tag_len,
                                        Span<const uint8_t> nonce,
                                        Span<const CRYPTO_IVEC> aadvecs) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx =
      (struct aead_chacha20_poly1305_ctx *)&ctx->state;

  return chacha20_poly1305_sealv(c20_ctx->key, iovecs, out_tag, out_tag_len,
                                 nonce, aadvecs, ctx->tag_len);
}

static int aead_xchacha20_poly1305_sealv(const EVP_AEAD_CTX *ctx,
                                         Span<const CRYPTO_IOVEC> iovecs,
                                         Span<uint8_t> out_tag,
                                         size_t *out_tag_len,
                                         Span<const uint8_t> nonce,
                                         Span<const CRYPTO_IVEC> aadvecs) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx =
      (struct aead_chacha20_poly1305_ctx *)&ctx->state;

  if (nonce.size() != 24) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_NONCE_SIZE);
    return 0;
  }

  alignas(4) uint8_t derived_key[32];
  alignas(4) uint8_t derived_nonce[12];
  CRYPTO_hchacha20(derived_key, c20_ctx->key, nonce.data());
  OPENSSL_memset(derived_nonce, 0, 4);
  OPENSSL_memcpy(&derived_nonce[4], &nonce[16], 8);

  return chacha20_poly1305_sealv(derived_key, iovecs, out_tag, out_tag_len,
                                 derived_nonce, aadvecs, ctx->tag_len);
}

static int chacha20_poly1305_openv_detached(const uint8_t *key,
                                            Span<const CRYPTO_IOVEC> iovecs,
                                            Span<const uint8_t> nonce,
                                            Span<const uint8_t> in_tag,
                                            Span<const CRYPTO_IVEC> aadvecs,
                                            size_t tag_len) {
  if (nonce.size() != 12) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_NONCE_SIZE);
    return 0;
  }

  if (in_tag.size() != tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  // `CRYPTO_chacha_20` uses a 32-bit block counter. Therefore we disallow
  // individual operations that work on more than 256GB at a time.
  // `in_len_64` is needed because, on 32-bit platforms, size_t is only
  // 32-bits and this produces a warning because it's always false.
  // Casting to uint64_t inside the conditional is not sufficient to stop
  // the warning.
  const uint64_t in_len_64 = bssl::iovec::TotalLength(iovecs);
  if (in_len_64 >= (UINT64_C(1) << 32) * 64 - 64) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  union chacha20_poly1305_open_data data;
  if (chacha20_poly1305_asm_capable() && iovecs.size() <= 1 &&
      aadvecs.size() <= 1) {
    // TODO(crbug.com/473454967): Support more than 1 ciphertext segment.
    OPENSSL_memcpy(data.in.key, key, 32);
    data.in.counter = 0;
    CopySpan(nonce, data.in.nonce);
    chacha20_poly1305_open(iovecs.size() >= 1 ? iovecs[0].out : nullptr,
                           iovecs.size() >= 1 ? iovecs[0].in : nullptr,
                           iovecs.size() >= 1 ? iovecs[0].len : 0,
                           aadvecs.size() >= 1 ? aadvecs[0].in : nullptr,
                           aadvecs.size() >= 1 ? aadvecs[0].len : 0, &data);
  } else {
    poly1305_state ctx;
    size_t ad_len = calc_tag_pre(&ctx, key, nonce.data(), aadvecs);

    size_t ciphertext_total = 0;
    size_t block = 1;
    bssl::iovec::ForEachBlockRange<64, /*WriteOut=*/true>(
        iovecs,
        [&](const uint8_t *in, uint8_t *out, size_t len) {
          // TODO(crbug.com/473454967): Maybe just provide asm version of this?
          // Here, len is always a multiple of 64.
          CRYPTO_poly1305_update(&ctx, in, len);
          CRYPTO_chacha_20(out, in, len, key, nonce.data(), block);
          ciphertext_total += len;
          block += len / 64;
          return true;
        },
        [&](const uint8_t *in, uint8_t *out, size_t len) {
          // Here, len may be anything. If an asm version can't handle that,
          // it will be worth splitting off multiples of 64 here.
          CRYPTO_poly1305_update(&ctx, in, len);
          CRYPTO_chacha_20(out, in, len, key, nonce.data(), block);
          ciphertext_total += len;
          return true;
        });

    calc_tag_post(&ctx, data.out.tag, ciphertext_total, ad_len);
  }

  if (CRYPTO_memcmp(data.out.tag, in_tag.data(), tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  return 1;
}

static int aead_chacha20_poly1305_openv_detached(
    const EVP_AEAD_CTX *ctx, Span<const CRYPTO_IOVEC> iovecs,
    Span<const uint8_t> nonce, Span<const uint8_t> in_tag,
    Span<const CRYPTO_IVEC> aadvecs) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx =
      (struct aead_chacha20_poly1305_ctx *)&ctx->state;

  return chacha20_poly1305_openv_detached(c20_ctx->key, iovecs, nonce, in_tag,
                                          aadvecs, ctx->tag_len);
}

static int aead_xchacha20_poly1305_openv_detached(
    const EVP_AEAD_CTX *ctx, Span<const CRYPTO_IOVEC> iovecs,
    Span<const uint8_t> nonce, Span<const uint8_t> in_tag,
    Span<const CRYPTO_IVEC> aadvecs) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx =
      (struct aead_chacha20_poly1305_ctx *)&ctx->state;

  if (nonce.size() != 24) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_NONCE_SIZE);
    return 0;
  }

  alignas(4) uint8_t derived_key[32];
  alignas(4) uint8_t derived_nonce[12];
  CRYPTO_hchacha20(derived_key, c20_ctx->key, nonce.data());
  OPENSSL_memset(derived_nonce, 0, 4);
  OPENSSL_memcpy(&derived_nonce[4], &nonce[16], 8);

  return chacha20_poly1305_openv_detached(derived_key, iovecs, derived_nonce,
                                          in_tag, aadvecs, ctx->tag_len);
}

static const EVP_AEAD aead_chacha20_poly1305 = {
    32,                // key len
    12,                // nonce len
    POLY1305_TAG_LEN,  // overhead
    POLY1305_TAG_LEN,  // max tag length

    aead_chacha20_poly1305_init,
    nullptr,  // init_with_direction
    aead_chacha20_poly1305_cleanup,
    nullptr,  // openv
    aead_chacha20_poly1305_sealv,
    aead_chacha20_poly1305_openv_detached,
    nullptr,  // get_iv
    nullptr,  // tag_len
};

static const EVP_AEAD aead_xchacha20_poly1305 = {
    32,                // key len
    24,                // nonce len
    POLY1305_TAG_LEN,  // overhead
    POLY1305_TAG_LEN,  // max tag length

    aead_chacha20_poly1305_init,
    nullptr,  // init_with_direction
    aead_chacha20_poly1305_cleanup,
    nullptr,  // openv
    aead_xchacha20_poly1305_sealv,
    aead_xchacha20_poly1305_openv_detached,
    nullptr,  // get_iv
    nullptr,  // tag_len
};

const EVP_AEAD *EVP_aead_chacha20_poly1305() { return &aead_chacha20_poly1305; }

const EVP_AEAD *EVP_aead_xchacha20_poly1305() {
  return &aead_xchacha20_poly1305;
}


// ChaCha20-Poly1305 as an `EVP_CIPHER`.
//
// The `EVP_AEAD` interface above is one-shot. OpenSSL additionally exposes
// ChaCha20-Poly1305 through the streaming `EVP_CIPHER` interface, which is what
// `EVP_EncryptUpdate`-style callers (notably Node's `crypto.createCipheriv`)
// use. The construction below is RFC 8439 built on `CRYPTO_chacha_20` and
// `CRYPTO_poly1305_*`. New code should prefer the `EVP_AEAD` interface.

#define CHACHA20_POLY1305_NONCE_LEN 12
#define CHACHA20_POLY1305_KEY_LEN 32
#define CHACHA20_POLY1305_BLOCK_LEN 64

// poly1305_state stores its working state at a 64-byte-aligned offset inside
// the buffer, so the state's position depends on where the buffer lands. See
// `poly1305_aligned_state` in crypto/poly1305.
#define POLY1305_STATE_ALIGNMENT 64

namespace {

struct cipher_chacha20_poly1305_ctx {
  uint8_t key[CHACHA20_POLY1305_KEY_LEN];
  uint8_t nonce[CHACHA20_POLY1305_NONCE_LEN];
  // tag holds the computed tag when encrypting, or the expected one when
  // decrypting.
  uint8_t tag[POLY1305_TAG_LEN];
  poly1305_state poly;
  // keystream is the ChaCha20 block the previous update stopped partway
  // through; its first keystream_used bytes are already spent.
  uint8_t keystream[CHACHA20_POLY1305_BLOCK_LEN];
  unsigned keystream_used;
  // counter is the block counter of the next ChaCha20 block to generate.
  uint32_t counter;
  uint64_t aad_len;
  uint64_t text_len;
  unsigned tag_len;
  bool key_set;
  bool nonce_set;
  bool tag_set;
  bool mac_inited;
  bool aad_done;
};

// RFC 8439's block counter is 32 bits wide and the message starts at block one,
// so a single message may not exceed (2^32 - 1) blocks.
constexpr uint64_t kMaxPlaintextLen =
    uint64_t{UINT32_MAX} * CHACHA20_POLY1305_BLOCK_LEN;

cipher_chacha20_poly1305_ctx *cipher_chacha20_poly1305_data(
    EVP_CIPHER_CTX *ctx) {
  return reinterpret_cast<cipher_chacha20_poly1305_ctx *>(ctx->cipher_data);
}

// The Poly1305 key is the first 32 bytes of the keystream at block counter
// zero; the message itself starts at block counter one. (RFC 8439, section 2.8)
void cipher_chacha20_poly1305_init_mac(cipher_chacha20_poly1305_ctx *c) {
  if (c->mac_inited) {
    return;
  }
  alignas(16) uint8_t poly1305_key[32];
  OPENSSL_memset(poly1305_key, 0, sizeof(poly1305_key));
  CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key), c->key,
                   c->nonce, 0);
  CRYPTO_poly1305_init(&c->poly, poly1305_key);
  OPENSSL_cleanse(poly1305_key, sizeof(poly1305_key));
  c->mac_inited = true;
}

// Both the additional data and the ciphertext are zero-padded to a 16-byte
// boundary before the length footer is hashed.
void cipher_chacha20_poly1305_pad16(cipher_chacha20_poly1305_ctx *c,
                                    uint64_t len) {
  static const uint8_t padding[16] = {0};
  size_t remainder = len % sizeof(padding);
  if (remainder != 0) {
    CRYPTO_poly1305_update(&c->poly, padding, sizeof(padding) - remainder);
  }
}

// All of the additional data is hashed before any ciphertext, so the padding
// that separates them is emitted when the first ciphertext byte arrives.
void cipher_chacha20_poly1305_finish_aad(cipher_chacha20_poly1305_ctx *c) {
  if (!c->aad_done) {
    cipher_chacha20_poly1305_pad16(c, c->aad_len);
    c->aad_done = true;
  }
}

int cipher_chacha20_poly1305_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                                      const uint8_t *iv, int enc) {
  cipher_chacha20_poly1305_ctx *c = cipher_chacha20_poly1305_data(ctx);

  // `EVP_CIPH_ALWAYS_CALL_INIT` means this also runs on the `EVP_CipherInit_ex`
  // call that only configures the cipher. `EVP_CTRL_INIT` set the defaults.
  if (key == nullptr && iv == nullptr) {
    return 1;
  }

  // A new key or nonce begins a new message. The tag and tag length are
  // configured separately and deliberately survive this.
  c->aad_len = 0;
  c->text_len = 0;
  c->counter = 1;
  c->keystream_used = CHACHA20_POLY1305_BLOCK_LEN;
  c->mac_inited = false;
  c->aad_done = false;

  if (key != nullptr) {
    OPENSSL_memcpy(c->key, key, sizeof(c->key));
    c->key_set = true;
  }

  if (iv != nullptr) {
    OPENSSL_memcpy(c->nonce, iv, sizeof(c->nonce));
    c->nonce_set = true;
  }

  return 1;
}

int cipher_chacha20_poly1305_update_aad(EVP_CIPHER_CTX *ctx, const uint8_t *in,
                                        size_t len) {
  cipher_chacha20_poly1305_ctx *c = cipher_chacha20_poly1305_data(ctx);
  if (!c->key_set || !c->nonce_set) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INPUT_NOT_INITIALIZED);
    return 0;
  }
  if (c->aad_done) {
    // Additional data cannot follow ciphertext.
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
    return 0;
  }

  cipher_chacha20_poly1305_init_mac(c);
  CRYPTO_poly1305_update(&c->poly, in, len);
  c->aad_len += len;
  return 1;
}

int cipher_chacha20_poly1305_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
                                    const uint8_t *in, size_t len) {
  cipher_chacha20_poly1305_ctx *c = cipher_chacha20_poly1305_data(ctx);
  if (!c->key_set || !c->nonce_set) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INPUT_NOT_INITIALIZED);
    return 0;
  }
  // Refuse to wrap the block counter rather than reuse keystream.
  if (len > kMaxPlaintextLen - c->text_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  cipher_chacha20_poly1305_init_mac(c);
  cipher_chacha20_poly1305_finish_aad(c);

  // Poly1305 covers the ciphertext, which when decrypting is the input. Hash it
  // before `out` is written, because `in` and `out` may alias.
  if (!ctx->encrypt) {
    CRYPTO_poly1305_update(&c->poly, in, len);
  }

  size_t done = 0;

  // Spend whatever is left of the block the previous update stopped inside.
  if (c->keystream_used < CHACHA20_POLY1305_BLOCK_LEN) {
    size_t todo = CHACHA20_POLY1305_BLOCK_LEN - c->keystream_used;
    if (todo > len) {
      todo = len;
    }
    for (size_t i = 0; i < todo; i++) {
      out[i] = in[i] ^ c->keystream[c->keystream_used + i];
    }
    c->keystream_used += static_cast<unsigned>(todo);
    done = todo;
  }

  // Whole blocks go straight through ChaCha20.
  size_t whole_blocks = (len - done) / CHACHA20_POLY1305_BLOCK_LEN;
  if (whole_blocks > 0) {
    size_t todo = whole_blocks * CHACHA20_POLY1305_BLOCK_LEN;
    CRYPTO_chacha_20(out + done, in + done, todo, c->key, c->nonce, c->counter);
    c->counter += static_cast<uint32_t>(whole_blocks);
    done += todo;
  }

  // Buffer a fresh block for the trailing partial one, so the next update can
  // resume mid-block.
  size_t remainder = len - done;
  if (remainder > 0) {
    OPENSSL_memset(c->keystream, 0, sizeof(c->keystream));
    CRYPTO_chacha_20(c->keystream, c->keystream, sizeof(c->keystream), c->key,
                     c->nonce, c->counter);
    c->counter++;
    for (size_t i = 0; i < remainder; i++) {
      out[done + i] = in[done + i] ^ c->keystream[i];
    }
    c->keystream_used = static_cast<unsigned>(remainder);
  }

  if (ctx->encrypt) {
    CRYPTO_poly1305_update(&c->poly, out, len);
  }
  c->text_len += len;
  return 1;
}

int cipher_chacha20_poly1305_final(EVP_CIPHER_CTX *ctx) {
  cipher_chacha20_poly1305_ctx *c = cipher_chacha20_poly1305_data(ctx);
  // A failed authentication leaves the error queue untouched, as `aes_gcm` does,
  // so that callers can tell it apart from an internal error.
  if (!c->key_set || !c->nonce_set) {
    return 0;
  }
  if (!ctx->encrypt && !c->tag_set) {
    // Nothing to authenticate the ciphertext against.
    return 0;
  }

  cipher_chacha20_poly1305_init_mac(c);
  cipher_chacha20_poly1305_finish_aad(c);
  cipher_chacha20_poly1305_pad16(c, c->text_len);
  poly1305_update_length(&c->poly, c->aad_len);
  poly1305_update_length(&c->poly, c->text_len);

  uint8_t tag[POLY1305_TAG_LEN];
  CRYPTO_poly1305_finish(&c->poly, tag);
  c->mac_inited = false;

  if (!ctx->encrypt) {
    if (CRYPTO_memcmp(tag, c->tag, c->tag_len) != 0) {
      return 0;
    }
  } else {
    OPENSSL_memcpy(c->tag, tag, sizeof(tag));
  }

  return 1;
}

void cipher_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx) {
  OPENSSL_cleanse(ctx->cipher_data, sizeof(cipher_chacha20_poly1305_ctx));
}

int cipher_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                  void *ptr) {
  cipher_chacha20_poly1305_ctx *c = cipher_chacha20_poly1305_data(ctx);

  switch (type) {
    case EVP_CTRL_INIT:
      OPENSSL_memset(c, 0, sizeof(*c));
      c->tag_len = POLY1305_TAG_LEN;
      c->keystream_used = CHACHA20_POLY1305_BLOCK_LEN;
      c->counter = 1;
      return 1;

    case EVP_CTRL_GET_IVLEN:
      *reinterpret_cast<int *>(ptr) = CHACHA20_POLY1305_NONCE_LEN;
      return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
      // RFC 8439 fixes the nonce at 96 bits.
      if (arg != CHACHA20_POLY1305_NONCE_LEN) {
        OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_NONCE_SIZE);
        return 0;
      }
      return 1;

    case EVP_CTRL_AEAD_SET_TAG:
      if (arg <= 0 || arg > POLY1305_TAG_LEN) {
        OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
        return 0;
      }
      if (ptr == nullptr) {
        // Only the tag length is being configured.
        c->tag_len = static_cast<unsigned>(arg);
        return 1;
      }
      if (ctx->encrypt) {
        OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
        return 0;
      }
      OPENSSL_memcpy(c->tag, ptr, static_cast<size_t>(arg));
      c->tag_len = static_cast<unsigned>(arg);
      c->tag_set = true;
      return 1;

    case EVP_CTRL_AEAD_GET_TAG:
      if (!ctx->encrypt || arg <= 0 || arg > POLY1305_TAG_LEN) {
        OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_INVALID_OPERATION);
        return 0;
      }
      OPENSSL_memcpy(ptr, c->tag, static_cast<size_t>(arg));
      return 1;

    case EVP_CTRL_COPY: {
      // `EVP_CIPHER_CTX_copy` byte-copies `cipher_data`, but `poly1305_state`
      // keeps its working state at a 64-byte-aligned offset inside its buffer,
      // which moves if the copy lands on a different alignment. Put it back.
      cipher_chacha20_poly1305_ctx *out = cipher_chacha20_poly1305_data(
          reinterpret_cast<EVP_CIPHER_CTX *>(ptr));
      uint8_t *src_poly = reinterpret_cast<uint8_t *>(&c->poly);
      uint8_t *out_poly = reinterpret_cast<uint8_t *>(&out->poly);
      size_t src_offset =
          static_cast<uint8_t *>(
              align_pointer(src_poly, POLY1305_STATE_ALIGNMENT)) -
          src_poly;
      size_t out_offset =
          static_cast<uint8_t *>(
              align_pointer(out_poly, POLY1305_STATE_ALIGNMENT)) -
          out_poly;
      // The state fits in the worst-case aligned window, so that much is always
      // safe to move within the buffer.
      OPENSSL_memmove(out_poly + out_offset, out_poly + src_offset,
                      sizeof(poly1305_state) - (POLY1305_STATE_ALIGNMENT - 1));
      return 1;
    }

    default:
      return -1;
  }
}

const EVP_CIPHER cipher_chacha20_poly1305 = {
    /*nid=*/NID_chacha20_poly1305,
    /*block_size=*/1,
    /*key_len=*/CHACHA20_POLY1305_KEY_LEN,
    /*iv_len=*/CHACHA20_POLY1305_NONCE_LEN,
    /*ctx_size=*/sizeof(cipher_chacha20_poly1305_ctx),
    /*flags=*/EVP_CIPH_STREAM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT |
        EVP_CIPH_CUSTOM_IV | EVP_CIPH_CTRL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER |
        EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CUSTOM_COPY,
    /*init=*/cipher_chacha20_poly1305_init_key,
    /*cipher_update=*/cipher_chacha20_poly1305_update,
    /*cipher_final=*/cipher_chacha20_poly1305_final,
    /*update_aad=*/cipher_chacha20_poly1305_update_aad,
    /*cleanup=*/cipher_chacha20_poly1305_cleanup,
    /*ctrl=*/cipher_chacha20_poly1305_ctrl,
};

}  // namespace

const EVP_CIPHER *EVP_chacha20_poly1305() { return &cipher_chacha20_poly1305; }
