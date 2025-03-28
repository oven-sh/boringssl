/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/evp.h>


void EVP_CIPHER_do_all_sorted(void (*callback)(const EVP_CIPHER *cipher,
                                               const char *name,
                                               const char *unused, void *arg),
                              void *arg) {
  callback(EVP_aes_128_cbc(), "aes-128-cbc", NULL, arg);
  callback(EVP_aes_128_cfb128(), "aes-128-cfb", NULL, arg);
  callback(EVP_aes_192_cbc(), "aes-192-cbc", NULL, arg);
  callback(EVP_aes_256_cbc(), "aes-256-cbc", NULL, arg);
  callback(EVP_aes_256_cfb128(), "aes-256-cfb", NULL, arg);
  callback(EVP_aes_128_ctr(), "aes-128-ctr", NULL, arg);
  callback(EVP_aes_192_ctr(), "aes-192-ctr", NULL, arg);
  callback(EVP_aes_256_ctr(), "aes-256-ctr", NULL, arg);
  callback(EVP_aes_128_ecb(), "aes-128-ecb", NULL, arg);
  callback(EVP_aes_192_ecb(), "aes-192-ecb", NULL, arg);
  callback(EVP_aes_256_ecb(), "aes-256-ecb", NULL, arg);
  callback(EVP_aes_128_ofb(), "aes-128-ofb", NULL, arg);
  callback(EVP_aes_192_ofb(), "aes-192-ofb", NULL, arg);
  callback(EVP_aes_256_ofb(), "aes-256-ofb", NULL, arg);
  callback(EVP_aes_128_gcm(), "aes-128-gcm", NULL, arg);
  callback(EVP_aes_192_gcm(), "aes-192-gcm", NULL, arg);
  callback(EVP_aes_256_gcm(), "aes-256-gcm", NULL, arg);
  callback(EVP_bf_cbc(), "bf-cbc", NULL, arg);
  callback(EVP_bf_cfb(), "bf-cfb", NULL, arg);
  callback(EVP_bf_ecb(), "bf-ecb", NULL, arg);
  callback(EVP_des_cbc(), "des-cbc", NULL, arg);
  callback(EVP_des_ecb(), "des-ecb", NULL, arg);
  callback(EVP_des_ede(), "des-ede", NULL, arg);
  callback(EVP_des_ede3(), "des-ede3", NULL, arg);
  callback(EVP_des_ede_cbc(), "des-ede-cbc", NULL, arg);
  callback(EVP_des_ede3_cbc(), "des-ede3-cbc", NULL, arg);
  callback(EVP_rc2_cbc(), "rc2-cbc", NULL, arg);
  callback(EVP_rc4(), "rc4", NULL, arg);
}

void EVP_MD_do_all_sorted(void (*callback)(const EVP_MD *cipher,
                                           const char *name, const char *unused,
                                           void *arg),
                          void *arg) {
  callback(EVP_md4(), "md4", NULL, arg);
  callback(EVP_md5(), "md5", NULL, arg);
  callback(EVP_sha1(), "sha1", NULL, arg);
  callback(EVP_sha224(), "sha224", NULL, arg);
  callback(EVP_sha256(), "sha256", NULL, arg);
  callback(EVP_sha384(), "sha384", NULL, arg);
  callback(EVP_sha512(), "sha512", NULL, arg);
  callback(EVP_sha512_224(), "sha512-224", NULL, arg);
  callback(EVP_sha512_256(), "sha512-256", NULL, arg);
  callback(EVP_ripemd160(), "ripemd160", NULL, arg);
}

void EVP_MD_do_all(void (*callback)(const EVP_MD *cipher, const char *name,
                                    const char *unused, void *arg),
                   void *arg) {
  EVP_MD_do_all_sorted(callback, arg);
}
