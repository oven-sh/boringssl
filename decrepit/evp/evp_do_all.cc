// Copyright 2016 The BoringSSL Authors
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
