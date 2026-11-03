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

#include <gtest/gtest.h>

#include "../test/file_test.h"
#include "../test/test_util.h"


BSSL_NAMESPACE_BEGIN
namespace {

TEST(BLAKE2B256Test, ABC) {
  // https://tools.ietf.org/html/rfc7693#appendix-A, except updated for the
  // 256-bit hash output.
  const uint8_t kExpected[] = {
      0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef,
      0x3f, 0xee, 0x98, 0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb,
      0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19,
  };

  uint8_t digest[BLAKE2B256_DIGEST_LENGTH];
  BLAKE2B256((const uint8_t *)"abc", 3, digest);
  EXPECT_EQ(Bytes(kExpected), Bytes(digest));
}

TEST(BLAKE2B256Test, TestVectors) {
  FileTestGTest("crypto/blake2/blake2b256_tests.txt", [](FileTest *t) {
    std::vector<uint8_t> msg, expected;
    ASSERT_TRUE(t->GetBytes(&msg, "IN"));
    ASSERT_TRUE(t->GetBytes(&expected, "HASH"));

    uint8_t digest[BLAKE2B256_DIGEST_LENGTH];
    BLAKE2B256(msg.data(), msg.size(), digest);
    EXPECT_EQ(Bytes(digest), Bytes(expected)) << msg.size();

    OPENSSL_memset(digest, 0, sizeof(digest));
    BLAKE2B_CTX b2b;
    BLAKE2B256_Init(&b2b);
    for (uint8_t b : msg) {
      BLAKE2B256_Update(&b2b, &b, 1);
    }
    BLAKE2B256_Final(digest, &b2b);
    EXPECT_EQ(Bytes(digest), Bytes(expected)) << msg.size();
  });
}

TEST(BLAKE2S256Test, ABC) {
  // https://tools.ietf.org/html/rfc7693#appendix-B
  const uint8_t kExpected[] = {
      0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b,
      0xa3, 0x4e, 0xeb, 0x45, 0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6,
      0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82,
  };

  uint8_t digest[BLAKE2S256_DIGEST_LENGTH];
  BLAKE2S256((const uint8_t *)"abc", 3, digest);
  EXPECT_EQ(Bytes(kExpected), Bytes(digest));
}

TEST(BLAKE2S256Test, TestVectors) {
  FileTestGTest("crypto/blake2/blake2s256_tests.txt", [](FileTest *t) {
    std::vector<uint8_t> msg, expected;
    ASSERT_TRUE(t->GetBytes(&msg, "IN"));
    ASSERT_TRUE(t->GetBytes(&expected, "HASH"));

    uint8_t digest[BLAKE2S256_DIGEST_LENGTH];
    BLAKE2S256(msg.data(), msg.size(), digest);
    EXPECT_EQ(Bytes(digest), Bytes(expected)) << msg.size();

    OPENSSL_memset(digest, 0, sizeof(digest));
    BLAKE2S_CTX b2s;
    BLAKE2S256_Init(&b2s);
    for (uint8_t b : msg) {
      BLAKE2S256_Update(&b2s, &b, 1);
    }
    BLAKE2S256_Final(digest, &b2s);
    EXPECT_EQ(Bytes(digest), Bytes(expected)) << msg.size();
  });
}

}  // namespace
BSSL_NAMESPACE_END
