// Copyright 2018 The BoringSSL Authors
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

#include <openssl/pem.h>

#include <functional>
#include <string>

#include <gtest/gtest.h>

#include <openssl/bio.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "../test/test_util.h"

#if defined(BORINGSSL_PEM_FAST_PUBLIC_BASE64)
#include <openssl/base64.h>

// A reference implementation of the embedder hooks in terms of the
// constant-time routines, recording which path was taken, so this suite can
// check that public labels are routed to the hooks, private ones are not, and
// the output is unchanged either way.
static int g_public_decodes = 0, g_public_encodes = 0;

int OPENSSL_pem_public_base64_decode(uint8_t *out, size_t *out_len,
                                     size_t max_out, const uint8_t *in,
                                     size_t in_len) {
  g_public_decodes++;
  std::vector<uint8_t> stripped;
  for (size_t i = 0; i < in_len; i++) {
    if (!OPENSSL_isspace(in[i])) {
      stripped.push_back(in[i]);
    }
  }
  return EVP_DecodeBase64(out, out_len, max_out, stripped.data(),
                          stripped.size());
}

size_t OPENSSL_pem_public_base64_encode(char *out, size_t max_out,
                                        const uint8_t *in, size_t in_len) {
  g_public_encodes++;
  size_t written = 0;
  while (in_len > 0) {
    size_t n = in_len > 48 ? 48 : in_len;
    // EVP_EncodeBlock also writes a NUL, which the newline then replaces.
    if (written + (n + 2) / 3 * 4 + 1 > max_out) {
      return 0;
    }
    written += EVP_EncodeBlock(reinterpret_cast<uint8_t *>(out + written), in, n);
    out[written++] = '\n';
    in += n;
    in_len -= n;
  }
  return written;
}
#endif


namespace {

// Test that implausible ciphers, notably an IV-less RC4, aren't allowed in PEM.
// This is a regression test for https://github.com/openssl/openssl/issues/6347,
// though our fix differs from upstream.
TEST(PEMTest, NoRC4) {
  static const char kPEM[] =
      "-----BEGIN RSA PUBLIC KEY-----\n"
      "Proc-Type: 4,ENCRYPTED\n"
      "DEK-Info: RC4 -\n"
      "extra-info\n"
      "router-signature\n"
      "\n"
      "Z1w=\n"
      "-----END RSA PUBLIC KEY-----\n";
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(kPEM, sizeof(kPEM) - 1));
  ASSERT_TRUE(bio);
  bssl::UniquePtr<RSA> rsa(PEM_read_bio_RSAPublicKey(
      bio.get(), nullptr, nullptr, const_cast<char *>("password")));
  EXPECT_FALSE(rsa);
  EXPECT_TRUE(
      ErrorEquals(ERR_get_error(), ERR_LIB_PEM, PEM_R_UNSUPPORTED_ENCRYPTION));
}

std::vector<uint8_t> DecodePEMBytes(const char *pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, -1));
  char *name, *header;
  uint8_t *data;
  long len;
  if (bio == nullptr ||  //
      !PEM_read_bio(bio.get(), &name, &header, &data, &len)) {
    return {};
  }
  bssl::UniquePtr<char> free_name(name), free_header(header);
  bssl::UniquePtr<uint8_t> free_data(data);
  return std::vector<uint8_t>(data, data + len);
}

TEST(PEMTest, DecryptPassword) {
  // A private key encrypted with the password "password", encrypted at the
  // PKCS#8 level.
  static const char kEncryptedPEM[] = R"(
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAjnhMUlb9deeQICCAAw
HQYJYIZIAWUDBAECBBAO8j5GA5VK8wjvNrzp/iVhBIGQyQKFfFKlFhxiDkFfyhUc
nPLr0eboQOz8eIaTW1Rblo/qDkQwNtONyfYn909SoIP7iU8UehcBG1UQe41WvQpu
yRKYQteoWSzFl+yzktL2Y/25K7Uc+f2NScjdonYMZ+9/m1HGmEzKO+Hz28cAsJL7
rH2gQ0lkxr1GtW77m2rfMKKuGYhpkgjWUbzJwP9v3iq+
-----END ENCRYPTED PRIVATE KEY-----
)";
  // The same key and password, but encrypted at the PEM level.
  static const char kEncryptedPEM2[] = R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,B3B2988AECAE6EAB0D043105994C1123

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)";

  for (const char *pem : {kEncryptedPEM, kEncryptedPEM2}) {
    SCOPED_TRACE(pem);
    // Decrypt with the correct password.
    {
      bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, -1));
      ASSERT_TRUE(bio);
      bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(
          bio.get(), nullptr, nullptr, const_cast<char *>("password")));
      EXPECT_TRUE(pkey);
    }

    // Decrypt with the wrong password.
    {
      bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, -1));
      ASSERT_TRUE(bio);
      bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(
          bio.get(), nullptr, nullptr, const_cast<char *>("wrong")));
      EXPECT_FALSE(pkey);
      EXPECT_TRUE(
          ErrorEquals(ERR_peek_error(), ERR_LIB_CIPHER, CIPHER_R_BAD_DECRYPT));
      ERR_clear_error();
    }

    // If the caller did not pass in a password, we should not proceed to try to
    // decrypt.
    {
      bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, -1));
      ASSERT_TRUE(bio);
      bssl::UniquePtr<EVP_PKEY> pkey(
          PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
      EXPECT_FALSE(pkey);
      EXPECT_TRUE(
          ErrorEquals(ERR_peek_error(), ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ));
      ERR_clear_error();
    }

    // If the password, with a NUL terminator, does not fit in the internal
    // buffer used by the PEM library, the PEM library should notice.
    {
      std::string too_long(PEM_BUFSIZE, 'a');
      bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, -1));
      ASSERT_TRUE(bio);
      bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(
          bio.get(), nullptr, nullptr, const_cast<char *>(too_long.c_str())));
      EXPECT_FALSE(pkey);
      EXPECT_TRUE(
          ErrorEquals(ERR_peek_error(), ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ));
      ERR_clear_error();
    }
  }

  // `d2i_PKCS8PrivateKey_bio` should also be able to manage the password
  // callback correctly.
  std::vector<uint8_t> bytes = DecodePEMBytes(kEncryptedPEM);
  ASSERT_FALSE(bytes.empty());
  {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(bytes.data(), bytes.size()));
    ASSERT_TRUE(bio);
    bssl::UniquePtr<EVP_PKEY> pkey(d2i_PKCS8PrivateKey_bio(
        bio.get(), nullptr, nullptr, const_cast<char *>("password")));
    EXPECT_TRUE(pkey);
  }

  {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(bytes.data(), bytes.size()));
    ASSERT_TRUE(bio);
    bssl::UniquePtr<EVP_PKEY> pkey(
        d2i_PKCS8PrivateKey_bio(bio.get(), nullptr, nullptr, nullptr));
    EXPECT_FALSE(pkey);
    EXPECT_TRUE(
        ErrorEquals(ERR_peek_error(), ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ));
    ERR_clear_error();
  }

  {
    std::string too_long(PEM_BUFSIZE, 'a');
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(bytes.data(), bytes.size()));
    ASSERT_TRUE(bio);
    bssl::UniquePtr<EVP_PKEY> pkey(d2i_PKCS8PrivateKey_bio(
        bio.get(), nullptr, nullptr, const_cast<char *>(too_long.c_str())));
    EXPECT_FALSE(pkey);
    EXPECT_TRUE(
        ErrorEquals(ERR_peek_error(), ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ));
    ERR_clear_error();
  }

  // A private key encrypted with the empty password, encrypted at the PKCS#8
  // level.
  static const char kEncryptedPEMEmpty[] = R"(
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBAXiHC8iDcjzF0I+D2g
zJOcAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBAgQQwupOMi8DtEWiuXt5
Odla9QSBkC37uJuG7HSCOyTVCEW76Kmf7GoH+Ou17bDAp6NGwm3KLxRfFoExki9g
hyLzdarBnhRbPqwMixhaQ2AtkpoSmjristGzZ9U7Y+TM3NnCA4+bu1TckdBn0g+Q
fvZI9eydS9buA0deGxCUytrMWrR3PxS1yoXBywMDJTom8u5hvvvkJ9WcNzUVRf0D
6z5NHHiXsQ==
-----END ENCRYPTED PRIVATE KEY-----
)";
  // THe same key and password, but encrypted at the PEM level.
  static const char kEncryptedPEMEmpty2[] = R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,A9505A7DD5C3B51D8AACED18F5758256

yfJKjep7Koj8hU/PtGC+NNXSNbItQ2zyeXDMVoazffraoDGMg6g1hFPPjg9reC+J
iQQIf9uACF27zi9fpWwbszszimrxl0u6n0ddBXizcK6xzkTvk3PZ67Vz1KYmotwC
XjgdgSEeixwKhDOuHKFdlFGP/7sw5GHlK3jPSpqi2gI=
-----END EC PRIVATE KEY-----
)";

  for (const char *pem : {kEncryptedPEMEmpty, kEncryptedPEMEmpty2}) {
    SCOPED_TRACE(pem);

    // The empty password should be correctly interpreted as a password.
    {
      bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, -1));
      ASSERT_TRUE(bio);
      bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(
          bio.get(), nullptr, nullptr, const_cast<char *>("")));
      EXPECT_TRUE(pkey);
    }
  }

  // `d2i_PKCS8PrivateKey_bio` should also be able to manage the password
  // callback correctly.
  bytes = DecodePEMBytes(kEncryptedPEMEmpty);
  {
    ASSERT_FALSE(bytes.empty());
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(bytes.data(), bytes.size()));
    ASSERT_TRUE(bio);
    bssl::UniquePtr<EVP_PKEY> pkey(d2i_PKCS8PrivateKey_bio(
        bio.get(), nullptr, nullptr, const_cast<char *>("")));
    EXPECT_TRUE(pkey);
  }
}

TEST(PEMTest, EncryptPassword) {
  static const char kKey[] = R"(
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBw8IcnrUoEqc3VnJ
TYlodwi1b8ldMHcO6NHJzgqLtGqhRANCAATmK2niv2Wfl74vHg2UikzVl2u3qR4N
Rvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYaHPUdfvGULUvPciLB
-----END PRIVATE KEY-----
)";
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(kKey, -1));
  ASSERT_TRUE(bio);
  bssl::UniquePtr<EVP_PKEY> pkey(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  EXPECT_TRUE(pkey);

  // There are many ways to encrypt a PEM blob with a password.
  struct PasswordMethod {
    const char *name;
    std::function<bool(BIO *, const char *)> func;
    bool is_callback;
  };
  const PasswordMethod kPasswordMethods[] = {
      {"PKCS#8 encryption, password from param",
       [&](BIO *out, const char *pass) -> bool {
         return PEM_write_bio_PrivateKey(
             out, pkey.get(), EVP_aes_128_cbc(),
             reinterpret_cast<const unsigned char *>(pass),
             pass == nullptr ? 0 : strlen(pass), nullptr, nullptr);
       },
       /*is_callback=*/false},
      {"PKCS#8 encryption, password from callback",
       [&](BIO *out, const char *pass) -> bool {
         return PEM_write_bio_PrivateKey(out, pkey.get(), EVP_aes_128_cbc(),
                                         nullptr, 0, nullptr,
                                         const_cast<char *>(pass));
       },
       /*is_callback=*/true},
      {"PEM-level encryption, password from param",
       [&](BIO *out, const char *pass) -> bool {
         return PEM_write_bio_ECPrivateKey(
             out, EVP_PKEY_get0_EC_KEY(pkey.get()), EVP_aes_128_cbc(), nullptr,
             0, nullptr, const_cast<char *>(pass));
       },
       /*is_callback=*/false},
      {"PKCS#8 encryption, password from callback",
       [&](BIO *out, const char *pass) -> bool {
         return PEM_write_bio_ECPrivateKey(
             out, EVP_PKEY_get0_EC_KEY(pkey.get()), EVP_aes_128_cbc(), nullptr,
             0, nullptr, const_cast<char *>(pass));
       },
       /*is_callback=*/true},
  };
  for (const auto &p : kPasswordMethods) {
    SCOPED_TRACE(p.name);

    // Encrypting the private key with a password should work.
    bio.reset(BIO_new(BIO_s_mem()));
    ASSERT_TRUE(bio);
    ASSERT_TRUE(p.func(bio.get(), "password"));

    // Check we can decrypt it.
    bssl::UniquePtr<EVP_PKEY> pkey2(PEM_read_bio_PrivateKey(
        bio.get(), nullptr, nullptr, const_cast<char *>("password")));
    ASSERT_TRUE(pkey2);

    // The empty string is a valid password.
    bio.reset(BIO_new(BIO_s_mem()));
    ASSERT_TRUE(bio);
    ASSERT_TRUE(p.func(bio.get(), ""));

    // Check we can decrypt it.
    pkey2.reset(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr,
                                        const_cast<char *>("")));
    ASSERT_TRUE(pkey2);

    // Check error-handling when the password is specified via the callback.
    if (p.is_callback) {
      bio.reset(BIO_new(BIO_s_mem()));
      ASSERT_TRUE(bio);
      EXPECT_FALSE(p.func(bio.get(), nullptr));
      EXPECT_TRUE(ErrorEquals(ERR_peek_error(), ERR_LIB_PEM, PEM_R_READ_KEY));
      ERR_clear_error();

      std::string too_long(PEM_BUFSIZE, 'a');
      bio.reset(BIO_new(BIO_s_mem()));
      ASSERT_TRUE(bio);
      EXPECT_FALSE(p.func(bio.get(), too_long.c_str()));
      EXPECT_TRUE(ErrorEquals(ERR_peek_error(), ERR_LIB_PEM, PEM_R_READ_KEY));
      ERR_clear_error();
    }
  }
}

TEST(PEMTest, BadHeaders) {
  const struct {
    const char *pem;
    int err_lib, err_reason;
  } kTests[] = {
      // Proc-Type must be the first header.
      {
          R"(
-----BEGIN EC PRIVATE KEY-----
DEK-Info: AES-128-CBC,B3B2988AECAE6EAB0D043105994C1123
Proc-Type: 4,ENCRYPTED

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)",
          ERR_LIB_PEM, PEM_R_NOT_PROC_TYPE},
      // Unsupported Proc-Type version.
      {
          R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 5,ENCRYPTED
DEK-Info: AES-128-CBC,B3B2988AECAE6EAB0D043105994C1123

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)",
          ERR_LIB_PEM, PEM_R_UNSUPPORTED_PROC_TYPE_VERSION},
      // Unsupported Proc-Type version.
      {
          R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 42,ENCRYPTED
DEK-Info: AES-128-CBC,B3B2988AECAE6EAB0D043105994C1123

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)",
          ERR_LIB_PEM, PEM_R_UNSUPPORTED_PROC_TYPE_VERSION},
      // Unsupported Proc-Type.
      {
          R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,MIC-ONLY
DEK-Info: AES-128-CBC,B3B2988AECAE6EAB0D043105994C1123

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)",
          ERR_LIB_PEM, PEM_R_NOT_ENCRYPTED},
      // Missing DEK-Info.
      {
          R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)",
          ERR_LIB_PEM, PEM_R_NOT_DEK_INFO},
      // Unsupported cipher.
      {
          R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-127-CBC,B3B2988AECAE6EAB0D043105994C1123

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)",
          ERR_LIB_PEM, PEM_R_UNSUPPORTED_ENCRYPTION},
      // IV is not hex.
      {
          R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,B3B2988AECAE6EAB0D043105994C112Z

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)",
          ERR_LIB_PEM, PEM_R_BAD_IV_CHARS},
      // Truncated IV.
      {
          R"(
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,B3B2988AECAE6EAB0D043105994C112

RK7DUIGDHWTFh2rpTX+dR88hUyC1PyDlIULiNCkuWFwHrJbc1gM6hMVOKmU196XC
iITrIKmilFm9CPD6Tpfk/NhI/QPxyJlk1geIkxpvUZ2FCeMuYI1To14oYOUKv14q
wr6JtaX2G+pOmwcSPymZC4u2TncAP7KHgS8UGcMw8CE=
-----END EC PRIVATE KEY-----
)",
          ERR_LIB_PEM, PEM_R_BAD_IV_CHARS},
  };
  for (const auto &t : kTests) {
    SCOPED_TRACE(t.pem);
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(t.pem, -1));
    ASSERT_TRUE(bio);
    bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(
        bio.get(), nullptr, nullptr, const_cast<char *>("password")));
    EXPECT_FALSE(pkey);
    EXPECT_TRUE(ErrorEquals(ERR_get_error(), t.err_lib, t.err_reason));
    ERR_clear_error();
  }
}

TEST(PEMTest, ParsingErrorsAndSuccesses) {
  const struct {
    const char *name;
    const char *pem;
    int err_reason;
    const char *want_name = nullptr;
    const char *want_header = nullptr;
    const char *want_body = nullptr;
  } kTests[] = {
      {"WithHeadersOK",
       "-----BEGIN BEST-----\nX-Hdr: h\n\nYmFzZTY0\n-----END BEST-----",  //
       0, "BEST", "X-Hdr: h\n", "base64"},
      {"NoHeadersNoBlankLineOK",
       "-----BEGIN FEST-----\nYmFzZTY0\n-----END FEST-----",  //
       0, "FEST", "", "base64"},
      {"WithHeadersWeirdLineSplitOK",
       "-----BEGIN JEST-----\nX-Hdr: h\n\nYmF\nzZTY0\n-----END JEST-----",  //
       0, "JEST", "X-Hdr: h\n", "base64"},
      {"NoHeadersNoBlankLineWeirdLineSplitOK",
       "-----BEGIN LEST-----\nYmF\nzZTY0\n-----END LEST-----",  //
       0, "LEST", "", "base64"},
      {"WithHeadersAndRubbishOK",
       "a\n-----BEGIN TEST-----\nX-Hdr: h\n\nYmFzZTY0\n-----END TEST-----\nb",
       0, "TEST", "X-Hdr: h\n", "base64"},
      {"NoHeadersNoBlankLineButRubbishOK",
       "a\n-----BEGIN ZEST-----\nYmFzZTY0\n-----END ZEST-----\nb",  //
       0, "ZEST", "", "base64"},
      {"ByteOrderMarkOK",
       "\xef\xbb\xbf-----BEGIN TEST-----\nYmFzZTY0\n-----END TEST-----",  //
       0, "TEST", "", "base64"},
      {"ByteOrderMarkAndRubbishOK",
       "\xef\xbb\xbf\n-----BEGIN TEST-----\nYmFzZTY0\n-----END TEST-----",  //
       0, "TEST", "", "base64"},
      {"ByteOrderMarkAfterRubbish",
       "a\n\xef\xbb\xbf-----BEGIN TEST-----\nYmFzZTY0\n-----END TEST-----",
       PEM_R_NO_START_LINE},
      {"TwoByteOrderMarks",
       "\xef\xbb\xbf\xef\xbb\xbf-----BEGIN TEST-----\nYmFzZTY0\n-----END "
       "TEST-----",
       PEM_R_NO_START_LINE},
      {"OnlyByteOrderMark", "\xef\xbb\xbf",  //
       PEM_R_NO_START_LINE},
      {"Empty", "",  //
       PEM_R_NO_START_LINE},
      {"NoStart",           //
       "Not a PEM file\n",  //
       PEM_R_NO_START_LINE},
      {"TruncatedBeforeStart",  //
       "-----BEGIN ",           //
       PEM_R_NO_START_LINE},
      {"TruncatedAfterStart",     //
       "-----BEGIN TEST-----\n",  //
       PEM_R_BAD_END_LINE},
      {"MismatchedEnd",                                //
       "-----BEGIN TEST-----\n-----END OTHER-----\n",  //
       PEM_R_BAD_END_LINE},
      {"MismatchedEndLonger",                          //
       "-----BEGIN TEST-----\n-----END TEST1-----\n",  //
       PEM_R_BAD_END_LINE},
      {"NoData",                                      //
       "-----BEGIN TEST-----\n-----END TEST-----\n",  //
       PEM_R_NO_DATA},
      {"NoDataButHeaders",                                        //
       "-----BEGIN TEST-----\nX-Hdr: h\n\n-----END TEST-----\n",  //
       PEM_R_NO_DATA},
      {"InvalidBase64",  //
       "-----BEGIN TEST-----\n!!!!\n-----END TEST-----\n",
       PEM_R_BAD_BASE64_DECODE},
  };

  for (const auto &t : kTests) {
    SCOPED_TRACE(t.name);
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(t.pem, -1));
    char *name, *header;
    uint8_t *data;
    long len;
    if (PEM_read_bio(bio.get(), &name, &header, &data, &len)) {
      EXPECT_EQ(t.err_reason, 0);
      EXPECT_EQ(Bytes(name), Bytes(t.want_name));
      EXPECT_EQ(Bytes(header), Bytes(t.want_header));
      EXPECT_EQ(Bytes(data, len), Bytes(t.want_body));
      OPENSSL_free(name);
      OPENSSL_free(header);
      OPENSSL_free(data);
    } else {
      EXPECT_NE(t.err_reason, 0);
      EXPECT_TRUE(ErrorEquals(ERR_get_error(), ERR_LIB_PEM, t.err_reason));
      ERR_clear_error();
    }
  }
}

TEST(PEMTest, LongLines) {
  const std::string kBody(1024, 'A');
  for (const char *eol : {"\n", "\r\n", "  \r\n"}) {
    for (size_t split = 1; split < kBody.size(); split++) {
      SCOPED_TRACE(split);
      const std::string first = kBody.substr(0, split) + eol;
      const std::string rest = kBody.substr(split) + eol + "-----END TEST-----";
      for (bool has_header : {false, true}) {
        const std::string pem = "-----BEGIN TEST-----\n" + first +
                                (has_header ? eol + first : "") + rest;
        bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));
        char *name, *header;
        uint8_t *data;
        long len;
        ASSERT_TRUE(PEM_read_bio(bio.get(), &name, &header, &data, &len));
        EXPECT_EQ(has_header, header[0] != '\0');
        EXPECT_EQ(768, len);
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
      }
    }
  }
}

// The placeholder ANY PRIVATE KEY value is not a valid key type.
TEST(PEMTest, AnyPrivateKey) {
  {
    static const char kInput[] = R"(
-----BEGIN ANY PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBw8IcnrUoEqc3VnJ
TYlodwi1b8ldMHcO6NHJzgqLtGqhRANCAATmK2niv2Wfl74vHg2UikzVl2u3qR4N
Rvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYaHPUdfvGULUvPciLB
-----END ANY PRIVATE KEY-----
)";
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(kInput, -1));
    ASSERT_TRUE(bio);
    bssl::UniquePtr<EVP_PKEY> pkey(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    EXPECT_FALSE(pkey);
    EXPECT_TRUE(ErrorEquals(ERR_get_error(), ERR_LIB_PEM, PEM_R_NO_START_LINE));
  }

  {
    static const char kInput[] = R"(
-----BEGIN ANY PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBw8IcnrUoEqc3VnJ
TYlodwi1b8ldMHcO6NHJzgqLtGqhRANCAATmK2niv2Wfl74vHg2UikzVl2u3qR4N
Rvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYaHPUdfvGULUvPciLB
-----END ANY PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBw8IcnrUoEqc3VnJ
TYlodwi1b8ldMHcO6NHJzgqLtGqhRANCAATmK2niv2Wfl74vHg2UikzVl2u3qR4N
Rvvdqakendy6WgHn1peoChj5w8SjHlbifINI2xYaHPUdfvGULUvPciLB
-----END PRIVATE KEY-----
)";
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(kInput, -1));
    ASSERT_TRUE(bio);
    bssl::UniquePtr<EVP_PKEY> pkey(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    ASSERT_TRUE(pkey);
    EXPECT_EQ(EVP_PKEY_id(pkey.get()), EVP_PKEY_EC);
  }
}

}  // namespace

// Round-trip PEM blocks of assorted sizes under public and private labels. When
// built with BORINGSSL_PEM_FAST_PUBLIC_BASE64, public labels must go through
// the embedder hooks and private labels must not; either way the encoding must
// be byte-for-byte what the constant-time path produces.
TEST(PEMTest, PublicBase64HookRoundTrip) {
  for (size_t len : {0, 1, 2, 3, 47, 48, 49, 64, 100, 1000, 4096, 5000}) {
    SCOPED_TRACE(len);
    std::vector<uint8_t> data(len);
    for (size_t i = 0; i < len; i++) {
      data[i] = static_cast<uint8_t>(i * 7 + len);
    }
    // The expected body, from the constant-time encoder.
    std::string expected_body;
    if (len > 0) {
      size_t max;
      ASSERT_TRUE(EVP_EncodedLength(&max, len));
      std::vector<uint8_t> tmp(max + max / 64 + 2);
      EVP_ENCODE_CTX ctx;
      int n = 0, total = 0;
      EVP_EncodeInit(&ctx);
      EVP_EncodeUpdate(&ctx, tmp.data(), &n, data.data(), len);
      total += n;
      EVP_EncodeFinal(&ctx, tmp.data() + total, &n);
      total += n;
      expected_body.assign(reinterpret_cast<char *>(tmp.data()), total);
    }
    for (const char *label : {"CERTIFICATE", "X509 CRL", "PUBLIC KEY",
                              "RSA PRIVATE KEY", "PRIVATE KEY",
                              "SSL SESSION PARAMETERS"}) {
      SCOPED_TRACE(label);
#if defined(BORINGSSL_PEM_FAST_PUBLIC_BASE64)
      int decodes_before = g_public_decodes, encodes_before = g_public_encodes;
      bool is_public = strstr(label, "PRIVATE") == nullptr &&
                       strstr(label, "SESSION") == nullptr;
#endif
      bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
      ASSERT_TRUE(bio);
      int ret = PEM_write_bio(bio.get(), label, "", data.data(), len);
      if (len == 0) {
        // An empty body has always been an error to write.
        EXPECT_EQ(0, ret);
        ERR_clear_error();
        continue;
      }
      ASSERT_EQ(static_cast<int>(expected_body.size()), ret);
      const uint8_t *contents;
      size_t contents_len;
      ASSERT_TRUE(BIO_mem_contents(bio.get(), &contents, &contents_len));
      std::string expected = std::string("-----BEGIN ") + label + "-----\n" +
                             expected_body + "-----END " + label + "-----\n";
      EXPECT_EQ(Bytes(expected), Bytes(contents, contents_len));

      char *name = nullptr, *header = nullptr;
      uint8_t *decoded = nullptr;
      long decoded_len = 0;
      ASSERT_TRUE(
          PEM_read_bio(bio.get(), &name, &header, &decoded, &decoded_len));
      EXPECT_STREQ(label, name);
      EXPECT_STREQ("", header);
      EXPECT_EQ(Bytes(data), Bytes(decoded, decoded_len));
      OPENSSL_free(name);
      OPENSSL_free(header);
      OPENSSL_free(decoded);
#if defined(BORINGSSL_PEM_FAST_PUBLIC_BASE64)
      EXPECT_EQ(decodes_before + (is_public ? 1 : 0), g_public_decodes);
      EXPECT_EQ(encodes_before + (is_public ? 1 : 0), g_public_encodes);
#endif
    }
  }

  // Invalid base64 under a public label is still rejected.
  static const char kBad[] =
      "-----BEGIN CERTIFICATE-----\nAAA*\n-----END CERTIFICATE-----\n";
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(kBad, strlen(kBad)));
  ASSERT_TRUE(bio);
  char *name = nullptr, *header = nullptr;
  uint8_t *decoded = nullptr;
  long decoded_len = 0;
  EXPECT_FALSE(PEM_read_bio(bio.get(), &name, &header, &decoded, &decoded_len));
  EXPECT_TRUE(
      ErrorEquals(ERR_get_error(), ERR_LIB_PEM, PEM_R_BAD_BASE64_DECODE));
}
