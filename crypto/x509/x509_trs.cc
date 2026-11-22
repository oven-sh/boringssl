// Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
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

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/x509.h>

#include "../internal.h"
#include "internal.h"


using namespace bssl;

namespace {

typedef struct x509_trust_st X509_TRUST;

struct x509_trust_st {
  int trust;
  int (*check_trust)(const X509_TRUST *, const X509 *, int);
  int nid;
} /* X509_TRUST */;

// obj_trust checks the trust settings of `x` for `id` or, if it is not
// `NID_undef`, `other_id`.
int obj_trust(int id, int other_id, const X509 *x, int flags) {
  auto *impl = FromOpaque(x);
  X509_CERT_AUX *ax = impl->aux;
  if (!ax) {
    return X509_TRUST_UNTRUSTED;
  }
  auto contains = [&](const STACK_OF(ASN1_OBJECT) *objs) {
    for (const ASN1_OBJECT *obj : objs) {
      int nid = OBJ_obj2nid(obj);
      if (nid != NID_undef && (nid == id || nid == other_id)) {
        return true;
      }
    }
    return false;
  };
  if (contains(ax->reject)) {
    return X509_TRUST_REJECTED;
  }
  if (contains(ax->trust)) {
    return X509_TRUST_TRUSTED;
  }
  // As in OpenSSL, a list of trusted uses rejects the others.
  return ax->trust != nullptr && !(flags & X509_TRUST_NO_IMPLIED_REJECT)
             ? X509_TRUST_REJECTED
             : X509_TRUST_UNTRUSTED;
}

int trust_compat(const X509_TRUST *trust, const X509 *x, int flags) {
  auto *impl = FromOpaque(x);
  if (!x509v3_cache_extensions(x)) {
    return X509_TRUST_UNTRUSTED;
  }
  if (!(flags & X509_TRUST_NO_SS_COMPAT) && (impl->ex_flags & EXFLAG_SS)) {
    return X509_TRUST_TRUSTED;
  } else {
    return X509_TRUST_UNTRUSTED;
  }
}

int trust_1oidany(const X509_TRUST *trust, const X509 *x, int flags) {
  int rv = obj_trust(trust->nid, NID_anyExtendedKeyUsage, x, flags);
  if (rv != X509_TRUST_UNTRUSTED) {
    return rv;
  }
  // No trust setting applies: for compatibility we return trusted if it is
  // self signed
  return trust_compat(trust, x, flags);
}

const X509_TRUST trstandard[] = {
    {X509_TRUST_COMPAT, trust_compat, 0},
    {X509_TRUST_SSL_CLIENT, trust_1oidany, NID_client_auth},
    {X509_TRUST_SSL_SERVER, trust_1oidany, NID_server_auth},
    {X509_TRUST_EMAIL, trust_1oidany, NID_email_protect},
    {X509_TRUST_OBJECT_SIGN, trust_1oidany, NID_code_sign},
    {X509_TRUST_TSA, trust_1oidany, NID_time_stamp}};

const X509_TRUST *X509_TRUST_get0(int id) {
  for (const auto &t : trstandard) {
    if (t.trust == id) {
      return &t;
    }
  }
  return nullptr;
}

}  // namespace

int X509_check_trust(const X509 *x, int id, int flags) {
  if (id == -1) {
    return X509_TRUST_TRUSTED;
  }
  // We get this as a default value
  if (id == 0) {
    int rv = obj_trust(NID_anyExtendedKeyUsage, NID_undef, x, flags);
    if (rv != X509_TRUST_UNTRUSTED) {
      return rv;
    }
    return trust_compat(nullptr, x, flags);
  }
  const X509_TRUST *pt = X509_TRUST_get0(id);
  if (pt == nullptr) {
    // Unknown trust IDs are silently reintrepreted as NIDs. This is unreachable
    // from the certificate verifier itself, but wpa_supplicant relies on it.
    // Note this relies on commonly-used NIDs and trust IDs not colliding.
    return obj_trust(id, NID_undef, x, flags);
  }
  return pt->check_trust(pt, x, flags);
}

int bssl::X509_is_valid_trust_id(int trust) {
  return X509_TRUST_get0(trust) != nullptr;
}
