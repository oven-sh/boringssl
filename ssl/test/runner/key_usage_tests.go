// Copyright 2025 The BoringSSL Authors
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

package runner

import (
	"crypto/x509"
	"strconv"
)

// As in OpenSSL, the handshake only matches ECDSA cipher suites to the key usage
// of the server's certificate. The rest is up to certificate verification.

func addECDSAKeyUsageTests() {
	cert := rootCA.Issue(X509Info{
		PrivateKey: &ecdsaP256Key,
		DNSNames:   []string{"test"},
		// An ECC certificate with only the keyAgreement key usage may
		// be used with ECDH, but not ECDSA.
		KeyUsage: x509.KeyUsageKeyAgreement,
	}).ToCredential()
	ed25519Cert := rootCA.Issue(X509Info{
		PrivateKey: ed25519Key,
		DNSNames:   []string{"test"},
		KeyUsage:   x509.KeyUsageKeyAgreement,
	}).ToCredential()

	for _, ver := range tlsVersions {
		if ver.version < VersionTLS12 {
			continue
		}

		for _, kind := range []struct {
			name string
			cert *Credential
		}{{"ECDSA", &cert}, {"Ed25519", &ed25519Cert}} {
			test := testCase{
				testType: clientTest,
				name:     kind.name + "KeyUsage-Client-" + ver.name,
				config: Config{
					MinVersion: ver.version,
					MaxVersion: ver.version,
					Credential: kind.cert,
				},
				flags: []string{
					"-verify-peer",
					"-verify-prefs", strconv.Itoa(int(signatureEd25519)),
					"-verify-prefs", strconv.Itoa(int(signatureECDSAWithP256AndSHA256)),
				},
			}
			if ver.version < VersionTLS13 {
				test.shouldFail = true
				test.expectedError = ":ECC_CERT_NOT_FOR_SIGNING:"
				test.expectedLocalError = "remote error: handshake failure"
			}
			testCases = append(testCases, test)
		}

		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "ECDSAKeyUsage-Server-" + ver.name,
			config: Config{
				MinVersion: ver.version,
				MaxVersion: ver.version,
				Credential: &cert,
			},
			flags: []string{"-require-any-client-certificate"},
		})

		only := testCase{
			testType: serverTest,
			name:     "ECDSAKeyUsage-Server-OnlyCredential-" + ver.name,
			config: Config{
				MinVersion: ver.version,
				MaxVersion: ver.version,
			},
			shimCertificate: &cert,
		}
		selected := &cert
		if ver.version < VersionTLS13 {
			only.shouldFail = true
			only.expectedError = ":NO_SHARED_CIPHER:"
			selected = &rsaCertificate
		}
		testCases = append(testCases, only)

		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "ECDSAKeyUsage-Server-FirstCredential-" + ver.name,
			config: Config{
				MinVersion: ver.version,
				MaxVersion: ver.version,
			},
			shimCredentials: []*Credential{&cert, &rsaCertificate},
			expectations:    connectionExpectations{peerCertificate: selected},
		})

		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "Ed25519KeyUsage-Server-OnlyCredential-" + ver.name,
			config: Config{
				MinVersion: ver.version,
				MaxVersion: ver.version,
			},
			shimCertificate: &ed25519Cert,
		})

		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "ECDSAKeyUsage-Client-OnlyCredential-" + ver.name,
			config: Config{
				MinVersion: ver.version,
				MaxVersion: ver.version,
				ClientAuth: RequireAnyClientCert,
			},
			shimCertificate: &cert,
			expectations:    connectionExpectations{peerCertificate: &cert},
		})
	}

	testCases = append(testCases, testCase{
		testType: serverTest,
		name:     "ECDSAKeyUsage-Server-PSK",
		config: Config{
			MaxVersion: VersionTLS12,
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
			},
			PreSharedKey: []byte("secret"),
		},
		shimCertificate: &cert,
		flags:           []string{"-psk", "secret", "-async"},
		expectations:    connectionExpectations{cipher: TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA},
	})
}

func addRSAKeyUsageTests() {
	dsCert := rootCA.Issue(X509Info{
		PrivateKey: &rsa2048Key,
		DNSNames:   []string{"test"},
		KeyUsage:   x509.KeyUsageDigitalSignature,
	}).ToCredential()
	encCert := rootCA.Issue(X509Info{
		PrivateKey: &rsa2048Key,
		DNSNames:   []string{"test"},
		KeyUsage:   x509.KeyUsageKeyEncipherment,
	}).ToCredential()

	dsSuites := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	}
	encSuites := []uint16{
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_128_CBC_SHA,
	}

	for _, ver := range tlsVersions {
		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "RSAKeyUsage-Client-WantSignature-GotEncipherment-" + ver.name,
			config: Config{
				MinVersion:   ver.version,
				MaxVersion:   ver.version,
				Credential:   &encCert,
				CipherSuites: dsSuites,
			},
			flags: []string{"-verify-peer"},
		})

		testCases = append(testCases, testCase{
			testType: clientTest,
			name:     "RSAKeyUsage-Client-WantSignature-GotSignature-" + ver.name,
			config: Config{
				MinVersion:   ver.version,
				MaxVersion:   ver.version,
				Credential:   &dsCert,
				CipherSuites: dsSuites,
			},
		})

		// TLS 1.3 removes the encipherment suites.
		if ver.version < VersionTLS13 {
			testCases = append(testCases, testCase{
				testType: clientTest,
				name:     "RSAKeyUsage-Client-WantEncipherment-GotEncipherment" + ver.name,
				config: Config{
					MinVersion:   ver.version,
					MaxVersion:   ver.version,
					Credential:   &encCert,
					CipherSuites: encSuites,
				},
			})

			testCases = append(testCases, testCase{
				testType: clientTest,
				name:     "RSAKeyUsage-Client-WantEncipherment-GotSignature-" + ver.name,
				config: Config{
					MinVersion:   ver.version,
					MaxVersion:   ver.version,
					Credential:   &dsCert,
					CipherSuites: encSuites,
				},
				flags: []string{"-verify-peer"},
			})
		}

		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "RSAKeyUsage-Server-OnlyCredential-" + ver.name,
			config: Config{
				MinVersion:   ver.version,
				MaxVersion:   ver.version,
				CipherSuites: dsSuites,
			},
			shimCertificate: &encCert,
		})

		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "RSAKeyUsage-Server-WantSignature-GotEncipherment-" + ver.name,
			config: Config{
				MinVersion: ver.version,
				MaxVersion: ver.version,
				Credential: &encCert,
			},
			flags: []string{"-require-any-client-certificate"},
		})

		testCases = append(testCases, testCase{
			testType: serverTest,
			name:     "RSAKeyUsage-Server-WantSignature-GotSignature-" + ver.name,
			config: Config{
				MinVersion: ver.version,
				MaxVersion: ver.version,
				Credential: &dsCert,
			},
			flags: []string{"-require-any-client-certificate"},
		})

	}
}
