# MTC test certs

This directory contains the following certs:

- `mtc-leaf.pem`
  - signatureless MTC issued by an MTC CA
- `mtc-ica.pem`
  - signatureless MTC issued by the same MTC CA
  - its BasicConstraints has `cA=TRUE`
- `leaf.pem`
  - classical ECDSA cert (SPKI) with ECDSA `signatureAlgorithm`
  - issued by `mtc-ica.pem`

## (Re)generating test certs

Generating these certs is done in two steps.

The first step is to generate a keypair for the ICA and use the private key to
sign the leaf cert:

1. Run `go run generate_leaf.go`
2. Copy the certificate PEM to `leaf.pem`
3. Copy the ICA SPKI base64 to the first `PublicKey` entry in `mtc-config.json`

The next step is to generate the MTC representation of the ICA:

1. Run `mkdir out`
2. Run
   `go run github.com/ietf-plants-wg/merkle-tree-certs.git/demo@9029a99bcfa4e91b8b8e9ba646ac386a6e1c208f -config=mtc-config.json -out=out`
3. Move `out/cert_0_0.pem` to `mtc-ica.pem`
4. Move `out/cert_1_0.pem` to `mtc-leaf.pem`
5. Copy the subtree and hash from the command output into
   `PathBuilderMTCPlants04Test::SetUp`.
6. Remove other artifacts created by the merkle-tree-certs/demo tool (e.g.
   `rm -r out`).
