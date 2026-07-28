#!/usr/bin/env bash
# Generate deterministic demo fixtures with openssl so the demo runs fully offline:
#   - a self-signed mesh CA (EC P-384 / ecdsa-with-SHA384), mirroring the c8s mesh CA
#   - a CDS leaf cert (EC P-256) signed by that CA, bundled with attestation
# Also copies a real recorded SNP evidence fixture from attestation-rs so the WASM
# verifier has genuine hardware-signed evidence to verify.
#
# Re-run only when you want to rotate the demo CA; the outputs are committed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/fixtures"
mkdir -p "$out"

ATT_RS="${ATTESTATION_RS:-$here/../../attestation-rs}"
EVIDENCE_SRC="$ATT_RS/crates/attestation/test_data/snp/live-evidence-genoa.json"

echo "==> mesh CA (EC P-384, self-signed)"
openssl ecparam -name secp384r1 -genkey -noout -out "$out/mesh-ca.key"
openssl req -new -x509 -key "$out/mesh-ca.key" -sha384 -days 3650 \
  -subj "/CN=c8s-demo-mesh-ca" -out "$out/mesh-ca.crt"

echo "==> CDS leaf (EC P-256) signed by the mesh CA"
openssl ecparam -name prime256v1 -genkey -noout -out "$out/cds-leaf.key"
openssl req -new -key "$out/cds-leaf.key" -subj "/CN=lb.demo.c8s.local" -out "$out/cds-leaf.csr"
cat > "$out/leaf.ext" <<EOF
subjectAltName = DNS:lb.demo.c8s.local
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF
openssl x509 -req -in "$out/cds-leaf.csr" -CA "$out/mesh-ca.crt" -CAkey "$out/mesh-ca.key" \
  -CAcreateserial -sha384 -days 825 -extfile "$out/leaf.ext" -out "$out/cds-leaf.crt"
rm -f "$out/cds-leaf.csr" "$out/leaf.ext" "$out/mesh-ca.srl"

echo "==> recorded SNP evidence (from attestation-rs)"
if [[ -f "$EVIDENCE_SRC" ]]; then
  cp "$EVIDENCE_SRC" "$out/snp-evidence-genoa.json"
  echo "    copied $EVIDENCE_SRC"
else
  echo "    WARNING: $EVIDENCE_SRC not found; set ATTESTATION_RS=/path/to/attestation-rs" >&2
fi

echo "==> done. Fixtures in $out:"
ls -1 "$out"
