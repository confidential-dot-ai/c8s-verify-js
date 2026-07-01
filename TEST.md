# Cross-repo demo: JS client ↔ real Go Load Balancer

This walks through running the **real `c8s` Go attestation + over-encryption sidecar**
(`c8s cds-attest`) and driving it with the **`c8s-verify-js` browser client**. It exercises
the whole `c8s-verify/v1` protocol — SEV-SNP attestation, the post-quantum hybrid
handshake, and the CBOR over-encrypted application tunnel — across two independent
implementations (Go and JavaScript). If the echo round-trips, the wire formats match.

> This is the integration counterpart to the JS-only e2e test (`npm test`, which runs the
> client against the JS mock LB in `demo/server.ts`). Here the server is the production Go
> code instead.

## Layout assumed

Both repos checked out side by side:

```
code/
├── c8s/             # the Go monorepo (cds-attest sidecar lives here)
└── c8s-verify-js/   # this repo (browser verifier + client)
```

Adjust the paths below if yours differ.

## What makes it a *demo* and not production

This runs the **real sidecar binary** but feeds it **committed fixtures** instead of a live
cluster, because the two things a real deployment provides — a TEE and the CDS — can't be
reproduced on a laptop. It is worth being precise about what is substituted, because the
setup steps below would look wrong in production:

| Concern | Real cluster | This offline demo |
| --- | --- | --- |
| **SNP evidence** | The sidecar pulls **live** evidence from the attestation-api; the TEE binds the session key into a fresh hardware report each session. | A **recorded** evidence fixture (`demo/fixtures/snp-evidence-genoa.json`, real hardware-signed evidence from attestation-rs). Its `report_data` is a fixed test value, so it can't bind *this* session — hence `requireFreshness: false`. |
| **Certificates** | The in-TEE **CDS** holds the mesh-CA key and issues the LB leaf (via get-cert / the raTLS mesh). The tls-lb **nginx serves `cds-cert.pem` statically**, so the sidecar runs **without** `--cds-cert-file`. | There is no CDS, so we use a **pre-generated openssl chain** (`mesh-ca.crt` + `cds-leaf.crt`, made by `npm run gen-fixtures`) and hand it to the sidecar via `--cds-cert-file` — the flag exists for exactly this dev/standalone case. |

So **step 2 below is not how certs come to be** — in a real cluster you'd start the cluster,
let the CDS generate the mesh CA and issue the LB leaf, and never touch these files. Here we
only *reconstruct the PEM that nginx would otherwise serve* from committed test certs. The
hardware signature, launch measurement, and the X.509 chain are still verified **for real**
by the client; only their *origin* is faked.

The expected launch measurement and these settings are centralised in
[`demo/config.ts`](demo/config.ts) (`DEMO_MEASUREMENTS`, `DEMO_GENERATION`,
`DEMO_PLATFORM`, `DEMO_REQUIRE_FRESHNESS`) and reused below so the two repos agree.

## 1. Build the Go sidecar

From the `c8s` repo:

```bash
cd ../c8s
go build -o build/c8s ./cmd/c8s      # or: make build
```

## 2. Assemble the CDS certificate chain (demo stand-in)

> In a real cluster you skip this entirely: the CDS issues the LB leaf and the tls-lb nginx
> serves `cds_cert_pem` statically, so the sidecar runs without `--cds-cert-file`. Offline
> there is no CDS, so we hand the sidecar a pre-generated chain instead — see the table
> above. (If `demo/fixtures/` is missing, run `npm run gen-fixtures` first.)

The served `cds_cert_pem` is the LB leaf followed by the mesh CA. Concatenate the two demo
certs into one PEM, in that order, exactly as the JS mock server builds it:

```bash
cat ../c8s-verify-js/demo/fixtures/cds-leaf.crt \
    ../c8s-verify-js/demo/fixtures/mesh-ca.crt \
    > /tmp/c8s-demo-cds-cert.pem
```

## 3. Run the real Go server

Still in `c8s`, point it at this repo's recorded fixture and the cert chain. With no
`--upstream` it uses the built-in echo backend, which is all the demo needs:

```bash
./build/c8s cds-attest \
  --port 8800 \
  --evidence-fixture ../c8s-verify-js/demo/fixtures/snp-evidence-genoa.json \
  --cds-cert-file   /tmp/c8s-demo-cds-cert.pem \
  --generation genoa --platform snp \
  --log-level info
```

You should see (the two `WARN`s are expected for the fixture/echo demo):

```
level=WARN msg="serving recorded evidence fixture (DEV ONLY): report_data is not bound to live session keys"
level=WARN msg="no --upstream set: using echo backend (demo only)"
level=INFO msg="LB browser-facing endpoints listening" addr=127.0.0.1:8800
```

Leave it running. The endpoints it now serves:

| Endpoint | Purpose |
| --- | --- |
| `GET  /.well-known/c8s/attestation?nonce=…` | attestation bundle (evidence + session pubkey + cert) |
| `POST /.well-known/c8s/handshake` | PQ hybrid key agreement → session id |
| `POST /.well-known/c8s/tunnel` | CBOR over-encrypted application traffic |
| `GET  /.well-known/c8s/cds-cert.pem` | the CDS leaf + mesh CA chain |

## 4. Drive it with the JS client

From this repo, run a small Node client against the Go server. (Node ≥ 20; no install
needed beyond `npm install`, which fetches `mlkem-wasm`.)

Installed as a dependency, the client is a normal package import:

```js
import { C8sClient } from "c8s-verify";
```

To drive it from a checkout of this repo, run the TypeScript sources directly
with `tsx` (no build step — only the WASM verifier needs generating once):

```bash
cd ../c8s-verify-js
npm run build:wasm                    # generate src/wasm/ verifier (once)
node --import tsx --input-type=module -e '
import { C8sClient } from "./src/index.js";
import { DEMO_MEASUREMENTS, DEMO_REQUIRE_FRESHNESS } from "./demo/config.js";

const client = new C8sClient({
  baseUrl: "http://localhost:8800",
  measurements: DEMO_MEASUREMENTS,        // pinned launch digest of the genoa fixture
  requireFreshness: DEMO_REQUIRE_FRESHNESS, // false: recorded fixture is not live-bound
});

const session = await client.connect();   // attestation + verify + PQ handshake
console.log("platform   :", session.attestation.platform);
console.log("measurement:", session.attestation.measurement);
console.log("cert CN    :", session.attestation.cert.subjectCN);

const res = await session.fetch("/v1/echo", {
  method: "POST",
  body: "hi from the JS client over CBOR",
});
console.log("status     :", res.status);
console.log("body       :", res.text());
'
```

Expected output:

```
platform   : snp
measurement: d9912ba396ce409c2947841d93a5076b6839b898c22b4aae05edb3b2b058a99927f8cf9a4f8617ee695deb14795496c8
cert CN    : lb.demo.c8s.local
status     : 200
body       : LB enclave received 31 bytes over the over-encrypted channel for POST /v1/echo: "hi from the JS client over CBOR"
```

The echo coming back through `session.fetch` means: the JS client's CBOR record + envelope
were decrypted and parsed by the Go enclave, and the Go response was re-sealed and decoded
by JS — i.e. the two implementations are wire-compatible over the CBOR tunnel.

## 5. (Optional) Forward to a real backend instead of echo

To prove the tunnel actually proxies HTTP, start any plain HTTP server and point the
sidecar at it with `--upstream`:

```bash
# terminal A: a trivial upstream
python3 -m http.server 9000

# terminal B: sidecar forwarding decrypted traffic to it
./build/c8s cds-attest --port 8800 \
  --evidence-fixture ../c8s-verify-js/demo/fixtures/snp-evidence-genoa.json \
  --cds-cert-file   /tmp/c8s-demo-cds-cert.pem \
  --generation genoa --platform snp \
  --upstream http://localhost:9000
```

Now `session.fetch("/")` returns the upstream's directory listing — encrypted end to end
to the enclave, plaintext only on the sidecar→backend hop (which a live cluster wraps in
its raTLS mesh). For an `https://` upstream, add `--upstream-ca`, `--upstream-cert`,
`--upstream-key`, and `--upstream-server-name` (CDS-issued client cert + mesh-CA
verification).

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `measurement_denied` | Fixture/`generation` mismatch. The fixture is **genoa**; keep `--generation genoa` and the default `DEMO_MEASUREMENTS`. |
| `report_data_mismatch` | You left freshness on. The recorded fixture isn't live-bound — use `requireFreshness: false` (as above). |
| `invalid_cert` / chain error | `cds_cert_pem` not assembled. Re-run step 2 (leaf **then** mesh CA, in that order). |
| `attestation endpoint returned HTTP …` | Server not running, or wrong `--port` / `baseUrl`. |
| one of `--attestation-api-url` or `--evidence-fixture` is required | The sidecar refuses to start without an evidence source; pass `--evidence-fixture` for the demo. |
| `channel_error` on `session.fetch` | Go and JS on **different** tunnel wire formats. Both must be on the CBOR tunnel (this client + a `c8s` build that uses CBOR records — see `PROTOCOL.md` §"Over-encrypted application tunnel"). |

## Browser variant

To run the verifier visually in a browser instead of Node, the self-contained path is the
bundled JS mock LB (`npm run demo`, served on `http://localhost:8799`) — see the README.
Pointing the in-browser demo at the Go server additionally requires serving this repo's
static assets and enabling CORS on the sidecar, so the Node client above is the simplest
way to exercise the *cross-repo* path.
