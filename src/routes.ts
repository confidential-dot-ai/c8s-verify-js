// Signed route manifests: the envelope a router publishes at
// /.well-known/c8s/routes, verified as c8s pkg/routes VerifySigned verifies
// it, and the route selection the manifest implies. Decoders follow the Go
// ones c8s uses (encoding/base64, encoding/pem, net.ParseIP), so a manifest
// verifies here exactly when it verifies there. Two deliberate exceptions
// are stricter: the token's alg must match the key's curve, and a crit
// header is refused.
//
// Both C8sClient and verifyPublishedRoutes check the full schema, backend
// fields included. The client alone would not need it, since its digest check
// ties the manifest to one an attested router applied, but the standalone
// verdict of verifyPublishedRoutes does; keep the schema in step with c8s.

import { readChildren, readTLV, decodeOID, TAG } from "./asn1.js";
import { bytesToBase64, bytesToBase64Url, bytesToHex, utf8ToBytes } from "./base64.js";
import { subtle } from "./crypto-env.js";
import { C8sVerifyError, fail } from "./errors.js";
import { decodePEM } from "./pem.js";
import { parseStrictJson, type JsonValue } from "./strict-json.js";
import { parseCertificate } from "./x509.js";

/** Largest publication body accepted, as c8s verify bounds it. */
export const MAX_ROUTE_PUBLICATION_BYTES = 4 << 20;

const SCHEMA = "c8s.routes/v1";
const MAX_REVISION = 2 ** 53 - 1;
const MAX_MAX_AGE_SECONDS = 2 ** 31 - 1;
const ROUTE_DIGEST_HEX = /^[0-9a-f]{64}$/;

/** A published manifest that verified under the operator keys. */
export interface PublishedRoutes {
  /** The manifest bytes. */
  manifest: Uint8Array;
  revision: number;
  /** SHA-256 of the manifest bytes, 64 lowercase hex: the route digest. */
  routeDigest: string;
  /**
   * Whether the manifest routes a request to a backend: `host` is the Host
   * header, `target` the origin-form request target. The router's reserved
   * paths are not applied.
   */
  routes(host: string, target: string): boolean;
}

/** The revision and route digest a client last accepted: its rollback floor. */
export interface RouteFloor {
  revision: number;
  /** 64 lowercase hex. */
  digest: string;
}

/** An error inside a document; the caller adds the error code and context. */
class Invalid extends Error {}

// ---------------------------------------------------------------------------
// Operator keys
// ---------------------------------------------------------------------------

const EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const CURVES: Record<string, string> = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
};
const CURVE_BYTES: Record<string, number> = { "P-256": 32, "P-384": 48, "P-521": 66 };

/** An operator public key: SubjectPublicKeyInfo DER and its curve. */
export interface RouteOperatorKey {
  spki: Uint8Array;
  curve: string;
}

/**
 * Parse a PEM bundle of operator public keys, ECDSA on P-256, P-384 or P-521.
 * Blocks other than PUBLIC KEY are ignored.
 */
export function parseRouteOperatorKeys(pem: string): RouteOperatorKey[] {
  if (typeof pem !== "string") {
    fail("invalid_request", "routeOperatorKeys must be a PEM string");
  }
  let blocks: Uint8Array[];
  try {
    blocks = decodePEM(pem, "PUBLIC KEY");
  } catch (e) {
    fail("invalid_request", "routeOperatorKeys holds a PEM block that is not base64", {
      cause: e,
    });
  }
  if (blocks.length === 0) {
    fail("invalid_request", "routeOperatorKeys holds no PEM PUBLIC KEY block");
  }
  return blocks.map((spki, i) => {
    let curve: string | undefined;
    try {
      const top = readTLV(spki, 0);
      const [alg, point] = readChildren(spki, top);
      const [oid, params] = readChildren(spki, alg);
      if (decodeOID(oid.content) === EC_PUBLIC_KEY && params?.tag === TAG.OID) {
        curve = CURVES[decodeOID(params.content)];
      }
      // An uncompressed point, the one form Go's x509 parses: no unused
      // bits, 0x04, then x and y. WebCrypto checks it is on the curve.
      const size = curve === undefined ? 0 : CURVE_BYTES[curve];
      const uncompressed =
        top.end === spki.length &&
        point?.tag === TAG.BIT_STRING &&
        point.content.length === 2 + 2 * size &&
        point.content[0] === 0 &&
        point.content[1] === 0x04;
      if (!uncompressed) curve = undefined;
    } catch {
      // Reported below as not an ECDSA key.
    }
    if (curve === undefined) {
      fail(
        "invalid_request",
        `routeOperatorKeys key ${i} is not an uncompressed ECDSA P-256, P-384 or P-521 public key`,
      );
    }
    return { spki, curve };
  });
}

/** Import operator keys for verification. */
export async function importRouteOperatorKeys(keys: RouteOperatorKey[]): Promise<CryptoKey[]> {
  return Promise.all(
    keys.map(async ({ spki, curve }, i) => {
      try {
        return await subtle().importKey("spki", spki, { name: "ECDSA", namedCurve: curve }, false, [
          "verify",
        ]);
      } catch (e) {
        fail("invalid_request", `routeOperatorKeys key ${i} does not import`, { cause: e });
      }
    }),
  );
}

// ---------------------------------------------------------------------------
// Envelope and write token
// ---------------------------------------------------------------------------

/**
 * Verify a publication body under the operator keys (PEM), as c8s
 * `routes.VerifySigned` does with no mesh CAs: the write token's signature,
 * exp−iat of at most five minutes, htm PUT and htu /routes, pbh over the
 * manifest bytes, then the manifest schema. Whether the token has expired is
 * not checked, nor is the revision.
 *
 * Throws `invalid_request` when the PEM holds no usable key,
 * `route_manifest_invalid` for a malformed envelope and
 * `route_manifest_denied` when verification fails.
 */
export async function verifyPublishedRoutes(
  body: Uint8Array | string,
  operatorKeysPem: string,
): Promise<PublishedRoutes> {
  const keys = await importRouteOperatorKeys(parseRouteOperatorKeys(operatorKeysPem));
  return verifySignedRoutes(typeof body === "string" ? utf8ToBytes(body) : body, keys);
}

/** {@link verifyPublishedRoutes} with imported keys. */
export async function verifySignedRoutes(
  body: Uint8Array,
  keys: CryptoKey[],
): Promise<PublishedRoutes> {
  let envelope: { manifest: Uint8Array; token: string };
  try {
    envelope = parseEnvelope(body);
  } catch (e) {
    throw rethrow(e, "route_manifest_invalid", "invalid route publication");
  }
  // A private copy, so the bytes hashed are the bytes parsed.
  const manifest = envelope.manifest.slice();
  const digest = new Uint8Array(await subtle().digest("SHA-256", manifest));
  let parsed: Manifest;
  try {
    await verifyToken(keys, envelope.token, digest);
    parsed = parseManifest(manifest);
  } catch (e) {
    throw rethrow(e, "route_manifest_denied", "the published route manifest does not verify");
  }
  return {
    manifest,
    revision: parsed.revision,
    routeDigest: bytesToHex(digest),
    routes: (host, target) => selects(parsed, host, target),
  };
}

function rethrow(e: unknown, code: "route_manifest_invalid" | "route_manifest_denied", at: string) {
  if (!(e instanceof Invalid) && !(e instanceof SyntaxError)) return e;
  return new C8sVerifyError(code, `${at}: ${e.message}`, { cause: e });
}

function parseEnvelope(body: Uint8Array): { manifest: Uint8Array; token: string } {
  const obj = members(json(body), "envelope", ["manifest", "token"], []);
  const encoded = stringValue(obj.get("manifest"), "manifest");
  const token = stringValue(obj.get("token"), "token");
  const manifest = goBase64(encoded, STD_ALPHABET, true);
  if (manifest === undefined || bytesToBase64(manifest) !== encoded) {
    throw new Invalid("manifest is not standard padded base64");
  }
  return { manifest, token };
}

const ES_ALGORITHMS: Record<string, { hash: string; curve: string }> = {
  ES256: { hash: "SHA-256", curve: "P-256" },
  ES384: { hash: "SHA-384", curve: "P-384" },
  ES512: { hash: "SHA-512", curve: "P-521" },
};

/** c8s operatorauth.MaxTokenValidity: the widest exp−iat window, in seconds. */
const MAX_TOKEN_VALIDITY_SECONDS = 300;

/**
 * Verify a stored write token as c8s operatorauth.VerifyStored does
 * (golang-jwt v5 without claims validation): an ES256, ES384 or ES512
 * signature under one of keys on the matching curve, exp−iat within
 * (0, MaxTokenValidity], then htm, htu and pbh.
 */
async function verifyToken(keys: CryptoKey[], token: string, digest: Uint8Array): Promise<void> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Invalid("write token does not have three segments");
  const header = tokenJson(parts[0], "header");
  const claims = tokenJson(parts[1], "claims");
  const alg = header.alg;
  if (typeof alg !== "string" || !Object.hasOwn(ES_ALGORITHMS, alg)) {
    throw new Invalid("write token alg is not ES256, ES384 or ES512");
  }
  if (Object.hasOwn(header, "crit")) throw new Invalid("write token header has crit");
  const signature = goBase64(parts[2], URL_ALPHABET, false);
  if (signature === undefined) throw new Invalid("write token signature is not base64url");
  const { curve } = ES_ALGORITHMS[alg];
  if (!keys.some((key) => (key.algorithm as EcKeyAlgorithm).namedCurve === curve)) {
    // c8s accepts a mismatched alg, so name the cause rather than a bad signature.
    throw new Invalid(
      `write token alg ${alg} needs a ${curve} operator key; re-sign with the algorithm matching the key's curve`,
    );
  }
  const input = utf8ToBytes(`${parts[0]}.${parts[1]}`);
  let verified = false;
  for (const key of keys) {
    if (await verifyES(key, ES_ALGORITHMS[alg], signature, input)) {
      verified = true;
      break;
    }
  }
  if (!verified) throw new Invalid("write token signature does not verify under any operator key");
  // golang-jwt truncates NumericDate to whole seconds; a non-number is absent.
  const iat = typeof claims.iat === "number" ? Math.floor(claims.iat) : undefined;
  const exp = typeof claims.exp === "number" ? Math.floor(claims.exp) : undefined;
  if (iat === undefined) throw new Invalid("write token has no iat claim");
  if (exp === undefined) throw new Invalid("write token has no exp claim");
  const validity = exp - iat;
  if (!(validity > 0 && validity <= MAX_TOKEN_VALIDITY_SECONDS)) {
    throw new Invalid(
      `write token validity ${validity}s is outside (0, ${MAX_TOKEN_VALIDITY_SECONDS}s]`,
    );
  }
  if (claims.htm !== "PUT") throw new Invalid("write token htm is not PUT");
  if (claims.htu !== "/routes") throw new Invalid("write token htu is not /routes");
  if (typeof claims.pbh !== "string" || claims.pbh === "") {
    throw new Invalid("write token has no pbh claim");
  }
  if (claims.pbh !== bytesToBase64Url(digest)) {
    throw new Invalid("write token pbh does not match the manifest bytes");
  }
}

/** Decode a token segment to a JSON object, as encoding/json reads it into a map. */
function tokenJson(segment: string, what: string): Record<string, unknown> {
  const bytes = goBase64(segment, URL_ALPHABET, false);
  let value: unknown;
  try {
    // Go maps invalid UTF-8 to U+FFFD and rejects a BOM, as these options
    // do, and refuses a number that overflows float64.
    value =
      bytes &&
      JSON.parse(new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes), (_, v: unknown) => {
        if (typeof v === "number" && !Number.isFinite(v)) throw new RangeError("number overflows");
        return v;
      });
  } catch {
    // Reported below.
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Invalid(`write token ${what} is not a base64url JSON object`);
  }
  return value as Record<string, unknown>;
}

/** Verify a raw r||s signature; the algorithm must match the key's curve. */
async function verifyES(
  key: CryptoKey,
  alg: { hash: string; curve: string },
  signature: Uint8Array,
  input: Uint8Array,
): Promise<boolean> {
  const curve = (key.algorithm as EcKeyAlgorithm).namedCurve;
  if (curve !== alg.curve || signature.length !== 2 * CURVE_BYTES[curve]) return false;
  try {
    return await subtle().verify({ name: "ECDSA", hash: alg.hash }, key, signature, input);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

interface Route {
  path: string;
  match: "exact" | "prefix";
}

interface Manifest {
  revision: number;
  hosts: Map<string, Route[]>;
}

function json(bytes: Uint8Array): JsonValue {
  try {
    return parseStrictJson(bytes);
  } catch (e) {
    throw new Invalid((e as Error).message);
  }
}

/** Parse manifest bytes against the c8s.routes/v1 schema, as c8s routes.Parse does. */
function parseManifest(bytes: Uint8Array): Manifest {
  const top = members(
    json(bytes),
    "manifest",
    ["schema", "revision", "notBefore", "maxAgeSeconds", "hosts"],
    [],
  );
  const schema = stringValue(top.get("schema"), "schema");
  if (schema !== SCHEMA) throw new Invalid(`schema: want ${SCHEMA}`);
  const revision = integer(top.get("revision"), "revision", MAX_REVISION);
  checkTimestamp(stringValue(top.get("notBefore"), "notBefore"));
  integer(top.get("maxAgeSeconds"), "maxAgeSeconds", MAX_MAX_AGE_SECONDS);
  return { revision, hosts: parseHosts(top.get("hosts")) };
}

function members(
  value: JsonValue | undefined,
  at: string,
  required: string[],
  optional: string[],
): Map<string, JsonValue> {
  if (value?.kind !== "object") throw new Invalid(`${at}: must be an object`);
  for (const name of required) {
    if (!value.members.has(name))
      throw new Invalid(`${at}: missing member ${JSON.stringify(name)}`);
  }
  for (const name of [...value.members.keys()].sort()) {
    if (!required.includes(name) && !optional.includes(name)) {
      throw new Invalid(`${at}: unknown member ${JSON.stringify(name)}`);
    }
  }
  return value.members;
}

function stringValue(value: JsonValue | undefined, at: string): string {
  if (value?.kind !== "string") throw new Invalid(`${at}: must be a string`);
  return value.value;
}

/** A decimal integer from 1 to limit, without sign, fraction, exponent or leading zero. */
function integer(value: JsonValue | undefined, at: string, limit: number): number {
  if (value?.kind !== "number" || !/^[1-9][0-9]*$/.test(value.text) || BigInt(value.text) > limit) {
    throw new Invalid(`${at}: must be an integer from 1 to ${limit}`);
  }
  return Number(value.text);
}

const DATE_TIME =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])([01]\d|2[0-3]):([0-5]\d))$/;

function isLeap(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysIn(month: number, year: number): number {
  if (month === 2) return isLeap(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/**
 * Check an RFC 3339 date-time with Go time.Parse's field ranges. Second 60
 * is valid only at 23:59 UTC on 30 June or 31 December.
 */
function checkTimestamp(s: string): void {
  const m = DATE_TIME.exec(s);
  if (m === null) throw new Invalid("notBefore: not an RFC 3339 date-time");
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  if (month < 1 || month > 12 || day < 1 || day > daysIn(month, year)) {
    throw new Invalid("notBefore: date out of range");
  }
  if (hour > 23 || minute > 59 || second > 60) throw new Invalid("notBefore: time out of range");
  if (second < 60) return;
  const offset = m[7] === undefined ? 0 : (m[7] === "-" ? -1 : 1) * (+m[8] * 60 + +m[9]);
  const minutes = hour * 60 + minute - offset;
  // An offset moves the UTC time by less than a day.
  let utcDay = day;
  let utcMonth = month;
  if (minutes < 0) {
    utcDay--;
    if (utcDay === 0) {
      utcMonth = month === 1 ? 12 : month - 1;
      utcDay = daysIn(utcMonth, month === 1 ? year - 1 : year);
    }
  } else if (minutes >= 24 * 60) {
    utcDay++;
    if (utcDay > daysIn(month, year)) {
      utcMonth = month === 12 ? 1 : month + 1;
      utcDay = 1;
    }
  }
  const utcMinutes = (minutes + 24 * 60) % (24 * 60);
  const halfYearEnd = (utcMonth === 6 && utcDay === 30) || (utcMonth === 12 && utcDay === 31);
  if (!halfYearEnd || utcMinutes !== 23 * 60 + 59) {
    throw new Invalid("notBefore: second 60 is only valid at 23:59 UTC on 30 June or 31 December");
  }
}

function parseHosts(value: JsonValue | undefined): Map<string, Route[]> {
  if (value?.kind !== "object") throw new Invalid("hosts: must be an object");
  const hosts = new Map<string, Route[]>();
  for (const name of [...value.members.keys()].sort()) {
    const at = `hosts[${JSON.stringify(name)}]`;
    checkHost(name, at);
    const routesValue = members(value.members.get(name), at, ["routes"], []).get("routes");
    if (routesValue?.kind !== "array") throw new Invalid(`${at}.routes: must be a list`);
    if (routesValue.items.length === 0) throw new Invalid(`${at}.routes: must not be empty`);
    const seen = new Set<string>();
    const routes = routesValue.items.map((item, i) => {
      const route = parseRoute(item, `${at}.routes[${i}]`);
      const key = `${route.match} ${route.path}`;
      if (seen.has(key))
        throw new Invalid(`${at}.routes[${i}]: another route has this path and match`);
      seen.add(key);
      return route;
    });
    hosts.set(name, routes);
  }
  return hosts;
}

function checkHost(name: string, at: string): void {
  if (parseIP(name)) throw new Invalid(`${at}: must not be an IP literal`);
  if (!validDNSName(name, true)) {
    throw new Invalid(`${at}: not a lower-case DNS host name without port or trailing dot`);
  }
  if (numericFinalLabel(name)) throw new Invalid(`${at}: final label must not be numeric`);
}

function parseRoute(value: JsonValue, at: string): Route {
  const obj = members(value, at, ["path", "match", "backend"], []);
  const path = stringValue(obj.get("path"), `${at}.path`);
  checkRoutePath(path, `${at}.path`);
  const match = stringValue(obj.get("match"), `${at}.match`);
  if (match !== "exact" && match !== "prefix") {
    throw new Invalid(`${at}.match: want "exact" or "prefix"`);
  }
  checkBackend(obj.get("backend"), `${at}.backend`);
  return { path, match };
}

function checkRoutePath(p: string, at: string): void {
  if (!p.startsWith("/")) throw new Invalid(`${at}: must begin with "/"`);
  if (/[?#%]/.test(p)) throw new Invalid(`${at}: must not contain "?", "#" or percent-encoding`);
  if (p.includes("//")) throw new Invalid(`${at}: must not contain "//"`);
  if (
    p
      .slice(1)
      .split("/")
      .some((seg) => seg === "." || seg === "..")
  ) {
    throw new Invalid(`${at}: must not contain a "." or ".." segment`);
  }
  for (const c of p) {
    if (c !== "/" && !pathChar(c))
      throw new Invalid(`${at}: holds a character not allowed in a URI path`);
  }
}

function checkBackend(value: JsonValue | undefined, at: string): void {
  const obj = members(value, at, ["address"], ["workload", "serverName", "ca"]);
  checkAddress(stringValue(obj.get("address"), `${at}.address`), `${at}.address`);
  const hasWorkload = obj.has("workload");
  const hasServerName = obj.has("serverName");
  const hasCA = obj.has("ca");
  if (hasWorkload && !hasServerName && !hasCA) {
    if (!validWorkloadName(stringValue(obj.get("workload"), `${at}.workload`))) {
      throw new Invalid(`${at}.workload: not a valid allowlist workload name`);
    }
    return;
  }
  if (!hasWorkload && hasServerName && hasCA) {
    const serverName = stringValue(obj.get("serverName"), `${at}.serverName`);
    if (!validDNSName(serverName, false)) throw new Invalid(`${at}.serverName: not a DNS name`);
    if (numericFinalLabel(serverName)) {
      throw new Invalid(`${at}.serverName: final label must not be numeric`);
    }
    checkAnchors(stringValue(obj.get("ca"), `${at}.ca`), `${at}.ca`);
    return;
  }
  throw new Invalid(`${at}: must have exactly one of workload, or serverName with ca`);
}

function checkAddress(addr: string, at: string): void {
  const split = splitHostPort(addr);
  if (split === undefined) throw new Invalid(`${at}: must be host:port`);
  const [host, port] = split;
  if (!parseIP(host) && !validDNSName(host, false)) {
    throw new Invalid(`${at}: host is neither an IP address nor a DNS name`);
  }
  if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535) {
    throw new Invalid(`${at}: port is not a decimal integer from 1 to 65535`);
  }
}

/** c8s workloadname.Valid. */
function validWorkloadName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(name);
}

/** An LDH host name of at most 253 octets with no trailing dot. */
function validDNSName(name: string, lowerOnly: boolean): boolean {
  if (name === "" || name.length > 253) return false;
  const label = lowerOnly ? /^[a-z0-9-]{1,63}$/ : /^[A-Za-z0-9-]{1,63}$/;
  return name.split(".").every((l) => label.test(l) && !l.startsWith("-") && !l.endsWith("-"));
}

/** Whether a WHATWG URL parser reads the final label as IPv4: decimal, or 0x and hex. */
function numericFinalLabel(name: string): boolean {
  const last = name.slice(name.lastIndexOf(".") + 1);
  if (/^0[xX]/.test(last)) return /^[0-9a-fA-F]*$/.test(last.slice(2));
  return /^[0-9]*$/.test(last);
}

/** Go net.SplitHostPort. */
function splitHostPort(hostport: string): [string, string] | undefined {
  const i = hostport.lastIndexOf(":");
  if (i < 0) return undefined;
  let host: string;
  let j = 0;
  let k = 0;
  if (hostport.startsWith("[")) {
    const end = hostport.indexOf("]");
    if (end < 0 || end + 1 !== i) return undefined;
    host = hostport.slice(1, end);
    j = 1;
    k = end + 1;
  } else {
    host = hostport.slice(0, i);
    if (host.includes(":")) return undefined;
  }
  if (hostport.slice(j).includes("[") || hostport.slice(k).includes("]")) return undefined;
  return [host, hostport.slice(i + 1)];
}

/** Whether s is an address Go net.ParseIP accepts: IPv4 or IPv6, no zone. */
function parseIP(s: string): boolean {
  for (const c of s) {
    if (c === ".") return ipv4Fields(s);
    if (c === ":") return ipv6(s);
    if (c === "%") return false;
  }
  return false;
}

/** Go netip parseIPv4Fields: four decimal octets, no leading zeros. */
function ipv4Fields(s: string): boolean {
  const fields = s.split(".");
  return fields.length === 4 && fields.every((f) => /^(?:0|[1-9][0-9]{0,2})$/.test(f) && +f <= 255);
}

/** Go netip parseIPv6, without a zone. */
function ipv6(input: string): boolean {
  if (input.includes("%")) return false;
  let s = input;
  let ellipsis = -1;
  if (s.startsWith("::")) {
    ellipsis = 0;
    s = s.slice(2);
    if (s === "") return true;
  }
  let i = 0;
  while (i < 16) {
    const group = /^[0-9a-fA-F]+/.exec(s)?.[0] ?? "";
    if (group.length === 0 || group.length > 4) return false;
    if (s[group.length] === ".") {
      if ((ellipsis < 0 && i !== 12) || i + 4 > 16 || !ipv4Fields(s)) return false;
      s = "";
      i += 4;
      break;
    }
    i += 2;
    s = s.slice(group.length);
    if (s === "") break;
    if (!s.startsWith(":") || s.length === 1) return false;
    s = s.slice(1);
    if (s.startsWith(":")) {
      if (ellipsis >= 0) return false;
      ellipsis = i;
      s = s.slice(1);
      if (s === "") break;
    }
  }
  if (s !== "") return false;
  return i < 16 ? ellipsis >= 0 : ellipsis < 0;
}

// ---------------------------------------------------------------------------
// PEM trust anchors (Go encoding/pem, byte for byte)
// ---------------------------------------------------------------------------

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const PEM_BEGIN = ascii("-----BEGIN ");
const PEM_END = ascii("\n-----END ");
const PEM_DASHES = ascii("-----");
const NL = 0x0a;

function indexOf(data: Uint8Array, needle: Uint8Array, from = 0): number {
  outer: for (let i = from; i + needle.length <= data.length; i++) {
    for (let j = 0; j < needle.length; j++) if (data[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function lastIndexOf(data: Uint8Array, needle: Uint8Array): number {
  for (let i = data.length - needle.length; i >= 0; i--) {
    if (indexOf(data.subarray(i, i + needle.length), needle) === 0) return i;
  }
  return -1;
}

const startsWith = (data: Uint8Array, prefix: Uint8Array) =>
  data.length >= prefix.length && indexOf(data.subarray(0, prefix.length), prefix) === 0;
const endsWith = (data: Uint8Array, suffix: Uint8Array) =>
  data.length >= suffix.length && startsWith(data.subarray(data.length - suffix.length), suffix);

function trimRight(data: Uint8Array, cut: string): Uint8Array {
  let end = data.length;
  while (end > 0 && cut.includes(String.fromCharCode(data[end - 1]))) end--;
  return data.subarray(0, end);
}

/** Go pem getLine: the line without its ending and trailing blanks, the rest, bytes consumed. */
function getLine(data: Uint8Array): [Uint8Array, Uint8Array, number] {
  let i = data.indexOf(NL);
  let j: number;
  if (i < 0) {
    i = data.length;
    j = i;
  } else {
    j = i + 1;
    if (i > 0 && data[i - 1] === 0x0d) i--;
  }
  return [trimRight(data.subarray(0, i), " \t"), data.subarray(j), j];
}

function latin1(data: Uint8Array): string {
  let s = "";
  for (const b of data) s += String.fromCharCode(b);
  return s;
}

interface PemBlock {
  type: string;
  headers: boolean;
  bytes: Uint8Array;
}

/** Go pem.Decode: the first block and the rest, or undefined. */
function pemDecode(data: Uint8Array): [PemBlock, Uint8Array] | undefined {
  let rest = data;
  let endTrailerIndex = 0;
  for (;;) {
    if (endTrailerIndex < 0 || endTrailerIndex > rest.length) return undefined;
    rest = rest.subarray(endTrailerIndex);
    let endIndex = indexOf(rest, PEM_END);
    if (endIndex < 0) return undefined;
    endTrailerIndex = endIndex + PEM_END.length;
    const beginIndex = lastIndexOf(rest.subarray(0, endIndex), PEM_BEGIN);
    if (beginIndex < 0 || (beginIndex > 0 && rest[beginIndex - 1] !== NL)) continue;
    const skip = beginIndex + PEM_BEGIN.length;
    rest = rest.subarray(skip);
    endIndex -= skip;
    endTrailerIndex -= skip;

    const [fullTypeLine, next, consumed] = getLine(rest);
    rest = next;
    endIndex -= consumed;
    endTrailerIndex -= consumed;
    if (!endsWith(fullTypeLine, PEM_DASHES)) continue;
    const typeLine = fullTypeLine.subarray(0, fullTypeLine.length - PEM_DASHES.length);

    let headers = false;
    for (;;) {
      if (rest.length === 0) return undefined;
      const [line, after, used] = getLine(rest);
      if (!line.includes(0x3a)) break;
      headers = true;
      rest = after;
      endIndex -= used;
      endTrailerIndex -= used;
    }
    if (headers && endIndex < 0) continue;
    if (endTrailerIndex < 0) return undefined;

    const trailer = rest.subarray(endTrailerIndex);
    const trailerLen = typeLine.length + PEM_DASHES.length;
    if (trailer.length < trailerLen) continue;
    const endLine = trailer.subarray(0, trailerLen);
    if (!startsWith(endLine, typeLine) || !endsWith(endLine, PEM_DASHES)) continue;
    if (getLine(trailer.subarray(trailerLen))[0].length !== 0) continue;

    let bytes = new Uint8Array(0);
    if (endIndex > 0) {
      const base64 = latin1(rest.subarray(0, endIndex)).replace(/[ \t]/g, "");
      const decoded = goBase64(base64, STD_ALPHABET, true);
      if (decoded === undefined) continue;
      bytes = decoded;
    }
    const after = getLine(rest.subarray(endIndex + PEM_END.length - 1))[1];
    return [{ type: latin1(typeLine), headers, bytes }, after];
  }
}

/**
 * A ca bundle holds at least one CERTIFICATE block, nothing else but
 * whitespace, and no PEM headers; each block parses as X.509.
 */
function checkAnchors(bundle: string, at: string): void {
  let rest = utf8ToBytes(bundle);
  let count = 0;
  for (;;) {
    let start = 0;
    while (start < rest.length && " \t\r\n".includes(String.fromCharCode(rest[start]))) start++;
    rest = rest.subarray(start);
    if (rest.length === 0) break;
    if (!startsWith(rest, PEM_BEGIN)) throw new Invalid(`${at}: data outside PEM blocks`);
    const decoded = pemDecode(rest);
    // pem.Decode skips a malformed block and returns a later one; refuse that.
    if (
      decoded === undefined ||
      countOf(rest.subarray(0, rest.length - decoded[1].length), PEM_BEGIN) !== 1
    ) {
      throw new Invalid(`${at}: malformed PEM block`);
    }
    const [block, next] = decoded;
    if (block.type !== "CERTIFICATE") throw new Invalid(`${at}: PEM block is not a CERTIFICATE`);
    if (block.headers) throw new Invalid(`${at}: PEM block has headers`);
    try {
      parseCertificate(block.bytes);
    } catch {
      throw new Invalid(`${at}: certificate ${count} does not parse`);
    }
    count++;
    rest = next;
  }
  if (count === 0) throw new Invalid(`${at}: must hold at least one CERTIFICATE block`);
}

function countOf(data: Uint8Array, needle: Uint8Array): number {
  let n = 0;
  for (let i = indexOf(data, needle); i >= 0; i = indexOf(data, needle, i + needle.length)) n++;
  return n;
}

// ---------------------------------------------------------------------------
// Base64 (Go encoding/base64, lenient decoding)
// ---------------------------------------------------------------------------

const STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Decode as Go's non-strict DecodeString does: CR and LF are skipped and
 * unused trailing bits are ignored. `padded` selects StdEncoding or
 * URLEncoding over their Raw forms.
 */
function goBase64(src: string, alphabet: string, padded: boolean): Uint8Array | undefined {
  const out: number[] = [];
  const isNewline = (c: string) => c === "\n" || c === "\r";
  let si = 0;
  for (;;) {
    const quantum = [0, 0, 0, 0];
    let n = 4;
    let last = false;
    for (let j = 0; j < 4; j++) {
      if (si === src.length) {
        if (j === 0) return Uint8Array.from(out);
        if (j === 1 || padded) return undefined;
        n = j;
        last = true;
        break;
      }
      const c = src[si++];
      const v = alphabet.indexOf(c);
      if (v >= 0) {
        quantum[j] = v;
        continue;
      }
      if (isNewline(c)) {
        j--;
        continue;
      }
      if (!padded || c !== "=" || j < 2) return undefined;
      if (j === 2) {
        while (si < src.length && isNewline(src[si])) si++;
        if (si === src.length || src[si] !== "=") return undefined;
        si++;
      }
      while (si < src.length && isNewline(src[si])) si++;
      if (si < src.length) return undefined;
      n = j;
      last = true;
      break;
    }
    const bits = (quantum[0] << 18) | (quantum[1] << 12) | (quantum[2] << 6) | quantum[3];
    if (n >= 2) out.push((bits >> 16) & 0xff);
    if (n >= 3) out.push((bits >> 8) & 0xff);
    if (n >= 4) out.push(bits & 0xff);
    if (last) return Uint8Array.from(out);
  }
}

// ---------------------------------------------------------------------------
// Route selection (c8s routes.Table, without reserved paths)
// ---------------------------------------------------------------------------

const unreserved = (c: string) => /^[A-Za-z0-9._~-]$/.test(c);
const pathChar = (c: string) => unreserved(c) || "!$&'()*+,;=:@".includes(c);

/**
 * The path the router matches a request by: unreserved escapes decoded,
 * other escapes in upper-case hex, dot segments resolved. Undefined when the
 * path matches no route.
 */
export function normalizePath(raw: string): string | undefined {
  if (!raw.startsWith("/")) return undefined;
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === "%") {
      const hex = raw.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) return undefined;
      const decoded = String.fromCharCode(parseInt(hex, 16));
      if (decoded === "/") return undefined;
      out += unreserved(decoded) ? decoded : `%${hex.toUpperCase()}`;
      i += 2;
    } else if (c === "/" || pathChar(c)) {
      out += c;
    } else {
      return undefined;
    }
  }
  return removeDotSegments(out);
}

function removeDotSegments(p: string): string | undefined {
  const segments = p.slice(1).split("/");
  const out: string[] = [];
  for (let i = 0; i < segments.length; i++) {
    const s = segments[i];
    const last = i === segments.length - 1;
    if (s !== "" && s !== "." && s !== "..") {
      out.push(s);
      continue;
    }
    if (s === "" && !last) return undefined;
    if (s === "..") {
      if (out.length === 0) return undefined;
      out.pop();
    }
    if (last) out.push("");
  }
  return "/" + out.join("/");
}

function prefixMatches(p: string, path: string): boolean {
  return (
    path.startsWith(p) && (path.length === p.length || p.endsWith("/") || path[p.length] === "/")
  );
}

/** Drop a port and lower-case ASCII letters only. */
function canonicalHost(host: string): string {
  const h = splitHostPort(host)?.[0] ?? host;
  return h.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function selects(m: Manifest, host: string, target: string): boolean {
  const path = normalizePath(target.split("?")[0]);
  const routes = m.hosts.get(canonicalHost(host));
  if (path === undefined || routes === undefined) return false;
  return routes.some((r) => (r.match === "exact" ? r.path === path : prefixMatches(r.path, path)));
}

// ---------------------------------------------------------------------------
// Rollback floor
// ---------------------------------------------------------------------------

/** Validate a caller-supplied floor. */
export function validateRouteFloor(floor: RouteFloor | undefined): void {
  if (floor === undefined) return;
  if (
    typeof floor !== "object" ||
    floor === null ||
    !Number.isSafeInteger(floor.revision) ||
    floor.revision < 1 ||
    typeof floor.digest !== "string" ||
    !ROUTE_DIGEST_HEX.test(floor.digest)
  ) {
    fail(
      "invalid_request",
      "routeFloor must be { revision: integer from 1 to 2^53-1, digest: 64 lowercase hex }",
    );
  }
}

/**
 * Refuse a manifest whose revision is below the floor (details.reason
 * "below_floor"), or equal to it with another digest ("revision_conflict").
 */
export function checkRouteFloor(routes: PublishedRoutes, floor: RouteFloor | undefined): void {
  if (floor === undefined) return;
  const details = (reason: string) => ({
    reason,
    revision: routes.revision,
    digest: routes.routeDigest,
    floor: { ...floor },
  });
  if (routes.revision < floor.revision) {
    fail(
      "route_manifest_denied",
      `a router replica may lag behind the accepted route manifest revision ${floor.revision}, ` +
        `or the manifest was rolled back: the attested manifest has revision ${routes.revision}`,
      { details: details("below_floor") },
    );
  }
  if (routes.revision === floor.revision && routes.routeDigest !== floor.digest) {
    fail(
      "route_manifest_denied",
      `the attested route manifest has the accepted revision ${floor.revision} with a different digest`,
      { details: details("revision_conflict") },
    );
  }
}
