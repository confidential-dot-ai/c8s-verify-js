// Caching a verified CDS identity, and using the cache to make downgrade
// detectable.
//
// Attesting CDS is not cheap — a DCAP quote parse, an ECDSA chain, a WASM
// instantiation — and it is pure: the same certificate bytes always produce the
// same verdict. So the verdict is cacheable, and CDS makes the invalidation
// signal free by re-issuing its certificate whenever the live allowlist
// changes. A changed fingerprint IS "re-attest now"; an unchanged one is
// "nothing moved". No staleness window to tune.
//
// The cache earns its keep a second time. Attestation is a statement about a
// single certificate, so it cannot see the one downgrade attack left standing:
// replaying yesterday's genuine (certificate, allowlist) pair, where every
// signature verifies and the only thing wrong is the age. Remembering the last
// verified notBefore turns that into a comparison — a new certificate must not
// be older than the one it replaces.
//
// That comparison is only sound because attestCDSIdentity verifies the
// certificate's self-signature: the validity window sits outside the REPORTDATA
// transcript, so without that check notBefore is attacker-chosen and monotonic
// tracking would compare two numbers the attacker picked.

import { fail } from "./errors.js";

/**
 * One verified CDS identity, flattened to JSON-safe primitives so a Web Storage
 * backend is a `JSON.stringify` away.
 */
export interface CDSCacheEntry {
  /** SHA-256 of the certificate DER, lowercase hex. The identity of the entry. */
  fingerprintSha256Hex: string;
  /** Certificate validity window, ISO-8601. Authenticated by the self-signature. */
  notBeforeISO: string;
  notAfterISO: string;
  /** Attested digests, lowercase hex; all-zero hex means the claims carried none. */
  meshCaDigestHex: string;
  allowlistDigestHex: string;
  /**
   * MRTD of the TD that issued the certificate, lowercase hex.
   *
   * Not in the original entry sketch, and load-bearing: without it a cache hit
   * cannot reconstruct `CDSIdentity.launchDigest`, and a reconstruction that
   * returns `""` for it is a trap — a caller comparing `id.launchDigest`
   * against a pinned measurement would silently compare against nothing.
   */
  launchDigestHex: string;
  /**
   * SHA-256 over the policy the verdict was reached under.
   *
   * Also not in the original sketch, and also load-bearing: a cached verdict is
   * only valid for the policy that produced it. Without this, a caller who
   * *tightens* `measurements` or adds an `expectedRtmr3` pin between calls
   * keeps being served the verdict reached under the looser policy — a cache
   * that quietly ignores a newly added pin. A policy change is a cache miss.
   */
  policyDigestHex: string;
  /** When the full verification ran, ISO-8601. Audit trail, not a trust input. */
  verifiedAtISO: string;
}

/**
 * Storage for verified CDS identities, keyed by caller-chosen string (a cluster
 * or base-URL identifier — NOT the fingerprint, which is what changes).
 *
 * Both methods may be synchronous or return a promise, so a `localStorage`
 * wrapper and an IndexedDB-backed one satisfy the same interface.
 */
export interface CDSIdentityCache {
  get(key: string): CDSCacheEntry | undefined | Promise<CDSCacheEntry | undefined>;
  set(key: string, entry: CDSCacheEntry): void | Promise<void>;
}

/** In-memory cache. Per-tab, lost on reload — the safe default. */
export class MemoryCDSIdentityCache implements CDSIdentityCache {
  private readonly entries = new Map<string, CDSCacheEntry>();

  get(key: string): CDSCacheEntry | undefined {
    const e = this.entries.get(key);
    // Hand back a copy: a caller mutating the returned entry must not be able
    // to move the stored notBefore, which is the rollback floor.
    return e ? { ...e } : undefined;
  }

  set(key: string, entry: CDSCacheEntry): void {
    this.entries.set(key, { ...entry });
  }

  /** Drop one key, or everything. For a deliberate re-bootstrap. */
  clear(key?: string): void {
    if (key === undefined) this.entries.clear();
    else this.entries.delete(key);
  }
}

/**
 * The minimum of the DOM `Storage` interface this cache uses, redeclared so the
 * module does not depend on DOM lib types (the package targets Node too).
 */
export interface WebStorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

/** Namespace for keys written to Web Storage, so we never collide with the app's. */
const STORAGE_PREFIX = "c8s-verify:cds-identity:";

/**
 * Web Storage cache — pass `localStorage` in a browser, a stub in tests.
 *
 * Persisting across reloads is the point: the rollback floor survives a page
 * refresh, so an attacker cannot clear it by making you reload. That does mean
 * the entry is only as trustworthy as the origin's storage; script execution on
 * the origin can rewrite it, but script execution on the origin has already
 * lost the game by other routes.
 */
export class StorageCDSIdentityCache implements CDSIdentityCache {
  constructor(
    private readonly storage: WebStorageLike,
    private readonly prefix: string = STORAGE_PREFIX,
  ) {}

  get(key: string): CDSCacheEntry | undefined {
    let raw: string | null;
    try {
      raw = this.storage.getItem(this.prefix + key);
    } catch {
      // Private-mode / disabled storage throws rather than returning null.
      return undefined;
    }
    if (raw === null) return undefined;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return undefined;
    }
    // A corrupt or half-written entry reads as a miss, never as a partial hit:
    // a hit with a missing notBefore would defeat the rollback check, so an
    // entry that does not fully validate is discarded and re-earned.
    return isCacheEntry(parsed) ? parsed : undefined;
  }

  set(key: string, entry: CDSCacheEntry): void {
    try {
      this.storage.setItem(this.prefix + key, JSON.stringify(entry));
    } catch {
      // A full or unavailable quota costs performance, not correctness: the
      // next call re-attests. Never fail a verified result over a write.
    }
  }

  clear(key: string): void {
    try {
      this.storage.removeItem(this.prefix + key);
    } catch {
      // See set().
    }
  }
}

const HEX = /^[0-9a-f]*$/;

/** Structural + shape validation of a value read back from untrusted storage. */
export function isCacheEntry(v: unknown): v is CDSCacheEntry {
  if (typeof v !== "object" || v === null) return false;
  const e = v as Record<string, unknown>;
  for (const k of [
    "fingerprintSha256Hex",
    "notBeforeISO",
    "notAfterISO",
    "meshCaDigestHex",
    "allowlistDigestHex",
    "launchDigestHex",
    "policyDigestHex",
    "verifiedAtISO",
  ]) {
    if (typeof e[k] !== "string") return false;
  }
  for (const k of [
    "fingerprintSha256Hex",
    "meshCaDigestHex",
    "allowlistDigestHex",
    "launchDigestHex",
    "policyDigestHex",
  ]) {
    if (!HEX.test(e[k] as string)) return false;
  }
  if ((e.fingerprintSha256Hex as string).length !== 64) return false;
  if ((e.policyDigestHex as string).length !== 64) return false;
  // A window that does not parse cannot be compared, and an uncomparable
  // window is exactly the input the rollback check must not receive.
  for (const k of ["notBeforeISO", "notAfterISO", "verifiedAtISO"]) {
    if (!Number.isFinite(Date.parse(e[k] as string))) return false;
  }
  return true;
}

/** Parse an entry timestamp, refusing to guess when it does not parse. */
export function entryDate(entry: CDSCacheEntry, field: "notBeforeISO" | "notAfterISO"): Date {
  const ms = Date.parse(entry[field]);
  if (!Number.isFinite(ms)) {
    fail("cds_identity_invalid", `cached CDS identity has an unparseable ${field}`);
  }
  return new Date(ms);
}
