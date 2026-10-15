// Strict JSON for signed route documents, matching c8s: exactly one UTF-8
// value, no duplicate member names, no unpaired surrogate escapes and nothing
// after the value but whitespace.

/** A parsed JSON value. Numbers keep their source text. */
export type JsonValue =
  | { kind: "object"; members: Map<string, JsonValue> }
  | { kind: "array"; items: JsonValue[] }
  | { kind: "string"; value: string }
  | { kind: "number"; text: string }
  | { kind: "literal"; value: boolean | null };

// c8s allows 10000 levels; every document parsed here fails its schema well
// before 64, so the lower bound changes no verdict and keeps recursion shallow.
const MAX_DEPTH = 64;

const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/**
 * Parse `bytes` strictly. Throws an Error that never quotes document content.
 */
export function parseStrictJson(bytes: Uint8Array): JsonValue {
  let text: string;
  try {
    // ignoreBOM keeps a leading BOM in the text, where it is a syntax error.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error("JSON must be UTF-8");
  }
  let i = 0;

  const syntax = (): never => {
    throw new Error(
      i >= text.length ? "JSON document is empty or truncated" : `invalid JSON at offset ${i}`,
    );
  };
  const skipSpace = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const hex4 = (): number => {
    const h = text.slice(i, i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) syntax();
    i += 4;
    return parseInt(h, 16);
  };

  const string = (): string => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) syntax();
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return out;
      }
      if (c < 0x20) syntax();
      if (c !== 0x5c) {
        out += text[i++];
        continue;
      }
      const e = text[i + 1];
      i += 2;
      const simple: Record<string, string> = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
      };
      if (e !== undefined && e in simple) {
        out += simple[e];
        continue;
      }
      if (e !== "u") syntax();
      const unit = hex4();
      if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error("unpaired Unicode surrogate");
      if (unit >= 0xd800 && unit <= 0xdbff) {
        if (text[i] !== "\\" || text[i + 1] !== "u") throw new Error("unpaired Unicode surrogate");
        i += 2;
        const low = hex4();
        if (low < 0xdc00 || low > 0xdfff) throw new Error("unpaired Unicode surrogate");
        out += String.fromCharCode(unit, low);
        continue;
      }
      out += String.fromCharCode(unit);
    }
  };

  const value = (depth: number): JsonValue => {
    skipSpace();
    const c = text[i];
    if (c === "{" || c === "[") {
      if (depth >= MAX_DEPTH) throw new Error(`JSON exceeds nesting depth ${MAX_DEPTH}`);
      i++;
      skipSpace();
      const close = c === "{" ? "}" : "]";
      const members = new Map<string, JsonValue>();
      const items: JsonValue[] = [];
      if (text[i] === close) {
        i++;
      } else {
        for (;;) {
          if (c === "{") {
            skipSpace();
            if (text[i] !== '"') syntax();
            const key = string();
            if (members.has(key)) throw new Error("duplicate JSON object key");
            skipSpace();
            if (text[i++] !== ":") syntax();
            members.set(key, value(depth + 1));
          } else {
            items.push(value(depth + 1));
          }
          skipSpace();
          const sep = text[i++];
          if (sep === close) break;
          if (sep !== ",") syntax();
        }
      }
      return c === "{" ? { kind: "object", members } : { kind: "array", items };
    }
    if (c === '"') return { kind: "string", value: string() };
    for (const [word, v] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return { kind: "literal", value: v };
      }
    }
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (m === null) return syntax();
    i += m[0].length;
    return { kind: "number", text: m[0] };
  };

  const doc = value(0);
  skipSpace();
  if (i !== text.length) throw new Error("expected exactly one JSON document");
  return doc;
}
