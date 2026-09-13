/**
 * Strict YAML subset parser (spec §3.2 / §9.3).
 *
 * Accepted: exactly one YAML 1.2 document over the JSON scalar subset, UTF-8.
 * Rejected: aliases, anchors, merge keys, custom tags, directives, implicit
 * timestamps, non-string mapping keys, duplicate keys, block scalars, tabs in
 * indentation, non-NFC strings, and ambiguous plain scalars (YAML-1.1 booleans,
 * floats/exponents, hex/octal, date-shaped tokens — these must be quoted).
 */
import { BedrockError } from "./errors.js";
import { MAX_DEPTH, MAX_MEMBERS, type Json } from "./canon.js";

function fail(msg: string): never {
  throw new BedrockError("PARSE", msg);
}

// ---------------------------------------------------------------------------
// Scalar resolution: JSON scalar subset only.
// ---------------------------------------------------------------------------

const INT_TOKEN = /^-?(0|[1-9][0-9]*)$/;
const FLOATISH = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;
const AMBIGUOUS_BOOL_NULL = /^(y|n|yes|no|on|off|true|false|null|~)$/i;
const DATE_LIKE = /^\d{4}-\d{1,2}-\d{1,2}([Tt ].*)?$/;
const OTHER_AMBIGUOUS = /^(\.|[-+]?\.|0x|0o|0b|\d+:|\d*\.?\d+[eE]|[-+]?\.inf|\.nan)/i;

function checkNfc(s: string): string {
  if (s !== s.normalize("NFC")) fail("string is not NFC");
  return s;
}

/** Resolve a plain (unquoted) scalar per the JSON subset. */
function resolvePlain(raw: string): Json {
  if (raw.length === 0) fail("empty plain scalar");
  if (raw === "null") return null;
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (INT_TOKEN.test(raw)) {
    const n = Number(raw);
    if (!Number.isSafeInteger(n)) fail("integer outside safe range");
    return n;
  }
  if (AMBIGUOUS_BOOL_NULL.test(raw)) {
    fail(`ambiguous plain scalar ${JSON.stringify(raw)} (quote it for a string)`);
  }
  if (FLOATISH.test(raw) || OTHER_AMBIGUOUS.test(raw) || DATE_LIKE.test(raw)) {
    fail(`numeric/date-looking plain scalar ${JSON.stringify(raw)} outside the JSON subset`);
  }
  return checkNfc(raw);
}

/** Resolve a mapping key; only string keys are admitted. */
function resolveKey(raw: string, quoted: boolean): string {
  if (quoted) return checkNfc(raw);
  const v = resolvePlain(raw);
  if (typeof v !== "string") fail("non-string mapping key");
  return v;
}

// ---------------------------------------------------------------------------
// Line-level preprocessing
// ---------------------------------------------------------------------------

interface Line {
  indent: number;
  text: string; // content after indentation, comment-stripped, right-trimmed
}

function stripComment(line: string): string {
  // A '#' starts a comment when at line start or preceded by whitespace,
  // outside of quotes.
  let inS = false;
  let inD = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (inS) {
      if (c === "'") {
        if (line[i + 1] === "'") i++;
        else inS = false;
      }
      continue;
    }
    if (inD) {
      if (c === "\\") i++;
      else if (c === '"') inD = false;
      continue;
    }
    if (c === "'") inS = true;
    else if (c === '"') inD = true;
    else if (c === "#" && (i === 0 || line[i - 1] === " " || line[i - 1] === "\t")) {
      return line.slice(0, i);
    }
  }
  return line;
}

function preprocess(text: string): Line[] {
  const rawLines = text.split(/\r?\n/);
  if (text.includes("\r")) {
    // tolerate only CRLF line endings — bare CR inside is already split above
  }
  const lines: Line[] = [];
  let docSeen = false;
  let docEnded = false;
  for (const raw of rawLines) {
    if (/^\t/.test(raw) || /^ +\t/.test(raw)) fail("tab in indentation");
    const noComment = stripComment(raw);
    const trimmedRight = noComment.replace(/ +$/, "");
    if (trimmedRight.trim() === "") continue;
    const indent = trimmedRight.length - trimmedRight.trimStart().length;
    const content = trimmedRight.trimStart();
    if (content.startsWith("%")) fail("YAML directives forbidden");
    if (content === "---") {
      if (docSeen) fail("exactly one YAML document required");
      docSeen = true;
      continue;
    }
    if (content === "...") {
      docEnded = true;
      continue;
    }
    if (docEnded) fail("content after document end");
    if (content.startsWith("---") || content.startsWith("...")) {
      fail("unexpected document marker");
    }
    lines.push({ indent, text: content });
  }
  return lines;
}

// ---------------------------------------------------------------------------
// Flow parsing (inline {..} / [..] / scalars within a single line)
// ---------------------------------------------------------------------------

class FlowParser {
  i = 0;
  constructor(readonly s: string) {}
  ws(): void {
    while (this.i < this.s.length && this.s[this.i] === " ") this.i++;
  }
  peek(): string | undefined {
    return this.s[this.i];
  }
  value(): Json {
    this.ws();
    const c = this.peek();
    if (c === "{") return this.flowMap();
    if (c === "[") return this.flowSeq();
    if (c === '"') return this.doubleQuoted();
    if (c === "'") return this.singleQuoted();
    if (c === "&" || c === "*" || c === "!") fail("anchors/aliases/tags forbidden");
    return this.plain();
  }
  plain(): Json {
    const start = this.i;
    while (this.i < this.s.length) {
      const c = this.s[this.i]!;
      if (c === "," || c === "}" || c === "]") break;
      this.i++;
    }
    const raw = this.s.slice(start, this.i).replace(/ +$/, "");
    return resolvePlain(raw);
  }
  singleQuoted(): string {
    this.i++; // '
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) fail("unterminated single-quoted scalar");
      const c = this.s[this.i]!;
      if (c === "'") {
        if (this.s[this.i + 1] === "'") {
          out += "'";
          this.i += 2;
          continue;
        }
        this.i++;
        break;
      }
      out += c;
      this.i++;
    }
    return checkNfc(out);
  }
  doubleQuoted(): string {
    this.i++; // "
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) fail("unterminated double-quoted scalar");
      const c = this.s[this.i]!;
      if (c === '"') {
        this.i++;
        break;
      }
      if (c === "\\") {
        this.i++;
        const e = this.s[this.i]!;
        this.i++;
        switch (e) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const h1 = this.s.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(h1)) fail("bad \\u escape");
            this.i += 4;
            const u1 = parseInt(h1, 16);
            if (u1 >= 0xd800 && u1 <= 0xdbff) {
              if (this.s[this.i] !== "\\" || this.s[this.i + 1] !== "u") fail("lone surrogate");
              const h2 = this.s.slice(this.i + 2, this.i + 6);
              if (!/^[0-9a-fA-F]{4}$/.test(h2)) fail("bad \\u escape");
              const u2 = parseInt(h2, 16);
              if (u2 < 0xdc00 || u2 > 0xdfff) fail("lone surrogate");
              this.i += 6;
              out += String.fromCharCode(u1, u2);
            } else if (u1 >= 0xdc00 && u1 <= 0xdfff) {
              fail("lone surrogate");
            } else {
              out += String.fromCharCode(u1);
            }
            break;
          }
          default:
            fail(`escape \\${e} outside the JSON subset`);
        }
        continue;
      }
      if (c < " ") fail("unescaped control character");
      out += c;
      this.i++;
    }
    return checkNfc(out);
  }
  flowMap(): Json {
    this.i++; // {
    const obj: Record<string, Json> = {};
    this.ws();
    if (this.peek() === "}") {
      this.i++;
      return obj;
    }
    for (;;) {
      this.ws();
      let key: string;
      const c = this.peek();
      if (c === '"') key = this.doubleQuoted();
      else if (c === "'") key = this.singleQuoted();
      else {
        const start = this.i;
        while (this.i < this.s.length && this.s[this.i] !== ":") this.i++;
        const raw = this.s.slice(start, this.i).replace(/ +$/, "");
        if (raw === "<<") fail("merge keys forbidden");
        key = resolveKey(raw, false);
      }
      if (key === "<<") fail("merge keys forbidden");
      this.ws();
      if (this.peek() !== ":") fail("expected ':' in flow mapping");
      this.i++;
      if (Object.prototype.hasOwnProperty.call(obj, key)) fail("duplicate mapping key");
      obj[key] = this.value();
      this.ws();
      const d = this.peek();
      if (d === ",") {
        this.i++;
        continue;
      }
      if (d === "}") {
        this.i++;
        break;
      }
      fail("expected ',' or '}'");
    }
    if (Object.keys(obj).length > MAX_MEMBERS) fail("object member count > 1024");
    return obj;
  }
  flowSeq(): Json {
    this.i++; // [
    const arr: Json[] = [];
    this.ws();
    if (this.peek() === "]") {
      this.i++;
      return arr;
    }
    for (;;) {
      arr.push(this.value());
      this.ws();
      const d = this.peek();
      if (d === ",") {
        this.i++;
        continue;
      }
      if (d === "]") {
        this.i++;
        break;
      }
      fail("expected ',' or ']'");
    }
    return arr;
  }
}

// ---------------------------------------------------------------------------
// Block parsing
// ---------------------------------------------------------------------------

export function parseYaml(text: string): Json {
  const lines = preprocess(text);
  if (lines.length === 0) fail("empty document");
  const p = new BlockParser(lines);
  const v = p.parseBlock(0);
  if (p.pos !== lines.length) fail("unexpected trailing/indented content");
  return v;
}

export function parseYamlBytes(bytes: Uint8Array): Json {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail("UTF-8 BOM not allowed");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("invalid UTF-8");
  }
  return parseYaml(text);
}

class BlockParser {
  pos = 0;
  constructor(readonly lines: Line[]) {}

  get cur(): Line | undefined {
    return this.lines[this.pos];
  }

  /** Parse the block node starting at this.pos, at this.cur.indent. */
  parseBlock(depth: number): Json {
    const first = this.cur!;
    const indent = first.indent;
    if (first.text === "-" || first.text.startsWith("- ")) {
      return this.parseSeq(indent, depth);
    }
    if (looksLikeMapEntry(first.text)) return this.parseMap(indent, depth);
    const fp = new FlowParser(first.text);
    const v = fp.value();
    fp.ws();
    if (fp.i !== first.text.length) fail("trailing content in scalar");
    this.pos++;
    return v;
  }

  parseSeq(indent: number, depth: number): Json[] {
    if (depth > MAX_DEPTH) fail("nesting depth > 16");
    const arr: Json[] = [];
    for (;;) {
      const line = this.cur;
      if (!line || line.indent !== indent) break;
      if (!(line.text === "-" || line.text.startsWith("- "))) break;
      const contentCol = line.text === "-" ? indent + 1 : indent + 2;
      const rest = line.text === "-" ? "" : line.text.slice(2);
      this.pos++;
      if (rest === "") {
        const nxt = this.cur;
        if (nxt && nxt.indent >= contentCol) {
          arr.push(this.parseBlock(depth + 1));
        } else {
          arr.push(null);
        }
        continue;
      }
      if (looksLikeMapEntry(rest)) {
        arr.push(this.parseInlineMap(contentCol, rest, depth));
      } else {
        const fp = new FlowParser(rest);
        const v = fp.value();
        fp.ws();
        if (fp.i !== rest.length) fail("trailing content in sequence item");
        arr.push(v);
      }
    }
    return arr;
  }

  /**
   * Inline mapping inside a sequence item: first entry is `firstText` (the
   * current line's post-dash content, already consumed); continuation entries
   * are following lines whose indent === col.
   */
  parseInlineMap(col: number, firstText: string, depth: number): Record<string, Json> {
    if (depth + 1 > MAX_DEPTH) fail("nesting depth > 16");
    const obj: Record<string, Json> = {};
    this.mapEntry(obj, firstText, col, depth);
    for (;;) {
      const nxt = this.cur;
      if (nxt && nxt.indent === col && looksLikeMapEntry(nxt.text)) {
        this.pos++;
        this.mapEntry(obj, nxt.text, col, depth);
        continue;
      }
      break;
    }
    if (Object.keys(obj).length > MAX_MEMBERS) fail("object member count > 1024");
    return obj;
  }

  parseMap(indent: number, depth: number): Record<string, Json> {
    if (depth + 1 > MAX_DEPTH) fail("nesting depth > 16");
    const obj: Record<string, Json> = {};
    for (;;) {
      const line = this.cur;
      if (!line || line.indent !== indent || !looksLikeMapEntry(line.text)) break;
      this.pos++;
      this.mapEntry(obj, line.text, indent, depth);
    }
    if (Object.keys(obj).length > MAX_MEMBERS) fail("object member count > 1024");
    return obj;
  }

  /**
   * Consume one "key: value" entry into obj. The key line has already been
   * consumed (this.pos points past it). `col` is the key's column.
   */
  mapEntry(obj: Record<string, Json>, text: string, col: number, depth: number): void {
    const { key, rest } = splitKey(text);
    if (key === "<<") fail("merge keys forbidden");
    if (Object.prototype.hasOwnProperty.call(obj, key)) fail("duplicate mapping key");
    if (rest !== "") {
      const fp = new FlowParser(rest);
      const v = fp.value();
      fp.ws();
      if (fp.i !== rest.length) fail("trailing content after value");
      obj[key] = v;
      return;
    }
    const nxt = this.cur;
    if (nxt && nxt.indent > col) {
      obj[key] = this.parseBlock(depth + 1);
      return;
    }
    if (nxt && nxt.indent === col && (nxt.text === "-" || nxt.text.startsWith("- "))) {
      // YAML permits a block sequence at the same column as its key.
      obj[key] = this.parseSeq(col, depth + 1);
      return;
    }
    obj[key] = null;
  }
}

/**
 * Split "key: value" / "key:" text into resolved key and rest-of-line.
 * Keys may be quoted scalars or plain scalars.
 */
function splitKey(text: string): { key: string; rest: string } {
  if (text.startsWith('"') || text.startsWith("'")) {
    const fp = new FlowParser(text);
    const key = text.startsWith('"') ? fp.doubleQuoted() : fp.singleQuoted();
    fp.ws();
    if (fp.peek() !== ":") fail("expected ':' after quoted key");
    fp.i++;
    const rest = text.slice(fp.i).replace(/^ /, "");
    return { key, rest };
  }
  // plain key: find ':' followed by space or end-of-line
  for (let i = 0; i < text.length; i++) {
    if (text[i] === ":" && (i + 1 === text.length || text[i + 1] === " ")) {
      const raw = text.slice(0, i).replace(/ +$/, "");
      const key = resolveKey(raw, false);
      const rest = text.slice(i + 1).replace(/^ /, "");
      return { key, rest };
    }
  }
  fail("expected mapping entry");
}

function looksLikeMapEntry(text: string): boolean {
  if (text.startsWith('"') || text.startsWith("'")) {
    // quoted key then ':'
    const fp = new FlowParser(text);
    try {
      if (text.startsWith('"')) fp.doubleQuoted();
      else fp.singleQuoted();
      fp.ws();
      return fp.peek() === ":";
    } catch {
      return false;
    }
  }
  if (text === "-" || text.startsWith("- ")) return false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (c === ":" && (i + 1 === text.length || text[i + 1] === " ")) return true;
    if (c === " " || c === "{" || c === "[" || c === "#") return false;
    if (c === "&" || c === "*" || c === "!" || c === "?" || c === "|" || c === ">") {
      fail("anchors/aliases/tags/block scalars forbidden");
    }
  }
  return false;
}
