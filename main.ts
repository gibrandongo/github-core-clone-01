// forge: a standalone, GitHub-compatible git forge in one process.
//
// Serves git smart HTTP (upload-pack v2 + v0, receive-pack v0), the REST v3
// API under /api/v3, GraphQL at /api/graphql, and MCP at /mcp, all over one
// in-memory store. Node 22, built-ins only, no dependencies, no git binary.
// Deterministic: every timestamp comes from a fixed base plus a counter, every
// id from a counter; no wall clock or randomness reaches any response.
//
// Lifecycle (wire contract): bind an ephemeral port, POST {"port":N} to
// $MAKEFUN_ENV_URL/register, then poll GET $MAKEFUN_ENV_URL/done until
// {"done":true} and exit 0. GET /healthz answers 200 {"ok":true}.

import http from 'node:http';
import { createHash } from 'node:crypto';
import zlib from 'node:zlib';
import { Buffer } from 'node:buffer';

// ------------------------------------------------------------------ constants

const ZERO_OID = '0000000000000000000000000000000000000000';
const AGENT_NAME = 'forge/1.0';
// The login the trial token names: the scenario's viewer. The scenario is
// fixed by the one constant seed in the wire contract, so this login is the
// same on every trial; repositories created through /user/repos, MCP and
// GraphQL belong to it, and the same name under another owner is a 404.
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const DEFAULT_BRANCH_FALLBACK = 'main';
// Timestamps come from MAKEFUN_TRIAL_NOW whenever it is set (the wire
// contract's trial clock), independent of MAKEFUN_ENV_URL; the fixed epoch
// below is only the local-testing fallback. Never the wall clock.
const TRIAL_NOW_RAW = process.env.MAKEFUN_TRIAL_NOW || '';
const BASE_EPOCH = (() => {
  const parsed = Date.parse(TRIAL_NOW_RAW || '2025-01-01T00:00:00Z');
  return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : 1735689600;
})();
const EXPECTED_TOKEN = process.env.MAKEFUN_SHOP_TOKEN || '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL || '').replace(/\/+$/, '');

// Deterministic clock: one counter, every stamp a second after the last.
let tick = 0;
function stamp() {
  tick += 1;
  const epoch = BASE_EPOCH + tick;
  return { epoch, iso: new Date(epoch * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') };
}

// Request ids: deterministic, non-empty, unique per request.
let reqCounter = 0;
function nextRequestId() {
  reqCounter += 1;
  return `req-${reqCounter.toString(16).padStart(8, '0')}`;
}

// ------------------------------------------------------------------ small utils

function sha1Hex(data) {
  return createHash('sha1').update(data).digest('hex');
}

function oidOf(type, data) {
  const header = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return sha1Hex(Buffer.concat([header, data]));
}

function b64encode(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

function b64decode(text) {
  try {
    return Buffer.from(String(text), 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function isOid(s) {
  return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
}

function clampInt(v, lo, hi, fallback) {
  const n = Number.parseInt(String(v), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(hi, Math.max(lo, n));
}

// ------------------------------------------------------------------ pkt-line framing

function pktLine(payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload), 'utf8');
  const len = body.length + 4;
  const head = len.toString(16).padStart(4, '0');
  return Buffer.concat([Buffer.from(head, 'ascii'), body]);
}

const FLUSH_PKT = Buffer.from('0000', 'ascii');
const DELIMITER_PKT = Buffer.from('0001', 'ascii');
const RESPONSE_END_PKT = Buffer.from('0002', 'ascii');

// Parse a buffer of pkt-lines. Returns {lines: string[], rest: Buffer, ok}.
// `rest` is the bytes after the first flush packet (or after the last full
// line when the buffer ends mid-stream, e.g. a packfile follows).
function parsePktLines(buf) {
  const lines = [];
  let pos = 0;
  while (pos + 4 <= buf.length) {
    const lenHex = buf.toString('ascii', pos, pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) break;
    const len = Number.parseInt(lenHex, 16);
    if (len === 0) return { lines, rest: buf.subarray(pos + 4), ok: true, flushed: true };
    if (len === 1 || len === 2) {
      // Delimiter (0001) / response-end (0002) packets: 4 bytes, no payload.
      pos += 4;
      continue;
    }
    if (len < 4 || pos + len > buf.length) break;
    lines.push(buf.toString('utf8', pos + 4, pos + len));
    pos += len;
  }
  return { lines, rest: buf.subarray(pos), ok: true, flushed: false };
}

// Parse pkt-lines from a buffer that ends at the body end (no flush needed):
// returns all complete lines, ignoring a trailing partial chunk.
function parsePktLinesToEnd(buf) {
  const lines = [];
  let pos = 0;
  while (pos + 4 <= buf.length) {
    const lenHex = buf.toString('ascii', pos, pos + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) break;
    const len = Number.parseInt(lenHex, 16);
    if (len === 0) {
      pos += 4;
      continue;
    }
    if (len === 1 || len === 2) {
      // Delimiter (0001) / response-end (0002) packets: 4 bytes, no payload.
      pos += 4;
      continue;
    }
    if (len < 4 || pos + len > buf.length) break;
    lines.push(buf.toString('utf8', pos + 4, pos + len));
    pos += len;
  }
  return { lines, rest: buf.subarray(pos) };
}

// Side-band framing (side-band-64k): channel byte + data, pkt-lines of at
// most 65520 bytes, terminated by a flush packet.
function sidebandFrame(data, channel) {
  const chunks = [];
  const max = 65520 - 5;
  for (let off = 0; off < data.length; off += max) {
    const piece = data.subarray(off, Math.min(data.length, off + max));
    chunks.push(pktLine(Buffer.concat([Buffer.from([channel]), piece])));
  }
  if (data.length === 0) chunks.push(pktLine(Buffer.from([channel])));
  chunks.push(FLUSH_PKT);
  return Buffer.concat(chunks);
}

// ------------------------------------------------------------------ zlib helpers

// Inflate the zlib stream starting at buf[start], knowing its uncompressed
// size. Returns {data, consumed}. The consumed length is found by binary
// search: inflateSync throws on a truncated stream and ignores trailing
// bytes, so the smallest succeeding prefix is the exact stream end.
function inflateAt(buf, start, expectedSize) {
  const whole = zlib.inflateSync(buf.subarray(start));
  if (whole.length !== expectedSize) {
    throw new Error(`inflate size mismatch: got ${whole.length}, want ${expectedSize}`);
  }
  let lo = start + 1;
  let hi = buf.length;
  let best = buf.length;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    try {
      const out = zlib.inflateSync(buf.subarray(start, mid));
      if (out.length === expectedSize) {
        best = mid;
        hi = mid - 1;
      } else {
        lo = mid + 1;
      }
    } catch {
      lo = mid + 1;
    }
  }
  return { data: whole, consumed: best - start };
}

function deflate(data) {
  return zlib.deflateSync(data, { level: 6 });
}

// ------------------------------------------------------------------ git objects

const OBJ_COMMIT = 1;
const OBJ_TREE = 2;
const OBJ_BLOB = 3;
const OBJ_TAG = 4;
const OBJ_OFS_DELTA = 6;
const OBJ_REF_DELTA = 7;
const TYPE_NAMES = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

// Parse a commit object's raw bytes: {tree, parents, author, committer, message, raw}
function parseCommit(data) {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
  const message = headEnd >= 0 ? text.slice(headEnd + 2) : '';
  const parents = [];
  let tree = '';
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message, raw: data };
}

function buildCommit({ tree, parents, author, committer, message }) {
  let out = `tree ${tree}\n`;
  for (const p of parents) out += `parent ${p}\n`;
  out += `author ${author}\ncommitter ${committer}\n\n${message}`;
  return Buffer.from(out, 'utf8');
}

// Parse a tree object's raw bytes: [{mode, name, oid}]
function parseTree(data) {
  const entries = [];
  let pos = 0;
  while (pos < data.length) {
    const sp = data.indexOf(0x20, pos);
    if (sp < 0) break;
    const mode = data.toString('ascii', pos, sp);
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0) break;
    const name = data.toString('utf8', sp + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    pos = nul + 21;
  }
  return entries;
}

function isTreeMode(mode) {
  return mode === '40000' || mode === '040000';
}

function buildTree(entries) {
  const sorted = entries.slice().sort((a, b) => {
    const an = a.name + (isTreeMode(a.mode) ? '/' : '');
    const bn = b.name + (isTreeMode(b.mode) ? '/' : '');
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseTag(data) {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
  let object = '';
  let type = '';
  let tag = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
  }
  return { object, type, tag, raw: data };
}

// ------------------------------------------------------------------ deltas

function readVarint7(buf, pos) {
  let value = 0;
  let shift = 0;
  let p = pos;
  for (;;) {
    const b = buf[p];
    p += 1;
    value |= (b & 0x7f) << shift;
    shift += 7;
    if ((b & 0x80) === 0) break;
  }
  return { value, next: p };
}

function applyDelta(base, delta) {
  let pos = 0;
  const src = readVarint7(delta, pos);
  pos = src.next;
  const tgt = readVarint7(delta, pos);
  pos = tgt.next;
  if (src.value !== base.length) throw new Error('delta base size mismatch');
  const out = [];
  let outLen = 0;
  while (pos < delta.length) {
    const op = delta[pos];
    pos += 1;
    if (op & 0x80) {
      let off = 0;
      let size = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) {
          off |= delta[pos] << (8 * i);
          pos += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) {
          size |= delta[pos] << (8 * i);
          pos += 1;
        }
      }
      if (size === 0) size = 0x10000;
      out.push(base.subarray(off, off + size));
      outLen += size;
    } else if (op !== 0) {
      out.push(delta.subarray(pos, pos + op));
      outLen += op;
      pos += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (outLen !== tgt.value) throw new Error('delta target size mismatch');
  return Buffer.concat(out, outLen);
}

// ------------------------------------------------------------------ packfiles

// Parse a packfile buffer. `resolveBase(oid)` finds a base object already in
// the store (for thin packs). Returns [{oid, type, data}].
function parsePack(buf, resolveBase) {
  if (buf.length < 12 || buf.toString('ascii', 0, 4) !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = buf.readUInt32BE(4);
  if (version !== 2) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const objects = [];
  const byPos = new Map();
  const byOid = new Map();
  let pos = 12;
  for (let i = 0; i < count; i += 1) {
    const start = pos;
    let b = buf[pos];
    pos += 1;
    const type = (b >> 4) & 7;
    let size = b & 15;
    let shift = 4;
    while (b & 0x80) {
      b = buf[pos];
      pos += 1;
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    if (type === OBJ_OFS_DELTA) {
      let offByte = buf[pos];
      pos += 1;
      let offset = offByte & 0x7f;
      while (offByte & 0x80) {
        offByte = buf[pos];
        pos += 1;
        offset = ((offset + 1) << 7) | (offByte & 0x7f);
      }
      const base = byPos.get(start - offset);
      if (!base) throw new Error('ofs-delta base missing');
      const inflated = inflateAt(buf, pos, size);
      pos += inflated.consumed;
      const data = applyDelta(base.data, inflated.data);
      const oid = oidOf(base.type, data);
      const obj = { oid, type: base.type, data };
      objects.push(obj);
      byPos.set(start, obj);
      byOid.set(oid, obj);
    } else if (type === OBJ_REF_DELTA) {
      const baseOid = buf.subarray(pos, pos + 20).toString('hex');
      pos += 20;
      const inflated = inflateAt(buf, pos, size);
      pos += inflated.consumed;
      const base = byOid.get(baseOid) || resolveBase(baseOid);
      if (!base) throw new Error(`ref-delta base ${baseOid} missing`);
      const data = applyDelta(base.data, inflated.data);
      const oid = oidOf(base.type, data);
      const obj = { oid, type: base.type, data };
      objects.push(obj);
      byPos.set(start, obj);
      byOid.set(oid, obj);
    } else if (type === OBJ_COMMIT || type === OBJ_TREE || type === OBJ_BLOB || type === OBJ_TAG) {
      const inflated = inflateAt(buf, pos, size);
      pos += inflated.consumed;
      const typeName = TYPE_NAMES[type];
      const oid = oidOf(typeName, inflated.data);
      const obj = { oid, type: typeName, data: inflated.data };
      objects.push(obj);
      byPos.set(start, obj);
      byOid.set(oid, obj);
    } else {
      throw new Error(`unknown pack object type ${type}`);
    }
  }
  return objects;
}

// Build a packfile from [{type, data}] (full objects only, no deltas).
function buildPack(objects) {
  const parts = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    const typeNum = { commit: 1, tree: 2, blob: 3, tag: 4 }[obj.type];
    const size = obj.data.length;
    const headBytes = [];
    let first = (typeNum << 4) | (size & 15);
    let rest = size >> 4;
    if (rest > 0) first |= 0x80;
    headBytes.push(first);
    while (rest > 0) {
      let byte = rest & 0x7f;
      rest >>= 7;
      if (rest > 0) byte |= 0x80;
      headBytes.push(byte);
    }
    parts.push(Buffer.from(headBytes));
    parts.push(deflate(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// ------------------------------------------------------------------ the store

let globalId = 1;
function nextGlobalId() {
  const id = globalId;
  globalId += 1;
  return id;
}

function nodeId(kind, numericId) {
  return b64encode(`${kind}:${numericId}`);
}

// One repository: git objects + refs + issues/PRs/labels/comments.
class Repo {
  constructor({ id, owner, name, description, isPrivate, defaultBranch, createdAt }) {
    this.id = id;
    this.owner = owner;
    this.name = name;
    this.description = description || '';
    this.private = !!isPrivate;
    this.defaultBranch = defaultBranch || DEFAULT_BRANCH_FALLBACK;
    this.createdAt = createdAt;
    this.updatedAt = createdAt;
    this.pushedAt = createdAt;
    this.objects = new Map(); // oid -> {type, data}
    this.refs = new Map(); // refname -> oid
    this.labels = new Map(); // name -> label
    this.issues = new Map(); // number -> issue
    this.pulls = new Map(); // number -> pull
    this.comments = new Map(); // issueNumber -> [comment]
    this.numberCounter = 0;
    this.packCache = new Map(); // cache key -> {pack, shallow}
  }

  get fullName() {
    return `${this.owner}/${this.name}`;
  }

  headRef() {
    return `refs/heads/${this.defaultBranch}`;
  }

  headOid() {
    return this.refs.get(this.headRef()) || ZERO_OID;
  }

  getObject(oid) {
    return this.objects.get(oid);
  }

  putObject(type, data) {
    const oid = oidOf(type, data);
    if (!this.objects.has(oid)) this.objects.set(oid, { type, data });
    return oid;
  }

  invalidatePackCache() {
    this.packCache.clear();
  }

  // Walk commit ancestry from `start`, calling fn(commitOid, commit, depth).
  // Stops descending past commits in `stopSet`. Depth 1 = the start commits.
  walkCommits(starts, { stopSet, maxDepth, fn }) {
    const seen = new Set();
    const queue = [];
    for (const s of starts) queue.push({ oid: s, depth: 1 });
    while (queue.length > 0) {
      const { oid, depth } = queue.shift();
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = this.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      const commit = parseCommit(obj.data);
      const boundary = stopSet.has(oid) || (maxDepth !== undefined && depth >= maxDepth);
      fn(oid, commit, depth, boundary);
      if (boundary) continue;
      for (const p of commit.parents) {
        if (!seen.has(p)) queue.push({ oid: p, depth: depth + 1 });
      }
    }
    return seen;
  }

  ancestorSet(starts) {
    const set = new Set();
    const queue = [...starts];
    while (queue.length > 0) {
      const oid = queue.pop();
      if (set.has(oid)) continue;
      set.add(oid);
      const obj = this.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const p of parseCommit(obj.data).parents) queue.push(p);
    }
    return set;
  }

  isAncestor(ancestor, descendant) {
    if (ancestor === descendant) return true;
    if (ancestor === ZERO_OID) return true;
    const queue = [descendant];
    const seen = new Set();
    while (queue.length > 0) {
      const oid = queue.pop();
      if (oid === ancestor) return true;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = this.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const p of parseCommit(obj.data).parents) queue.push(p);
    }
    return false;
  }

  mergeBase(a, b) {
    const ancestorsA = this.ancestorSet([a]);
    const queue = [b];
    const seen = new Set();
    while (queue.length > 0) {
      const oid = queue.shift();
      if (ancestorsA.has(oid)) return oid;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = this.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const p of parseCommit(obj.data).parents) queue.push(p);
    }
    return null;
  }

  // Peel a tag (possibly nested) to a commit oid; returns {oid, peeledTags}.
  peelToCommit(oid) {
    const peeledTags = [];
    let cur = oid;
    for (let i = 0; i < 16; i += 1) {
      const obj = this.objects.get(cur);
      if (!obj) return { oid: null, peeledTags };
      if (obj.type === 'commit') return { oid: cur, peeledTags };
      if (obj.type === 'tag') {
        peeledTags.push(cur);
        cur = parseTag(obj.data).object;
        continue;
      }
      return { oid: null, peeledTags };
    }
    return { oid: null, peeledTags };
  }

  // Flatten a tree (recursively) into Map<path, {oid, mode}>.
  flattenTree(treeOid, prefix, out) {
    out = out || new Map();
    prefix = prefix || '';
    const obj = this.objects.get(treeOid);
    if (!obj || obj.type !== 'tree') return out;
    for (const e of parseTree(obj.data)) {
      const path = prefix + e.name;
      if (isTreeMode(e.mode)) this.flattenTree(e.oid, `${path}/`, out);
      else out.set(path, { oid: e.oid, mode: e.mode });
    }
    return out;
  }

  // Read the entry at `path` in the tree: {oid, mode, isTree} or null.
  treeLookup(treeOid, path) {
    const parts = path.split('/').filter((p) => p !== '');
    let cur = treeOid;
    for (let i = 0; i < parts.length; i += 1) {
      const obj = this.objects.get(cur);
      if (!obj || obj.type !== 'tree') return null;
      const found = parseTree(obj.data).find((e) => e.name === parts[i]);
      if (!found) return null;
      if (i === parts.length - 1) return { oid: found.oid, mode: found.mode, isTree: isTreeMode(found.mode) };
      if (!isTreeMode(found.mode)) return null;
      cur = found.oid;
    }
    return { oid: cur, mode: '40000', isTree: true };
  }

  // Return a new tree oid with `path` set to (blobOid, mode) or removed (blobOid null).
  treeSetPath(treeOid, path, blobOid, mode) {
    const parts = path.split('/').filter((p) => p !== '');
    const rec = (curOid, idx) => {
      const obj = curOid && this.objects.get(curOid);
      const entries = obj && obj.type === 'tree' ? parseTree(obj.data) : [];
      const name = parts[idx];
      const last = idx === parts.length - 1;
      const next = [];
      let replaced = false;
      for (const e of entries) {
        if (e.name !== name) {
          next.push(e);
          continue;
        }
        replaced = true;
        if (last) {
          if (blobOid !== null) next.push({ mode: mode || '100644', name, oid: blobOid });
        } else {
          const child = rec(isTreeMode(e.mode) ? e.oid : null, idx + 1);
          if (child !== null) next.push({ mode: '40000', name, oid: child });
        }
      }
      if (!replaced) {
        if (last) {
          if (blobOid !== null) next.push({ mode: mode || '100644', name, oid: blobOid });
        } else {
          const child = rec(null, idx + 1);
          if (child !== null) next.push({ mode: '40000', name, oid: child });
        }
      }
      if (next.length === 0) return null;
      return this.putObject('tree', buildTree(next));
    };
    const result = rec(treeOid, 0);
    if (result === null) {
      // Empty tree.
      return this.putObject('tree', buildTree([]));
    }
    return result;
  }

  // Resolve a ref-ish (branch name, full ref, or oid) to a commit oid.
  resolveRef(refish) {
    if (!refish) return this.headOid();
    if (isOid(refish)) {
      const peeled = this.peelToCommit(refish);
      return peeled.oid || ZERO_OID;
    }
    const candidates = [refish, `refs/heads/${refish}`, `refs/tags/${refish}`, `refs/remotes/${refish}`];
    for (const c of candidates) {
      const oid = this.refs.get(c);
      if (oid) {
        const peeled = this.peelToCommit(oid);
        return peeled.oid || ZERO_OID;
      }
    }
    return ZERO_OID;
  }

  // Create a commit on top of `parentOids` with the given tree.
  createCommit({ tree, parents, message, authorName, authorEmail }) {
    const { epoch } = stamp();
    const ident = `${authorName} <${authorEmail}> ${epoch} +0000`;
    const data = buildCommit({ tree, parents, author: ident, committer: ident, message });
    return this.putObject('commit', data);
  }

  // Compute the objects needed for an upload-pack response.
  // wants: commit oids (already peeled). haves: commit oids the client has.
  // maxDepth: undefined for full, N for shallow. Returns {objects, shallow}.
  collectPack(wants, haves, maxDepth) {
    const excluded = this.ancestorSet(haves);
    const included = new Map(); // oid -> {type, data}
    const shallow = [];
    const tagObjects = [];
    const commitOids = [];
    this.walkCommits(wants, {
      stopSet: excluded,
      maxDepth,
      fn: (oid, commit, depth, boundary) => {
        if (excluded.has(oid)) return;
        commitOids.push(oid);
        if (maxDepth !== undefined && depth >= maxDepth) shallow.push(oid);
      },
    });
    // Add the commits themselves, then their trees and blobs.
    const seenTrees = new Set();
    const addTree = (treeOid) => {
      if (seenTrees.has(treeOid)) return;
      seenTrees.add(treeOid);
      const obj = this.objects.get(treeOid);
      if (!obj || obj.type !== 'tree') return;
      included.set(treeOid, obj);
      for (const e of parseTree(obj.data)) {
        if (isTreeMode(e.mode)) addTree(e.oid);
        else {
          const blob = this.objects.get(e.oid);
          if (blob) included.set(e.oid, blob);
        }
      }
    };
    for (const oid of commitOids) {
      const obj = this.objects.get(oid);
      if (obj) included.set(oid, obj);
      const commit = parseCommit(obj.data);
      addTree(commit.tree);
    }
    // Include tag objects that point at included commits when requested by
    // the caller via tagObjects (filled by the caller beforehand).
    for (const tagOid of tagObjects) {
      const obj = this.objects.get(tagOid);
      if (obj) included.set(tagOid, obj);
    }
    const ordered = [];
    for (const [oid, obj] of included) {
      if (obj.type === 'commit') ordered.push({ oid, type: obj.type, data: obj.data });
    }
    for (const [oid, obj] of included) {
      if (obj.type === 'tree') ordered.push({ oid, type: obj.type, data: obj.data });
    }
    for (const [oid, obj] of included) {
      if (obj.type === 'blob') ordered.push({ oid, type: obj.type, data: obj.data });
    }
    for (const [oid, obj] of included) {
      if (obj.type === 'tag') ordered.push({ oid, type: obj.type, data: obj.data });
    }
    return { objects: ordered, shallow };
  }
}

// Global store: key `${owner}/${name}` -> Repo.
const repos = new Map();
function repoKey(owner, name) {
  return `${owner}/${name}`;
}
function getRepo(owner, name) {
  return repos.get(repoKey(owner, name)) || null;
}

function createRepoRecord({ owner, name, description, isPrivate, defaultBranch }) {
  const { iso } = stamp();
  const repo = new Repo({
    id: nextGlobalId(),
    owner,
    name,
    description,
    isPrivate,
    defaultBranch: defaultBranch || DEFAULT_BRANCH_FALLBACK,
    createdAt: iso,
  });
  repos.set(repoKey(owner, name), repo);
  return repo;
}

// Diff two trees: [{path, status, oldOid, newOid, oldMode, newMode}]
function diffTrees(repo, oldTreeOid, newTreeOid) {
  const oldMap = oldTreeOid ? repo.flattenTree(oldTreeOid) : new Map();
  const newMap = newTreeOid ? repo.flattenTree(newTreeOid) : new Map();
  const paths = new Set([...oldMap.keys(), ...newMap.keys()]);
  const out = [];
  for (const path of [...paths].sort()) {
    const o = oldMap.get(path);
    const n = newMap.get(path);
    if (o && !n) out.push({ path, status: 'removed', oldOid: o.oid, newOid: null, oldMode: o.mode, newMode: null });
    else if (!o && n) out.push({ path, status: 'added', oldOid: null, newOid: n.oid, oldMode: null, newMode: n.mode });
    else if (o.oid !== n.oid || o.mode !== n.mode) out.push({ path, status: 'modified', oldOid: o.oid, newOid: n.oid, oldMode: o.mode, newMode: n.mode });
  }
  return out;
}

// Three-way mergeability: compare base tree (merge-base), ours (base branch
// tip tree) and theirs (head tip tree). A path changed on both sides to
// different contents is a conflict.
function isMergeable(repo, baseTip, headTip) {
  const base = repo.mergeBase(baseTip, headTip);
  if (!base) return true; // unrelated histories: squash takes the head tree
  const baseCommit = parseCommit(repo.objects.get(base).data);
  const oursCommit = parseCommit(repo.objects.get(baseTip).data);
  const theirsCommit = parseCommit(repo.objects.get(headTip).data);
  const baseMap = repo.flattenTree(baseCommit.tree);
  const oursMap = repo.flattenTree(oursCommit.tree);
  const theirsMap = repo.flattenTree(theirsCommit.tree);
  const paths = new Set([...baseMap.keys(), ...oursMap.keys(), ...theirsMap.keys()]);
  for (const path of paths) {
    const b = baseMap.get(path);
    const o = oursMap.get(path);
    const t = theirsMap.get(path);
    const bOid = b ? b.oid : null;
    const oOid = o ? o.oid : null;
    const tOid = t ? t.oid : null;
    if (oOid === tOid) continue;
    if (oOid === bOid) continue;
    if (tOid === bOid) continue;
    return false;
  }
  return true;
}

// ------------------------------------------------------------------ HTTP helpers

let SERVER_PORT = 0;
function publicBase() {
  return `http://127.0.0.1:${SERVER_PORT}`;
}

function sendJson(res, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-GitHub-Request-Id': nextRequestId(),
    'Content-Length': Buffer.byteLength(body),
    ...(extraHeaders || {}),
  };
  res.writeHead(status, headers);
  res.end(body);
}

function sendError(res, status, message, extra) {
  sendJson(res, status, { message, ...(extra || {}) });
}

function sendNoContent(res) {
  res.writeHead(204, { 'X-GitHub-Request-Id': nextRequestId() });
  res.end();
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(buf) {
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(buf.toString('utf8')) };
  } catch {
    return { ok: false, value: null };
  }
}

// ------------------------------------------------------------------ serializers

function userObject(login) {
  const id = login === VIEWER_LOGIN ? VIEWER_ID : nextGlobalIdForLogin(login);
  return {
    login,
    id,
    node_id: nodeId('User', id),
    avatar_url: `${publicBase()}/avatars/${encodeURIComponent(login)}`,
    gravatar_id: '',
    url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}`,
    html_url: `${publicBase()}/${encodeURIComponent(login)}`,
    followers_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/followers`,
    following_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/following{/other_user}`,
    gists_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/gists{/gist_id}`,
    starred_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/starred{/owner}{/repo}`,
    subscriptions_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/subscriptions`,
    organizations_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/orgs`,
    repos_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/repos`,
    events_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/events{/privacy}`,
    received_events_url: `${publicBase()}/api/v3/users/${encodeURIComponent(login)}/received_events`,
    type: 'User',
    user_view_type: 'public',
    site_admin: false,
  };
}

// Stable ids for logins seen in commits/params (other than the viewer).
const loginIds = new Map();
function nextGlobalIdForLogin(login) {
  let id = loginIds.get(login);
  if (id === undefined) {
    id = nextGlobalId();
    loginIds.set(login, id);
  }
  return id;
}

function repoObject(repo) {
  const base = publicBase();
  const full = repo.fullName;
  return {
    id: repo.id,
    node_id: nodeId('Repository', repo.id),
    name: repo.name,
    full_name: full,
    owner: userObject(repo.owner),
    private: repo.private,
    html_url: `${base}/${full}`,
    description: repo.description,
    fork: false,
    url: `${base}/api/v3/repos/${full}`,
    archive_url: `${base}/api/v3/repos/${full}/{archive_format}{/ref}`,
    assignees_url: `${base}/api/v3/repos/${full}/assignees{/user}`,
    blobs_url: `${base}/api/v3/repos/${full}/git/blobs{/sha}`,
    branches_url: `${base}/api/v3/repos/${full}/branches{/branch}`,
    clone_url: `${base}/${full}.git`,
    collaborators_url: `${base}/api/v3/repos/${full}/collaborators{/collaborator}`,
    comments_url: `${base}/api/v3/repos/${full}/comments{/number}`,
    commits_url: `${base}/api/v3/repos/${full}/commits{/sha}`,
    compare_url: `${base}/api/v3/repos/${full}/compare/{base}...{head}`,
    contents_url: `${base}/api/v3/repos/${full}/contents/{+path}`,
    contributors_url: `${base}/api/v3/repos/${full}/contributors`,
    deployments_url: `${base}/api/v3/repos/${full}/deployments`,
    downloads_url: `${base}/api/v3/repos/${full}/downloads`,
    events_url: `${base}/api/v3/repos/${full}/events`,
    forks_url: `${base}/api/v3/repos/${full}/forks`,
    git_commits_url: `${base}/api/v3/repos/${full}/git/commits{/sha}`,
    git_refs_url: `${base}/api/v3/repos/${full}/git/refs{/sha}`,
    git_tags_url: `${base}/api/v3/repos/${full}/git/tags{/sha}`,
    git_url: `git://127.0.0.1/${full}.git`,
    issue_comment_url: `${base}/api/v3/repos/${full}/issues/comments{/number}`,
    issue_events_url: `${base}/api/v3/repos/${full}/issues/events{/number}`,
    issues_url: `${base}/api/v3/repos/${full}/issues{/number}`,
    keys_url: `${base}/api/v3/repos/${full}/keys{/key_id}`,
    labels_url: `${base}/api/v3/repos/${full}/labels{/name}`,
    languages_url: `${base}/api/v3/repos/${full}/languages`,
    merges_url: `${base}/api/v3/repos/${full}/merges`,
    milestones_url: `${base}/api/v3/repos/${full}/milestones{/number}`,
    notifications_url: `${base}/api/v3/repos/${full}/notifications{?since,all,participating}`,
    pulls_url: `${base}/api/v3/repos/${full}/pulls{/number}`,
    releases_url: `${base}/api/v3/repos/${full}/releases{/id}`,
    ssh_url: `git@127.0.0.1:${full}.git`,
    stargazers_url: `${base}/api/v3/repos/${full}/stargazers`,
    statuses_url: `${base}/api/v3/repos/${full}/statuses/{sha}`,
    subscribers_url: `${base}/api/v3/repos/${full}/subscribers`,
    subscription_url: `${base}/api/v3/repos/${full}/subscription`,
    tags_url: `${base}/api/v3/repos/${full}/tags`,
    teams_url: `${base}/api/v3/repos/${full}/teams`,
    trees_url: `${base}/api/v3/repos/${full}/git/trees{/sha}`,
    homepage: null,
    language: null,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    size: repo.objects.size,
    default_branch: repo.defaultBranch,
    open_issues_count: [...repo.issues.values()].filter((i) => i.state === 'open').length
      + [...repo.pulls.values()].filter((p) => p.state === 'open').length,
    is_template: false,
    topics: [],
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    has_downloads: true,
    has_discussions: false,
    archived: false,
    disabled: false,
    visibility: repo.private ? 'private' : 'public',
    pushed_at: repo.pushedAt,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
    allow_rebase_merge: true,
    allow_squash_merge: true,
    allow_merge_commit: true,
    allow_update_branch: false,
    delete_branch_on_merge: false,
    license: null,
    organization: null,
    network_count: 0,
    subscribers_count: 0,
  };
}

function labelObject(repo, label) {
  return {
    id: label.id,
    node_id: nodeId('Label', label.id),
    url: `${publicBase()}/api/v3/repos/${repo.fullName}/labels/${encodeURIComponent(label.name)}`,
    name: label.name,
    description: label.description || '',
    color: label.color || 'ededed',
    default: false,
  };
}

function issueObject(repo, issue) {
  const base = publicBase();
  const full = repo.fullName;
  return {
    id: issue.id,
    node_id: nodeId('Issue', issue.id),
    url: `${base}/api/v3/repos/${full}/issues/${issue.number}`,
    repository_url: `${base}/api/v3/repos/${full}`,
    labels_url: `${base}/api/v3/repos/${full}/issues/${issue.number}/labels{/name}`,
    comments_url: `${base}/api/v3/repos/${full}/issues/${issue.number}/comments`,
    events_url: `${base}/api/v3/repos/${full}/issues/${issue.number}/events`,
    html_url: `${base}/${full}/issues/${issue.number}`,
    number: issue.number,
    state: issue.state,
    state_reason: null,
    title: issue.title,
    body: issue.body,
    user: userObject(issue.user),
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return label ? labelObject(repo, label) : { id: 0, node_id: nodeId('Label', 0), url: '', name, description: '', color: 'ededed', default: false };
    }),
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    active_lock_reason: null,
    comments: issue.commentsCount || 0,
    closed_at: issue.closedAt,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    author_association: issue.user === repo.owner ? 'OWNER' : 'CONTRIBUTOR',
    type: null,
    sub_issues_summary: { total: 0, completed: 0, percent_completed: 0 },
    reactions: { url: `${base}/api/v3/repos/${full}/issues/${issue.number}/reactions`, total_count: 0, '+1': 0, '-1': 0, laugh: 0, hooray: 0, confused: 0, heart: 0, rocket: 0, eyes: 0 },
    timeline_url: `${base}/api/v3/repos/${full}/issues/${issue.number}/timeline`,
    performed_via_github_app: null,
    draft: false,
  };
}

// A pull request rendered as an issue (for GET /issues/{n} and the issues list).
function pullAsIssueObject(repo, pull) {
  const obj = issueObject(repo, {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    labels: pull.labels || [],
    user: pull.user,
    createdAt: pull.createdAt,
    updatedAt: pull.updatedAt,
    closedAt: pull.closedAt,
    commentsCount: 0,
  });
  obj.node_id = nodeId('PullRequest', pull.id);
  obj.pull_request = {
    url: `${publicBase()}/api/v3/repos/${repo.fullName}/pulls/${pull.number}`,
    html_url: `${publicBase()}/${repo.fullName}/pull/${pull.number}`,
    diff_url: `${publicBase()}/${repo.fullName}/pull/${pull.number}.diff`,
    patch_url: `${publicBase()}/${repo.fullName}/pull/${pull.number}.patch`,
    merged_at: pull.mergedAt,
  };
  return obj;
}

function pullRefObject(repo, refName, sha) {
  return {
    label: `${repo.owner}:${refName}`,
    ref: refName,
    sha,
    user: userObject(repo.owner),
    repo: repoObject(repo),
  };
}

function pullObject(repo, pull) {
  const base = publicBase();
  const full = repo.fullName;
  const headSha = repo.refs.get(`refs/heads/${pull.headRef}`) || pull.headSha || ZERO_OID;
  const baseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) || pull.baseSha || ZERO_OID;
  const mergeable = pull.state === 'open' && headSha !== ZERO_OID && baseSha !== ZERO_OID
    ? isMergeable(repo, baseSha, headSha) : false;
  const files = pullFiles(repo, pull);
  const additions = files.reduce((s, f) => s + f.additions, 0);
  const deletions = files.reduce((s, f) => s + f.deletions, 0);
  return {
    id: pull.id,
    node_id: nodeId('PullRequest', pull.id),
    url: `${base}/api/v3/repos/${full}/pulls/${pull.number}`,
    html_url: `${base}/${full}/pull/${pull.number}`,
    diff_url: `${base}/${full}/pull/${pull.number}.diff`,
    patch_url: `${base}/${full}/pull/${pull.number}.patch`,
    issue_url: `${base}/api/v3/repos/${full}/issues/${pull.number}`,
    commits_url: `${base}/api/v3/repos/${full}/pulls/${pull.number}/commits`,
    review_comments_url: `${base}/api/v3/repos/${full}/pulls/${pull.number}/comments`,
    review_comment_url: `${base}/api/v3/repos/${full}/pulls/comments{/number}`,
    comments_url: `${base}/api/v3/repos/${full}/issues/${pull.number}/comments`,
    statuses_url: `${base}/api/v3/repos/${full}/statuses/${headSha}`,
    number: pull.number,
    state: pull.state,
    locked: false,
    title: pull.title,
    user: userObject(pull.user),
    body: pull.body,
    labels: (pull.labels || []).map((name) => {
      const label = repo.labels.get(name);
      return label ? labelObject(repo, label) : { id: 0, node_id: nodeId('Label', 0), url: '', name, description: '', color: 'ededed', default: false };
    }),
    milestone: null,
    active_lock_reason: null,
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    closed_at: pull.closedAt,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    assignee: null,
    assignees: [],
    requested_reviewers: [],
    requested_teams: [],
    head: pullRefObject(repo, pull.headRef, headSha),
    base: pullRefObject(repo, pull.baseRef, baseSha),
    _links: {
      self: { href: `${base}/api/v3/repos/${full}/pulls/${pull.number}` },
      html: { href: `${base}/${full}/pull/${pull.number}` },
      issue: { href: `${base}/api/v3/repos/${full}/issues/${pull.number}` },
      comments: { href: `${base}/api/v3/repos/${full}/issues/${pull.number}/comments` },
      review_comments: { href: `${base}/api/v3/repos/${full}/pulls/${pull.number}/comments` },
      review_comment: { href: `${base}/api/v3/repos/${full}/pulls/comments{/number}` },
      commits: { href: `${base}/api/v3/repos/${full}/pulls/${pull.number}/commits` },
      statuses: { href: `${base}/api/v3/repos/${full}/statuses/${headSha}` },
    },
    author_association: pull.user === repo.owner ? 'OWNER' : 'CONTRIBUTOR',
    auto_merge: null,
    draft: false,
    merged: pull.merged,
    mergeable,
    rebaseable: mergeable,
    mergeable_state: pull.state === 'open' ? (mergeable ? 'clean' : 'dirty') : 'closed',
    merged_by: pull.merged ? userObject(pull.user) : null,
    comments: 0,
    review_comments: 0,
    maintainer_can_modify: false,
    commits: pullCommits(repo, pull).length,
    additions,
    deletions,
    changed_files: files.length,
  };
}

function commentObject(repo, issueNumber, comment) {
  const base = publicBase();
  return {
    id: comment.id,
    node_id: nodeId('IssueComment', comment.id),
    url: `${base}/api/v3/repos/${repo.fullName}/issues/comments/${comment.id}`,
    html_url: `${base}/${repo.fullName}/issues/${issueNumber}#issuecomment-${comment.id}`,
    body: comment.body,
    user: userObject(comment.user),
    created_at: comment.createdAt,
    updated_at: comment.updatedAt,
    issue_url: `${base}/api/v3/repos/${repo.fullName}/issues/${issueNumber}`,
    author_association: comment.user === repo.owner ? 'OWNER' : 'CONTRIBUTOR',
    reactions: { url: `${base}/api/v3/repos/${repo.fullName}/issues/comments/${comment.id}/reactions`, total_count: 0, '+1': 0, '-1': 0, laugh: 0, hooray: 0, confused: 0, heart: 0, rocket: 0, eyes: 0 },
    performed_via_github_app: null,
  };
}

function parseIdent(line) {
  // "Name <email> 1234567890 +0000"
  const m = /^(.*?) <(.*?)> (\d+) ([+-]\d{4})$/.exec(line || '');
  if (!m) return { name: '', email: '', date: new Date(BASE_EPOCH * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') };
  return { name: m[1], email: m[2], date: new Date(Number(m[3]) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') };
}

function commitObject(repo, oid) {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return null;
  const commit = parseCommit(obj.data);
  const author = parseIdent(commit.author);
  const committer = parseIdent(commit.committer);
  const base = publicBase();
  const full = repo.fullName;
  const authorLogin = author.email === VIEWER_EMAIL ? VIEWER_LOGIN : author.name.replace(/[^a-zA-Z0-9-]/g, '').toLowerCase() || VIEWER_LOGIN;
  return {
    sha: oid,
    node_id: nodeId('Commit', oid),
    commit: {
      author: { name: author.name, email: author.email, date: author.date },
      committer: { name: committer.name, email: committer.email, date: committer.date },
      message: commit.message,
      tree: { sha: commit.tree, url: `${base}/api/v3/repos/${full}/git/trees/${commit.tree}` },
      url: `${base}/api/v3/repos/${full}/git/commits/${oid}`,
      comment_count: 0,
      verification: { verified: false, reason: 'unsigned', signature: null, payload: null, verified_at: null },
    },
    url: `${base}/api/v3/repos/${full}/commits/${oid}`,
    html_url: `${base}/${full}/commit/${oid}`,
    comments_url: `${base}/api/v3/repos/${full}/commits/${oid}/comments`,
    author: userObject(authorLogin),
    committer: userObject(authorLogin),
    parents: commit.parents.map((p) => ({ sha: p, url: `${base}/api/v3/repos/${full}/commits/${p}`, html_url: `${base}/${full}/commit/${p}` })),
  };
}

function branchObject(repo, refName, oid) {
  const base = publicBase();
  return {
    name: refName,
    commit: { sha: oid, url: `${base}/api/v3/repos/${repo.fullName}/commits/${oid}` },
    protected: false,
    protection_url: `${base}/api/v3/repos/${repo.fullName}/branches/${encodeURIComponent(refName)}/protection`,
  };
}

// ------------------------------------------------------------------ pull helpers

function pullBaseTree(repo, pull) {
  const headSha = repo.refs.get(`refs/heads/${pull.headRef}`) || pull.headSha;
  const baseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) || pull.baseSha;
  if (!headSha || !baseSha || headSha === ZERO_OID || baseSha === ZERO_OID) return { files: [], commits: [] };
  const mergeBase = repo.mergeBase(baseSha, headSha);
  const baseTree = mergeBase ? parseCommit(repo.objects.get(mergeBase).data).tree : null;
  const headTree = parseCommit(repo.objects.get(headSha).data).tree;
  return { baseTree, headTree, baseSha, headSha, mergeBase };
}

function countLineDiff(oldText, newText) {
  const oldLines = oldText.split('\n');
  const newLines = newText.split('\n');
  const oldSet = new Map();
  for (const l of oldLines) oldSet.set(l, (oldSet.get(l) || 0) + 1);
  let additions = 0;
  for (const l of newLines) {
    const c = oldSet.get(l) || 0;
    if (c > 0) oldSet.set(l, c - 1);
    else additions += 1;
  }
  let deletions = 0;
  for (const c of oldSet.values()) deletions += c;
  return { additions, deletions };
}

function pullFiles(repo, pull) {
  const ctx = pullBaseTree(repo, pull);
  if (!ctx.headTree) return [];
  const diffs = diffTrees(repo, ctx.baseTree, ctx.headTree);
  return diffs.map((d) => {
    let additions = 0;
    let deletions = 0;
    let patch = '';
    const oldData = d.oldOid ? repo.objects.get(d.oldOid) : null;
    const newData = d.newOid ? repo.objects.get(d.newOid) : null;
    const oldText = oldData ? oldData.data.toString('utf8') : '';
    const newText = newData ? newData.data.toString('utf8') : '';
    const counts = countLineDiff(oldText, newText);
    additions = counts.additions;
    deletions = counts.deletions;
    const oldCount = d.oldOid ? oldText.split('\n').length : 0;
    const newCount = d.newOid ? newText.split('\n').length : 0;
    const hunks = [];
    if (d.oldOid) for (const l of oldText.split('\n')) hunks.push(`-${l}`);
    if (d.newOid) for (const l of newText.split('\n')) hunks.push(`+${l}`);
    patch = `@@ -1,${oldCount} +1,${newCount} @@\n${hunks.join('\n')}`;
    return {
      sha: d.newOid || d.oldOid,
      filename: d.path,
      status: d.status,
      additions,
      deletions,
      changes: additions + deletions,
      blob_url: `${publicBase()}/${repo.fullName}/blob/${ctx.headSha}/${d.path}`,
      raw_url: `${publicBase()}/${repo.fullName}/raw/${ctx.headSha}/${d.path}`,
      contents_url: `${publicBase()}/api/v3/repos/${repo.fullName}/contents/${d.path}?ref=${ctx.headSha}`,
      patch,
    };
  });
}

function pullCommits(repo, pull) {
  const ctx = pullBaseTree(repo, pull);
  if (!ctx.headSha || !ctx.baseSha) return [];
  const baseAncestors = repo.ancestorSet([ctx.baseSha]);
  const out = [];
  const queue = [ctx.headSha];
  const seen = new Set();
  while (queue.length > 0) {
    const oid = queue.shift();
    if (seen.has(oid) || baseAncestors.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    out.push(oid);
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  out.reverse();
  return out.map((oid) => commitObject(repo, oid)).filter(Boolean);
}

// ------------------------------------------------------------------ pagination

function paginate(req, res, items, query) {
  const perPage = clampInt(query.per_page, 1, 100, 30);
  const page = clampInt(query.page, 1, 1000000, 1);
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const links = [];
  const path = req.url.split('?')[0];
  const mk = (p, rel) => {
    const q = new URLSearchParams(query);
    q.set('page', String(p));
    q.set('per_page', String(perPage));
    links.push(`<${publicBase()}${path}?${q.toString()}>; rel="${rel}"`);
  };
  if (page < totalPages) mk(page + 1, 'next');
  if (page > 1) mk(page - 1, 'prev');
  mk(1, 'first');
  mk(totalPages, 'last');
  return { slice, linkHeader: links.join(', ') };
}

// ------------------------------------------------------------------ REST v3

function decodeSeg(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function splitPath(pathname) {
  return pathname.split('/').filter((s) => s !== '').map(decodeSeg);
}

async function handleRest(req, res, segments, query) {
  const method = req.method;
  // Body for methods that carry one.
  let body = {};
  if (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') {
    const raw = await readBody(req, 64 * 1024 * 1024);
    const parsed = parseJsonBody(raw);
    if (!parsed.ok) {
      sendError(res, 400, 'Malformed JSON in request body');
      return;
    }
    body = parsed.value && typeof parsed.value === 'object' ? parsed.value : {};
  }

  // GET /api/v3/
  if (segments.length === 0) {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    const base = publicBase();
    sendJson(res, 200, {
      current_user_url: `${base}/api/v3/user`,
      current_user_authorizations_html_url: `${base}/settings/applications`,
      authorizations_url: `${base}/api/v3/authorizations`,
      code_search_url: `${base}/api/v3/search/code?q={query}{&page,per_page,sort,order}`,
      commit_search_url: `${base}/api/v3/search/commits?q={query}{&page,per_page,sort,order}`,
      emails_url: `${base}/api/v3/user/emails`,
      emojis_url: `${base}/api/v3/emojis`,
      events_url: `${base}/api/v3/events`,
      feeds_url: `${base}/api/v3/feeds`,
      followers_url: `${base}/api/v3/user/followers`,
      following_url: `${base}/api/v3/user/following{/target}`,
      gists_url: `${base}/api/v3/gists{/gist_id}`,
      hub_url: `${base}/api/v3/hub`,
      issue_search_url: `${base}/api/v3/search/issues?q={query}{&page,per_page,sort,order}`,
      issues_url: `${base}/api/v3/issues`,
      keys_url: `${base}/api/v3/user/keys`,
      label_search_url: `${base}/api/v3/search/labels?q={query}&repository_id={repository_id}{&page,per_page}`,
      notifications_url: `${base}/api/v3/notifications`,
      organization_url: `${base}/api/v3/orgs/{org}`,
      organization_repositories_url: `${base}/api/v3/orgs/{org}/repos{?type,page,per_page,sort}`,
      organization_teams_url: `${base}/api/v3/orgs/{org}/teams`,
      public_gists_url: `${base}/api/v3/gists/public`,
      rate_limit_url: `${base}/api/v3/rate_limit`,
      repository_url: `${base}/api/v3/repos/{owner}/{repo}`,
      repository_search_url: `${base}/api/v3/search/repositories?q={query}{&page,per_page,sort,order}`,
      current_user_repositories_url: `${base}/api/v3/user/repos{?type,page,per_page,sort}`,
      starred_url: `${base}/api/v3/user/starred{/owner}{/repo}`,
      starred_gists_url: `${base}/api/v3/gists/starred`,
      topic_search_url: `${base}/api/v3/search/topics?q={query}{&page,per_page}`,
      user_url: `${base}/api/v3/users/{user}`,
      user_organizations_url: `${base}/api/v3/user/orgs`,
      user_repositories_url: `${base}/api/v3/user/repos{?type,page,per_page,sort}`,
      user_search_url: `${base}/api/v3/search/users?q={query}{&page,per_page,sort,order}`,
    }, { 'X-OAuth-Scopes': 'repo, user' });
    return;
  }

  // GET /api/v3/meta
  if (segments.length === 1 && segments[0] === 'meta') {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, {
      verifiable_password_authentication: false,
      ssh_key_fingerprints: {},
      ssh_keys: [],
      hooks: [],
      web: [],
      api: [],
      git: [],
      packages: [],
      pages: [],
      importer: [],
      actions: [],
      dependabot: [],
      github_enterprise_impersonation: false,
      installed_version: '1.0.0',
    });
    return;
  }

  // GET /api/v3/user
  if (segments.length === 1 && segments[0] === 'user') {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    const u = userObject(VIEWER_LOGIN);
    sendJson(res, 200, {
      ...u,
      name: VIEWER_NAME,
      company: null,
      blog: '',
      location: null,
      email: VIEWER_EMAIL,
      hireable: null,
      bio: null,
      twitter_username: null,
      public_repos: [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).length,
      public_gists: 0,
      followers: 0,
      following: 0,
      created_at: new Date(BASE_EPOCH * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      updated_at: new Date(BASE_EPOCH * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      private_gists: 0,
      total_private_repos: 0,
      owned_private_repos: 0,
      disk_usage: 0,
      collaborators: 0,
      two_factor_authentication: false,
      plan: { name: 'free', space: 976562499, collaborators: 0, private_repos: 10000 },
    });
    return;
  }

  // /api/v3/user/repos
  if (segments.length === 2 && segments[0] === 'user' && segments[1] === 'repos') {
    if (method === 'GET') {
      const mine = [...repos.values()]
        .filter((r) => r.owner === VIEWER_LOGIN)
        .sort((a, b) => a.id - b.id)
        .map(repoObject);
      const { slice, linkHeader } = paginate(req, res, mine, query);
      sendJson(res, 200, slice, { Link: linkHeader });
      return;
    }
    if (method === 'POST') {
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (!name) {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Repository', field: 'name', code: 'missing' }] });
        return;
      }
      if (getRepo(VIEWER_LOGIN, name)) {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Repository', field: 'name', code: 'already_exists' }] });
        return;
      }
      const repo = createRepoRecord({
        owner: VIEWER_LOGIN,
        name,
        description: body.description,
        isPrivate: body.private === true,
        defaultBranch: typeof body.default_branch === 'string' && body.default_branch ? body.default_branch : undefined,
      });
      sendJson(res, 201, repoObject(repo));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // POST /api/v3/orgs/{org}/repos
  if (segments.length === 3 && segments[0] === 'orgs' && segments[2] === 'repos') {
    if (method !== 'POST') {
      sendError(res, 404, 'Not Found');
      return;
    }
    const org = segments[1];
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!name) {
      sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Repository', field: 'name', code: 'missing' }] });
      return;
    }
    if (getRepo(org, name)) {
      sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Repository', field: 'name', code: 'already_exists' }] });
      return;
    }
    const repo = createRepoRecord({
      owner: org,
      name,
      description: body.description,
      isPrivate: body.private === true,
      defaultBranch: typeof body.default_branch === 'string' && body.default_branch ? body.default_branch : undefined,
    });
    sendJson(res, 201, repoObject(repo));
    return;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (segments.length >= 3 && segments[0] === 'repos') {
    const owner = segments[1];
    const name = segments[2];
    const repo = getRepo(owner, name);
    if (!repo) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const rest = segments.slice(3);
    await handleRepoRoute(req, res, repo, rest, query, body);
    return;
  }

  sendError(res, 404, 'Not Found');
}

async function handleRepoRoute(req, res, repo, rest, query, body) {
  const method = req.method;

  // /repos/{o}/{r}
  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repoObject(repo));
      return;
    }
    if (method === 'PATCH') {
      const { iso } = stamp();
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.private === 'boolean') repo.private = body.private;
      if (typeof body.default_branch === 'string' && body.default_branch) repo.defaultBranch = body.default_branch;
      if (typeof body.name === 'string' && body.name.trim() && body.name !== repo.name) {
        const newName = body.name.trim();
        if (getRepo(repo.owner, newName)) {
          sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Repository', field: 'name', code: 'already_exists' }] });
          return;
        }
        repos.delete(repoKey(repo.owner, repo.name));
        repo.name = newName;
        repos.set(repoKey(repo.owner, repo.name), repo);
      }
      repo.updatedAt = iso;
      sendJson(res, 200, repoObject(repo));
      return;
    }
    if (method === 'DELETE') {
      repos.delete(repoKey(repo.owner, repo.name));
      sendNoContent(res);
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  const head = rest[0];

  // ---- branches ----
  if (head === 'branches') {
    if (rest.length === 1 && method === 'GET') {
      const branches = [...repo.refs.keys()]
        .filter((r) => r.startsWith('refs/heads/'))
        .map((r) => r.slice('refs/heads/'.length))
        .sort()
        .map((b) => branchObject(repo, b, repo.refs.get(`refs/heads/${b}`)));
      const { slice, linkHeader } = paginate(req, res, branches, query);
      sendJson(res, 200, slice, { Link: linkHeader });
      return;
    }
    if (rest.length >= 2 && method === 'GET') {
      const branch = rest.slice(1).join('/');
      const oid = repo.refs.get(`refs/heads/${branch}`);
      if (!oid) {
        sendError(res, 404, 'Branch not found');
        return;
      }
      sendJson(res, 200, branchObject(repo, branch, oid));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // ---- commits ----
  if (head === 'commits') {
    if (rest.length === 1 && method === 'GET') {
      const refish = query.sha || repo.defaultBranch;
      const tip = repo.resolveRef(refish);
      if (tip === ZERO_OID) {
        sendJson(res, 200, []);
        return;
      }
      const list = [];
      const seen = new Set();
      const queue = [tip];
      while (queue.length > 0) {
        const oid = queue.shift();
        if (seen.has(oid)) continue;
        seen.add(oid);
        const obj = repo.objects.get(oid);
        if (!obj || obj.type !== 'commit') continue;
        list.push(commitObject(repo, oid));
        for (const p of parseCommit(obj.data).parents) queue.push(p);
      }
      const { slice, linkHeader } = paginate(req, res, list, query);
      sendJson(res, 200, slice, { Link: linkHeader });
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      const oid = repo.resolveRef(rest[1]);
      if (oid === ZERO_OID) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const obj = commitObject(repo, oid);
      if (!obj) {
        sendError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, obj);
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // ---- tags ----
  if (head === 'tags' && rest.length === 1 && method === 'GET') {
    const tags = [...repo.refs.keys()]
      .filter((r) => r.startsWith('refs/tags/'))
      .map((r) => r.slice('refs/tags/'.length))
      .sort()
      .map((t) => ({
        name: t,
        commit: { sha: repo.refs.get(`refs/tags/${t}`), url: `${publicBase()}/api/v3/repos/${repo.fullName}/commits/${repo.refs.get(`refs/tags/${t}`)}` },
        zipball_url: `${publicBase()}/api/v3/repos/${repo.fullName}/zipball/${t}`,
        tarball_url: `${publicBase()}/api/v3/repos/${repo.fullName}/tarball/${t}`,
        node_id: nodeId('Tag', `${repo.id}:${t}`),
      }));
    const { slice, linkHeader } = paginate(req, res, tags, query);
    sendJson(res, 200, slice, { Link: linkHeader });
    return;
  }

  // ---- contents ----
  if (head === 'contents') {
    await handleContents(req, res, repo, rest.slice(1).join('/'), query, body);
    return;
  }

  // ---- git/* ----
  if (head === 'git') {
    await handleGitApi(req, res, repo, rest.slice(1), query, body);
    return;
  }

  // ---- compare ----
  if (head === 'compare' && rest.length === 2 && method === 'GET') {
    const range = rest[1];
    const parts = range.split('...');
    if (parts.length !== 2) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const baseOid = repo.resolveRef(parts[0]);
    const headOid = repo.resolveRef(parts[1]);
    if (baseOid === ZERO_OID || headOid === ZERO_OID) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const mergeBase = repo.mergeBase(baseOid, headOid);
    const baseAncestors = repo.ancestorSet([baseOid]);
    const headAncestors = repo.ancestorSet([headOid]);
    const ahead = [...headAncestors].filter((o) => !baseAncestors.has(o));
    const behind = [...baseAncestors].filter((o) => !headAncestors.has(o));
    const baseTree = mergeBase ? parseCommit(repo.objects.get(mergeBase).data).tree : null;
    const headTree = parseCommit(repo.objects.get(headOid).data).tree;
    const files = diffTrees(repo, baseTree, headTree).map((d) => ({
      sha: d.newOid || d.oldOid,
      filename: d.path,
      status: d.status,
      additions: 0,
      deletions: 0,
      changes: 0,
      blob_url: '',
      raw_url: '',
      contents_url: '',
      patch: '',
    }));
    const status = ahead.length === 0 && behind.length === 0 ? 'identical'
      : ahead.length > 0 && behind.length === 0 ? 'ahead'
      : ahead.length === 0 && behind.length > 0 ? 'behind' : 'diverged';
    sendJson(res, 200, {
      url: `${publicBase()}/api/v3/repos/${repo.fullName}/compare/${range}`,
      html_url: `${publicBase()}/${repo.fullName}/compare/${range}`,
      permalink_url: `${publicBase()}/${repo.fullName}/compare/${baseOid}...${headOid}`,
      diff_url: `${publicBase()}/${repo.fullName}/compare/${range}.diff`,
      patch_url: `${publicBase()}/${repo.fullName}/compare/${range}.patch`,
      base_commit: commitObject(repo, baseOid),
      merge_base_commit: mergeBase ? commitObject(repo, mergeBase) : null,
      status,
      ahead_by: ahead.length,
      behind_by: behind.length,
      total_commits: ahead.length,
      commits: ahead.map((o) => commitObject(repo, o)).filter(Boolean),
      files,
    });
    return;
  }

  // ---- labels ----
  if (head === 'labels') {
    if (rest.length === 1) {
      if (method === 'GET') {
        const list = [...repo.labels.values()].map((l) => labelObject(repo, l));
        const { slice, linkHeader } = paginate(req, res, list, query);
        sendJson(res, 200, slice, { Link: linkHeader });
        return;
      }
      if (method === 'POST') {
        const name = typeof body.name === 'string' ? body.name.trim() : '';
        if (!name) {
          sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Label', field: 'name', code: 'missing' }] });
          return;
        }
        if (repo.labels.has(name)) {
          sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Label', field: 'name', code: 'already_exists' }] });
          return;
        }
        const label = {
          id: nextGlobalId(),
          name,
          color: typeof body.color === 'string' ? body.color.replace(/^#/, '') : 'ededed',
          description: typeof body.description === 'string' ? body.description : '',
        };
        repo.labels.set(name, label);
        sendJson(res, 201, labelObject(repo, label));
        return;
      }
    }
    if (rest.length === 2) {
      const label = repo.labels.get(rest[1]);
      if (!label) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, labelObject(repo, label));
        return;
      }
      if (method === 'PATCH') {
        if (typeof body.name === 'string' && body.name.trim() && body.name !== label.name) {
          repo.labels.delete(label.name);
          label.name = body.name.trim();
          repo.labels.set(label.name, label);
        }
        if (typeof body.color === 'string') label.color = body.color.replace(/^#/, '');
        if (typeof body.description === 'string') label.description = body.description;
        sendJson(res, 200, labelObject(repo, label));
        return;
      }
      if (method === 'DELETE') {
        repo.labels.delete(label.name);
        sendNoContent(res);
        return;
      }
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // ---- issues ----
  if (head === 'issues') {
    await handleIssues(req, res, repo, rest.slice(1), query, body);
    return;
  }

  // ---- pulls ----
  if (head === 'pulls') {
    await handlePulls(req, res, repo, rest.slice(1), query, body);
    return;
  }

  sendError(res, 404, 'Not Found');
}

// ------------------------------------------------------------------ contents API

function contentsFileObject(repo, path, entry, refSha) {
  const obj = repo.objects.get(entry.oid);
  const size = obj ? obj.data.length : 0;
  const name = path.split('/').pop();
  return {
    type: 'file',
    encoding: 'base64',
    size,
    name,
    path,
    content: obj ? obj.data.toString('base64') : '',
    sha: entry.oid,
    url: `${publicBase()}/api/v3/repos/${repo.fullName}/contents/${path}?ref=${refSha}`,
    git_url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/blobs/${entry.oid}`,
    html_url: `${publicBase()}/${repo.fullName}/blob/${refSha}/${path}`,
    download_url: `${publicBase()}/${repo.fullName}/raw/${refSha}/${path}`,
    _links: {
      git: `${publicBase()}/api/v3/repos/${repo.fullName}/git/blobs/${entry.oid}`,
      self: `${publicBase()}/api/v3/repos/${repo.fullName}/contents/${path}?ref=${refSha}`,
      html: `${publicBase()}/${repo.fullName}/blob/${refSha}/${path}`,
    },
  };
}

function contentsDirEntry(repo, path, entry, refSha) {
  const obj = entry.isTree ? null : repo.objects.get(entry.oid);
  return {
    type: entry.isTree ? 'dir' : 'file',
    size: obj ? obj.data.length : 0,
    name: path.split('/').pop(),
    path,
    sha: entry.oid,
    url: `${publicBase()}/api/v3/repos/${repo.fullName}/contents/${path}?ref=${refSha}`,
    git_url: entry.isTree
      ? `${publicBase()}/api/v3/repos/${repo.fullName}/git/trees/${entry.oid}`
      : `${publicBase()}/api/v3/repos/${repo.fullName}/git/blobs/${entry.oid}`,
    html_url: `${publicBase()}/${repo.fullName}/${entry.isTree ? 'tree' : 'blob'}/${refSha}/${path}`,
    download_url: entry.isTree ? null : `${publicBase()}/${repo.fullName}/raw/${refSha}/${path}`,
    _links: {
      git: entry.isTree
        ? `${publicBase()}/api/v3/repos/${repo.fullName}/git/trees/${entry.oid}`
        : `${publicBase()}/api/v3/repos/${repo.fullName}/git/blobs/${entry.oid}`,
      self: `${publicBase()}/api/v3/repos/${repo.fullName}/contents/${path}?ref=${refSha}`,
      html: `${publicBase()}/${repo.fullName}/${entry.isTree ? 'tree' : 'blob'}/${refSha}/${path}`,
    },
  };
}

async function handleContents(req, res, repo, path, query, body) {
  const method = req.method;
  const branch = (typeof body.branch === 'string' && body.branch)
    || (typeof query.ref === 'string' && query.ref)
    || repo.defaultBranch;

  if (method === 'GET') {
    const refish = (typeof query.ref === 'string' && query.ref) || branch;
    const tip = repo.resolveRef(refish);
    if (tip === ZERO_OID) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const tree = parseCommit(repo.objects.get(tip).data).tree;
    if (!path) {
      const entries = parseTree(repo.objects.get(tree).data);
      sendJson(res, 200, entries.map((e) => contentsDirEntry(repo, e.name, { oid: e.oid, isTree: isTreeMode(e.mode) }, tip)));
      return;
    }
    const entry = repo.treeLookup(tree, path);
    if (!entry) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (entry.isTree) {
      const entries = parseTree(repo.objects.get(entry.oid).data);
      sendJson(res, 200, entries.map((e) => contentsDirEntry(repo, `${path}/${e.name}`, { oid: e.oid, isTree: isTreeMode(e.mode) }, tip)));
      return;
    }
    sendJson(res, 200, contentsFileObject(repo, path, entry, tip));
    return;
  }

  if (method === 'PUT' || method === 'DELETE') {
    if (!path) {
      sendError(res, 422, 'Validation Failed');
      return;
    }
    const refName = `refs/heads/${branch}`;
    const tip = repo.refs.get(refName) || ZERO_OID;
    const isEmptyRepo = tip === ZERO_OID;
    if (!isEmptyRepo) {
      const obj = repo.objects.get(tip);
      if (!obj || obj.type !== 'commit') {
        sendError(res, 404, 'Not Found');
        return;
      }
    } else if (!repo.refs.has(refName) && repo.refs.size > 0 && branch !== repo.defaultBranch) {
      sendError(res, 404, 'Branch not found');
      return;
    }
    const baseTree = isEmptyRepo ? repo.putObject('tree', buildTree([])) : parseCommit(repo.objects.get(tip).data).tree;
    const existing = isEmptyRepo ? null : repo.treeLookup(baseTree, path);

    if (method === 'PUT') {
      if (typeof body.content !== 'string') {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Commit', field: 'content', code: 'missing' }] });
        return;
      }
      const content = Buffer.from(body.content.replace(/\s/g, ''), 'base64');
      if (existing && !existing.isTree && typeof body.sha === 'string' && body.sha !== existing.oid) {
        sendError(res, 409, 'Conflict: sha does not match the current file');
        return;
      }
      if (existing && existing.isTree) {
        sendError(res, 422, 'Validation Failed: path is a directory');
        return;
      }
      const blobOid = repo.putObject('blob', content);
      const newTree = repo.treeSetPath(baseTree, path, blobOid, '100644');
      const message = typeof body.message === 'string' && body.message ? body.message : `Update ${path}`;
      const commitOid = repo.createCommit({
        tree: newTree,
        parents: isEmptyRepo ? [] : [tip],
        message,
        authorName: VIEWER_LOGIN,
        authorEmail: VIEWER_EMAIL,
      });
      repo.refs.set(refName, commitOid);
      repo.invalidatePackCache();
      const { iso } = stamp();
      repo.updatedAt = iso;
      repo.pushedAt = iso;
      const status = existing ? 200 : 201;
      sendJson(res, status, {
        content: contentsFileObject(repo, path, { oid: blobOid }, commitOid),
        commit: commitObject(repo, commitOid),
      });
      return;
    }

    // DELETE
    if (!existing || existing.isTree) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (typeof body.sha === 'string' && body.sha !== existing.oid) {
      sendError(res, 409, 'Conflict: sha does not match the current file');
      return;
    }
    const newTree = repo.treeSetPath(baseTree, path, null, null);
    const message = typeof body.message === 'string' && body.message ? body.message : `Delete ${path}`;
    const commitOid = repo.createCommit({
      tree: newTree,
      parents: [tip],
      message,
      authorName: VIEWER_LOGIN,
      authorEmail: VIEWER_EMAIL,
    });
    repo.refs.set(refName, commitOid);
    repo.invalidatePackCache();
    const { iso } = stamp();
    repo.updatedAt = iso;
    repo.pushedAt = iso;
    sendJson(res, 200, { content: null, commit: commitObject(repo, commitOid) });
    return;
  }

  sendError(res, 404, 'Not Found');
}

// ------------------------------------------------------------------ git/* API

async function handleGitApi(req, res, repo, rest, query, body) {
  const method = req.method;
  const head = rest[0];

  if (head === 'refs') {
    const refPath = rest.slice(1).join('/');
    if (method === 'GET' && !refPath) {
      const list = [...repo.refs.keys()].sort().map((ref) => ({
        ref,
        node_id: nodeId('Ref', `${repo.id}:${ref}`),
        url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/${ref}`,
        object: { sha: repo.refs.get(ref), type: 'commit', url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/commits/${repo.refs.get(ref)}` },
      }));
      const { slice, linkHeader } = paginate(req, res, list, query);
      sendJson(res, 200, slice, { Link: linkHeader });
      return;
    }
    if (method === 'GET' && refPath) {
      const full = `refs/${refPath}`;
      if (repo.refs.has(full)) {
        const sha = repo.refs.get(full);
        sendJson(res, 200, {
          ref: full,
          node_id: nodeId('Ref', `${repo.id}:${full}`),
          url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/${full}`,
          object: { sha, type: 'commit', url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/commits/${sha}` },
        });
        return;
      }
      const matches = [...repo.refs.keys()].filter((r) => r.startsWith(full)).sort();
      if (matches.length > 0) {
        sendJson(res, 200, matches.map((ref) => ({
          ref,
          node_id: nodeId('Ref', `${repo.id}:${ref}`),
          url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/${ref}`,
          object: { sha: repo.refs.get(ref), type: 'commit', url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/commits/${repo.refs.get(ref)}` },
        })));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (method === 'POST' && !refPath) {
      const ref = typeof body.ref === 'string' ? body.ref : '';
      const sha = typeof body.sha === 'string' ? body.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.get(sha)) {
        sendError(res, 422, 'Validation Failed');
        return;
      }
      if (repo.refs.has(ref)) {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Reference', field: 'ref', code: 'already_exists' }] });
        return;
      }
      repo.refs.set(ref, sha);
      repo.invalidatePackCache();
      sendJson(res, 201, {
        ref,
        node_id: nodeId('Ref', `${repo.id}:${ref}`),
        url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/${ref}`,
        object: { sha, type: 'commit', url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/commits/${sha}` },
      });
      return;
    }
    if ((method === 'PATCH' || method === 'DELETE') && refPath) {
      const full = `refs/${refPath}`;
      if (!repo.refs.has(full)) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'DELETE') {
        if (full === repo.headRef()) {
          sendError(res, 422, 'Validation Failed: cannot delete the default branch');
          return;
        }
        repo.refs.delete(full);
        repo.invalidatePackCache();
        sendNoContent(res);
        return;
      }
      const sha = typeof body.sha === 'string' ? body.sha : '';
      const force = body.force === true;
      if (!isOid(sha) || !repo.objects.get(sha)) {
        sendError(res, 422, 'Validation Failed');
        return;
      }
      const current = repo.refs.get(full);
      if (!force && !repo.isAncestor(current, sha)) {
        sendError(res, 422, 'Validation Failed: update is not a fast-forward');
        return;
      }
      repo.refs.set(full, sha);
      repo.invalidatePackCache();
      sendJson(res, 200, {
        ref: full,
        node_id: nodeId('Ref', `${repo.id}:${full}`),
        url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/${full}`,
        object: { sha, type: 'commit', url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/commits/${sha}` },
      });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (head === 'trees' && rest.length === 2 && method === 'GET') {
    const sha = rest[1];
    const obj = repo.objects.get(sha);
    if (!obj || obj.type !== 'tree') {
      sendError(res, 404, 'Not Found');
      return;
    }
    const recursive = query.recursive === '1' || query.recursive === 'true';
    const entries = [];
    const walk = (treeOid, prefix) => {
      for (const e of parseTree(repo.objects.get(treeOid).data)) {
        entries.push({
          path: prefix + e.name,
          mode: e.mode.padStart(6, '0'),
          type: isTreeMode(e.mode) ? 'tree' : 'blob',
          sha: e.oid,
          size: isTreeMode(e.mode) ? undefined : (repo.objects.get(e.oid)?.data.length || 0),
          url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/${isTreeMode(e.mode) ? 'trees' : 'blobs'}/${e.oid}`,
        });
        if (recursive && isTreeMode(e.mode)) walk(e.oid, `${prefix + e.name}/`);
      }
    };
    walk(sha, '');
    sendJson(res, 200, { sha, url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/trees/${sha}`, tree: entries, truncated: false });
    return;
  }

  if (head === 'blobs' && rest.length === 2 && method === 'GET') {
    const obj = repo.objects.get(rest[1]);
    if (!obj || obj.type !== 'blob') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, {
      node_id: nodeId('Blob', rest[1]),
      sha: rest[1],
      size: obj.data.length,
      url: `${publicBase()}/api/v3/repos/${repo.fullName}/git/blobs/${rest[1]}`,
      content: obj.data.toString('base64'),
      encoding: 'base64',
    });
    return;
  }

  if (head === 'commits' && rest.length === 2 && method === 'GET') {
    const obj = commitObject(repo, rest[1]);
    if (!obj) {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, obj);
    return;
  }

  sendError(res, 404, 'Not Found');
}

// ------------------------------------------------------------------ issues API

function validateIssueLabels(repo, labels) {
  if (!Array.isArray(labels)) return { ok: true, names: [] };
  const names = [];
  for (const l of labels) {
    const name = typeof l === 'string' ? l : (l && typeof l.name === 'string' ? l.name : '');
    if (!name) continue;
    if (!repo.labels.has(name)) return { ok: false, missing: name };
    names.push(name);
  }
  return { ok: true, names };
}

async function handleIssues(req, res, repo, rest, query, body) {
  const method = req.method;

  if (rest.length === 0) {
    if (method === 'GET') {
      const state = query.state || 'open';
      const labelFilter = typeof query.labels === 'string' && query.labels
        ? query.labels.split(',').map((s) => s.trim()).filter(Boolean) : [];
      const all = [];
      for (const issue of repo.issues.values()) all.push(issueObject(repo, issue));
      for (const pull of repo.pulls.values()) all.push(pullAsIssueObject(repo, pull));
      let filtered = all;
      if (state !== 'all') filtered = filtered.filter((i) => i.state === state);
      if (labelFilter.length > 0) {
        filtered = filtered.filter((i) => labelFilter.every((l) => i.labels.some((x) => x.name === l)));
      }
      filtered.sort((a, b) => {
        const dir = query.direction === 'asc' ? 1 : -1;
        const by = query.sort === 'created' || !query.sort ? 'created_at' : query.sort;
        if (by === 'created_at' || by === 'created') {
          return (a.created_at < b.created_at ? -1 : a.created_at > b.created_at ? 1 : a.number - b.number) * dir;
        }
        return (a.number - b.number) * dir;
      });
      const { slice, linkHeader } = paginate(req, res, filtered, query);
      sendJson(res, 200, slice, { Link: linkHeader });
      return;
    }
    if (method === 'POST') {
      const title = typeof body.title === 'string' ? body.title.trim() : '';
      if (!title) {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Issue', field: 'title', code: 'missing' }] });
        return;
      }
      const checked = validateIssueLabels(repo, body.labels);
      if (!checked.ok) {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Issue', field: 'labels', code: 'invalid', message: `Label '${checked.missing}' does not exist` }] });
        return;
      }
      const { iso } = stamp();
      repo.numberCounter += 1;
      const issue = {
        id: nextGlobalId(),
        number: repo.numberCounter,
        title,
        body: typeof body.body === 'string' ? body.body : null,
        state: 'open',
        labels: checked.names,
        user: VIEWER_LOGIN,
        createdAt: iso,
        updatedAt: iso,
        closedAt: null,
        commentsCount: 0,
      };
      repo.issues.set(issue.number, issue);
      repo.comments.set(issue.number, []);
      sendJson(res, 201, issueObject(repo, issue));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  const number = Number.parseInt(rest[0], 10);
  if (!Number.isInteger(number)) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const issue = repo.issues.get(number);
  const pull = repo.pulls.get(number);

  if (rest.length === 1) {
    if (method === 'GET') {
      if (issue) {
        sendJson(res, 200, issueObject(repo, issue));
        return;
      }
      if (pull) {
        sendJson(res, 200, pullAsIssueObject(repo, pull));
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (method === 'PATCH') {
      if (!issue && !pull) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const target = issue || pull;
      if (body.labels !== undefined) {
        const checked = validateIssueLabels(repo, body.labels);
        if (!checked.ok) {
          sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Issue', field: 'labels', code: 'invalid', message: `Label '${checked.missing}' does not exist` }] });
          return;
        }
        target.labels = checked.names;
      }
      const { iso } = stamp();
      if (typeof body.title === 'string') target.title = body.title;
      if (typeof body.body === 'string' || body.body === null) target.body = body.body;
      if (body.state === 'open' || body.state === 'closed') {
        target.state = body.state;
        target.closedAt = body.state === 'closed' ? iso : null;
      }
      target.updatedAt = iso;
      if (issue) sendJson(res, 200, issueObject(repo, issue));
      else sendJson(res, 200, pullAsIssueObject(repo, pull));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (rest[1] === 'comments') {
    if (!issue && !pull) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (method === 'GET') {
      const list = (repo.comments.get(number) || []).map((c) => commentObject(repo, number, c));
      const { slice, linkHeader } = paginate(req, res, list, query);
      sendJson(res, 200, slice, { Link: linkHeader });
      return;
    }
    if (method === 'POST') {
      const text = typeof body.body === 'string' ? body.body : '';
      if (!text) {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'IssueComment', field: 'body', code: 'missing' }] });
        return;
      }
      const { iso } = stamp();
      const comment = { id: nextGlobalId(), body: text, user: VIEWER_LOGIN, createdAt: iso, updatedAt: iso };
      if (!repo.comments.has(number)) repo.comments.set(number, []);
      repo.comments.get(number).push(comment);
      if (issue) issue.commentsCount = (issue.commentsCount || 0) + 1;
      sendJson(res, 201, commentObject(repo, number, comment));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (rest[1] === 'labels') {
    if (!issue && !pull) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const target = issue || pull;
    if (method === 'GET') {
      sendJson(res, 200, (target.labels || []).map((name) => labelObject(repo, repo.labels.get(name))).filter(Boolean));
      return;
    }
    if (method === 'POST') {
      const names = Array.isArray(body.labels) ? body.labels : (Array.isArray(body) ? body : []);
      const checked = validateIssueLabels(repo, names);
      if (!checked.ok) {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'Issue', field: 'labels', code: 'invalid', message: `Label '${checked.missing}' does not exist` }] });
        return;
      }
      for (const n of checked.names) {
        if (!target.labels.includes(n)) target.labels.push(n);
      }
      sendJson(res, 200, target.labels.map((name) => labelObject(repo, repo.labels.get(name))).filter(Boolean));
      return;
    }
    if (method === 'DELETE' && rest.length === 3) {
      target.labels = (target.labels || []).filter((n) => n !== rest[2]);
      sendJson(res, 200, target.labels.map((name) => labelObject(repo, repo.labels.get(name))).filter(Boolean));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  sendError(res, 404, 'Not Found');
}

// ------------------------------------------------------------------ pulls API

function parseHeadRef(head) {
  if (typeof head !== 'string') return null;
  const idx = head.indexOf(':');
  if (idx >= 0) return { owner: head.slice(0, idx), ref: head.slice(idx + 1) };
  return { owner: null, ref: head };
}

async function handlePulls(req, res, repo, rest, query, body) {
  const method = req.method;

  if (rest.length === 0) {
    if (method === 'GET') {
      const state = query.state || 'open';
      let list = [...repo.pulls.values()];
      if (state !== 'all') list = list.filter((p) => p.state === state);
      list.sort((a, b) => {
        const dir = query.direction === 'asc' ? 1 : -1;
        return (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : a.number - b.number) * dir;
      });
      const { slice, linkHeader } = paginate(req, res, list.map((p) => pullObject(repo, p)), query);
      sendJson(res, 200, slice, { Link: linkHeader });
      return;
    }
    if (method === 'POST') {
      const title = typeof body.title === 'string' ? body.title.trim() : '';
      const parsedHead = parseHeadRef(body.head);
      const base = typeof body.base === 'string' && body.base ? body.base : repo.defaultBranch;
      if (!title || !parsedHead || !parsedHead.ref) {
        sendError(res, 422, 'Validation Failed', { errors: [{ resource: 'PullRequest', field: 'head', code: 'missing' }] });
        return;
      }
      if (parsedHead.owner && parsedHead.owner !== repo.owner) {
        sendError(res, 422, 'Validation Failed: cross-repository pull requests are not supported');
        return;
      }
      const headOid = repo.refs.get(`refs/heads/${parsedHead.ref}`);
      const baseOid = repo.refs.get(`refs/heads/${base}`);
      if (!headOid || !baseOid) {
        sendError(res, 422, 'Validation Failed: head or base branch does not exist');
        return;
      }
      const { iso } = stamp();
      repo.numberCounter += 1;
      const pull = {
        id: nextGlobalId(),
        number: repo.numberCounter,
        title,
        body: typeof body.body === 'string' ? body.body : null,
        state: 'open',
        headRef: parsedHead.ref,
        baseRef: base,
        headSha: headOid,
        baseSha: baseOid,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        labels: [],
        user: VIEWER_LOGIN,
        createdAt: iso,
        updatedAt: iso,
        closedAt: null,
      };
      repo.pulls.set(pull.number, pull);
      if (!repo.comments.has(pull.number)) repo.comments.set(pull.number, []);
      sendJson(res, 201, pullObject(repo, pull));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  const number = Number.parseInt(rest[0], 10);
  if (!Number.isInteger(number)) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const pull = repo.pulls.get(number);

  if (rest.length === 1) {
    if (method === 'GET') {
      if (!pull) {
        sendError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, pullObject(repo, pull));
      return;
    }
    if (method === 'PATCH') {
      if (!pull) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const { iso } = stamp();
      if (typeof body.title === 'string') pull.title = body.title;
      if (typeof body.body === 'string' || body.body === null) pull.body = body.body;
      if (body.state === 'open' || body.state === 'closed') {
        pull.state = body.state;
        pull.closedAt = body.state === 'closed' ? iso : null;
      }
      if (typeof body.base === 'string' && body.base && repo.refs.has(`refs/heads/${body.base}`)) {
        pull.baseRef = body.base;
      }
      pull.updatedAt = iso;
      sendJson(res, 200, pullObject(repo, pull));
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  if (rest[1] === 'files' && rest.length === 2 && method === 'GET') {
    if (!pull) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const { slice, linkHeader } = paginate(req, res, pullFiles(repo, pull), query);
    sendJson(res, 200, slice, { Link: linkHeader });
    return;
  }

  if (rest[1] === 'commits' && rest.length === 2 && method === 'GET') {
    if (!pull) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const { slice, linkHeader } = paginate(req, res, pullCommits(repo, pull), query);
    sendJson(res, 200, slice, { Link: linkHeader });
    return;
  }

  if (rest[1] === 'merge') {
    if (!pull) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (method === 'GET') {
      // GitHub: 204 when merged, 404 when not.
      if (pull.merged) {
        sendNoContent(res);
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (method === 'PUT') {
      if (pull.merged) {
        sendJson(res, 200, { sha: pull.mergeCommitSha, merged: true, message: 'Already merged' });
        return;
      }
      if (pull.state !== 'open') {
        sendError(res, 405, 'Pull request is closed');
        return;
      }
      const headSha = repo.refs.get(`refs/heads/${pull.headRef}`) || pull.headSha;
      const baseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) || pull.baseSha;
      if (!headSha || !baseSha || headSha === ZERO_OID || baseSha === ZERO_OID) {
        sendError(res, 405, 'Head or base branch is missing');
        return;
      }
      if (!isMergeable(repo, baseSha, headSha)) {
        sendError(res, 405, 'Pull request is not mergeable: merge conflict');
        return;
      }
      const headTree = parseCommit(repo.objects.get(headSha).data).tree;
      const title = typeof body.commit_title === 'string' && body.commit_title
        ? body.commit_title : `${pull.title} (#${pull.number})`;
      const extra = typeof body.commit_message === 'string' && body.commit_message ? `\n\n${body.commit_message}` : '';
      const commitOid = repo.createCommit({
        tree: headTree,
        parents: [baseSha],
        message: `${title}${extra}`,
        authorName: VIEWER_LOGIN,
        authorEmail: VIEWER_EMAIL,
      });
      repo.refs.set(`refs/heads/${pull.baseRef}`, commitOid);
      repo.invalidatePackCache();
      const { iso } = stamp();
      pull.merged = true;
      pull.state = 'closed';
      pull.mergedAt = iso;
      pull.closedAt = iso;
      pull.updatedAt = iso;
      pull.mergeCommitSha = commitOid;
      repo.updatedAt = iso;
      repo.pushedAt = iso;
      sendJson(res, 200, { sha: commitOid, merged: true, message: 'Pull request successfully merged' });
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  sendError(res, 404, 'Not Found');
}

// ------------------------------------------------------------------ git smart HTTP

function refAdvertisementV0(repo, caps) {
  const lines = [];
  const headOid = repo.headOid();
  const refs = [...repo.refs.keys()].sort();
  const capStr = caps.join(' ');
  if (refs.length === 0) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${capStr}\n`));
  } else {
    lines.push(pktLine(`${headOid} HEAD\0${capStr}\n`));
    for (const ref of refs) {
      lines.push(pktLine(`${repo.refs.get(ref)} ${ref}\n`));
    }
  }
  lines.push(FLUSH_PKT);
  return Buffer.concat(lines);
}

function uploadPackCapsV0(repo) {
  return [
    'side-band-64k',
    'side-band',
    'thin-pack',
    'ofs-delta',
    'shallow',
    'deepen-since',
    'deepen-not',
    'include-tag',
    'allow-tip-sha1-in-want',
    'allow-reachable-sha1-in-want',
    `symref=HEAD:${repo.headRef()}`,
    `agent=${AGENT_NAME}`,
  ];
}

function receivePackCapsV0() {
  return ['report-status', 'side-band-64k', 'delete-refs', 'ofs-delta', `agent=${AGENT_NAME}`];
}

async function handleInfoRefs(req, res, repo, service) {
  if (service === 'git-upload-pack') {
    const proto = (req.headers['git-protocol'] || '').toString();
    if (proto === 'version=2') {
      const lines = [
        pktLine('version 2\n'),
        pktLine(`agent=${AGENT_NAME}\n`),
        pktLine('ls-refs=unborn\n'),
        pktLine('fetch=shallow\n'),
        pktLine('object-format=sha1\n'),
        FLUSH_PKT,
      ];
      const body = Buffer.concat(lines);
      res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-advertisement', 'Content-Length': body.length, 'X-GitHub-Request-Id': nextRequestId() });
      res.end(body);
      return;
    }
    const preamble = pktLine('# service=git-upload-pack\n');
    const body = Buffer.concat([preamble, FLUSH_PKT, refAdvertisementV0(repo, uploadPackCapsV0(repo))]);
    res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-advertisement', 'Content-Length': body.length, 'X-GitHub-Request-Id': nextRequestId() });
    res.end(body);
    return;
  }
  if (service === 'git-receive-pack') {
    const preamble = pktLine('# service=git-receive-pack\n');
    const body = Buffer.concat([preamble, FLUSH_PKT, refAdvertisementV0(repo, receivePackCapsV0())]);
    res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-advertisement', 'Content-Length': body.length, 'X-GitHub-Request-Id': nextRequestId() });
    res.end(body);
    return;
  }
  sendError(res, 404, 'Not Found');
}

// Build the pack + shallow list for a set of wants, with caching.
function getPackFor(repo, wants, haves, maxDepth, includeTag, clientShallows) {
  const key = JSON.stringify({
    w: [...wants].sort(),
    h: [...haves].sort(),
    d: maxDepth === undefined ? null : maxDepth,
    t: !!includeTag,
    s: [...clientShallows].sort(),
  });
  const cached = repo.packCache.get(key);
  if (cached) return cached;
  const { objects, shallow } = repo.collectPack(wants, haves, maxDepth);
  const all = objects.slice();
  if (includeTag) {
    const includedCommits = new Set(objects.filter((o) => o.type === 'commit').map((o) => o.oid));
    for (const [ref, oid] of repo.refs) {
      if (!ref.startsWith('refs/tags/')) continue;
      const obj = repo.objects.get(oid);
      if (obj && obj.type === 'tag') {
        const peeled = repo.peelToCommit(oid);
        if (peeled.oid && includedCommits.has(peeled.oid) && !all.some((o) => o.oid === oid)) {
          all.push({ oid, type: 'tag', data: obj.data });
        }
      }
    }
  }
  const pack = buildPack(all);
  const result = { pack, shallow, commitOids: new Set(objects.filter((o) => o.type === 'commit').map((o) => o.oid)) };
  if (repo.packCache.size > 64) {
    const first = repo.packCache.keys().next().value;
    repo.packCache.delete(first);
  }
  repo.packCache.set(key, result);
  return result;
}

async function handleUploadPackV0(req, res, repo, bodyBuf) {
  const { lines } = parsePktLinesToEnd(bodyBuf);
  const wants = [];
  const haves = [];
  const clientShallows = [];
  let maxDepth;
  let sideband = false;
  let includeTag = false;
  let doneReceived = false;
  let firstWant = true;
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('want ')) {
      const rest = line.slice(5);
      const oid = rest.slice(0, 40);
      wants.push(oid);
      if (firstWant) {
        firstWant = false;
        const capsPart = rest.slice(41);
        if (capsPart) {
          const caps = capsPart.split(' ');
          if (caps.includes('side-band-64k') || caps.includes('side-band')) sideband = true;
          if (caps.includes('include-tag')) includeTag = true;
        }
      }
    } else if (line.startsWith('have ')) {
      haves.push(line.slice(5, 45));
    } else if (line.startsWith('shallow ')) {
      clientShallows.push(line.slice(8, 48));
    } else if (line.startsWith('deepen ')) {
      const n = Number.parseInt(line.slice(7), 10);
      if (Number.isFinite(n) && n > 0) maxDepth = n;
    } else if (line === 'done') {
      doneReceived = true;
    }
    // deepen-since / deepen-not / filter: accepted, filter ignored.
  }

  // Peel tag wants to commits, remembering the tag objects to include.
  const peeledWants = [];
  const extraTags = [];
  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (!obj) {
      const err = pktLine(`ERR ${want} not found\n`);
      res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': err.length, 'X-GitHub-Request-Id': nextRequestId() });
      res.end(err);
      return;
    }
    if (obj.type === 'tag') {
      const peeled = repo.peelToCommit(want);
      if (!peeled.oid) {
        const err = pktLine(`ERR ${want} cannot be peeled\n`);
        res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': err.length, 'X-GitHub-Request-Id': nextRequestId() });
        res.end(err);
        return;
      }
      extraTags.push(...peeled.peeledTags);
      peeledWants.push(peeled.oid);
    } else if (obj.type === 'commit') {
      peeledWants.push(want);
    } else {
      const err = pktLine(`ERR ${want} is not a commit\n`);
      res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': err.length, 'X-GitHub-Request-Id': nextRequestId() });
      res.end(err);
      return;
    }
  }

  const excluded = new Set([...haves, ...clientShallows]);
  const { pack, shallow, commitOids } = getPackFor(repo, peeledWants, excluded, maxDepth, includeTag, clientShallows);
  // Add explicitly-wanted tag objects.
  let finalPack = pack;
  if (extraTags.length > 0) {
    const tagObjs = extraTags.map((oid) => ({ oid, type: 'tag', data: repo.objects.get(oid).data }));
    // Rebuild: unpack the cached pack is wasteful; instead build a small
    // second pack is invalid (one pack per response). Rebuild fully.
    const { objects } = repo.collectPack(peeledWants, excluded, maxDepth);
    const all = objects.slice();
    for (const t of tagObjs) if (!all.some((o) => o.oid === t.oid)) all.push(t);
    finalPack = buildPack(all);
  }

  const out = [];
  // Shallow section (v0): shallow/unshallow lines with NO trailing newline
  // (matching git 2.43), terminated by a flush packet. The client reads
  // shallow lines until the flush, then expects NAK/ACK; without the flush
  // it dies with "expected shallow/unshallow, got NAK".
  let emittedShallow = false;
  for (const s of shallow) { out.push(pktLine(`shallow ${s}`)); emittedShallow = true; }
  for (const s of clientShallows) {
    if (commitOids.has(s) && !shallow.includes(s)) { out.push(pktLine(`unshallow ${s}`)); emittedShallow = true; }
  }
  if (emittedShallow) out.push(FLUSH_PKT);
  // Shallow negotiation, round 1: the client sent `deepen` but no `done`,
  // so it wants ONLY the shallow list now and will re-POST with `done`.
  // Sending NAK + pack here leaves unread bytes on the keep-alive
  // connection, which the client then misreads as the start of round 2's
  // response ("expected shallow list"). Answer the shallow list + flush
  // and nothing else.
  if (!doneReceived && maxDepth !== undefined) {
    const shallowOnly = Buffer.concat(out);
    res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': shallowOnly.length, 'X-GitHub-Request-Id': nextRequestId() });
    res.end(shallowOnly);
    return;
  }
  out.push(pktLine('NAK\n'));
  const head = Buffer.concat(out);
  let response;
  if (sideband) {
    response = Buffer.concat([head, sidebandFrame(finalPack, 1)]);
  } else {
    response = Buffer.concat([head, finalPack]);
  }
  res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': response.length, 'X-GitHub-Request-Id': nextRequestId() });
  res.end(response);
}

async function handleUploadPackV2(req, res, repo, bodyBuf) {
  const { lines } = parsePktLinesToEnd(bodyBuf);
  const commandLine = (lines[0] || '').replace(/\n$/, '');
  const m = /^command=([a-z-]+)$/.exec(commandLine);
  if (!m) {
    const err = Buffer.concat([pktLine('ERR unknown command\n'), FLUSH_PKT]);
    res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': err.length, 'X-GitHub-Request-Id': nextRequestId() });
    res.end(err);
    return;
  }
  const command = m[1];
  const args = lines.slice(1).map((l) => l.replace(/\n$/, ''));

  if (command === 'ls-refs') {
    let peel = false;
    let unborn = false;
    let symrefs = false;
    const prefixes = [];
    for (const arg of args) {
      if (arg === 'peel') peel = true;
      else if (arg === 'unborn') unborn = true;
      else if (arg === 'symrefs') symrefs = true;
      else if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
    }
    const out = [];
    const headTarget = repo.headRef();
    const headOid = repo.refs.get(headTarget);
    const candidates = [];
    if (headOid) {
      candidates.push({ name: 'HEAD', oid: headOid, symref: headTarget });
    } else if (unborn) {
      candidates.push({ name: 'HEAD', oid: ZERO_OID, symref: headTarget, unborn: true });
    }
    for (const ref of [...repo.refs.keys()].sort()) {
      candidates.push({ name: ref, oid: repo.refs.get(ref) });
    }
    for (const c of candidates) {
      if (prefixes.length > 0 && !prefixes.some((p) => c.name.startsWith(p))) continue;
      if (c.unborn) {
        // Unborn refs use a dedicated line form: the literal word `unborn`
        // REPLACES the oid (`unborn HEAD symref-target:...`). Sending the
        // zero oid with an `unborn` attribute makes the client fetch the
        // zero oid and die. Verified against git 2.43.
        const attrs = [];
        if (symrefs && c.symref) attrs.push(`symref-target:${c.symref}`);
        out.push(pktLine(`unborn ${c.name}${attrs.length > 0 ? ` ${attrs.join(' ')}` : ''}\n`));
        continue;
      }
      const attrs = [];
      if (peel) {
        const obj = repo.objects.get(c.oid);
        if (obj && obj.type === 'tag') {
          const peeled = repo.peelToCommit(c.oid);
          if (peeled.oid) attrs.push(`peeled:${peeled.oid}`);
        }
      }
      if (symrefs && c.symref) attrs.push(`symref-target:${c.symref}`);
      out.push(pktLine(`${c.oid} ${c.name}${attrs.length > 0 ? ` ${attrs.join(' ')}` : ''}\n`));
    }
    out.push(FLUSH_PKT);
    const body = Buffer.concat(out);
    res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': body.length, 'X-GitHub-Request-Id': nextRequestId() });
    res.end(body);
    return;
  }

  if (command === 'fetch') {
    const wants = [];
    const haves = [];
    const clientShallows = [];
    let maxDepth;
    let sidebandAll = false;
    let doneReceived = false;
    for (const arg of args) {
      if (arg.startsWith('want ')) wants.push(arg.slice(5, 45));
      else if (arg.startsWith('have ')) haves.push(arg.slice(5, 45));
      else if (arg.startsWith('shallow ')) clientShallows.push(arg.slice(8, 48));
      else if (arg.startsWith('deepen ')) {
        const n = Number.parseInt(arg.slice(7), 10);
        if (Number.isFinite(n) && n > 0) maxDepth = n;
      } else if (arg === 'sideband-all') sidebandAll = true;
      else if (arg === 'done') doneReceived = true;
      // filter / ofs-delta / thin-pack / agent / wait-for-done: accepted.
    }
    const peeledWants = [];
    const extraTags = [];
    for (const want of wants) {
      const obj = repo.objects.get(want);
      if (!obj) {
        const err = Buffer.concat([pktLine(`ERR ${want} not found\n`), FLUSH_PKT]);
        res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': err.length, 'X-GitHub-Request-Id': nextRequestId() });
        res.end(err);
        return;
      }
      if (obj.type === 'tag') {
        const peeled = repo.peelToCommit(want);
        if (!peeled.oid) {
          const err = Buffer.concat([pktLine(`ERR ${want} cannot be peeled\n`), FLUSH_PKT]);
          res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': err.length, 'X-GitHub-Request-Id': nextRequestId() });
          res.end(err);
          return;
        }
        extraTags.push(...peeled.peeledTags);
        peeledWants.push(peeled.oid);
      } else if (obj.type === 'commit') {
        peeledWants.push(want);
      } else {
        const err = Buffer.concat([pktLine(`ERR ${want} is not a commit\n`), FLUSH_PKT]);
        res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': err.length, 'X-GitHub-Request-Id': nextRequestId() });
        res.end(err);
        return;
      }
    }
    // Multi-round negotiation: the client sent haves but no `done`, so it
    // wants ONLY the acknowledgement section now and will follow up with a
    // second request carrying `done`. Answer `acknowledgments` + ACK lines +
    // flush, and NOTHING else: the HTTP body close ends the response (an
    // explicit 0002 response-end packet is rejected as "unexpected", and a
    // pack following the flush dies with "expected response end packet").
    // Header spelling `acknowledgments` (with an s) verified against git 2.43.
    // Single-round requests (haves + `done` together) skip this section.
    if (haves.length > 0 && !doneReceived) {
      const ackOut = [pktLine('acknowledgments\n')];
      const wantAncestors = repo.ancestorSet(peeledWants);
      for (const h of haves) {
        if (wantAncestors.has(h) && repo.objects.get(h)) ackOut.push(pktLine(`ACK ${h}\n`));
      }
      ackOut.push(FLUSH_PKT);
      const ackBody = Buffer.concat(ackOut);
      res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': ackBody.length, 'X-GitHub-Request-Id': nextRequestId() });
      res.end(ackBody);
      return;
    }
    const excluded = new Set([...haves, ...clientShallows]);
    const { pack, shallow, commitOids } = getPackFor(repo, peeledWants, excluded, maxDepth, false, clientShallows);
    let finalPack = pack;
    if (extraTags.length > 0) {
      const { objects } = repo.collectPack(peeledWants, excluded, maxDepth);
      const all = objects.slice();
      for (const oid of extraTags) {
        if (!all.some((o) => o.oid === oid)) all.push({ oid, type: 'tag', data: repo.objects.get(oid).data });
      }
      finalPack = buildPack(all);
    }
    const out = [];
    // Shallow section: `shallow-info` header, shallow/unshallow lines with
    // NO trailing newline (matching git 2.43), closed by a delimiter packet.
    const unshallows = clientShallows.filter((s) => commitOids.has(s) && !shallow.includes(s));
    if (shallow.length > 0 || unshallows.length > 0) {
      out.push(pktLine('shallow-info\n'));
      for (const s of shallow) out.push(pktLine(`shallow ${s}`));
      for (const s of unshallows) out.push(pktLine(`unshallow ${s}`));
      out.push(DELIMITER_PKT);
    }
    out.push(pktLine('packfile\n'));
    const head = Buffer.concat(out);
    // The v2 packfile section is ALWAYS sideband-framed (channel 1),
    // whether or not the client asked for sideband-all: git's own
    // upload-pack frames it unconditionally, and git's fetch client reads
    // pkt-lines after the `packfile` line (a raw pack dies with
    // "bad line length character: PACK"). Verified against git 2.43.
    const response = Buffer.concat([head, sidebandFrame(finalPack, 1)]);
    res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': response.length, 'X-GitHub-Request-Id': nextRequestId() });
    res.end(response);
    return;
  }

  const err = Buffer.concat([pktLine(`ERR unknown command '${command}'\n`), FLUSH_PKT]);
  res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'Content-Length': err.length, 'X-GitHub-Request-Id': nextRequestId() });
  res.end(err);
}

async function handleReceivePack(req, res, repo, bodyBuf) {
  const { lines, rest } = parsePktLines(bodyBuf);
  const updates = [];
  let caps = [];
  let first = true;
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (!line) continue;
    let text = line;
    if (first) {
      first = false;
      const nul = text.indexOf('\0');
      if (nul >= 0) {
        caps = text.slice(nul + 1).split(' ').filter(Boolean);
        text = text.slice(0, nul);
      }
    }
    const parts = text.split(' ');
    if (parts.length < 3) continue;
    updates.push({ old: parts[0], new: parts[1], ref: parts.slice(2).join(' ') });
  }
  const sideband = caps.includes('side-band-64k') || caps.includes('side-band');

  const reportLines = [];
  let unpackOk = true;
  let unpackError = '';
  if (rest.length > 0) {
    try {
      const objects = parsePack(rest, (oid) => repo.objects.get(oid) || null);
      for (const obj of objects) {
        if (!repo.objects.has(obj.oid)) repo.objects.set(obj.oid, { type: obj.type, data: obj.data });
      }
    } catch (e) {
      unpackOk = false;
      unpackError = e.message || 'unpack failed';
    }
  }

  const results = [];
  let changed = false;
  for (const u of updates) {
    if (!unpackOk) {
      results.push(`ng ${u.ref} unpack error`);
      continue;
    }
    if (u.new === ZERO_OID) {
      if (repo.refs.has(u.ref)) {
        repo.refs.delete(u.ref);
        changed = true;
      }
      results.push(`ok ${u.ref}`);
      continue;
    }
    const newObj = repo.objects.get(u.new);
    if (!newObj) {
      results.push(`ng ${u.ref} object not found`);
      continue;
    }
    const current = repo.refs.get(u.ref);
    if (current === undefined) {
      if (u.old !== ZERO_OID) {
        results.push(`ng ${u.ref} non-fast-forward`);
        continue;
      }
      repo.refs.set(u.ref, u.new);
      changed = true;
      results.push(`ok ${u.ref}`);
      continue;
    }
    if (current === u.new) {
      results.push(`ok ${u.ref}`);
      continue;
    }
    if (repo.isAncestor(current, u.new)) {
      repo.refs.set(u.ref, u.new);
      changed = true;
      results.push(`ok ${u.ref}`);
    } else {
      results.push(`ng ${u.ref} non-fast-forward`);
    }
  }
  if (changed) {
    repo.invalidatePackCache();
    const { iso } = stamp();
    repo.updatedAt = iso;
    repo.pushedAt = iso;
  }

  if (unpackOk) reportLines.push('unpack ok');
  else reportLines.push(`unpack ${unpackError}`);
  for (const r of results) reportLines.push(r);
  const text = reportLines.map((l) => `${l}\n`).join('');
  let response;
  if (sideband) {
    // With side-band-64k the report lines travel as pkt-lines INSIDE the
    // sideband channel-1 stream (the client demuxes, then reads pkt-lines),
    // terminated by a flush inside the channel.
    const inner = Buffer.concat([
      ...reportLines.map((l) => pktLine(`${l}\n`)),
      FLUSH_PKT,
    ]);
    response = sidebandFrame(inner, 1);
  } else {
    const parts = reportLines.map((l) => pktLine(`${l}\n`));
    parts.push(FLUSH_PKT);
    response = Buffer.concat(parts);
  }
  res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-result', 'Content-Length': response.length, 'X-GitHub-Request-Id': nextRequestId() });
  res.end(response);
}

async function handleGit(req, res, segments, query) {
  // /{owner}/{repo}.git/{action}
  const owner = segments[0];
  const repoSeg = segments[1];
  const repoName = repoSeg.slice(0, -4);
  const action = segments.slice(2).join('/');
  const repo = getRepo(owner, repoName);
  if (!repo) {
    sendError(res, 404, 'Not Found');
    return;
  }
  if (action === 'info/refs' && req.method === 'GET') {
    const service = query.service;
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      sendError(res, 404, 'Not Found');
      return;
    }
    await handleInfoRefs(req, res, repo, service);
    return;
  }
  if (action === 'git-upload-pack' && req.method === 'POST') {
    const bodyBuf = await readBody(req, 128 * 1024 * 1024);
    const proto = (req.headers['git-protocol'] || '').toString();
    if (proto === 'version=2') await handleUploadPackV2(req, res, repo, bodyBuf);
    else await handleUploadPackV0(req, res, repo, bodyBuf);
    return;
  }
  if (action === 'git-receive-pack' && req.method === 'POST') {
    const bodyBuf = await readBody(req, 128 * 1024 * 1024);
    await handleReceivePack(req, res, repo, bodyBuf);
    return;
  }
  sendError(res, 404, 'Not Found');
}

// ------------------------------------------------------------------ GraphQL: parser

function gqlTokenize(src) {
  const tokens = [];
  let i = 0;
  const isNameStart = (c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c === '_';
  const isNameChar = (c) => isNameStart(c) || (c >= '0' && c <= '9');
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '.' && src[i + 1] === '.' && src[i + 2] === '.') {
      tokens.push({ kind: 'ELLIPSIS', value: '...' });
      i += 3;
      continue;
    }
    if ('{}():!=$@[]|&'.includes(c)) {
      tokens.push({ kind: 'PUNCT', value: c });
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const e = src[j + 1];
          if (e === 'n') out += '\n';
          else if (e === 't') out += '\t';
          else if (e === 'r') out += '\r';
          else if (e === 'b') out += '\b';
          else if (e === 'f') out += '\f';
          else if (e === 'u') {
            out += String.fromCharCode(Number.parseInt(src.slice(j + 2, j + 6), 16));
            j += 4;
          } else out += e;
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      tokens.push({ kind: 'STRING', value: out });
      i = j + 1;
      continue;
    }
    if (isNameStart(c)) {
      let j = i;
      while (j < src.length && isNameChar(src[j])) j += 1;
      tokens.push({ kind: 'NAME', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if ((c >= '0' && c <= '9') || (c === '-' && src[i + 1] >= '0' && src[i + 1] <= '9')) {
      let j = i;
      if (src[j] === '-') j += 1;
      while (j < src.length && src[j] >= '0' && src[j] <= '9') j += 1;
      let isFloat = false;
      if (src[j] === '.' && src[j + 1] >= '0' && src[j + 1] <= '9') {
        isFloat = true;
        j += 1;
        while (j < src.length && src[j] >= '0' && src[j] <= '9') j += 1;
      }
      if (src[j] === 'e' || src[j] === 'E') {
        isFloat = true;
        j += 1;
        if (src[j] === '+' || src[j] === '-') j += 1;
        while (j < src.length && src[j] >= '0' && src[j] <= '9') j += 1;
      }
      tokens.push({ kind: isFloat ? 'FLOAT' : 'INT', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`GraphQL syntax: unexpected character ${JSON.stringify(c)}`);
  }
  tokens.push({ kind: 'EOF', value: '' });
  return tokens;
}

class GqlParser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }

  peek() {
    return this.tokens[this.pos];
  }

  next() {
    return this.tokens[this.pos++];
  }

  expectPunct(value) {
    const t = this.next();
    if (t.kind !== 'PUNCT' || t.value !== value) throw new Error(`GraphQL syntax: expected '${value}', got '${t.value}'`);
  }

  expectName(value) {
    const t = this.next();
    if (t.kind !== 'NAME' || (value !== undefined && t.value !== value)) throw new Error(`GraphQL syntax: expected name '${value || ''}', got '${t.value}'`);
    return t.value;
  }

  skipPunct(value) {
    const t = this.peek();
    if (t.kind === 'PUNCT' && t.value === value) {
      this.pos += 1;
      return true;
    }
    return false;
  }

  parseDocument() {
    const definitions = [];
    while (this.peek().kind !== 'EOF') definitions.push(this.parseDefinition());
    return { kind: 'Document', definitions };
  }

  parseDefinition() {
    const t = this.peek();
    if (t.kind === 'PUNCT' && t.value === '{') {
      return { kind: 'OperationDefinition', operation: 'query', name: null, variableDefinitions: [], directives: [], selectionSet: this.parseSelectionSet() };
    }
    if (t.kind === 'NAME' && (t.value === 'query' || t.value === 'mutation' || t.value === 'subscription')) {
      const operation = this.next().value;
      let name = null;
      if (this.peek().kind === 'NAME') name = this.next().value;
      const variableDefinitions = this.parseVariableDefinitions();
      const directives = this.parseDirectives();
      return { kind: 'OperationDefinition', operation, name, variableDefinitions, directives, selectionSet: this.parseSelectionSet() };
    }
    if (t.kind === 'NAME' && t.value === 'fragment') {
      this.next();
      const name = this.expectName();
      this.expectName('on');
      const typeCondition = this.expectName();
      const directives = this.parseDirectives();
      return { kind: 'FragmentDefinition', name, typeCondition, directives, selectionSet: this.parseSelectionSet() };
    }
    throw new Error(`GraphQL syntax: unexpected definition starting with '${t.value}'`);
  }

  parseVariableDefinitions() {
    const defs = [];
    if (!this.skipPunct('(')) return defs;
    while (!this.skipPunct(')')) {
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      const type = this.parseTypeRef();
      let defaultValue;
      if (this.skipPunct('=')) defaultValue = this.parseValue(true);
      this.parseDirectives();
      defs.push({ name, type, defaultValue });
    }
    return defs;
  }

  parseTypeRef() {
    if (this.skipPunct('[')) {
      const inner = this.parseTypeRef();
      this.expectPunct(']');
      let type = { kind: 'List', ofType: inner };
      if (this.skipPunct('!')) type = { kind: 'NonNull', ofType: type };
      return type;
    }
    const name = this.expectName();
    let type = { kind: 'Named', name };
    if (this.skipPunct('!')) type = { kind: 'NonNull', ofType: type };
    return type;
  }

  parseDirectives() {
    const dirs = [];
    while (this.peek().kind === 'PUNCT' && this.peek().value === '@') {
      this.next();
      const name = this.expectName();
      const args = this.parseArguments();
      dirs.push({ name, args });
    }
    return dirs;
  }

  parseArguments() {
    const args = {};
    if (!this.skipPunct('(')) return args;
    while (!this.skipPunct(')')) {
      const name = this.expectName();
      this.expectPunct(':');
      args[name] = this.parseValue(false);
    }
    return args;
  }

  parseValue(isConst) {
    const t = this.next();
    if (t.kind === 'PUNCT' && t.value === '$' && !isConst) {
      return { kind: 'Variable', name: this.expectName() };
    }
    if (t.kind === 'INT') return { kind: 'IntValue', value: Number.parseInt(t.value, 10) };
    if (t.kind === 'FLOAT') return { kind: 'FloatValue', value: Number.parseFloat(t.value) };
    if (t.kind === 'STRING') return { kind: 'StringValue', value: t.value };
    if (t.kind === 'NAME') {
      if (t.value === 'true') return { kind: 'BooleanValue', value: true };
      if (t.value === 'false') return { kind: 'BooleanValue', value: false };
      if (t.value === 'null') return { kind: 'NullValue', value: null };
      return { kind: 'EnumValue', value: t.value };
    }
    if (t.kind === 'PUNCT' && t.value === '[') {
      const values = [];
      while (!this.skipPunct(']')) values.push(this.parseValue(isConst));
      return { kind: 'ListValue', values };
    }
    if (t.kind === 'PUNCT' && t.value === '{') {
      const fields = {};
      while (!this.skipPunct('}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields[name] = this.parseValue(isConst);
      }
      return { kind: 'ObjectValue', fields };
    }
    throw new Error(`GraphQL syntax: unexpected value token '${t.value}'`);
  }

  parseSelectionSet() {
    this.expectPunct('{');
    const selections = [];
    while (!this.skipPunct('}')) selections.push(this.parseSelection());
    return { kind: 'SelectionSet', selections };
  }

  parseSelection() {
    const t = this.peek();
    if (t.kind === 'ELLIPSIS') {
      this.next();
      if (this.peek().kind === 'NAME' && this.peek().value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        const directives = this.parseDirectives();
        return { kind: 'InlineFragment', typeCondition, directives, selectionSet: this.parseSelectionSet() };
      }
      if (this.peek().kind === 'NAME') {
        const name = this.next().value;
        const directives = this.parseDirectives();
        return { kind: 'FragmentSpread', name, directives };
      }
      const directives = this.parseDirectives();
      return { kind: 'InlineFragment', typeCondition: null, directives, selectionSet: this.parseSelectionSet() };
    }
    let alias = null;
    let name = this.expectName();
    if (this.peek().kind === 'PUNCT' && this.peek().value === ':') {
      this.next();
      alias = name;
      name = this.expectName();
    }
    const args = this.parseArguments();
    const directives = this.parseDirectives();
    let selectionSet = null;
    if (this.peek().kind === 'PUNCT' && this.peek().value === '{') selectionSet = this.parseSelectionSet();
    return { kind: 'Field', alias, name, args, directives, selectionSet };
  }
}

function parseGraphQL(query) {
  return new GqlParser(gqlTokenize(query)).parseDocument();
}

// Evaluate an argument value AST node with variables.
function evalGqlValue(node, variables) {
  switch (node.kind) {
    case 'Variable': {
      const v = variables[node.name];
      return v === undefined ? null : v;
    }
    case 'IntValue':
    case 'FloatValue':
    case 'StringValue':
    case 'BooleanValue':
      return node.value;
    case 'NullValue':
      return null;
    case 'EnumValue':
      return node.value;
    case 'ListValue':
      return node.values.map((v) => evalGqlValue(v, variables));
    case 'ObjectValue': {
      const out = {};
      for (const [k, v] of Object.entries(node.fields)) out[k] = evalGqlValue(v, variables);
      return out;
    }
    default:
      return null;
  }
}

// ------------------------------------------------------------------ GraphQL: schema model

const GQL_ENUMS = {
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'WIKI', 'TOPIC', 'APP'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['COMMENTS', 'CREATED_AT', 'UPDATED_AT'],
  OrderDirection: ['ASC', 'DESC'],
  PullRequestOrderField: ['CREATED_AT', 'UPDATED_AT'],
  TypeKind: ['SCALAR', 'OBJECT', 'INTERFACE', 'UNION', 'ENUM', 'INPUT_OBJECT', 'LIST', 'NON_NULL'],
  DirectiveLocation: ['QUERY', 'MUTATION', 'SUBSCRIPTION', 'FIELD', 'FRAGMENT_DEFINITION', 'FRAGMENT_SPREAD', 'INLINE_FRAGMENT', 'SCHEMA', 'SCALAR', 'OBJECT', 'FIELD_DEFINITION', 'ARGUMENT_DEFINITION', 'INTERFACE', 'UNION', 'ENUM', 'ENUM_VALUE', 'INPUT_OBJECT', 'INPUT_FIELD_DEFINITION'],
};

const GQL_INPUTS = {
  IssueOrder: { field: 'IssueOrderField', direction: 'OrderDirection' },
  PullRequestOrder: { field: 'PullRequestOrderField', direction: 'OrderDirection' },
  CreatePullRequestInput: { repositoryId: 'ID!', baseRefName: 'String!', headRefName: 'String!', title: 'String!', body: 'String', clientMutationId: 'String' },
  CreateIssueInput: { repositoryId: 'ID!', title: 'String!', body: 'String', clientMutationId: 'String' },
  CloseIssueInput: { issueId: 'ID!', clientMutationId: 'String' },
  ReopenIssueInput: { issueId: 'ID!', clientMutationId: 'String' },
};

function F(type, args, description) {
  return { type, args: args || {}, description: description || '' };
}

const GQL_TYPES = {
  Query: { kind: 'OBJECT', fields: {
    repository: F('Repository', { owner: 'String!', name: 'String!' }, 'A repository by owner and name.'),
    viewer: F('User!', {}, 'The authenticated user.'),
    node: F('Node', { id: 'ID!' }, 'A node by its global id.'),
    search: F('SearchResultItemConnection!', { query: 'String!', type: 'SearchType!', first: 'Int', after: 'String' }, 'Search across issues and more.'),
    user: F('User', { login: 'String!' }, 'A user by login.'),
    organization: F('Organization', { login: 'String!' }, 'An organization by login.'),
  } },
  Mutation: { kind: 'OBJECT', fields: {
    createPullRequest: F('CreatePullRequestPayload', { input: 'CreatePullRequestInput!' }),
    createIssue: F('CreateIssuePayload', { input: 'CreateIssueInput!' }),
    closeIssue: F('CloseIssuePayload', { input: 'CloseIssueInput!' }),
    reopenIssue: F('ReopenIssuePayload', { input: 'ReopenIssueInput!' }),
  } },
  Node: { kind: 'INTERFACE', fields: { id: F('ID!') } },
  Actor: { kind: 'INTERFACE', fields: { id: F('ID!'), login: F('String!'), url: F('URI!') } },
  Repository: { kind: 'OBJECT', fields: {
    id: F('ID!'), databaseId: F('Int'), name: F('String!'), nameWithOwner: F('String!'),
    description: F('String'), owner: F('RepositoryOwner!'), defaultBranchRef: F('Ref'),
    viewerPermission: F('RepositoryPermission'), hasIssuesEnabled: F('Boolean!'),
    isPrivate: F('Boolean!'), url: F('URI!'), createdAt: F('DateTime!'), updatedAt: F('DateTime!'),
    issue: F('Issue', { number: 'Int!' }), issues: F('IssueConnection!', { first: 'Int', after: 'String', orderBy: 'IssueOrder', states: '[IssueState!]' }),
    pullRequest: F('PullRequest', { number: 'Int!' }), pullRequests: F('PullRequestConnection!', { first: 'Int', after: 'String', orderBy: 'PullRequestOrder', states: '[PullRequestState!]' }),
  } },
  RepositoryOwner: { kind: 'INTERFACE', fields: { id: F('ID!'), login: F('String!'), url: F('URI!') } },
  User: { kind: 'OBJECT', fields: {
    id: F('ID!'), login: F('String!'), name: F('String'), email: F('String'), url: F('URI!'),
    avatarUrl: F('URI!'), createdAt: F('DateTime!'), updatedAt: F('DateTime!'),
  } },
  Organization: { kind: 'OBJECT', fields: {
    id: F('ID!'), login: F('String!'), name: F('String'), url: F('URI!'), avatarUrl: F('URI!'),
  } },
  Ref: { kind: 'OBJECT', fields: { id: F('ID!'), name: F('String!'), target: F('GitObject') } },
  GitObject: { kind: 'INTERFACE', fields: { id: F('ID!'), oid: F('GitObjectID!') } },
  Commit: { kind: 'OBJECT', fields: { id: F('ID!'), oid: F('GitObjectID!'), message: F('String!') } },
  Issue: { kind: 'OBJECT', fields: {
    id: F('ID!'), databaseId: F('Int'), number: F('Int!'), title: F('String!'), body: F('String'),
    state: F('IssueState!'), author: F('Actor'), labels: F('LabelConnection', { first: 'Int', after: 'String' }),
    createdAt: F('DateTime!'), updatedAt: F('DateTime!'), closedAt: F('DateTime'), url: F('URI!'),
    repository: F('Repository!'),
  } },
  PullRequest: { kind: 'OBJECT', fields: {
    id: F('ID!'), databaseId: F('Int'), number: F('Int!'), title: F('String!'), body: F('String'),
    state: F('PullRequestState!'), headRefName: F('String!'), baseRefName: F('String!'),
    headRefOid: F('GitObjectID!'), baseRefOid: F('GitObjectID!'), mergeable: F('MergeableState!'),
    merged: F('Boolean!'), mergedAt: F('DateTime'), mergeCommit: F('Commit'), author: F('Actor'),
    files: F('PullRequestChangedFileConnection', { first: 'Int', after: 'String' }),
    createdAt: F('DateTime!'), updatedAt: F('DateTime!'), closedAt: F('DateTime'), url: F('URI!'),
    repository: F('Repository!'),
  } },
  Label: { kind: 'OBJECT', fields: { id: F('ID!'), name: F('String!'), color: F('String!'), description: F('String') } },
  LabelConnection: { kind: 'OBJECT', fields: { nodes: F('[Label]'), edges: F('[LabelEdge]'), pageInfo: F('PageInfo!'), totalCount: F('Int!') } },
  LabelEdge: { kind: 'OBJECT', fields: { node: F('Label'), cursor: F('String!') } },
  IssueConnection: { kind: 'OBJECT', fields: { nodes: F('[Issue]'), edges: F('[IssueEdge]'), pageInfo: F('PageInfo!'), totalCount: F('Int!') } },
  IssueEdge: { kind: 'OBJECT', fields: { node: F('Issue'), cursor: F('String!') } },
  PullRequestConnection: { kind: 'OBJECT', fields: { nodes: F('[PullRequest]'), edges: F('[PullRequestEdge]'), pageInfo: F('PageInfo!'), totalCount: F('Int!') } },
  PullRequestEdge: { kind: 'OBJECT', fields: { node: F('PullRequest'), cursor: F('String!') } },
  PageInfo: { kind: 'OBJECT', fields: { hasNextPage: F('Boolean!'), hasPreviousPage: F('Boolean!'), startCursor: F('String'), endCursor: F('String') } },
  PullRequestChangedFileConnection: { kind: 'OBJECT', fields: { nodes: F('[PullRequestChangedFile]'), edges: F('[PullRequestChangedFileEdge]'), pageInfo: F('PageInfo!'), totalCount: F('Int!') } },
  PullRequestChangedFileEdge: { kind: 'OBJECT', fields: { node: F('PullRequestChangedFile'), cursor: F('String!') } },
  PullRequestChangedFile: { kind: 'OBJECT', fields: { path: F('String!'), additions: F('Int!'), deletions: F('Int!'), changeType: F('String!') } },
  SearchResultItemConnection: { kind: 'OBJECT', fields: { nodes: F('[SearchResultItem]'), edges: F('[SearchResultItemEdge]'), pageInfo: F('PageInfo!'), totalCount: F('Int!'), issueCount: F('Int!') } },
  SearchResultItemEdge: { kind: 'OBJECT', fields: { node: F('SearchResultItem'), cursor: F('String!') } },
  SearchResultItem: { kind: 'UNION', fields: {} },
  CreatePullRequestPayload: { kind: 'OBJECT', fields: { pullRequest: F('PullRequest'), clientMutationId: F('String') } },
  CreateIssuePayload: { kind: 'OBJECT', fields: { issue: F('Issue'), clientMutationId: F('String') } },
  CloseIssuePayload: { kind: 'OBJECT', fields: { issue: F('Issue'), clientMutationId: F('String') } },
  ReopenIssuePayload: { kind: 'OBJECT', fields: { issue: F('Issue'), clientMutationId: F('String') } },
  __Schema: { kind: 'OBJECT', fields: {
    description: F('String'), types: F('[__Type!]!'), queryType: F('__Type!'), mutationType: F('__Type'),
    subscriptionType: F('__Type'), directives: F('[__Directive!]!'),
  } },
  __Type: { kind: 'OBJECT', fields: {
    kind: F('__TypeKind!'), name: F('String'), description: F('String'),
    fields: F('[__Field!]', { includeDeprecated: 'Boolean' }), interfaces: F('[__Type!]'),
    possibleTypes: F('[__Type!]'), enumValues: F('[__EnumValue!]', { includeDeprecated: 'Boolean' }),
    inputFields: F('[__InputValue!]'), ofType: F('__Type'), specifiedByURL: F('String'),
  } },
  __Field: { kind: 'OBJECT', fields: {
    name: F('String!'), description: F('String'), args: F('[__InputValue!]!'), type: F('__Type!'),
    isDeprecated: F('Boolean!'), deprecationReason: F('String'),
  } },
  __InputValue: { kind: 'OBJECT', fields: {
    name: F('String!'), description: F('String'), type: F('__Type!'), defaultValue: F('String'),
  } },
  __EnumValue: { kind: 'OBJECT', fields: {
    name: F('String!'), description: F('String'), isDeprecated: F('Boolean!'), deprecationReason: F('String'),
  } },
  __Directive: { kind: 'OBJECT', fields: {
    name: F('String!'), description: F('String'), locations: F('[__DirectiveLocation!]!'), args: F('[__InputValue!]!'),
    isRepeatable: F('Boolean!'),
  } },
};

const GQL_SCALARS = ['String', 'Int', 'Float', 'Boolean', 'ID', 'URI', 'DateTime', 'GitObjectID'];

function gqlTypeKind(name) {
  if (GQL_TYPES[name]) return GQL_TYPES[name].kind;
  if (GQL_ENUMS[name]) return 'ENUM';
  if (GQL_INPUTS[name]) return 'INPUT_OBJECT';
  if (GQL_SCALARS.includes(name)) return 'SCALAR';
  return null;
}

function gqlNamedType(typeStr) {
  return typeStr.replace(/[\[\]!]/g, '');
}

function gqlTypeRefView(typeStr) {
  // Parse 'String!', '[Issue!]!', 'Int' into nested __Type views.
  let s = typeStr;
  let nonNull = false;
  if (s.endsWith('!')) {
    nonNull = true;
    s = s.slice(0, -1);
  }
  let view;
  if (s.startsWith('[') && s.endsWith(']')) {
    view = { __typename: '__Type', name: null, kind: 'LIST', description: null, ofType: gqlTypeRefView(s.slice(1, -1)), _named: null };
  } else {
    view = { __typename: '__Type', name: s, kind: gqlTypeKind(s) || 'SCALAR', description: null, ofType: null, _named: s };
  }
  if (nonNull) {
    return { __typename: '__Type', name: null, kind: 'NON_NULL', description: null, ofType: view, _named: null };
  }
  return view;
}

function gqlTypeView(name) {
  const kind = gqlTypeKind(name);
  if (!kind) return null;
  return { __typename: '__Type', name, kind, description: null, ofType: null, _named: name };
}

function gqlFieldView(typeName, fieldName, def) {
  return {
    __typename: '__Field',
    name: fieldName,
    description: def.description || null,
    args: Object.entries(def.args || {}).map(([argName, argType]) => ({
      __typename: '__InputValue',
      name: argName,
      description: null,
      type: gqlTypeRefView(argType),
      defaultValue: null,
    })),
    type: gqlTypeRefView(def.type),
    isDeprecated: false,
    deprecationReason: null,
  };
}

// ------------------------------------------------------------------ GraphQL: views

function gqlUserView(login) {
  const id = login === VIEWER_LOGIN ? VIEWER_ID : nextGlobalIdForLogin(login);
  return {
    __typename: 'User',
    id: nodeId('User', id),
    login,
    name: login === VIEWER_LOGIN ? VIEWER_NAME : null,
    email: login === VIEWER_LOGIN ? VIEWER_EMAIL : null,
    url: `${publicBase()}/${encodeURIComponent(login)}`,
    avatarUrl: `${publicBase()}/avatars/${encodeURIComponent(login)}`,
    createdAt: new Date(BASE_EPOCH * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    updatedAt: new Date(BASE_EPOCH * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
}

function gqlRepoView(repo) {
  return {
    __typename: 'Repository',
    _repo: repo,
    id: nodeId('Repository', repo.id),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: repo.fullName,
    description: repo.description || null,
    isPrivate: repo.private,
    url: `${publicBase()}/${repo.fullName}`,
    createdAt: repo.createdAt,
    updatedAt: repo.updatedAt,
    hasIssuesEnabled: true,
    viewerPermission: 'ADMIN',
  };
}

function gqlIssueView(repo, issue) {
  return {
    __typename: 'Issue',
    _repo: repo,
    _issue: issue,
    id: nodeId('Issue', issue.id),
    databaseId: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    createdAt: issue.createdAt,
    updatedAt: issue.updatedAt,
    closedAt: issue.closedAt,
    url: `${publicBase()}/${repo.fullName}/issues/${issue.number}`,
  };
}

function gqlPullView(repo, pull) {
  const headSha = repo.refs.get(`refs/heads/${pull.headRef}`) || pull.headSha || ZERO_OID;
  const baseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) || pull.baseSha || ZERO_OID;
  let mergeable = 'UNKNOWN';
  if (pull.state === 'open' && headSha !== ZERO_OID && baseSha !== ZERO_OID) {
    mergeable = isMergeable(repo, baseSha, headSha) ? 'MERGEABLE' : 'CONFLICTING';
  }
  return {
    __typename: 'PullRequest',
    _repo: repo,
    _pull: pull,
    id: nodeId('PullRequest', pull.id),
    databaseId: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : (pull.state === 'open' ? 'OPEN' : 'CLOSED'),
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    headRefOid: headSha,
    baseRefOid: baseSha,
    mergeable,
    merged: pull.merged,
    mergedAt: pull.mergedAt,
    createdAt: pull.createdAt,
    updatedAt: pull.updatedAt,
    closedAt: pull.closedAt,
    url: `${publicBase()}/${repo.fullName}/pull/${pull.number}`,
  };
}

function gqlLabelView(repo, label) {
  return { __typename: 'Label', id: nodeId('Label', label.id), name: label.name, color: label.color, description: label.description || null };
}

function gqlCursor(index) {
  return b64encode(`cursor:${index}`);
}

function gqlConnection(typeName, edgeTypeName, orderedItems, args) {
  const total = orderedItems.length;
  let start = 0;
  if (typeof args.after === 'string' && args.after) {
    const decoded = b64decode(args.after);
    const m = /^cursor:(\d+)$/.exec(decoded);
    if (m) start = Number(m[1]) + 1;
  }
  const first = typeof args.first === 'number' ? args.first : total;
  const page = orderedItems.slice(start, start + Math.max(0, first));
  const edges = page.map((node, i) => ({ __typename: edgeTypeName, node, cursor: gqlCursor(start + i) }));
  return {
    __typename: typeName,
    nodes: page,
    edges,
    totalCount: total,
    pageInfo: {
      __typename: 'PageInfo',
      hasNextPage: start + page.length < total,
      hasPreviousPage: start > 0,
      startCursor: edges.length > 0 ? edges[0].cursor : null,
      endCursor: edges.length > 0 ? edges[edges.length - 1].cursor : null,
    },
  };
}

function gqlOrderIssues(items, orderBy, states) {
  let list = items.slice();
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toUpperCase()));
    list = list.filter((it) => wanted.has(it.state === 'open' ? 'OPEN' : 'CLOSED'));
  }
  const field = (orderBy && orderBy.field) || 'CREATED_AT';
  const dir = (orderBy && orderBy.direction) || 'DESC';
  const mul = dir === 'ASC' ? 1 : -1;
  list.sort((a, b) => {
    let cmp = 0;
    if (field === 'CREATED_AT') cmp = a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0;
    else if (field === 'UPDATED_AT') cmp = a.updatedAt < b.updatedAt ? -1 : a.updatedAt > b.updatedAt ? 1 : 0;
    if (cmp !== 0) return cmp * mul;
    return (a.number - b.number) * mul;
  });
  return list;
}

function parseNodeId(id) {
  if (typeof id !== 'string') return null;
  let m = /^(Repository|Issue|PullRequest|User|Label|IssueComment):(\d+)$/.exec(b64decode(id));
  if (m) return { kind: m[1], num: Number(m[2]) };
  m = /^(Repository|Issue|PullRequest|User):(\d+)$/.exec(id);
  if (m) return { kind: m[1], num: Number(m[2]) };
  if (/^\d+$/.test(id)) return { kind: null, num: Number(id) };
  return null;
}

function findRepoByNumericId(num) {
  for (const repo of repos.values()) if (repo.id === num) return repo;
  return null;
}

function findIssueOrPullByGlobalId(num) {
  for (const repo of repos.values()) {
    for (const issue of repo.issues.values()) if (issue.id === num) return { repo, issue };
    for (const pull of repo.pulls.values()) if (pull.id === num) return { repo, pull };
  }
  return null;
}

// ------------------------------------------------------------------ GraphQL: resolvers

const GQL_RESOLVERS = {
  Query: {
    repository: (parent, args) => {
      const repo = getRepo(args.owner, args.name);
      return repo ? gqlRepoView(repo) : null;
    },
    viewer: () => gqlUserView(VIEWER_LOGIN),
    user: (parent, args) => gqlUserView(args.login),
    organization: (parent, args) => {
      const id = nextGlobalIdForLogin(`org:${args.login}`);
      return { __typename: 'Organization', id: nodeId('Organization', id), login: args.login, name: null, url: `${publicBase()}/${encodeURIComponent(args.login)}`, avatarUrl: `${publicBase()}/avatars/${encodeURIComponent(args.login)}` };
    },
    node: (parent, args) => {
      const parsed = parseNodeId(args.id);
      if (!parsed) return null;
      if (parsed.kind === 'Repository') {
        const repo = findRepoByNumericId(parsed.num);
        return repo ? gqlRepoView(repo) : null;
      }
      if (parsed.kind === 'User') return gqlUserView(VIEWER_LOGIN);
      if (parsed.kind === 'Issue' || parsed.kind === 'PullRequest') {
        const found = findIssueOrPullByGlobalId(parsed.num);
        if (!found) return null;
        if (parsed.kind === 'Issue' && found.issue) return gqlIssueView(found.repo, found.issue);
        if (parsed.kind === 'PullRequest' && found.pull) return gqlPullView(found.repo, found.pull);
        return null;
      }
      if (parsed.kind === null) {
        // Plain numeric id: ids share one counter space, so try the repo
        // first, then issues/pulls; at most one can match.
        const repo = findRepoByNumericId(parsed.num);
        if (repo) return gqlRepoView(repo);
        const found = findIssueOrPullByGlobalId(parsed.num);
        if (!found) return null;
        if (found.issue) return gqlIssueView(found.repo, found.issue);
        if (found.pull) return gqlPullView(found.repo, found.pull);
        return null;
      }
      return null;
    },
    search: (parent, args) => {
      const q = String(args.query || '').toLowerCase();
      const items = [];
      if (args.type === 'ISSUE') {
        for (const repo of repos.values()) {
          for (const issue of repo.issues.values()) {
            if ((issue.title || '').toLowerCase().includes(q) || (issue.body || '').toLowerCase().includes(q)) {
              items.push(gqlIssueView(repo, issue));
            }
          }
        }
      }
      const conn = gqlConnection('SearchResultItemConnection', 'SearchResultItemEdge', items, args);
      conn.issueCount = items.length;
      return conn;
    },
  },
  Mutation: {
    createPullRequest: (parent, args) => {
      const input = args.input || {};
      const parsed = parseNodeId(input.repositoryId);
      const repo = parsed ? findRepoByNumericId(parsed.num) : null;
      if (!repo) throw new Error('Repository not found');
      const headRef = input.headRefName;
      const baseRef = input.baseRefName || repo.defaultBranch;
      const headOid = repo.refs.get(`refs/heads/${headRef}`);
      const baseOid = repo.refs.get(`refs/heads/${baseRef}`);
      if (!headOid || !baseOid) throw new Error('Head or base branch does not exist');
      const { iso } = stamp();
      repo.numberCounter += 1;
      const pull = {
        id: nextGlobalId(),
        number: repo.numberCounter,
        title: input.title || '',
        body: typeof input.body === 'string' ? input.body : null,
        state: 'open',
        headRef,
        baseRef,
        headSha: headOid,
        baseSha: baseOid,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        labels: [],
        user: VIEWER_LOGIN,
        createdAt: iso,
        updatedAt: iso,
        closedAt: null,
      };
      repo.pulls.set(pull.number, pull);
      if (!repo.comments.has(pull.number)) repo.comments.set(pull.number, []);
      return { __typename: 'CreatePullRequestPayload', pullRequest: gqlPullView(repo, pull), clientMutationId: input.clientMutationId || null };
    },
    createIssue: (parent, args) => {
      const input = args.input || {};
      const parsed = parseNodeId(input.repositoryId);
      const repo = parsed ? findRepoByNumericId(parsed.num) : null;
      if (!repo) throw new Error('Repository not found');
      const { iso } = stamp();
      repo.numberCounter += 1;
      const issue = {
        id: nextGlobalId(),
        number: repo.numberCounter,
        title: input.title || '',
        body: typeof input.body === 'string' ? input.body : null,
        state: 'open',
        labels: [],
        user: VIEWER_LOGIN,
        createdAt: iso,
        updatedAt: iso,
        closedAt: null,
        commentsCount: 0,
      };
      repo.issues.set(issue.number, issue);
      repo.comments.set(issue.number, []);
      return { __typename: 'CreateIssuePayload', issue: gqlIssueView(repo, issue), clientMutationId: input.clientMutationId || null };
    },
    closeIssue: (parent, args) => {
      const input = args.input || {};
      const parsed = parseNodeId(input.issueId);
      const found = parsed ? findIssueOrPullByGlobalId(parsed.num) : null;
      if (!found || !found.issue) throw new Error('Issue not found');
      const { iso } = stamp();
      found.issue.state = 'closed';
      found.issue.closedAt = iso;
      found.issue.updatedAt = iso;
      return { __typename: 'CloseIssuePayload', issue: gqlIssueView(found.repo, found.issue), clientMutationId: input.clientMutationId || null };
    },
    reopenIssue: (parent, args) => {
      const input = args.input || {};
      const parsed = parseNodeId(input.issueId);
      const found = parsed ? findIssueOrPullByGlobalId(parsed.num) : null;
      if (!found || !found.issue) throw new Error('Issue not found');
      const { iso } = stamp();
      found.issue.state = 'open';
      found.issue.closedAt = null;
      found.issue.updatedAt = iso;
      return { __typename: 'ReopenIssuePayload', issue: gqlIssueView(found.repo, found.issue), clientMutationId: input.clientMutationId || null };
    },
  },
  Repository: {
    owner: (parent) => gqlUserView(parent._repo.owner),
    defaultBranchRef: (parent) => {
      const repo = parent._repo;
      const oid = repo.refs.get(repo.headRef());
      if (!oid) return null;
      return { __typename: 'Ref', id: nodeId('Ref', `${repo.id}:${repo.headRef()}`), name: repo.defaultBranch, target: { __typename: 'Commit', id: nodeId('Commit', oid), oid, message: '' } };
    },
    issue: (parent, args) => {
      const issue = parent._repo.issues.get(args.number);
      return issue ? gqlIssueView(parent._repo, issue) : null;
    },
    issues: (parent, args) => {
      const ordered = gqlOrderIssues([...parent._repo.issues.values()], args.orderBy, args.states);
      return gqlConnection('IssueConnection', 'IssueEdge', ordered.map((i) => gqlIssueView(parent._repo, i)), args);
    },
    pullRequest: (parent, args) => {
      const pull = parent._repo.pulls.get(args.number);
      return pull ? gqlPullView(parent._repo, pull) : null;
    },
    pullRequests: (parent, args) => {
      const ordered = gqlOrderIssues([...parent._repo.pulls.values()], args.orderBy, args.states);
      return gqlConnection('PullRequestConnection', 'PullRequestEdge', ordered.map((p) => gqlPullView(parent._repo, p)), args);
    },
  },
  Issue: {
    author: (parent) => gqlUserView(parent._issue.user),
    labels: (parent, args) => {
      const repo = parent._repo;
      const items = (parent._issue.labels || []).map((n) => repo.labels.get(n)).filter(Boolean).map((l) => gqlLabelView(repo, l));
      return gqlConnection('LabelConnection', 'LabelEdge', items, args);
    },
    repository: (parent) => gqlRepoView(parent._repo),
  },
  PullRequest: {
    author: (parent) => gqlUserView(parent._pull.user),
    mergeCommit: (parent) => {
      const pull = parent._pull;
      if (!pull.mergeCommitSha) return null;
      const obj = parent._repo.objects.get(pull.mergeCommitSha);
      const message = obj ? parseCommit(obj.data).message : '';
      return { __typename: 'Commit', id: nodeId('Commit', pull.mergeCommitSha), oid: pull.mergeCommitSha, message };
    },
    files: (parent, args) => {
      const files = pullFiles(parent._repo, parent._pull).map((f) => ({
        __typename: 'PullRequestChangedFile',
        path: f.filename,
        additions: f.additions,
        deletions: f.deletions,
        changeType: f.status.toUpperCase(),
      }));
      return gqlConnection('PullRequestChangedFileConnection', 'PullRequestChangedFileEdge', files, args);
    },
    repository: (parent) => gqlRepoView(parent._repo),
  },
  __Type: {
    fields: (parent) => {
      const name = parent._named;
      const def = GQL_TYPES[name];
      if (!def) return null;
      return Object.entries(def.fields).map(([fn, fd]) => gqlFieldView(name, fn, fd));
    },
    enumValues: (parent) => {
      const name = parent._named;
      const values = GQL_ENUMS[name];
      if (!values) return null;
      return values.map((v) => ({ __typename: '__EnumValue', name: v, description: null, isDeprecated: false, deprecationReason: null }));
    },
    inputFields: (parent) => {
      const name = parent._named;
      const input = GQL_INPUTS[name];
      if (!input) return null;
      return Object.entries(input).map(([fn, ft]) => ({ __typename: '__InputValue', name: fn, description: null, type: gqlTypeRefView(ft), defaultValue: null }));
    },
    interfaces: (parent) => {
      if (parent._named === 'User') return [gqlTypeView('Node'), gqlTypeView('Actor'), gqlTypeView('RepositoryOwner')];
      if (parent._named === 'Organization') return [gqlTypeView('RepositoryOwner')];
      if (parent._named === 'Commit') return [gqlTypeView('GitObject'), gqlTypeView('Node')];
      if (parent._named === 'Issue' || parent._named === 'PullRequest' || parent._named === 'Repository' || parent._named === 'Label') return [gqlTypeView('Node')];
      return [];
    },
    possibleTypes: (parent) => {
      if (parent._named === 'Node') return ['Repository', 'Issue', 'PullRequest', 'User', 'Label', 'Commit'].map(gqlTypeView);
      if (parent._named === 'Actor') return [gqlTypeView('User')];
      if (parent._named === 'RepositoryOwner') return [gqlTypeView('User'), gqlTypeView('Organization')];
      if (parent._named === 'SearchResultItem') return [gqlTypeView('Issue'), gqlTypeView('PullRequest'), gqlTypeView('Repository'), gqlTypeView('User')];
      if (parent._named === 'GitObject') return [gqlTypeView('Commit')];
      return null;
    },
    ofType: (parent) => parent.ofType || null,
  },
  __Schema: {
    types: () => {
      const names = [...Object.keys(GQL_TYPES), ...Object.keys(GQL_ENUMS), ...Object.keys(GQL_INPUTS), ...GQL_SCALARS];
      return names.map(gqlTypeView).filter(Boolean);
    },
    queryType: () => gqlTypeView('Query'),
    mutationType: () => gqlTypeView('Mutation'),
    subscriptionType: () => null,
    directives: () => [],
  },
};

// ------------------------------------------------------------------ GraphQL: execution

function gqlDirectivesAllow(directives, variables) {
  for (const d of directives || []) {
    if (d.name === 'skip' || d.name === 'include') {
      const ifArg = d.args && d.args.if;
      const value = ifArg ? evalGqlValue(ifArg, variables) : false;
      if (d.name === 'skip' && value === true) return false;
      if (d.name === 'include' && value !== true) return false;
    }
  }
  return true;
}

function gqlFragmentApplies(typeCondition, parentType) {
  if (!typeCondition) return true;
  if (typeCondition === parentType) return true;
  if (typeCondition === 'Node') return ['Repository', 'Issue', 'PullRequest', 'User', 'Label', 'Commit'].includes(parentType);
  if (typeCondition === 'Actor') return parentType === 'User';
  if (typeCondition === 'RepositoryOwner') return parentType === 'User' || parentType === 'Organization';
  if (typeCondition === 'GitObject') return parentType === 'Commit';
  if (typeCondition === 'SearchResultItem') return ['Issue', 'PullRequest', 'Repository', 'User'].includes(parentType);
  return false;
}

function gqlCollectFields(selectionSet, parentType, variables, fragments, out) {
  out = out || [];
  for (const sel of selectionSet.selections) {
    if (sel.kind === 'Field') {
      if (gqlDirectivesAllow(sel.directives, variables)) out.push(sel);
    } else if (sel.kind === 'FragmentSpread') {
      if (!gqlDirectivesAllow(sel.directives, variables)) continue;
      const frag = fragments[sel.name];
      if (frag && gqlFragmentApplies(frag.typeCondition, parentType)) {
        gqlCollectFields(frag.selectionSet, parentType, variables, fragments, out);
      }
    } else if (sel.kind === 'InlineFragment') {
      if (!gqlDirectivesAllow(sel.directives, variables)) continue;
      if (gqlFragmentApplies(sel.typeCondition, parentType)) {
        gqlCollectFields(sel.selectionSet, parentType, variables, fragments, out);
      }
    }
  }
  return out;
}

function gqlValidate(document, fragments) {
  const errors = [];
  const checkSelections = (selectionSet, parentType) => {
    const def = GQL_TYPES[parentType];
    for (const sel of selectionSet.selections) {
      if (sel.kind === 'Field') {
        const name = sel.name;
        if (name === '__typename') continue;
        if (name === '__schema') {
          if (sel.selectionSet) checkSelections(sel.selectionSet, '__Schema');
          continue;
        }
        if (name === '__type') {
          if (sel.selectionSet) checkSelections(sel.selectionSet, '__Type');
          continue;
        }
        if (!def || !def.fields[name]) {
          errors.push(`Cannot query field "${name}" on type "${parentType}".`);
          continue;
        }
        if (sel.selectionSet) {
          const named = gqlNamedType(def.fields[name].type);
          checkSelections(sel.selectionSet, named);
        }
      } else if (sel.kind === 'FragmentSpread') {
        const frag = fragments[sel.name];
        if (frag) checkSelections(frag.selectionSet, frag.typeCondition || parentType);
      } else if (sel.kind === 'InlineFragment') {
        checkSelections(sel.selectionSet, sel.typeCondition || parentType);
      }
    }
  };
  for (const defn of document.definitions) {
    if (defn.kind === 'OperationDefinition') {
      const root = defn.operation === 'mutation' ? 'Mutation' : 'Query';
      checkSelections(defn.selectionSet, root);
    }
  }
  return errors;
}

function gqlExecuteSelectionSet(selectionSet, parent, parentType, variables, fragments, errors, path) {
  const fields = gqlCollectFields(selectionSet, parentType, variables, fragments);
  const result = {};
  for (const field of fields) {
    const responseKey = field.alias || field.name;
    const fieldPath = [...path, responseKey];
    try {
      let value;
      if (field.name === '__typename') {
        value = parentType;
      } else if (field.name === '__schema') {
        value = { __typename: '__Schema' };
      } else if (field.name === '__type') {
        const args = {};
        for (const [k, v] of Object.entries(field.args)) args[k] = evalGqlValue(v, variables);
        value = gqlTypeView(args.name);
      } else {
        const args = {};
        for (const [k, v] of Object.entries(field.args)) args[k] = evalGqlValue(v, variables);
        const resolver = GQL_RESOLVERS[parentType] && GQL_RESOLVERS[parentType][field.name];
        if (resolver) value = resolver(parent, args);
        else value = parent[field.name];
        if (value === undefined) value = null;
      }
      if (value === null || value === undefined) {
        result[responseKey] = null;
        continue;
      }
      if (field.selectionSet) {
        const fieldDef = GQL_TYPES[parentType] && GQL_TYPES[parentType].fields[field.name];
        const named = field.name === '__schema' ? '__Schema' : field.name === '__type' ? '__Type' : (fieldDef ? gqlNamedType(fieldDef.type) : parentType);
        if (Array.isArray(value)) {
          result[responseKey] = value.map((item) => {
            if (item === null) return null;
            const itemType = item.__typename || named;
            return gqlExecuteSelectionSet(field.selectionSet, item, itemType, variables, fragments, errors, fieldPath);
          });
        } else if (typeof value === 'object') {
          const itemType = value.__typename || named;
          result[responseKey] = gqlExecuteSelectionSet(field.selectionSet, value, itemType, variables, fragments, errors, fieldPath);
        } else {
          result[responseKey] = value;
        }
      } else {
        result[responseKey] = value;
      }
    } catch (e) {
      errors.push({ message: e.message || 'Internal error', path: fieldPath });
      result[responseKey] = null;
    }
  }
  return result;
}

function gqlExecuteOne(payload) {
  const query = payload.query;
  if (typeof query !== 'string') {
    return { errors: [{ message: 'Must provide query string.' }] };
  }
  let document;
  try {
    document = parseGraphQL(query);
  } catch (e) {
    return { errors: [{ message: e.message }] };
  }
  const fragments = {};
  for (const defn of document.definitions) {
    if (defn.kind === 'FragmentDefinition') fragments[defn.name] = defn;
  }
  const operations = document.definitions.filter((d) => d.kind === 'OperationDefinition');
  let operation = null;
  if (payload.operationName) {
    operation = operations.find((o) => o.name === payload.operationName) || null;
    if (!operation) return { errors: [{ message: `Unknown operation named "${payload.operationName}".` }] };
  } else if (operations.length === 1) {
    operation = operations[0];
  } else if (operations.length === 0) {
    return { errors: [{ message: 'Must provide an operation.' }] };
  } else {
    return { errors: [{ message: 'Must provide operation name if query contains multiple operations.' }] };
  }
  const variables = { ...(payload.variables || {}) };
  for (const vd of operation.variableDefinitions || []) {
    if (variables[vd.name] === undefined && vd.defaultValue !== undefined) {
      variables[vd.name] = evalGqlValue(vd.defaultValue, variables);
    }
  }
  const validationErrors = gqlValidate({ definitions: [operation, ...Object.values(fragments)] }, fragments);
  if (validationErrors.length > 0) {
    return { data: null, errors: validationErrors.map((message) => ({ message })) };
  }
  const errors = [];
  const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
  const root = { __typename: rootType };
  const data = gqlExecuteSelectionSet(operation.selectionSet, root, rootType, variables, fragments, errors, []);
  if (errors.length > 0) return { data, errors };
  return { data };
}

async function handleGraphQL(req, res) {
  if (req.method !== 'POST') {
    sendError(res, 404, 'Not Found');
    return;
  }
  const raw = await readBody(req, 16 * 1024 * 1024);
  const parsed = parseJsonBody(raw);
  if (!parsed.ok) {
    sendError(res, 400, 'Malformed JSON in request body');
    return;
  }
  const payload = parsed.value;
  if (Array.isArray(payload)) {
    const results = payload.map((p) => gqlExecuteOne(p && typeof p === 'object' ? p : {}));
    sendJson(res, 200, results);
    return;
  }
  if (!payload || typeof payload !== 'object') {
    sendError(res, 400, 'Request body must be a JSON object');
    return;
  }
  sendJson(res, 200, gqlExecuteOne(payload));
}

// ------------------------------------------------------------------ MCP

const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_LATEST_VERSION = '2026-07-28';

function mcpTool(name, description, properties, required) {
  return {
    name,
    description,
    inputSchema: { type: 'object', properties, required: required || [], additionalProperties: true },
  };
}

// Built once: two tools/list calls answer the same list, byte for byte.
const MCP_TOOLS = Object.freeze([
  mcpTool('create_repo', 'Create a new repository owned by the authenticated user.', {
    name: { type: 'string', description: 'The repository name.' },
    description: { type: 'string', description: 'A short description of the repository.' },
    private: { type: 'boolean', description: 'Whether the repository is private.' },
  }, ['name']),
  mcpTool('get_repo', 'Get a repository by owner and name.', {
    owner: { type: 'string', description: 'The repository owner login.' },
    repo: { type: 'string', description: 'The repository name.' },
    full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
  }, ['owner', 'repo']),
  mcpTool('create_issue', 'Create an issue in a repository.', {
    owner: { type: 'string', description: 'The repository owner login.' },
    repo: { type: 'string', description: 'The repository name.' },
    full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
    title: { type: 'string', description: 'The issue title.' },
    body: { type: 'string', description: 'The issue body.' },
    labels: { type: 'array', items: { type: 'string' }, description: 'Labels the issue carries; each must already exist.' },
  }, ['owner', 'repo', 'title']),
  mcpTool('list_issues', 'List issues in a repository.', {
    owner: { type: 'string', description: 'The repository owner login.' },
    repo: { type: 'string', description: 'The repository name.' },
    full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
    state: { type: 'string', description: 'Filter by state: open, closed, or all.', enum: ['open', 'closed', 'all'] },
  }, ['owner', 'repo']),
  mcpTool('create_pull_request', 'Create a pull request in a repository.', {
    owner: { type: 'string', description: 'The repository owner login.' },
    repo: { type: 'string', description: 'The repository name.' },
    full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
    title: { type: 'string', description: 'The pull request title.' },
    body: { type: 'string', description: 'The pull request body.' },
    head: { type: 'string', description: 'The head branch name.' },
    base: { type: 'string', description: 'The base branch name.' },
  }, ['owner', 'repo', 'title', 'head', 'base']),
  mcpTool('merge_pull_request', 'Merge a pull request with a squash commit.', {
    owner: { type: 'string', description: 'The repository owner login.' },
    repo: { type: 'string', description: 'The repository name.' },
    full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
    pull_number: { type: 'integer', description: 'The pull request number.' },
  }, ['owner', 'repo', 'pull_number']),
  mcpTool('get_issue', 'Get a single issue by number.', {
    owner: { type: 'string', description: 'The repository owner login.' },
    repo: { type: 'string', description: 'The repository name.' },
    full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
    issue_number: { type: 'integer', description: 'The issue number.' },
  }, ['owner', 'repo', 'issue_number']),
  mcpTool('list_pull_requests', 'List pull requests in a repository.', {
    owner: { type: 'string', description: 'The repository owner login.' },
    repo: { type: 'string', description: 'The repository name.' },
    full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
    state: { type: 'string', description: 'Filter by state: open, closed, or all.', enum: ['open', 'closed', 'all'] },
  }, ['owner', 'repo']),
  mcpTool('get_pull_request', 'Get a single pull request by number.', {
    owner: { type: 'string', description: 'The repository owner login.' },
    repo: { type: 'string', description: 'The repository name.' },
    full_name: { type: 'string', description: 'The repository full name, owner/repo.' },
    pull_number: { type: 'integer', description: 'The pull request number.' },
  }, ['owner', 'repo', 'pull_number']),
]);

function normalizeToolName(name) {
  const lower = String(name || '').toLowerCase();
  const stripped = lower.includes('__') ? lower.slice(lower.lastIndexOf('__') + 2) : lower;
  return stripped.replace(/-/g, '_');
}

function pickArg(args, names) {
  if (!args || typeof args !== 'object') return undefined;
  const norm = new Map();
  for (const [k, v] of Object.entries(args)) {
    norm.set(String(k).toLowerCase().replace(/[_-]/g, ''), v);
  }
  for (const name of names) {
    const key = name.toLowerCase().replace(/[_-]/g, '');
    if (norm.has(key)) return norm.get(key);
  }
  return undefined;
}

function resolveMcpRepo(args) {
  let owner = pickArg(args, ['owner']);
  let repoName = pickArg(args, ['repo', 'repository', 'name']);
  const fullName = pickArg(args, ['full_name', 'fullname', 'fullName']);
  if ((!owner || !repoName) && typeof fullName === 'string' && fullName.includes('/')) {
    const [o, r] = fullName.split('/');
    owner = owner || o;
    repoName = repoName || r;
  }
  if (!owner || !repoName) return { repo: null, error: 'missing owner/repo' };
  const repo = getRepo(String(owner), String(repoName));
  if (!repo) return { repo: null, error: 'repository not found' };
  return { repo, error: null };
}

function mcpTextResult(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj };
}

function mcpErrorResult(message) {
  return { content: [{ type: 'text', text: JSON.stringify({ error: message }) }], isError: true };
}

function mcpCallTool(name, args) {
  const tool = normalizeToolName(name);
  switch (tool) {
    case 'create_repo': {
      const repoName = pickArg(args, ['name']);
      if (typeof repoName !== 'string' || !repoName.trim()) return mcpErrorResult('missing required argument: name');
      if (getRepo(VIEWER_LOGIN, repoName.trim())) return mcpErrorResult('repository already exists');
      const repo = createRepoRecord({
        owner: VIEWER_LOGIN,
        name: repoName.trim(),
        description: pickArg(args, ['description']),
        isPrivate: pickArg(args, ['private']) === true,
        defaultBranch: undefined,
      });
      return mcpTextResult(repoObject(repo));
    }
    case 'get_repo': {
      const { repo, error } = resolveMcpRepo(args);
      if (!repo) return mcpErrorResult(error);
      return mcpTextResult(repoObject(repo));
    }
    case 'create_issue': {
      const { repo, error } = resolveMcpRepo(args);
      if (!repo) return mcpErrorResult(error);
      const title = pickArg(args, ['title']);
      if (typeof title !== 'string' || !title.trim()) return mcpErrorResult('missing required argument: title');
      const labels = pickArg(args, ['labels']);
      const checked = validateIssueLabels(repo, Array.isArray(labels) ? labels : []);
      if (!checked.ok) return mcpErrorResult(`Label '${checked.missing}' does not exist`);
      const { iso } = stamp();
      repo.numberCounter += 1;
      const issue = {
        id: nextGlobalId(),
        number: repo.numberCounter,
        title: title.trim(),
        body: typeof pickArg(args, ['body']) === 'string' ? pickArg(args, ['body']) : null,
        state: 'open',
        labels: checked.names,
        user: VIEWER_LOGIN,
        createdAt: iso,
        updatedAt: iso,
        closedAt: null,
        commentsCount: 0,
      };
      repo.issues.set(issue.number, issue);
      repo.comments.set(issue.number, []);
      return mcpTextResult(issueObject(repo, issue));
    }
    case 'list_issues': {
      const { repo, error } = resolveMcpRepo(args);
      if (!repo) return mcpErrorResult(error);
      const state = pickArg(args, ['state']) || 'open';
      const all = [];
      for (const issue of repo.issues.values()) all.push(issueObject(repo, issue));
      for (const pull of repo.pulls.values()) all.push(pullAsIssueObject(repo, pull));
      const filtered = state === 'all' ? all : all.filter((i) => i.state === state);
      filtered.sort((a, b) => a.number - b.number);
      return mcpTextResult(filtered);
    }
    case 'create_pull_request': {
      const { repo, error } = resolveMcpRepo(args);
      if (!repo) return mcpErrorResult(error);
      const title = pickArg(args, ['title']);
      const head = pickArg(args, ['head']);
      const base = pickArg(args, ['base']) || repo.defaultBranch;
      if (typeof title !== 'string' || !title.trim()) return mcpErrorResult('missing required argument: title');
      if (typeof head !== 'string' || !head) return mcpErrorResult('missing required argument: head');
      const parsedHead = parseHeadRef(head);
      if (parsedHead.owner && parsedHead.owner !== repo.owner) return mcpErrorResult('cross-repository pull requests are not supported');
      const headOid = repo.refs.get(`refs/heads/${parsedHead.ref}`);
      const baseOid = repo.refs.get(`refs/heads/${base}`);
      if (!headOid || !baseOid) return mcpErrorResult('head or base branch does not exist');
      const { iso } = stamp();
      repo.numberCounter += 1;
      const pull = {
        id: nextGlobalId(),
        number: repo.numberCounter,
        title: title.trim(),
        body: typeof pickArg(args, ['body']) === 'string' ? pickArg(args, ['body']) : null,
        state: 'open',
        headRef: parsedHead.ref,
        baseRef: base,
        headSha: headOid,
        baseSha: baseOid,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        labels: [],
        user: VIEWER_LOGIN,
        createdAt: iso,
        updatedAt: iso,
        closedAt: null,
      };
      repo.pulls.set(pull.number, pull);
      if (!repo.comments.has(pull.number)) repo.comments.set(pull.number, []);
      return mcpTextResult(pullObject(repo, pull));
    }
    case 'merge_pull_request': {
      const { repo, error } = resolveMcpRepo(args);
      if (!repo) return mcpErrorResult(error);
      const num = Number(pickArg(args, ['pull_number', 'pullNumber', 'number']));
      if (!Number.isInteger(num)) return mcpErrorResult('missing required argument: pull_number');
      const pull = repo.pulls.get(num);
      if (!pull) return mcpErrorResult('pull request not found');
      if (pull.merged) return mcpTextResult({ sha: pull.mergeCommitSha, merged: true, message: 'Already merged' });
      if (pull.state !== 'open') return mcpErrorResult('pull request is closed');
      const headSha = repo.refs.get(`refs/heads/${pull.headRef}`) || pull.headSha;
      const baseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) || pull.baseSha;
      if (!headSha || !baseSha || headSha === ZERO_OID || baseSha === ZERO_OID) return mcpErrorResult('head or base branch is missing');
      if (!isMergeable(repo, baseSha, headSha)) return mcpErrorResult('pull request is not mergeable: merge conflict');
      const headTree = parseCommit(repo.objects.get(headSha).data).tree;
      const commitOid = repo.createCommit({
        tree: headTree,
        parents: [baseSha],
        message: `${pull.title} (#${pull.number})`,
        authorName: VIEWER_LOGIN,
        authorEmail: VIEWER_EMAIL,
      });
      repo.refs.set(`refs/heads/${pull.baseRef}`, commitOid);
      repo.invalidatePackCache();
      const { iso } = stamp();
      pull.merged = true;
      pull.state = 'closed';
      pull.mergedAt = iso;
      pull.closedAt = iso;
      pull.updatedAt = iso;
      pull.mergeCommitSha = commitOid;
      repo.updatedAt = iso;
      repo.pushedAt = iso;
      return mcpTextResult({ sha: commitOid, merged: true, message: 'Pull request successfully merged' });
    }
    case 'get_issue': {
      const { repo, error } = resolveMcpRepo(args);
      if (!repo) return mcpErrorResult(error);
      const num = Number(pickArg(args, ['issue_number', 'issueNumber', 'number']));
      if (!Number.isInteger(num)) return mcpErrorResult('missing required argument: issue_number');
      const issue = repo.issues.get(num);
      if (issue) return mcpTextResult(issueObject(repo, issue));
      const pull = repo.pulls.get(num);
      if (pull) return mcpTextResult(pullAsIssueObject(repo, pull));
      return mcpErrorResult('issue not found');
    }
    case 'list_pull_requests': {
      const { repo, error } = resolveMcpRepo(args);
      if (!repo) return mcpErrorResult(error);
      const state = pickArg(args, ['state']) || 'open';
      let list = [...repo.pulls.values()];
      if (state !== 'all') list = list.filter((p) => p.state === state);
      list.sort((a, b) => a.number - b.number);
      return mcpTextResult(list.map((p) => pullObject(repo, p)));
    }
    case 'get_pull_request': {
      const { repo, error } = resolveMcpRepo(args);
      if (!repo) return mcpErrorResult(error);
      const num = Number(pickArg(args, ['pull_number', 'pullNumber', 'number']));
      if (!Number.isInteger(num)) return mcpErrorResult('missing required argument: pull_number');
      const pull = repo.pulls.get(num);
      if (!pull) return mcpErrorResult('pull request not found');
      return mcpTextResult(pullObject(repo, pull));
    }
    default:
      return null;
  }
}

function mcpHandleMessage(msg) {
  // Returns a JSON-RPC response object, or null for notifications.
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } };
  }
  const hasId = Object.prototype.hasOwnProperty.call(msg, 'id');
  const id = hasId ? msg.id : null;
  const method = msg.method;
  if (typeof method !== 'string') {
    if (!hasId) return null;
    return { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid Request' } };
  }
  if (method.startsWith('notifications/')) return null;
  const params = msg.params && typeof msg.params === 'object' ? msg.params : {};
  switch (method) {
    case 'initialize': {
      const requested = params.protocolVersion;
      const negotiated = MCP_SUPPORTED_VERSIONS.includes(requested) ? requested : MCP_LATEST_VERSION;
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: negotiated,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'forge', version: '1.0.0' },
        },
      };
    }
    case 'server/discover': {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          supportedVersions: [...MCP_SUPPORTED_VERSIONS],
          protocolVersion: MCP_LATEST_VERSION,
          serverInfo: { name: 'forge', version: '1.0.0' },
          capabilities: { tools: { listChanged: false } },
        },
      };
    }
    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };
    case 'tools/list':
      return { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } };
    case 'tools/call': {
      const name = params.name;
      if (typeof name !== 'string' || !name) {
        return { jsonrpc: '2.0', id, error: { code: -32602, message: 'Invalid params: missing tool name' } };
      }
      const normalized = normalizeToolName(name);
      const known = MCP_TOOLS.some((t) => normalizeToolName(t.name) === normalized);
      if (!known) {
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
      }
      const result = mcpCallTool(name, params.arguments || {});
      return { jsonrpc: '2.0', id, result };
    }
    case 'resources/list':
      return { jsonrpc: '2.0', id, result: { resources: [] } };
    case 'prompts/list':
      return { jsonrpc: '2.0', id, result: { prompts: [] } };
    default:
      return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
  }
}

async function handleMcp(req, res) {
  if (req.method === 'GET') {
    sendError(res, 405, 'Method Not Allowed');
    return;
  }
  if (req.method !== 'POST') {
    sendError(res, 404, 'Not Found');
    return;
  }
  const raw = await readBody(req, 16 * 1024 * 1024);
  let payload;
  try {
    payload = JSON.parse(raw.toString('utf8'));
  } catch {
    const body = JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    res.writeHead(400, { 'Content-Type': 'application/json', 'X-GitHub-Request-Id': nextRequestId(), 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
    return;
  }
  const sessionId = req.headers['mcp-session-id'];
  const extra = {};
  if (typeof sessionId === 'string' && sessionId) extra['Mcp-Session-Id'] = sessionId;
  if (Array.isArray(payload)) {
    const responses = [];
    for (const msg of payload) {
      const r = mcpHandleMessage(msg);
      if (r !== null) responses.push(r);
    }
    if (responses.length === 0) {
      res.writeHead(202, { 'X-GitHub-Request-Id': nextRequestId(), ...extra });
      res.end();
      return;
    }
    sendJson(res, 200, responses, extra);
    return;
  }
  const response = mcpHandleMessage(payload);
  if (response === null) {
    res.writeHead(202, { 'X-GitHub-Request-Id': nextRequestId(), ...extra });
    res.end();
    return;
  }
  sendJson(res, 200, response, extra);
}

// ------------------------------------------------------------------ server + routing

function isAuthorized(req) {
  const auth = (req.headers['authorization'] || '').toString();
  if (!auth.startsWith('Bearer ')) return false;
  const token = auth.slice('Bearer '.length).trim();
  if (!token) return false;
  if (EXPECTED_TOKEN) return token === EXPECTED_TOKEN;
  return true;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const pathname = url.pathname.replace(/\/+$/, '') || '/';
    const query = Object.fromEntries(url.searchParams.entries());
    const segments = splitPath(url.pathname);

    if (pathname === '/healthz') {
      if (req.method === 'GET') {
        sendJson(res, 200, { ok: true });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    const isGit = segments.length >= 2 && segments[1].endsWith('.git');
    const isApi = pathname === '/api/graphql' || pathname === '/api/v3' || pathname.startsWith('/api/v3/')
      || pathname === '/mcp' || isGit;
    if (isApi && !isAuthorized(req)) {
      sendError(res, 401, 'Unauthorized');
      return;
    }

    if (isGit) {
      await handleGit(req, res, segments, query);
      return;
    }
    if (pathname === '/api/v3' || pathname.startsWith('/api/v3/')) {
      await handleRest(req, res, segments.slice(2), query);
      return;
    }
    if (pathname === '/api/graphql') {
      await handleGraphQL(req, res);
      return;
    }
    if (pathname === '/mcp') {
      await handleMcp(req, res);
      return;
    }
    sendError(res, 404, 'Not Found');
  } catch (e) {
    try {
      sendError(res, 500, e && e.message ? String(e.message) : 'Internal Server Error');
    } catch {
      try { res.end(); } catch { /* ignore */ }
    }
  }
});

server.keepAliveTimeout = 30000;
server.headersTimeout = 10000;
server.requestTimeout = 0;
server.maxRequestsPerSocket = 0;

process.on('uncaughtException', (e) => {
  console.error('uncaught', e && e.message ? e.message : e);
});
process.on('unhandledRejection', (e) => {
  console.error('unhandled rejection', e && e.message ? e.message : e);
});

// ------------------------------------------------------------------ lifecycle

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function registerAndPoll() {
  if (!ENV_URL) return; // local run: serve forever
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const r = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: SERVER_PORT }),
      });
      if (r.ok || r.status === 409) break;
    } catch {
      // retry below
    }
    await sleep(Math.min(2000, 100 * 2 ** attempt));
  }
  let attempt = 0;
  for (;;) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 30000);
      const r = await fetch(`${ENV_URL}/done`, { signal: ctrl.signal });
      clearTimeout(timer);
      const data = await r.json();
      if (data && data.done === true) {
        process.exit(0);
      }
    } catch {
      // keep polling
    }
    await sleep(Math.min(2000, 250 * 2 ** attempt));
    attempt += 1;
  }
}

server.listen(0, '0.0.0.0', () => {
  SERVER_PORT = server.address().port;
  registerAndPoll();
});
