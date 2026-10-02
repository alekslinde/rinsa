// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Sanitisation: trim, whitespace collapse, control/invisible/bidi removal,
 * allow/block lists, encoding repair, length limits.
 *
 * Performance design:
 * - `compileSanitizer()` precomputes all flags/tables once; the returned
 *   closure does a single pass with lazy allocation (returns the input
 *   string itself when nothing changes).
 * - ASCII fast branch (`code < 128`) avoids Set lookups and surrogate logic.
 * - No regex in the hot path (except user-supplied allow/block regexes).
 */

import { ASCII_CLASS, C_CTL, C_WS, isInvisibleCP } from './tables.js';

export type TrimMode = boolean | 'start' | 'end' | 'both' | 'none';

export interface SanitizeOptions {
  trim?: TrimMode;
  collapseWhitespace?: boolean | string;
  removeControls?: boolean;
  removeZeroWidth?: boolean;
  removeBidi?: boolean;
  allow?: string | RegExp | null;
  block?: string | RegExp | null;
  maxChars?: number;
  maxBytes?: number;
  replacement?: string;
  form?: 'NFC' | 'NFD' | 'NFKC' | 'NFKD' | false | null;
  fixEncoding?: boolean;
}

interface CompiledAllow {
  bmp: Uint8Array | null; // 65536 bitmap when allow given as string
  set: Set<number> | null; // astral / overflow
  re: RegExp | null;
}

interface SanitizerState {
  trimStart: boolean;
  trimEnd: boolean;
  collapse: boolean;
  collapseTo: string;
  rmControls: boolean;
  rmInvisible: boolean; // zero-width incl. bidi
  rmBidiOnly: boolean; // removeBidi true while removeZeroWidth false
  replacement: string;
  allowBmp: Uint8Array | null;
  allowSet: Set<number> | null;
  allowRe: RegExp | null;
  hasAllow: boolean;
  blockBmp: Uint8Array | null;
  blockSet: Set<number> | null;
  blockRe: RegExp | null;
  hasBlock: boolean;
  maxChars: number;
  maxBytes: number;
  form: 'NFC' | 'NFD' | 'NFKC' | 'NFKD' | null;
  fixEncoding: boolean;
  /** True when every option is at its no-op default. */
  isNoop: boolean;
}

const DEFAULTS: Required<
  Pick<
    SanitizeOptions,
    | 'trim'
    | 'collapseWhitespace'
    | 'removeControls'
    | 'removeZeroWidth'
    | 'removeBidi'
    | 'replacement'
    | 'fixEncoding'
  >
> = {
  trim: true,
  collapseWhitespace: true,
  removeControls: true,
  removeZeroWidth: true,
  removeBidi: true,
  replacement: '',
  fixEncoding: true,
};

function toTrimPair(trim: TrimMode | undefined): [boolean, boolean] {
  if (trim === undefined) return [true, true];
  if (trim === true || trim === 'both') return [true, true];
  if (trim === false || trim === 'none') return [false, false];
  if (trim === 'start') return [true, false];
  return [false, true];
}

function buildCharMatcher(
  src: string | RegExp | null | undefined,
): { bmp: Uint8Array | null; set: Set<number> | null; re: RegExp | null } {
  if (src == null) return { bmp: null, set: null, re: null };
  if (src instanceof RegExp) {
    // Force non-global, single-char anchored test semantics for the compiled fn.
    const flags = src.flags.replace('g', '').replace('y', '');
    return { bmp: null, set: null, re: new RegExp(src.source, flags) };
  }
  const bmp = new Uint8Array(0x10000);
  let set: Set<number> | null = null;
  for (const ch of src) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x10000) bmp[cp] = 1;
    else {
      if (!set) set = new Set();
      set.add(cp);
    }
  }
  return { bmp, set, re: null };
}

function compileState(opts: SanitizeOptions = {}): SanitizerState {
  const trim = opts.trim ?? DEFAULTS.trim;
  const [trimStart, trimEnd] = toTrimPair(trim);
  const cw = opts.collapseWhitespace ?? DEFAULTS.collapseWhitespace;
  const collapse = cw !== false;
  const collapseTo = typeof cw === 'string' ? cw : ' ';
  const rmControls = opts.removeControls ?? DEFAULTS.removeControls;
  const rmZero = opts.removeZeroWidth ?? DEFAULTS.removeZeroWidth;
  const rmBidi = opts.removeBidi ?? DEFAULTS.removeBidi;
  const replacement = opts.replacement ?? DEFAULTS.replacement;
  const allow = buildCharMatcher(opts.allow ?? null);
  const block = buildCharMatcher(opts.block ?? null);
  const maxChars = opts.maxChars ?? Infinity;
  const maxBytes = opts.maxBytes ?? Infinity;
  const form = (opts.form ?? null) as SanitizerState['form'];
  const fixEncoding = opts.fixEncoding ?? DEFAULTS.fixEncoding;
  const hasAllow = allow.bmp !== null || allow.set !== null || allow.re !== null;
  const hasBlock = block.bmp !== null || block.set !== null || block.re !== null;
  const isNoop =
    !trimStart &&
    !trimEnd &&
    !collapse &&
    !rmControls &&
    !rmZero &&
    !rmBidi &&
    !hasAllow &&
    !hasBlock &&
    maxChars === Infinity &&
    maxBytes === Infinity &&
    form === null &&
    !fixEncoding;
  return {
    trimStart,
    trimEnd,
    collapse,
    collapseTo,
    rmControls,
    rmInvisible: rmZero,
    rmBidiOnly: !rmZero && rmBidi,
    replacement,
    allowBmp: allow.bmp,
    allowSet: allow.set,
    allowRe: allow.re,
    hasAllow,
    blockBmp: block.bmp,
    blockSet: block.set,
    blockRe: block.re,
    hasBlock,
    maxChars,
    maxBytes,
    form,
    fixEncoding,
    isNoop,
  };
}

function utf8Len(cp: number): number {
  if (cp < 0x80) return 1;
  if (cp < 0x800) return 2;
  if (cp < 0x10000) return 3;
  return 4;
}

function utf8LenStr(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const lo = s.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        n += 4;
        i++;
      } else n += 3;
    } else n += 3;
  }
  return n;
}

/** Test a single character (may be astral, length 1-2) against a compiled matcher. */
function matchBmp(
  bmp: Uint8Array | null,
  set: Set<number> | null,
  re: RegExp | null,
  cp: number,
  ch: string,
): boolean {
  if (re) {
    re.lastIndex = 0;
    return re.test(ch);
  }
  if (cp < 0x10000) return bmp !== null && bmp[cp] === 1;
  return set !== null && set.has(cp);
}

const BIDI_SET = new Set([0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);

/**
 * Core single-pass sanitizer. Returns the input string itself when unchanged.
 * Exported for fusion use; prefer compileSanitizer() for reuse.
 */
export function sanitizeWithState(input: string, st: SanitizerState): string {
  const len = input.length;
  if (len === 0) return input;
  if (st.isNoop) return input;

  let s = input;
  // Unicode normalisation first so the scan sees final characters.
  if (st.form !== null) {
    // Fast path: pure ASCII is already in every normal form.
    if (!isAscii(s)) s = s.normalize(st.form);
    if (s.length === 0) return '';
  }

  const n = s.length;
  // Skip leading whitespace when trimming (no allocation).
  let start = 0;
  if (st.trimStart) {
    while (start < n) {
      const c = s.charCodeAt(start);
      if (c < 128) {
        if ((ASCII_CLASS[c]! & C_WS) === 0) break;
        start++;
      } else {
        // Unicode whitespace: use WS regex-free check via code point
        const cp = s.codePointAt(start)!;
        if (!isUnicodeWS(cp)) break;
        start += cp > 0xffff ? 2 : 1;
      }
    }
    if (start >= n) return '';
  }

  // Fast pre-check: if no limits/allow/block and only trim requested, do slice.
  // (Handled implicitly below, but this avoids the general loop entirely.)
  if (
    !st.collapse &&
    !st.rmControls &&
    !st.rmInvisible &&
    !st.rmBidiOnly &&
    !st.hasAllow &&
    !st.hasBlock &&
    st.maxChars === Infinity &&
    st.maxBytes === Infinity &&
    !st.fixEncoding
  ) {
    if (!st.trimEnd) return start === 0 ? s : s.slice(start);
    let end = n;
    while (end > start) {
      const c = s.charCodeAt(end - 1);
      if (c < 128) {
        if ((ASCII_CLASS[c]! & C_WS) === 0) break;
        end--;
      } else {
        const cp = s.codePointAt(end - 1)!; // low surrogate trail: codePointAt still works backwards? handle manually
        void cp;
        // scan backwards by one code point
        let j = end - 1;
        const lo = s.charCodeAt(j);
        let cpB: number;
        let width: number;
        if (lo >= 0xdc00 && lo <= 0xdfff && j - 1 >= start) {
          const hi = s.charCodeAt(j - 1);
          if (hi >= 0xd800 && hi <= 0xdbff) {
            cpB = (hi - 0xd800) * 0x400 + (lo - 0xdc00) + 0x10000;
            width = 2;
          } else {
            cpB = lo;
            width = 1;
          }
        } else {
          cpB = lo;
          width = 1;
        }
        if (!isUnicodeWS(cpB)) break;
        end -= width;
      }
    }
    if (start === 0 && end === n) return s;
    return s.slice(start, end);
  }

  const repl = st.replacement;
  const replBytes = repl ? utf8LenStr(repl) : 0;
  let out: string[] | null = null; // lazy
  let outLen = 0; // chars appended (UTF-16 units in parts)
  let pendingSpaces = 0; // collapsed whitespace run length (in units, normalized later)
  let emittedChars = 0; // code points emitted (for maxChars)
  let emittedBytes = 0; // utf-8 bytes emitted (for maxBytes)
  let lastNonSpacePart = -1; // index in out of last non-space content (for trimEnd)
  let lastNonSpaceLen = 0;
  let i = start;

  // Helper to flush: copy s[start..i) gap into out when first change detected.
  // Instead of gap-copy bookkeeping, we push kept chars individually;
  // ASCII chars are pushed as 1-char strings (V8 joins efficiently).
  // To keep zero-copy: while clean, push nothing and just advance; on first
  // dirty event, backfill s.slice(start, i-dirtyWidth) then continue pushing.
  let cleanUpTo = start; // s.slice(start, cleanUpTo) is pending clean content not yet flushed

  const flushClean = (upto: number): void => {
    if (out === null) out = [];
    if (upto > cleanUpTo) {
      const chunk = s.slice(cleanUpTo, upto);
      out.push(chunk);
      outLen += chunk.length;
      cleanUpTo = upto;
    }
  };
  const pushStr = (chunk: string, cpCount: number, byteCount: number): void => {
    if (out === null) out = [];
    out.push(chunk);
    outLen += chunk.length;
    emittedChars += cpCount;
    emittedBytes += byteCount;
    if (chunk !== st.collapseTo || !st.collapse) {
      lastNonSpacePart = out.length - 1;
      lastNonSpaceLen = outLen;
    }
  };

  // Precompute: if no trimEnd, lastNonSpace tracking unneeded; keep anyway (cheap).

  while (i < n) {
    const c = s.charCodeAt(i);

    // ---- ASCII fast branch ----
    if (c < 128) {
      const cls = ASCII_CLASS[c]!;
      const isWS = (cls & C_WS) !== 0;
      if (isWS) {
        if (st.collapse) {
          // Collapse run: count the whole run now, emit one separator later (or nothing if trailing+trimEnd).
          let j = i + 1;
          while (j < n) {
            const d = s.charCodeAt(j);
            if (d < 128) {
              if ((ASCII_CLASS[d]! & C_WS) === 0) break;
              j++;
            } else {
              const cp2 = s.codePointAt(j)!;
              if (!isUnicodeWS(cp2)) break;
              j += cp2 > 0xffff ? 2 : 1;
            }
          }
          // If trimming end and this run reaches EOS, drop it.
          if (st.trimEnd) {
            // peek: is rest all WS? j already at first non-WS or EOS
            if (j >= n) {
              // trailing WS: mark dirty (if not already) and stop
              if (out === null && cleanUpTo === start && pendingSpaces === 0) {
                // check whether anything was skipped at all: if clean so far, we still need to drop trailing
                // trailing exists => dirty unless input had no trailing... it does, so dirty.
              }
              flushClean(i); // flush content before the trailing run
              cleanUpTo = n;
              i = n;
              break;
            }
          }
          // Enforce limits for the separator
          const sepBytes = st.collapseTo === ' ' ? 1 : utf8LenStr(st.collapseTo);
          if (
            emittedChars + 1 > st.maxChars ||
            emittedBytes + sepBytes > st.maxBytes
          ) {
            flushClean(i);
            cleanUpTo = n;
            i = n;
            break;
          }
          flushClean(i);
          cleanUpTo = j;
          if (out === null) out = [];
          out.push(st.collapseTo);
          outLen += st.collapseTo.length;
          emittedChars += 1; // collapseTo counted as 1 char (approx for multi-char separators)
          emittedBytes += sepBytes;
          pendingSpaces = 0;
          i = j;
          continue;
        } else {
          // No collapse: WS passes through (subject to allow/block below)
          if (!st.hasAllow && !st.hasBlock) {
            if (st.maxChars !== Infinity) {
              // count
              if (emittedChars + 1 > st.maxChars) {
                flushClean(i);
                cleanUpTo = n;
                break;
              }
            }
            if (st.maxBytes !== Infinity) {
              if (emittedBytes + 1 > st.maxBytes) {
                flushClean(i);
                cleanUpTo = n;
                break;
              }
            }
            emittedChars += st.maxChars !== Infinity ? 1 : 0;
            emittedBytes += st.maxBytes !== Infinity ? 1 : 0;
            i++;
            continue; // clean
          }
          // else fall through to allow/block check with ch=' '
        }
      } else if ((cls & C_CTL) !== 0) {
        if (st.rmControls) {
          flushClean(i);
          cleanUpTo = i + 1;
          if (repl) {
            if (
              emittedChars + 1 <= st.maxChars &&
              emittedBytes + replBytes <= st.maxBytes
            ) {
              pushStr(repl, 1, replBytes);
            } else {
              i = n;
              cleanUpTo = n;
              break;
            }
          }
          i++;
          continue;
        }
        // else keep control (unusual): fall to allow/block
      }
      // Normal ASCII char (or kept WS/CTL): allow/block check
      if (st.hasAllow || st.hasBlock) {
        const ch = s[i]!;
        const cp = c;
        let drop = false;
        if (st.hasAllow) {
          const ok = matchBmp(st.allowBmp, st.allowSet, st.allowRe, cp, ch);
          if (!ok) drop = true;
        }
        if (!drop && st.hasBlock) {
          if (matchBmp(st.blockBmp, st.blockSet, st.blockRe, cp, ch)) drop = true;
        }
        if (drop) {
          flushClean(i);
          cleanUpTo = i + 1;
          if (repl) {
            if (
              emittedChars + 1 <= st.maxChars &&
              emittedBytes + replBytes <= st.maxBytes
            )
              pushStr(repl, 1, replBytes);
            else {
              i = n;
              cleanUpTo = n;
              break;
            }
          }
          i++;
          continue;
        }
        // kept: count limits
        if (st.maxChars !== Infinity || st.maxBytes !== Infinity) {
          if (
            emittedChars + 1 > st.maxChars ||
            emittedBytes + 1 > st.maxBytes
          ) {
            flushClean(i);
            cleanUpTo = n;
            break;
          }
          emittedChars += st.maxChars !== Infinity ? 1 : 0;
          emittedBytes += st.maxBytes !== Infinity ? 1 : 0;
          // mark flushed region: since we're counting, content is no longer "clean sliceable"
          // easiest: flush incrementally
          flushClean(i + 1);
          cleanUpTo = i + 1;
          // out is now non-null; lastNonSpace update
          lastNonSpacePart = (out as string[]).length - 1;
          lastNonSpaceLen = outLen;
          i++;
          continue;
        }
        i++;
        continue;
      }
      // clean ASCII, maybe counting
      if (st.maxChars !== Infinity || st.maxBytes !== Infinity) {
        if (emittedChars + 1 > st.maxChars || emittedBytes + 1 > st.maxBytes) {
          flushClean(i);
          cleanUpTo = n;
          break;
        }
        emittedChars += st.maxChars !== Infinity ? 1 : 0;
        emittedBytes += st.maxBytes !== Infinity ? 1 : 0;
        if (out !== null) {
          flushClean(i + 1);
          cleanUpTo = i + 1;
        }
      }
      i++;
      continue;
    }

    // ---- Non-ASCII slow branch ----
    const cp = s.codePointAt(i)!;
    const width = cp > 0xffff ? 2 : 1;
    const ch = width === 2 ? s.slice(i, i + 2) : s[i]!;

    // Lone surrogates: codePointAt returns the unit itself for unpaired surrogates.
    const isLoneSurrogate = cp >= 0xd800 && cp <= 0xdfff;
    if (isLoneSurrogate) {
      if (st.fixEncoding) {
        flushClean(i);
        cleanUpTo = i + 1;
        const r = repl || '�';
        const rb = utf8LenStr(r);
        if (emittedChars + 1 <= st.maxChars && emittedBytes + rb <= st.maxBytes) {
          pushStr(r, 1, rb);
        } else {
          i = n;
          cleanUpTo = n;
          break;
        }
        i += 1;
        continue;
      }
      // keep as-is
      i += 1;
      continue;
    }

    const bytes = utf8Len(cp);
    const ws = isUnicodeWS(cp);

    if (ws) {
      if (st.collapse) {
        let j = i + width;
        while (j < n) {
          const d = s.charCodeAt(j);
          let cp2: number;
          let w2: number;
          if (d < 128) {
            if ((ASCII_CLASS[d]! & C_WS) === 0) break;
            cp2 = d;
            w2 = 1;
          } else {
            cp2 = s.codePointAt(j)!;
            if (cp2 >= 0xd800 && cp2 <= 0xdfff) break; // lone surrogate stops run
            if (!isUnicodeWS(cp2)) break;
            w2 = cp2 > 0xffff ? 2 : 1;
          }
          void cp2;
          j += w2;
        }
        if (st.trimEnd && j >= n) {
          flushClean(i);
          cleanUpTo = n;
          i = n;
          break;
        }
        const sepBytes = st.collapseTo === ' ' ? 1 : utf8LenStr(st.collapseTo);
        if (emittedChars + 1 > st.maxChars || emittedBytes + sepBytes > st.maxBytes) {
          flushClean(i);
          cleanUpTo = n;
          i = n;
          break;
        }
        flushClean(i);
        cleanUpTo = j;
        if (out === null) out = [];
        out.push(st.collapseTo);
        outLen += st.collapseTo.length;
        emittedChars += 1;
        emittedBytes += sepBytes;
        i = j;
        continue;
      }
      // no collapse: fall through to filters
    }

    // Control check (C1, etc.): non-ASCII controls are Cc/Cf handled below;
    // ASCII controls already handled. Here check general Cf/Cc via ranges + invisible set.
    let drop = false;
    if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      if (st.rmControls) drop = true;
    } else if (st.rmInvisible && isInvisibleCP(cp)) {
      drop = true;
    } else if (st.rmBidiOnly && BIDI_SET.has(cp)) {
      drop = true;
    }

    if (!drop && (st.hasAllow || st.hasBlock)) {
      if (st.hasAllow && !matchBmp(st.allowBmp, st.allowSet, st.allowRe, cp, ch)) drop = true;
      else if (st.hasBlock && matchBmp(st.blockBmp, st.blockSet, st.blockRe, cp, ch)) drop = true;
    }

    if (drop) {
      flushClean(i);
      cleanUpTo = i + width;
      if (repl) {
        if (emittedChars + 1 <= st.maxChars && emittedBytes + replBytes <= st.maxBytes) {
          pushStr(repl, 1, replBytes);
        } else {
          i = n;
          cleanUpTo = n;
          break;
        }
      }
      i += width;
      continue;
    }

    // kept char: enforce limits
    if (st.maxChars !== Infinity || st.maxBytes !== Infinity) {
      if (emittedChars + 1 > st.maxChars || emittedBytes + bytes > st.maxBytes) {
        flushClean(i);
        cleanUpTo = n;
        break;
      }
      emittedChars += st.maxChars !== Infinity ? 1 : 0;
      emittedBytes += st.maxBytes !== Infinity ? bytes : 0;
      if (out !== null) {
        flushClean(i + width);
        cleanUpTo = i + width;
      }
    }
    i += width;
  }

  if (out === null) {
    // Never dirtied. cleanUpTo tracks start; trailing already handled in collapse path.
    // Limits path may have set cleanUpTo=n with out===null (pure truncation of clean input).
    let end = cleanUpTo === start ? n : cleanUpTo;
    if (st.trimEnd && !st.collapse && end > start) {
      // Strip trailing whitespace that the clean fast path preserved.
      let e = end;
      while (e > start) {
        const c = s.charCodeAt(e - 1);
        if (c < 128) {
          if ((ASCII_CLASS[c]! & C_WS) === 0) break;
          e--;
        } else {
          const lo = s.charCodeAt(e - 1);
          let cpB: number;
          let w: number;
          if (lo >= 0xdc00 && lo <= 0xdfff && e - 2 >= start) {
            const hi = s.charCodeAt(e - 2);
            if (hi >= 0xd800 && hi <= 0xdbff) {
              cpB = (hi - 0xd800) * 0x400 + (lo - 0xdc00) + 0x10000;
              w = 2;
            } else {
              cpB = lo;
              w = 1;
            }
          } else {
            cpB = lo;
            w = 1;
          }
          if (!isUnicodeWS(cpB)) break;
          e -= w;
        }
      }
      end = e;
    }
    if (end === n && start === 0) return s;
    return s.slice(start, end);
  }
  if (cleanUpTo < i) flushClean(i);
  let result = out.join('');
  // trimEnd for non-collapse paths: trailing WS may remain (kept WS). Strip it.
  if (st.trimEnd && !st.collapse) {
    let e = result.length;
    while (e > 0) {
      const c = result.charCodeAt(e - 1);
      let wCp: number;
      let w: number;
      if (c < 128) {
        if ((ASCII_CLASS[c]! & C_WS) === 0) break;
        e -= 1;
        continue;
      }
      const lo = c;
      if (lo >= 0xdc00 && lo <= 0xdfff && e - 2 >= 0) {
        const hi = result.charCodeAt(e - 2);
        if (hi >= 0xd800 && hi <= 0xdbff) {
          wCp = (hi - 0xd800) * 0x400 + (lo - 0xdc00) + 0x10000;
          w = 2;
        } else {
          wCp = lo;
          w = 1;
        }
      } else {
        wCp = lo;
        w = 1;
      }
      if (!isUnicodeWS(wCp)) break;
      e -= w;
    }
    if (e !== result.length) result = result.slice(0, e);
  }
  void lastNonSpacePart;
  void lastNonSpaceLen;
  void pendingSpaces;
  void outLen;
  return result;
}

/** Unicode whitespace test for a code point (covers White_Space + common extras). */
function isUnicodeWS(cp: number): boolean {
  if (cp < 128) return cp === 0x20 || (cp >= 0x09 && cp <= 0x0d);
  return (
    cp === 0x85 ||
    cp === 0xa0 ||
    cp === 0x1680 ||
    (cp >= 0x2000 && cp <= 0x200a) ||
    cp === 0x2028 ||
    cp === 0x2029 ||
    cp === 0x202f ||
    cp === 0x205f ||
    cp === 0x3000 ||
    cp === 0xfeff
  );
}

function isAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) >= 128) return false;
  return true;
}

/** Compile options once; reuse the returned function for many inputs. */
export function compileSanitizer(opts: SanitizeOptions = {}): (input: string) => string {
  const st = compileState(opts);
  if (st.isNoop) return (input: string) => input;
  return (input: string) => sanitizeWithState(input, st);
}

/** One-shot convenience wrapper (compiles options on every call — prefer compileSanitizer in loops). */
export function sanitize(input: string, opts: SanitizeOptions = {}): string {
  return sanitizeWithState(input, compileState(opts));
}

/** Validate UTF-8 bytes without allocating. */
export function isValidUTF8(bytes: Uint8Array): boolean {
  let i = 0;
  const n = bytes.length;
  while (i < n) {
    const b0 = bytes[i]!;
    if (b0 < 0x80) {
      i++;
      continue;
    }
    let need: number;
    let lo: number;
    let hi: number;
    if (b0 >= 0xc2 && b0 <= 0xdf) {
      need = 1;
      lo = 0x80;
      hi = 0xbf;
    } else if (b0 === 0xe0) {
      need = 2;
      lo = 0xa0;
      hi = 0xbf;
    } else if (b0 >= 0xe1 && b0 <= 0xec) {
      need = 2;
      lo = 0x80;
      hi = 0xbf;
    } else if (b0 === 0xed) {
      need = 2;
      lo = 0x80;
      hi = 0x9f;
    } else if (b0 >= 0xee && b0 <= 0xef) {
      need = 2;
      lo = 0x80;
      hi = 0xbf;
    } else if (b0 === 0xf0) {
      need = 3;
      lo = 0x90;
      hi = 0xbf;
    } else if (b0 >= 0xf1 && b0 <= 0xf3) {
      need = 3;
      lo = 0x80;
      hi = 0xbf;
    } else if (b0 === 0xf4) {
      need = 3;
      lo = 0x80;
      hi = 0x8f;
    } else {
      return false;
    }
    void hi;
    if (i + need >= n) return false;
    for (let k = 1; k <= need; k++) {
      const b = bytes[i + k]!;
      const low = k === 1 ? lo : 0x80;
      const high = k === 1 ? hi : 0xbf;
      if (b < low || b > high) return false;
    }
    i += need + 1;
  }
  return true;
}

/** UTF-8 byte length of a string (counts lone surrogates as 3, matching WTF-8/JS encoding). */
export function utf8ByteLength(s: string): number {
  return utf8LenStr(s);
}

/** Decode bytes as UTF-8 (replacing invalid sequences) then sanitize. For Buffer/Uint8Array inputs. */
export function sanitizeBytes(bytes: Uint8Array, opts: SanitizeOptions = {}): string {
  // TextDecoder without fatal replaces malformed sequences with U+FFFD — the safe default.
  const dec = new TextDecoder('utf-8', { fatal: false, ignoreBOM: false });
  const s = dec.decode(bytes);
  return sanitize(s, opts);
}

/** Number of Unicode code points (NOT UTF-16 units). */
export function charLength(s: string): number {
  let count = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const lo = s.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) i++;
    }
    count++;
  }
  return count;
}