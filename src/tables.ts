// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Precomputed ASCII classification tables.
 * Hot paths index these instead of branching or calling regex/charCode chains.
 */

// bit flags
export const C_WS = 1; // space, \t \n \r \f \v
export const C_CTL = 2; // other C0/C1 controls + DEL
export const C_DIGIT = 4;
export const C_ALPHA = 8;
export const C_ALNUM = 16;
export const C_HEX = 32;
export const C_B64URL = 64;
export const C_IDSAFE = 128; // [A-Za-z0-9_-] for identifiers

function buildAsciiClass(): Uint8Array {
  const t = new Uint8Array(128);
  for (let c = 0; c < 128; c++) {
    let f = 0;
    if (c === 0x20 || (c >= 0x09 && c <= 0x0d)) f |= C_WS;
    else if (c < 0x20 || c === 0x7f) f |= C_CTL;
    if (c >= 0x30 && c <= 0x39) f |= C_DIGIT | C_ALNUM | C_HEX | C_B64URL;
    if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)) f |= C_ALPHA | C_ALNUM | C_B64URL;
    if ((c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)) f |= C_HEX;
    if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x2d || c === 0x5f) f |= C_IDSAFE;
    // base64url extra: '-' '_' already; digits+alpha covered
    t[c] = f;
  }
  // '+' '/' are b64 but not b64url; handled by callers that need them
  return t;
}

export const ASCII_CLASS = buildAsciiClass();

/** Lowercase map for ASCII (identity for non-letters). */
export const ASCII_LOWER = new Uint8Array(128);
/** Uppercase map for ASCII. */
export const ASCII_UPPER = new Uint8Array(128);
for (let c = 0; c < 128; c++) {
  ASCII_LOWER[c] = c >= 65 && c <= 90 ? c + 32 : c;
  ASCII_UPPER[c] = c >= 97 && c <= 122 ? c - 32 : c;
}

/** True for ASCII whitespace (space \t\n\r\f\v). Branchless lookup. */
export function isAsciiWS(code: number): boolean {
  return code < 128 && (ASCII_CLASS[code]! & C_WS) !== 0;
}

/** True for ASCII control (C0, DEL). Excludes \t\n\r and space which are WS. */
export function isAsciiCtl(code: number): boolean {
  return code < 128 && (ASCII_CLASS[code]! & C_CTL) !== 0;
}

/** Zero-width / invisible characters removed by default (beyond ASCII controls). */
export const ZERO_WIDTH = new Set([
  0x00ad, // soft hyphen
  0x034f, // combining grapheme joiner
  0x061c, // arabic letter mark (also bidi; removed in both paths)
  0x115f, 0x1160, // hangul fillers
  0x17b4, 0x17b5, // khmer
  0x180b, 0x180c, 0x180d, 0x180e, // mongolian
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f, // zwsp zwnj zwj lrm rlm
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidi embeddings/overrides
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // word joiner, invisible operators
  0x2066, 0x2067, 0x2068, 0x2069, // bidi isolates
  0xfeff, // zw nbsp / BOM
  0xffa0, // halfwidth filler
  0x1d173, 0x1d174, 0x1d175, 0x1d176, 0x1d177, 0x1d178, 0x1d179, 0x1d17a, // musical format
  0xe0001, 0xe0020, 0xe007f, // tags
]);

/** Bidi/format characters subset (overlaps ZERO_WIDTH; kept separate for messaging). */
export const BIDI_FORMAT = new Set([
  0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
]);

/** Fast check: is this BMP code invisible/format? (astral handled via Set lookup by callers) */
const BMP_INVISIBLE = new Uint8Array(0x10000);
for (const cp of ZERO_WIDTH) {
  if (cp < 0x10000) BMP_INVISIBLE[cp] = 1;
}

export function isInvisibleBMP(code: number): boolean {
  return code < 0x10000 && BMP_INVISIBLE[code] === 1;
}

export function isInvisibleCP(cp: number): boolean {
  if (cp < 0x10000) return BMP_INVISIBLE[cp] === 1;
  return ZERO_WIDTH.has(cp);
}