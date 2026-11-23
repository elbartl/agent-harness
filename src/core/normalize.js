'use strict';

// Invisible and format characters to strip during normalization:
// U+200B-U+200F, U+2060-U+2064, U+FEFF, U+00AD, U+180E, \0
const INVISIBLE_CHARS_REGEX = /[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD\u180E\0]/g;
const INVISIBLE_CHARS_TEST_REGEX = /[\u200B-\u200F\u2060-\u2064\uFEFF\u00AD\u180E\0]/;

// Bidirectional override and isolate characters:
// U+202A-U+202E, U+2066-U+2069
const BIDI_CHARS_REGEX = /[\u202A-\u202E\u2066-\u2069]/;

// Homoglyphs table: Cyrillic and Greek mapping to Latin equivalents
const HOMOGLYPHS = {
    // Cyrillic lowercase
    '\u0430': 'a', // Cyrillic small a
    '\u0435': 'e', // Cyrillic small ie
    '\u043E': 'o', // Cyrillic small o
    '\u0440': 'p', // Cyrillic small er
    '\u0441': 'c', // Cyrillic small es
    '\u0445': 'x', // Cyrillic small ha
    '\u0443': 'y', // Cyrillic small u
    '\u0456': 'i', // Cyrillic small Byelorussian-Ukrainian i
    '\u0458': 'j', // Cyrillic small je
    '\u0455': 's', // Cyrillic small dze
    '\u0501': 'd', // Cyrillic small komi de
    '\u0261': 'g', // Latin small script g

    // Cyrillic uppercase
    '\u0410': 'a',
    '\u0412': 'b',
    '\u0415': 'e',
    '\u041A': 'k',
    '\u041C': 'm',
    '\u041D': 'h',
    '\u041E': 'o',
    '\u0420': 'p',
    '\u0421': 'c',
    '\u0422': 't',
    '\u0425': 'x',
    '\u0423': 'y',
    '\u0406': 'i',
    '\u0408': 'j',
    '\u0405': 's',

    // Greek uppercase
    '\u0391': 'a', // Alpha
    '\u0392': 'b', // Beta
    '\u0395': 'e', // Epsilon
    '\u0396': 'z', // Zeta
    '\u0397': 'h', // Eta
    '\u0399': 'i', // Iota
    '\u039A': 'k', // Kappa
    '\u039C': 'm', // Mu
    '\u039D': 'n', // Nu
    '\u039F': 'o', // Omicron
    '\u03A1': 'p', // Rho
    '\u03A4': 't', // Tau
    '\u03A7': 'x', // Chi
    '\u03A5': 'y', // Upsilon

    // Greek lowercase
    '\u03B1': 'a', // alpha
    '\u03B5': 'e', // epsilon
    '\u03B9': 'i', // iota
    '\u03BA': 'k', // kappa
    '\u03BF': 'o', // omicron
    '\u03BD': 'v', // nu
    '\u03C1': 'p', // rho
    '\u03C4': 't', // tau
    '\u03C7': 'x', // chi
    '\u03C5': 'y', // upsilon
    '\u03C9': 'w', // omega
};

function normalizeForMatch(str) {
    if (typeof str !== 'string') return '';
    let norm = str.normalize('NFKC');
    norm = norm.replace(INVISIBLE_CHARS_REGEX, '');
    let mapped = '';
    for (let i = 0; i < norm.length; i++) {
        const ch = norm[i];
        mapped += HOMOGLYPHS[ch] || ch;
    }
    return mapped.toLowerCase();
}

function hasBidiChars(str) {
    if (typeof str !== 'string') return false;
    return BIDI_CHARS_REGEX.test(str);
}

function hasInvisibleChars(str) {
    if (typeof str !== 'string') return false;
    return INVISIBLE_CHARS_TEST_REGEX.test(str);
}

module.exports = {
    INVISIBLE_CHARS_REGEX,
    INVISIBLE_CHARS_TEST_REGEX,
    BIDI_CHARS_REGEX,
    HOMOGLYPHS,
    normalizeForMatch,
    hasBidiChars,
    hasInvisibleChars,
};
