#! /usr/bin/env python3
"""
Attempt to break a cipher text encrypted with a repeating key.

The encryption method being broken is that of the Vigenere Cipher using a
repeating key of known length or alternatively, hex XOR encryption with a
repeating key if the input is valid hex and the `x` flag is passed.

Assumtions:
  * The input is ASCII text or HEX (in the case of `--xor`)
    without punctuation.
  * The plain-text is in English.
  * The content of the plain-text is sufficiently similar to every day
    English that character frequencies are similar to the standard rankings.
"""
import sys
import argparse
from operator import itemgetter
from collections import Counter
from functools import lru_cache
from string import ascii_uppercase, ascii_lowercase
from itertools import repeat, zip_longest, combinations


# Terminal colour codes
YELLOW = "\033[0;33m"
NC = "\033[0m"

# Set so that A == 0
OFFSET = ord("A")  # 65

# Relative frequencies for characters in the English Language.
# Useful for comparing distributions of characters
# >>> https://en.wikipedia.org/wiki/Frequency_analysis
REL_CHAR_FREQS = {
    "e": 12.70,
    "t": 9.06,
    "a": 8.17,
    "o": 7.51,
    "i": 6.97,
    "n": 6.75,
    "s": 6.33,
    "h": 6.09,
    "r": 5.99,
    "d": 4.25,
    "l": 4.03,
    "c": 2.78,
    "u": 2.76,
    "m": 2.41,
    "w": 2.36,
    "f": 2.23,
    "g": 2.02,
    "y": 1.97,
    "p": 1.93,
    "b": 1.29,
    "v": 0.98,
    "k": 0.77,
    "j": 0.15,
    "x": 0.15,
    "q": 0.10,
    "z": 0.07,
}

# As above but normalised so that the least frequent (z) has a value of 1
# This is useful for scoring a decryption attempt based on the characters
# that are present (adding ints is faster than adding floats!)
INT_CHAR_FREQS = {
    "e": 27,
    "t": 26,
    "a": 25,
    "o": 24,
    "i": 23,
    "n": 22,
    "s": 21,
    "r": 20,
    "h": 19,
    "l": 18,
    "d": 17,
    "c": 16,
    "u": 15,
    "m": 14,
    "f": 13,
    "p": 12,
    "g": 11,
    "w": 10,
    "y": 9,
    "b": 8,
    "v": 7,
    "k": 6,
    "x": 5,
    " ": 4,
    "j": 3,
    "q": 2,
    "z": 1,
}


# ----------------------------------------------------------------------------
# .: Helpers :.
# ----------------------------------------------------------------------------
def expand_key(key, length):
    """
    Repeat a key to get it to the required length.
    """
    # repeat until we get past the length of the plaintext
    _key = "".join(repeat(key, ((length // len(key)) + 1)))
    # trim down to match the length of the plaintext
    return _key[:length]


def chi_squared(expected, candidate):
    """
    Compute Pearson's Chi-squared test for the candidate vs an expected
    result.
    >>> https://en.wikipedia.org/wiki/Pearson%27s_chi-squared_test

    See here for critical values: DoF is len(plaintext alphabet) - 1
    http://www.itl.nist.gov/div898/handbook/eda/section3/eda3674.htm
    """
    return sum(((c - e) ** 2) / e for e, c in zip(expected, candidate))


@lru_cache(maxsize=None)
def levenshtein(s1, s2):
    """
    Compute the Levenshtein edit distance between two strings. This is
    the minimum number of edits required to turn one string into the other.
    >>> https://en.wikipedia.org/wiki/Levenshtein_distance
    """
    # If one string is empty then the edit distance is simply adding each
    # character of the remaining string.
    if s1 == "":
        return len(s2)
    elif s2 == "":
        return len(s1)
    # If the first characters match then they contribute 0 to the edit
    # distance and we recurse.
    elif s1[0] == s2[0]:
        return levenshtein(s1[1:], s2[1:])
    # Finally, we check to see if we simpy have an extra character at the
    # start of one of the strings, bumping the edit distance by one.
    else:
        l1 = levenshtein(s1, s2[1:])
        l2 = levenshtein(s1[1:], s2)
        l3 = levenshtein(s1[1:], s2[1:])
        return 1 + min(l1, l2, l3)


def check_decryption_attempt(candidate):
    """
    Compute some useful metric for comparing decryption attempts on a
    Cypher Text.
    """
    # Find letter frequecies and compare similarity with English
    count = Counter(candidate.lower())
    _freqs = {k: v * 100 / len(candidate) for k, v in count.items()}
    freqs = {a: 0 for a in ascii_lowercase}
    freqs.update(_freqs)

    # Rank the frequency of each letter for running through chi-squared.
    cand_freqs = [freqs[c] for c in sorted(freqs) if c in REL_CHAR_FREQS]
    eng_freqs = [REL_CHAR_FREQS[c] for c in sorted(REL_CHAR_FREQS)]
    cs = chi_squared(eng_freqs, cand_freqs)

    # Score the text based on the letters it contains. The idea is that a
    # piece of text that is in English will have a high score as it will
    # contain a lot of the most common English letters.
    score = sum(INT_CHAR_FREQS.get(c.lower(), 0) for c in candidate)

    return {
        "plaintext": candidate,
        "chi-squared": cs,
        "score": score,
        "freqs": freqs,
    }


# ----------------------------------------------------------------------------
# .: Main Functions :.
# ----------------------------------------------------------------------------
def vigenere(cipher_text, key):
    """
    Run the Vigenere cipher by adding the "value" of each character
    with a repeating key, wrapping when we get past Z.
    """

    def mask_char(char, mask):
        """Mask the given character and wrap around at Z."""
        if char == " ":
            return char

        char, mask = ord(char) - OFFSET, ord(mask) - OFFSET
        return chr((char + mask) % 26 + OFFSET)

    key = expand_key(key, len(cipher_text))
    return "".join(mask_char(c, k) for (c, k) in zip(cipher_text, key))


def xor(cipher_text, key):
    """
    Computes the bytewise XOR of two equal length buffers.
    """
    # Assume that utf-8 strings are hex encoded and convert them
    # to byte-strings to run the XOR.
    # NOTE: This will raise a ValueError if there are non-hex
    #       characters in the input
    key = bytes.fromhex(expand_key(key, len(cipher_text)))
    cipher_text = bytes.fromhex(cipher_text)
    xord = b"".join(bytes([a ^ b]) for (a, b) in zip(cipher_text, key))
    # Convert back to a UTF-8 sting for returning into the rest
    # of the program.
    return xord.decode("utf-8")


def break_single_char_key(cipher_text, key_chars=ascii_uppercase, encrypt_func=vigenere):
    """
    Attempt to decode a string that has been encoded using a single
    character key.
    """
    results = []

    for key in key_chars:
        cand = encrypt_func(cipher_text, key)
        summary = check_decryption_attempt(cand)
        summary["key"] = key
        results.append(summary)

    ordered = sorted(results, key=itemgetter("score"), reverse=True)
    return ordered[0]


def break_rep_key(cipher_text, key_len, encrypt_func=vigenere):
    """
    Attempt to partition and find a repeating key.
    """
    if key_len > 1:
        chunks = [cipher_text[i : i + key_len] for i in range(0, len(cipher_text), key_len)]
        # Transpose to split the input into subspaces that have all
        # been encrypted with the same character of the key.
        chunksT = [c for c in zip_longest(*chunks, fillvalue=None)]
        # Attempt to find the most likely candidate key for each
        # of the subspaces.
        key = "".join(
            [
                break_single_char_key("".join(c for c in chunk if c), encrypt_func=encrypt_func,)[
                    "key"
                ]
                for chunk in chunksT
            ]
        )
    else:
        key = break_single_char_key(cipher_text, encrypt_func)["key"]

    return key


def determine_key_length(cipher_text, max_key_size=10, encrypt_func=vigenere):
    """
    Use Levenshtein distance as a metric to determine the most likely key
    legth of the cipher-text and then work through the lengths in rank order.
    Chi-squared is used as a measure to determine if we hae been successfull,
    returning immediately if we pass 99.9% probability that the plain-text
    is valid English or returning the most likely candidate otherwise.
    """
    lev = {}
    msg = "{}[+] Attempting to determine most likely key length...{}\n"
    print(msg.format(YELLOW, NC))

    # Shortest Levenshtein distance is the most likely but not guaranteed
    # to be correct. This is really just to be more efficient with ordering
    # our attempts incase the cipher-text is particularly large.
    for k in range(1, max_key_size + 1):
        sample = cipher_text[: k * 4]
        lev_score = 0
        chunks = [sample[i : i + k] for i in range(0, len(sample), k)]
        for a, b in combinations(chunks, 2):
            lev_score += levenshtein(a, b)
        lev[k] = lev_score / k

    ranked = sorted(lev, key=lev.get, reverse=False)

    msg = "{}[+] Levenshtein distances (lower is more likely)\n"
    msg += "================================================\n{}"
    msg += "".join("  {}: {}\n".format(l, lev[l]) for l in ranked[:10])
    print(msg.format(YELLOW, NC))

    candidate = {"chi-squared": 9999999999}

    for kl in ranked:
        msg = "\n{}[+] Attempting keysize {}...".format(YELLOW, kl)
        print(msg, "\n" + "=" * len(msg) + NC)

        key = break_rep_key(cipher_text, kl)
        cand = encrypt_func(cipher_text, key)
        summary = check_decryption_attempt(cand)
        summary["key"] = key

        for k, v in summary.items():
            if k not in ["plaintext", "letter_dist", "freqs"]:
                print(k, ": ", v)

        # Critical value for chi-squared with 26 degrees of freedom
        # is 52.62 for 0.999 probability of being correct.
        if summary["chi-squared"] < 52:
            return summary
        elif summary["chi-squared"] < candidate["chi-squared"]:
            candidate = summary

    # If nothing passed the threshold then return the best we've got.
    return candidate


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="Provide a specific key to use for decryption.")
    parser.add_argument(
        "-l", "--keylength", type=int, help="Specify a single known keylength to break."
    )
    parser.add_argument(
        "-a",
        "--auto",
        type=int,
        default=10,
        required=False,
        help="Attempt auto decryption with a maximum key length (Default: 10).",
    )
    parser.add_argument(
        "-x",
        "--xor",
        action="store_true",
        help="Use XOR rather than the Vigenere cipher for encrypt/decrypt.",
    )
    args = parser.parse_args()

    cipher_text = "".join([c for c in sys.stdin.read().strip() if c != " "])

    # If `-x` is passed we use simple XOR for encryption
    # rather than vigenere wrapping at `Z`.
    encrypt_func = xor if args.xor else vigenere

    if args.key:
        print(encrypt_func(cipher_text, args.key))

    elif args.auto:
        max_key_length = args.auto
        candidate = determine_key_length(cipher_text, max_key_length, encrypt_func)
        print(
            "\n{}[+] Most likely key is {} (length: {}){}\n".format(
                YELLOW, candidate["key"], len(candidate["key"]), NC
            )
        )
        print(candidate["plaintext"][:50] + "...")

    elif args.keylength:
        key = break_rep_key(cipher_text, args.keylength)
        print("{}[+] Key candidate: {}\nDecrypting...{}".format(YELLOW, key, NC))
        print(vigenere(cipher_text, key)[:50] + "...")
