#! /usr/bin/env python3
'''
Perform simple frequency analysis on stdin.

This tool can:
  - Analyse single letter frequencies.
  - Analyse bi/tri-gram frequencies.
  - Perform automated decryption based on analysis.
  - Perform user specified partial translation.
'''
import sys
import argparse
from collections import Counter
from string import ascii_lowercase


# Punctuation that is not useful for freq analysis
PUNCTUATION = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

# Letters ordered by frequency in English
ETAOIN = 'etaoinshrdlcumwfgypbvkjxqz'

# The top 16 trigrams in the English language. These are three letter
# groups that are allowed to span word boundaries.
# >>> https://en.wikipedia.org/wiki/Trigram
ENG_TRIGRAMS = [
    'the', 'and', 'tha', 'ent', 'ing', 'ion', 'tio', 'for',
    'nde', 'has', 'nce', 'edt', 'tis', 'oft', 'sth', 'men'
]

# The top 16 bigrams in the English language. These are two letter
# groups that are allowed to span word boundaries.
# >>> https://en.wikipedia.org/wiki/Bigram
ENG_BIGRAMS = [
    'th', 'he', 'in', 'er', 'an', 're', 'nd', 'at',
    'on', 'nt', 'ha', 'es', 'st', 'en', 'ed', 'to'
]

# The top 16 double letter frequencies in English.
# https://blogs.sas.com/content/iml/2014/10/03/double-letter-bigrams.html
ENG_DOUBLE = 'lseotfprmcndgiba'

# Terminal colour codes
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
NC = '\033[0m'


def n_grams(s, n=3):
    '''
    Get all trigrams from a string. (triplets of alpha-numeric characters)
    See link with eng_trigrams for more information.
    '''
    s = s.lower()
    t = [s[k:k+n] for k in range(len(s) - n - 1)]
    t = [cand for cand in t if all(c in ascii_lowercase for c in cand)]
    return [c[0] for c in Counter(t).most_common(16)]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t', '--trans',
        default='',
        help='Comma separated translation pairs.'
    )
    parser.add_argument(
        '--fulltrans',
        action='store_true',
        help='Attempt a full translation using raw freq analysis.'
    )
    parser.add_argument(
        '--highlowtrans',
        action='store_true',
        help='Attempt a full translation using raw freq analysis.'
    )
    parser.add_argument(
        '--ngrams',
        action='store_true',
        help='Show bigram frequencies.'
    )
    parser.add_argument(
        '--doubles',
        action='store_true',
        help='Show double letter frequencies.'
    )
    args = parser.parse_args()

    ciphertext = sys.stdin.read()
    chars = [c for c in ciphertext.lower() if c in ascii_lowercase]

    if args.ngrams:
        # Show bigram and trigram ranks
        buff_1, buff_2 = [], []
        bigrams = n_grams(ciphertext, 2)
        trigrams = n_grams(ciphertext, 3)

        buff_1.append('{}[+] Bigram frequency rank{}'.format(YELLOW, NC))
        buff_1.append('{}========================={}'.format(YELLOW, NC))
        for result in zip(bigrams, ENG_BIGRAMS):
            buff_1.append('      %s -> %s' % result)

        buff_2.append('{}[+] Trigram frequency rank{}'.format(YELLOW, NC))
        buff_2.append('{}=========================={}'.format(YELLOW, NC))
        for result in zip(trigrams, ENG_TRIGRAMS):
            buff_2.append('                  %s -> %s' % result)

        for b1, b2 in zip(buff_1, buff_2):
            print(b1, '  ', b2)
        print('')

    if args.doubles:
        doubles = Counter()
        prev = ciphertext[0]
        for c in ciphertext[1:]:
            if c == prev:
                doubles[c.lower()] += 1
            prev = c
        doubles = [d[0] for d in doubles.most_common(16)]
        print('{}[+] Double Letter frequency rank{}'.format(YELLOW, NC))
        print('{}================================{}'.format(YELLOW, NC))
        print('  English:\t', ENG_DOUBLE)
        print('  Ciphertext:\t', ''.join(doubles), '\n')

    # Run character frequency analysis
    freqs = Counter(chars)
    for char in freqs:
        freqs[char] = round(freqs[char] / len(chars), 4)

    for a in ascii_lowercase:
        if a not in freqs:
            freqs[a] = 0

    ranked = [r[0] for r in freqs.most_common()]

    print('{}[+] Single Letter frequency rank{}'.format(YELLOW, NC))
    print('{}================================{}'.format(YELLOW, NC))
    print('  English:\t', ETAOIN)
    print('  Ciphertext:\t', ''.join(ranked))

    if args.fulltrans:
        print('')
        print(('{}[!] Assume that the frequencies match'
               ' perfectly to etaoin{}').format(YELLOW, NC))
        print(('{}====================================='
               '===================={}').format(YELLOW, NC))
        t_map = dict(zip(ranked, ETAOIN))
        print(''.join(t_map.get(c, c) for c in ciphertext.lower()))

    elif args.highlowtrans:
        # Only take the top/bottom 6 from etaoin
        print('')
        print(('{}[+] Translate only the top/bottom'
               ' 6 letters from etaoin{}').format(YELLOW, NC))
        print(('{}================================='
               '======================{}').format(YELLOW, NC))
        hl_ranked = ranked[:7] + ranked[-6:]
        hl_etaoin = ETAOIN[:7] + ETAOIN[-6:]
        t_map = {
            p[0]: GREEN + p[1].upper() + NC
            for p in zip(hl_ranked, hl_etaoin)
        }
        print(''.join(
            t_map.get(c, RED + c + NC)
            for c in ciphertext.lower())
        )

    elif args.trans:
        # User specified translation
        pairs = args.trans.split(',')
        print('')
        print('{}[+] Running user specified translation'.format(YELLOW, NC))
        print('{}======================================'.format(YELLOW, NC))
        t_map = {p[0]: GREEN + p[1].upper() + NC for p in pairs}
        print(''.join(
            t_map.get(c, RED + c + NC)
            for c in ciphertext.lower())
        )
