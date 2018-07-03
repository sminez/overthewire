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
# http://letterfrequency.org/
ENG_DOUBLE = 'setflmo'

# Terminal colour codes
BLACK = '\033[0;30m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLACKBG = '\033[0;40m'
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
        '--ngrams',
        action='store_true',
        help='Show bigram frequencies.'
    )
    parser.add_argument(
        '--doubles',
        action='store_true',
        help='Show double letter frequencies.'
    )
    parser.add_argument(
        '--black',
        action='store_true',
        help='Render remaining ciphertext in black.'
    )
    args = parser.parse_args()

    ciphertext = sys.stdin.read()
    chars = [c for c in ciphertext.lower() if c in ascii_lowercase]

    if args.ngrams:
        # Show bigram and trigram ranks
        buff_1, buff_2 = [], []
        bigrams = n_grams(ciphertext, 2)
        trigrams = n_grams(ciphertext, 3)

        # NOTE: Working with two buffers to allow us to place the results
        #       side by side when printing to the screen.
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
        # Check the frequency of double letters
        doubles = Counter()
        prev = ciphertext[0]
        for c in ciphertext[1:]:
            if c == prev:
                doubles[c.lower()] += 1
            prev = c
        doubles = [d[0] for d in doubles.most_common(len(ENG_DOUBLE))]
        print('{}[+] Double Letter frequency rank{}'.format(YELLOW, NC))
        print('{}================================{}'.format(YELLOW, NC))
        print('  English:\t', ENG_DOUBLE)
        print('  Ciphertext:\t', ''.join(doubles), '\n')

    # Run single character frequency analysis
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

    # Set the foreground colour for remaining ciphertext
    fg = BLACK if args.black else RED

    if args.trans:
        # User specified translation
        pairs = args.trans.split(',')
        print('')
        print('{}[+] Running user specified translation'.format(YELLOW, NC))
        print('{}======================================'.format(YELLOW, NC))

        # Form the translation map
        t_map = {}
        for k, v in pairs:
            # Make sure we haven't seen either the key or value yet
            if k in t_map:
                print('{}[!] Repeated translation key found: {}{}'.format(
                    RED, k, NC))
                sys.exit(42)
            elif v in t_map.values():
                print('{}[!] Repeated translation target found: {}{}'.format(
                    RED, v, NC))
                sys.exit(42)

            # OK to add to the map, printing in green caps
            t_map[k] = GREEN + v.upper() + NC

        remaining = [c for c in ascii_lowercase if c not in t_map]
        if remaining:
            print('{}[ ] Remaining characters: {}{}\n'.format(
                BLACKBG, ''.join(remaining), NC
            ))

        print(''.join(
            t_map.get(c, fg + c + NC)
            for c in ciphertext.lower())
        )
