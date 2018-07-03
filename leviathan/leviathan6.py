'''
Simple brute force of the passcode
'''
from itertools import permutations
from subprocess import check_output


# Generate all 4-digit codes
four_digit_codes = permutations(range(10), 4)

for ix, code in enumerate(four_digit_codes):
    str_code = ''.join(str(c) for c in code)
    result = check_output(['/home/leviathan6/leviathan6', str_code])
    if b'Wrong' not in result:
        print(code)
        print(result)

    if ix % 10 == 0:
        print('.', end='')
