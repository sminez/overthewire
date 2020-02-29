"""
The random number generator seems to be a bit crap and always uses the same
offset at each character position in the cipher text. We can build up a
translation map showing what each character get mapped to in each position of
the cipher text and then work backwords to the plain text from there.

It looks like the method being used for this is a LSFR.
>>> https://en.wikipedia.org/wiki/Linear-feedback_shift_register
"""
from subprocess import call
from string import ascii_uppercase


DIR_NAME = "/tmp/sminez88_krypton6/"
CIPHER_TEXT = "PNUKLYLWRQKGKBE"
RUN_ENCRYTION = False


if RUN_ENCRYTION:
    # Try the whole alphabet
    fname = DIR_NAME + "alphabet"
    with open(fname, "w") as f:
        f.write(ascii_uppercase)
    call(["/krypton/krypton6/encrypt6", fname, fname + "_out"])

    # Try all each character
    for char in ascii_uppercase:
        # Write out the plain-text
        fname = DIR_NAME + char
        with open(fname, "w") as f:
            # The cipher text is 15 characters long
            f.write(char * 15)

        call(["/krypton/krypton6/encrypt6", fname, fname + "_out"])

# Now check the results
ct_map = {}

# Show the whole alphabet result
print(ascii_uppercase)
with open(DIR_NAME + "alphabet_out", "r") as f:
    print(f.read())

# Show the individual character results
for char in ascii_uppercase:
    with open(DIR_NAME + char + "_out", "r") as f:
        ct_map[char] = f.read().strip()
        print(char, "-->", ct_map[char])

# To work back, we want to check each index for the character
# in the cipher text and match it to the character than generated it.
for ix, char in enumerate(CIPHER_TEXT):
    for pt_char, indicies in ct_map.items():
        if indicies[ix] == char:
            print(pt_char, end="")
            break
print("")
# Answer is: LFSRISNOTRANDOM
