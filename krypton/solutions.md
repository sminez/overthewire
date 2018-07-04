krypton
-------

### lvl-0
Welcome to Krypton! The first level is easy. The following string encodes the
password using Base64:

S1JZUFRPTklTR1JFQVQ=

Use this password to log in to krypton.labs.overthewire.org with username
krypton1 using SSH on port 2222. You can find the files for other levels in
/krypton/

```bash
$ echo 'S1JZUFRPTklTR1JFQVQ=' | base64 -d
KRYPTONISGREAT
```

or in python:
```python
>>> import base64
>>> base64.decodebytes(b'S1JZUFRPTklTR1JFQVQ=' )
KRYPTONISGREAT
```

### lvl-1

Welcome to Krypton!

This game is intended to give hands on experience with cryptography and
cryptanalysis.  The levels progress from classic ciphers, to modern, easy to
harder.

Although there are excellent public tools, like cryptool,to perform the simple
analysis, we strongly encourage you to try and do these without them for now.
We will use them in later excercises.

** Please try these levels without cryptool first **


The first level is easy.  The password for level 2 is in the file 'krypton2'.
It is 'encrypted' using a simple rotation called ROT13.  It is also in
non-standard ciphertext format.  When using alpha characters for cipher text it
is normal to group the letters into 5 letter clusters, regardless of word
boundaries.  This helps obfuscate any patterns.

This file has kept the plain text word boundaries and carried them to the cipher
text.

Enjoy!

```bash
krypton1@krypton:~$ cat /krypton/krypton1/krypton2 
YRIRY GJB CNFFJBEQ EBGGRA


krypton1@krypton:~$ cat /krypton/krypton1/krypton2 | tr '[A-Za-z]' '[N-ZA-Mn-za-m]'
LEVEL TWO PASSWORD ROTTEN
```
ROTTEN

### lvl-2

ROT13 is a simple substitution cipher.

Substitution ciphers are a simple replacement algorithm.  In this example of a
substitution cipher, we will explore a 'monoalphebetic' cipher.  Monoalphebetic
means, literally, "one alphabet" and you will see why.

This level contains an old form of cipher called a 'Caesar Cipher'.  A Caesar
cipher shifts the alphabet by a set number.  For example:

plain:	a b c d e f g h i j k ...  cipher:	G H I J K L M N O P Q ...

In this example, the letter 'a' in plaintext is replaced by a 'G' in the
ciphertext so, for example, the plaintext 'bad' becomes 'HGJ' in ciphertext.

The password for level 3 is in the file krypton3.  It is in 5 letter group
ciphertext.  It is encrypted with a Caesar Cipher.  Without any further
information, this cipher text may be difficult to break.  You do not have direct
access to the key, however you do have access to a program that will encrypt
anything you wish to give it using the key.  If you think logically, this is
completely easy.

One shot can solve it!

Have fun.

Additional Information:

The `encrypt` binary will look for the keyfile in your current working
directory. Therefore, it might be best to create a working direcory in /tmp and
in there a link to the keyfile. As the `encrypt` binary runs setuid `krypton3`,
you also need to give `krypton3` access to your working directory.

Here is an example:

```bash
krypton2@melinda:~$ mktemp -d
/tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:~$ cd /tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ln -s /krypton/krypton2/keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ chmod 777 .
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ /krypton/krypton2/encrypt /etc/issue
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
ciphertext  keyfile.dat
```

OK, so we have access to the encryption program so encrypt something easy and
run it through `tr`:
```bash
# From within /krypton/krypton2/
$ ./encrypt 
 usage: encrypt foo  - where foo is the file containing the plaintext

$ mkdir /tmp/sminez88_tmp
$ echo "AZaz" >> /tmp/sminez88_tmp/plaintext
$ ./encrypt  /tmp/sminez88_tmp/plaintext
failed to create cipher file 

# Maybe follow the instructions...
$ cd /tmp/sminez88_tmp
$ ln -s /krypton/krypton2/keyfile.dat
$ chmod 777 .
$ /krypton/krypton2/encrypt plaintext
$ ls
ciphertext  plaintext  keyfile.dat
$ cat ciphertext 
MLML
# So we want tr '[M-ZA-Lm-za-l]' '[A-Za-z]'  to reverse it
$ cat /krypton/krypton2/krypton3 | tr '[M-ZA-Lm-za-l]' '[A-Za-z]'
CAESARISEASY
```

### lvl-3

Well done. You've moved past an easy substitution cipher.

Hopefully you just encrypted the alphabet a plaintext to fully expose the key in
one swoop.

The main weakness of a simple substitution cipher is repeated use of a simple
key. In the previous exercise you were able to introduce arbitrary plaintext to
expose the key. In this example, the cipher mechanism is not available to you,
the attacker.

However, you have been lucky.  You have intercepted more than one message.  The
password to the next level is found in the file 'krypton4'.  You have also found
3 other files. (found1, found2, found3)

You know the following important details:

- The message plaintexts are in English (*** very important)
- They were produced from the same key (*** even better!)


Enjoy.

#### Ciphertext additional messages
Given that we have the same key each time AND that it's in English...freq
analysis time!
```bash
$ cat found1 
CGZNL YJBEN QYDLQ ZQSUQ NZCYD SNQVU BFGBK GQUQZ QSUQN UZCYD SNJDS UDCXJ ZCYDS
NZQSU QNUZB WSBNZ QSUQN UDCXJ CUBGS BXJDS UCTYV SUJQG WTBUJ KCWSV LFGBK GSGZN
LYJCB GJSZD GCHMS UCJCU QJLYS BXUMA UJCJM JCBGZ CYDSN CGKDC ZDSQZ DVSJJ SNCGJ
DSYVQ CGJSO JCUNS YVQZS WALQV SJJSN UBTSX COSWG MTASN BXYBU CJCBG UWBKG JDSQV
YDQAS JXBNS OQTYV SKCJD QUDCX JBXQK BMVWA SNSYV QZSWA LWAKB MVWAS ZBTSS QGWUB
BGJDS TSJDB WCUGQ TSWQX JSNRM VCMUZ QSUQN KDBMU SWCJJ BZBTT MGCZQ JSKCJ DDCUE
SGSNQ VUJDS SGZNL YJCBG UJSYY SNXBN TSWAL QZQSU QNZCY DSNCU BXJSG CGZBN YBNQJ
SWQUY QNJBX TBNSZ BTYVS OUZDS TSUUM ZDQUJ DSICE SGNSZ CYDSN QGWUJ CVVDQ UTBWS
NGQYY VCZQJ CBGCG JDSNB JULUJ STQUK CJDQV VUCGE VSQVY DQASJ UMAUJ CJMJC BGZCY
DSNUJ DSZQS UQNZC YDSNC USQUC VLANB FSGQG WCGYN QZJCZ SBXXS NUSUU SGJCQ VVLGB
ZBTTM GCZQJ CBGUS ZMNCJ LUDQF SUYSQ NSYNB WMZSW TBUJB XDCUF GBKGK BNFAS JKSSG
QGWDC USQNV LYVQL UKSNS TQCGV LZBTS WCSUQ GWDCU JBNCS UESGN SUDSN QCUSW JBJDS
YSQFB XUBYD CUJCZ QJCBG QGWQN JCUJN LALJD SSGWB XJDSU COJSS GJDZS GJMNL GSOJD
SKNBJ STQCG VLJNQ ESWCS UMGJC VQABM JCGZV MWCGE DQTVS JFCGE VSQNQ GWTQZ ASJDZ
BGUCW SNSWU BTSBX JDSXC GSUJS OQTYV SUCGJ DSSGE VCUDV QGEMQ ESCGD CUVQU JYDQU
SDSKN BJSJN QECZB TSWCS UQVUB FGBKG QUNBT QGZSU QGWZB VVQAB NQJSW KCJDB JDSNY
VQLKN CEDJU TQGLB XDCUY VQLUK SNSYM AVCUD SWCGS WCJCB GUBXI QNLCG EHMQV CJLQG
WQZZM NQZLW MNCGE DCUVC XSJCT SQGWC GJKBB XDCUX BNTSN JDSQJ NCZQV ZBVVS QEMSU
YMAVC UDSWJ DSXCN UJXBV CBQZB VVSZJ SWSWC JCBGB XDCUW NQTQJ CZKBN FUJDQ JCGZV
MWSWQ VVAMJ JKBBX JDSYV QLUGB KNSZB EGCUS WQUUD QFSUY SQNSU

$ cat found2 
QVJDB MEDGB QJJSG WQGZS NSZBN WUXBN JDSYS NCBWU MNICI STBUJ ACBEN QYDSN UQENS
SJDQJ UDQFS UYSQN SKQUS WMZQJ SWQJJ DSFCG EUGSK UZDBB VCGUJ NQJXB NWQXN SSUZD
BBVZD QNJSN SWCGQ ABMJQ HMQNJ SNBXQ TCVSX NBTDC UDBTS ENQTT QNUZD BBVUI QNCSW
CGHMQ VCJLW MNCGE JDSSV CPQAS JDQGS NQAMJ JDSZM NNCZM VMTKQ UWCZJ QJSWA LVQKJ
DNBME DBMJS GEVQG WQGWJ DSUZD BBVKB MVWDQ ISYNB ICWSW QGCGJ SGUCI SSWMZ QJCBG
CGVQJ CGENQ TTQNQ GWJDS ZVQUU CZUQJ JDSQE SBXUD QFSUY SQNST QNNCS WJDSL SQNBV
WQGGS DQJDQ KQLJD SZBGU CUJBN LZBMN JBXJD SWCBZ SUSBX KBNZS UJSNC UUMSW QTQNN
CQESV CZSGZ SBGGB ISTAS NJKBB XDQJD QKQLU GSCED ABMNU YBUJS WABGW UJDSG SOJWQ
LQUUM NSJLJ DQJJD SNSKS NSGBC TYSWC TSGJU JBJDS TQNNC QESJD SZBMY VSTQL DQISQ
NNQGE SWJDS ZSNST BGLCG UBTSD QUJSU CGZSJ DSKBN ZSUJS NZDQG ZSVVB NQVVB KSWJD
STQNN CQESA QGGUJ BASNS QWBGZ SCGUJ SQWBX JDSMU MQVJD NSSJC TSUQG GSUYN SEGQG
ZLZBM VWDQI SASSG JDSNS QUBGX BNJDC UUCOT BGJDU QXJSN JDSTQ NNCQE SUDSE QISAC
NJDJB QWQME DJSNU MUQGG QKDBK QUAQY JCUSW BGTQL JKCGU UBGDQ TGSJQ GWWQM EDJSN
RMWCJ DXBVV BKSWQ VTBUJ JKBLS QNUVQ JSNQG WKSNS AQYJC USWBG XSANM QNLDQ TGSJW
CSWBX MGFGB KGZQM USUQJ JDSQE SBXQG WKQUA MNCSW BGQME MUJQX JSNJD SACNJ DBXJD
SJKCG UJDSN SQNSX SKDCU JBNCZ QVJNQ ZSUBX UDQFS UYSQN SMGJC VDSCU TSGJC BGSWQ
UYQNJ BXJDS VBGWB GJDSQ JNSUZ SGSCG ASZQM USBXJ DCUEQ YUZDB VQNUN SXSNJ BJDSL
SQNUA SJKSS GQGWQ UUDQF SUYSQ NSUVB UJLSQ NUACB ENQYD SNUQJ JSTYJ CGEJB QZZBM
GJXBN JDCUY SNCBW DQISN SYBNJ SWTQG LQYBZ NLYDQ VUJBN CSUGC ZDBVQ UNBKS UDQFS
UYSQN SUXCN UJACB ENQYD SNNSZ BMGJS WQUJN QJXBN WVSES GWJDQ JUDQF SUYSQ NSXVS
WJDSJ BKGXB NVBGW BGJBS UZQYS YNBUS ZMJCB GXBNW SSNYB QZDCG EQGBJ DSNSC EDJSS
GJDZS GJMNL UJBNL DQUUD QFSUY SQNSU JQNJC GEDCU JDSQJ NCZQV ZQNSS NTCGW CGEJD
SDBNU SUBXJ DSQJN SYQJN BGUCG VBGWB GRBDG QMANS LNSYB NJSWJ DQJUD QFSUY SQNSD
QWASS GQZBM GJNLU ZDBBV TQUJS NUBTS JKSGJ CSJDZ SGJMN LUZDB VQNUD QISUM EESUJ
SWJDQ JUDQF SUYSQ NSTQL DQISA SSGST YVBLS WQUQU ZDBBV TQUJS NALQV SOQGW SNDBE
DJBGB XVQGZ QUDCN SQZQJ DBVCZ VQGWB KGSNK DBGQT SWQZS NJQCG KCVVC QTUDQ FSUDQ
XJSCG DCUKC VVGBS ICWSG ZSUMA UJQGJ CQJSU UMZDU JBNCS UBJDS NJDQG DSQNU QLZBV
VSZJS WQXJS NDCUW SQJD

$ cat found3
DSNSM YBGVS ENQGW QNBUS KCJDQ ENQIS QGWUJ QJSVL QCNQG WANBM EDJTS JDSAS SJVSX
NBTQE VQUUZ QUSCG KDCZD CJKQU SGZVB USWCJ KQUQA SQMJC XMVUZ QNQAQ SMUQG WQJJD
QJJCT SMGFG BKGJB GQJMN QVCUJ UBXZB MNUSQ ENSQJ YNCPS CGQUZ CSGJC XCZYB CGJBX
ICSKJ DSNSK SNSJK BNBMG WAVQZ FUYBJ UGSQN BGSSO JNSTC JLBXJ DSAQZ FQGWQ VBGEB
GSGSQ NJDSB JDSNJ DSUZQ VSUKS NSSOZ SSWCG EVLDQ NWQGW EVBUU LKCJD QVVJD SQYYS
QNQGZ SBXAM NGCUD SWEBV WJDSK SCEDJ BXJDS CGUSZ JKQUI SNLNS TQNFQ AVSQG WJQFC
GEQVV JDCGE UCGJB ZBGUC WSNQJ CBGCZ BMVWD QNWVL AVQTS RMYCJ SNXBN DCUBY CGCBG
NSUYS ZJCGE CJ

$ cat krypton4
KSVVW BGSJD SVSIS VXBMN YQUUK BNWCU ANMJS
```

So, after a lot of trial and error (and finally remembering to check the
password cipher text as well...!) I've got it! The `fa.py` script turned out
rather nicely as a little util for tinkering with this sort of thing.

```bash
$ cat lvl3/krypton4 | ./fa.py -t jt,dh,se,hq,mu,vl,bo,kw,iv,wd,gn,xf,nr,yp,qa,us,ci,fk,ab,eg,zc,ly,tm,ox,rj,pk 
[+] Single Letter frequency rank
================================
  English:	 etaoinshrdlcumwfgypbvkjxqz
  Ciphertext:	 svbunjmwkdycxgqiarhozptfle

[+] Running user specified translation
======================================
WELLD ONETH ELEVE LFOUR PASSW ORDIS BRUTE
```
WELL DONE THE LEVEL FOUR PASSWORD IS BRUTE

### lvl-4
Good job!

You more than likely used frequency analysis and some common sense to solve that
one.

So far we have worked with simple substitution ciphers.  They have also been
'monoalphabetic', meaning using a fixed key, and giving a one to one mapping of
plaintext (P) to ciphertext (C).  Another type of substitution cipher is
referred to as 'polyalphabetic', where one character of P may map to many, or
all, possible ciphertext characters.

An example of a polyalphabetic cipher is called a Vigenere Cipher.  It works
like this:

If we use the key(K)  'GOLD', and P = PROCEED MEETING AS AGREED, then "add" P to
K, we get C.  When adding, if we exceed 25, then we roll to 0 (modulo 26).


P     P R O C E   E D M E E   T I N G A   S A G R E   E D
K     G O L D G   O L D G O   L D G O L   D G O L D   G O

becomes:

P     15 17 14 2  4  4  3 12  4 4  19  8 13 6  0  18 0  6 17 4 4   3
K     6  14 11 3  6 14 11  3  6 14 11  3  6 14 11  3 6 14 11 3 6  14
C     21 5  25 5 10 18 14 15 10 18  4 11 19 20 11 21 6 20  2 8 10 17

So, we get a ciphertext of:

VFZFK SOPKS ELTUL VGUCH KR

This level is a Vigenere Cipher.  You have intercepted two longer, English
language messages.  You also have a key piece of information. You know the key
length!

For this exercise, the key length is 6. The password to level five is in the
usual place, encrypted with the 6 letter key.

Have fun!

#### Solution
OK, this one is fun! I've revised my cracker from when I gave Cryptopals a try
a year or two ago and have modified it to use Vigenere. At the moment it takes
a known key length or a specific key: if given a key length it will try to find
the most likely key using frequency analysis of the generated plain text.
If given a key, it will use that to attempt decryption.
At the moment, it strips out spaces in the input and assumes that we are working
only with uppercase ASCII in the cipher text.
```bash
# Try with the first file
$ cat lvl4/found1 | ./repkey.py -l 6
VJWQWC
# And the second
$ cat lvl4/found1 | ./repkey.py -l 6
VJWQWC
# Same key each time, lets try it!
$ cat lvl4/krypton5 | ./repkey.py -k VJWQWC
CLEARTEXT
```

### lvl-5
Frequency analysis can break a known key length as well.  Lets try one
last polyalphabetic cipher, but this time the key length is unknown.


Enjoy.

...so, looks like adding in the keylen finder happens now! :D

```bash
$ cat lvl5/found1 | ./repkey.py --auto 10
[+] Attempting to determine most likely key length...

[+] Levenshtein distances (lower is more likely)
================================================
  3: 5.333333333333333
  2: 5.5
  6: 5.5
  7: 5.571428571428571
  9: 5.666666666666667
  10: 5.7
  8: 5.875
  1: 6.0
  4: 6.0
  5: 6.0


[+] Attempting keysize 3... 
===================================
key :  QWN
score :  26104
chi-squared :  130.1881554886363

[+] Attempting keysize 2... 
===================================
key :  WW
score :  23307
chi-squared :  291.5638521072484

[+] Attempting keysize 6... 
===================================
key :  PWNQWN
score :  26149
chi-squared :  123.56967004187594

[+] Attempting keysize 7... 
===================================
key :  WHQDWWN
score :  23691
chi-squared :  248.95323585084589

[+] Attempting keysize 9... 
===================================
key :  QWCPWNUHT
score :  30649
chi-squared :  2.470823582723844

[+] Most likely key is QWCPWNUHT (length: 9)

ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGE...

$ cat lvl5/krypton5 | ./repkey.py -k QWCPWNUHT
RANDOM
```

### lvl-6
Oooooh...this time there is a binary and a dir called `onetime`...! The README
has the following in it:

Hopefully by now its obvious that encryption using repeating keys is a bad idea.
Frequency analysis can destroy repeating/fixed key substitution crypto.

A feature of good crypto is random ciphertext. A good cipher must not reveal
any clues about the plaintext. Since natural language plaintext (in this case,
English) contains patterns, it is left up to the encryption key or the
encryption algorithm to add the 'randomness'.

Modern ciphers are similar to older plain substitution ciphers, but improve the
'random' nature of the key.

An example of an older cipher using a complex, random, large key is a vigniere
using a key of the same size of the plaintext. For example, imagine you and
your confident have agreed on a key using the book 'A Tale of Two Cities' as
your key, in 256 byte blocks.

The cipher works as such:

Each plaintext message is broken into 256 byte blocks. For each block of
plaintext, a corresponding 256 byte block from the book is used as the key,
starting from the first chapter, and progressing.  No part of the book is ever
re-used as key. The use of a key of the same length as the plaintext, and only
using it once is called a "One Time Pad".

Look in the krypton6/onetime  directory. You will find a file called 'plain1',
a 256 byte block. You will also see a file 'key1', the first 256 bytes of 'A
Tale of Two Cities'. The file 'cipher1' is the cipher text of plain1.  As you
can see (and try) it is very difficult to break the cipher without the key
knowledge.

(NOTE - it is possible though.  Using plain language as a one time pad key has a
weakness. As a secondary challenge, open README in that directory)

If the encryption is truly random letters, and only used once, then it is
impossible to break. A truly random "One Time Pad" key cannot be broken.
Consider intercepting a ciphertext message of 1000 bytes. One could brute force
for the key, but due to the random key nature, you would produce every single
valid 1000 letter plaintext as well. Who is to know which is the real
plaintext?!?

Choosing keys that are the same size as the plaintext is impractical.
Therefore, other methods must be used to obscure ciphertext against frequency
analysis in a simple substitution cipher. The impracticality of an 'infinite'
key means that the randomness, or entropy, of the encryption is introduced via
the method.

We have seen the method of 'substitution'. Even in modern crypto, substitution
is a valid technique. Another technique is 'transposition', or swapping of
bytes.

Modern ciphers break into two types; symmetric and asymmetric.

Symmetric ciphers come in two flavours: block and stream.

Until now, we have been playing with classical ciphers, approximating 'block'
ciphers. A block cipher is done in fixed size blocks (suprise!). For example,
in the previous paragraphs we discussed breaking text and keys into 256 byte
blocks, and working on those blocks. Block ciphers use a fixed key to perform
substitution and transposition ciphers on each block discretely.

Its time to employ a stream cipher. A stream cipher attempts to create an
on-the-fly 'random' keystream to encrypt the incoming plaintext one byte at a
time.  Typically, the 'random' key byte is xor'd with the plaintext to produce
the ciphertext. If the random keystream can be replicated at the receiving end,
then a further xor will produce the plaintext once again.

From this example forward, we will be working with bytes, not ASCII text, so a
hex editor/dumper like hexdump is a necessity. Now is the right time to start
to learn to use tools like cryptool.

In this example, the keyfile is in your directory, however it is not readable by
you.  The binary 'encrypt6' is also available.  It will read the keyfile and
encrypt any message you desire, using the key AND a 'random' number.  You get to
perform a 'known ciphertext' attack by introducing plaintext of your choice.
The challenge here is not simple, but the 'random' number generator is weak.

As stated, it is now that we suggest you begin to use public tools, like
cryptool, to help in your analysis.  You will most likely need a hint to get
going.  See 'HINT1' if you need a kick start.

If you have further difficulty, there is a hint in 'HINT2'.

The password for level 7 (krypton7) is encrypted with 'encrypt6'.

Good Luck!
