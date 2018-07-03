Bandit
------
http://overthewire.org/wargames/bandit/

- Connections are `ssh banditX@bandit.labs.overthewire.org -p 2220`
- Passwords/ssh-keys are found for the next level.
- First password is `bandit0`

### lvl-0
Just in the readme file
```bash
$ cat readme
```
boJ9jbbUNNfktd78OOpsqOltutMc3MY1

### lvl-1
Cat the single file in home. Requires `./` before the filename as there is a
special char (- == stdin).
```bash
$ cat ./-
```
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9

### lvl-2
Escape spaces in filenames.
```bash
$ cat spaces\ in\ this\ filename
```
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK

### lvl-3
Hidden files.
```bash
cat inhere/.hidden
```
pIwrPrtPN36QITSp3EQaw936yaFoFgAB

### lvl-4
Only one non-binary file, all have a `-` prefix.
```bash
$ for f in $(ls inhere); do
    cat inhere/$f;
    echo "";  # Line break to clear up the binary mess
  done;
```
koReBOKuIDDepwhWk7jZC0RTdopnAYKh

### lvl-5
Lots of directories to check for a file with the following spec:
  * human-readable
  * 1033 bytes in size
  * not executable
```bash
$ find inhere -type f -size 1033c ! -executable | xargs cat
```
DXjZPULLxYr17uwoI01bNLQbtFemEgo7

### lvl-6
Pwd is somewhere on the server with:
  * user bandit7
  * usergroup bandit6
  * 33 bytes in size
```bash
$ find / -type f -group bandit6 -user bandit7 -size 33c
```
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs

### lvl-7
Pwd is in data.txt next to the word `millionth`
```bash
$ grep millionth data.txt | cut -f2
```
cvX2JJa4CFALtqS87jk27qwqGhBM9plV

### lvl-8
Only unique line in data.txt
```bash
$ cat data.txt | sort | uniq -u  # uniq requires the input to be sorted
```
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR

### lvl-9
In data.txt as one of the few human-readable strings, prefixed with several `=`
characters. (NOTE: This solution uses the `strings` program that prints each of
the human-readable strings from within a file.)
```bash
$ strings data.txt | grep "^==" | cut -d' ' -f2 | tail -1
```
truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk

### lvl-10
The password is in data.txt and base64 encoded.
```bash
$ base64 -d data.txt
```
IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR

### lvl-11
data.txt is rot13. `tr` takes an input character set and an output set; they
must be the same length and they form a 1-1 map.
```bash
cat data.txt | tr '[A-Za-z]' '[N-ZA-Mn-za-m]'
```
5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

### lvl-12
data.txt is a hex-dump of a file that has been repeatedly compressed.
- You can find the header formats in the descriptions:
  * Zip (.zip) format description, starts with 0x50, 0x4b, 0x03, 0x04
      (unless empty — then the last two are 0x05, 0x06 or 0x06, 0x06)
  * Gzip (.gz) format description, starts with 0x1f, 0x8b, 0x08
  * xz (.xz) format description, starts with 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00
  * bzip2 (.bz2) starts with 0x42, 0x5a, 0x68

```bash
$ mkdir /tmp/sminez88
$ cp data.txt /tmp/sminez88/
$ cd /tmp/sminez88
$ xxd -r data.txt > data2.bin  # xxd creates/reverts hex-dumps
$ file data2.bin  # `file` will give you file details. If that fails for some reason then (for compressed files)
                  # look at the hex-dump and consult the table above concerning headers.
data2.bin: gzip compressed data, was "data2.bin", last modified: Thu Dec 28 13:34:36 2017, max compression, from Unix
$ gunzip data2.bin -S .bin  # -S forces the suffix to be accepted if it is non-standard
$ file data2
data2: bzip2 compressed data, block size = 900k
$ bzip2 -d data2
$ gunzip data2.out -S .out
$ file data2
data2: POSIX tar archive (GNU)
$ tar -xf data2
$ file data5.bin 
data5.bin: POSIX tar archive (GNU)
$ tar -xf data5.bin
$ file data6.bin
data6.bin: bzip2 compressed data, block size = 900k
$ bzip2 -d data6.bin
$ file data6.bin.out
data6.bin.out: POSIX tar archive (GNU)
$ tar -xf data6.bin.out
$ file data8.bin 
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu Dec 28 13:34:36 2017, max compression, from Unix
$ gunzip data8.bin -S .bin
$ cat data8
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL
```

### lvl-13
No password this time but an ssh key to log in as bandit14 to access the next
password in
```bash
$ ssh -i sshkey.private bandit14@localhost
$ cat  /etc/bandit_pass/bandit14
```
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e

### lvl-14
The password for the next level can be retrieved by submitting the password of
the current level to port 30000 on localhost. (Several options but nc/netcat is
the simplest.)
```bash
$ echo "4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e" | nc localhost 30000
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr
```

### lvl-15
Same idea as lvl-14 but this time over ssl and on port 30001. We need to use the
`-ign_eof` flag to keep the connection alive when EOF is reached in the input so
we can receive the response from the server. (`-quiet` implicitly turns on
`ign_eof` as well but also removes debug output).
```bash
$ echo "BfMYroe26WYalil77FoDi9qh59eK5xNr" | openssl s_client -connect localhost:30001 -quiet  
depth=0 CN = bandit
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = bandit
verify return:1
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd
```

### lvl-16
The credentials for the next level can be retrieved by submitting the password
of the current level to a port on localhost in the range 31000 to 32000. Some of
the servers are on SSL and only one gives the next password, the others are echo
servers.

```bash
$ nmap -sT localhost -p 31000-32000

Starting Nmap 7.01 ( https://nmap.org ) at 2018-07-02 11:17 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00019s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 996 closed ports
PORT      STATE SERVICE
31046/tcp open  unknown
31518/tcp open  unknown
31691/tcp open  unknown
31790/tcp open  unknown
31960/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds

$ for port in 31046 31518 31691 31790 31960; do
$   echo $port;
$   echo "cluFn7wTiGryunymYOu4RcffSxQluehd" | nc localhost $port;
$ done;

31046
cluFn7wTiGryunymYOu4RcffSxQluehd
31518
31691
cluFn7wTiGryunymYOu4RcffSxQluehd
31790
31960
cluFn7wTiGryunymYOu4RcffSxQluehd

$ echo "cluFn7wTiGryunymYOu4RcffSxQluehd" | openssl s_client -connect localhost:31518 -quiet
depth=0 CN = bandit
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = bandit
verify return:1
cluFn7wTiGryunymYOu4RcffSxQluehd

$ echo "cluFn7wTiGryunymYOu4RcffSxQluehd" | openssl s_client -connect localhost:31790 -quiet
depth=0 CN = bandit
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = bandit
verify return:1
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
```

### lvl-17
Copy the ssh-key details into a file and then `chmod 600` it to connect to the
next host.
There are 2 files in the home directory: passwords.old and passwords.new. The
password for the next level is in passwords.new and is the only line that has
been changed between passwords.old and passwords.new.
```bash
$ diff passwords.old passwords.new 
42c42
< 6vcSC74ROI95NqkKaeEC2ABVMDX9TyUr
---
> kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd
```
kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd

### lvl-18
The .bashrc file for this user is set up log you out when you connect over SSH.
The password is in a file called `readme` in the home directory
```bash
$ ssh bandit18@bandit.labs.overthewire.org -p 2220 'cat readme'
```
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x

### lvl-19
There is a setuid binary in the home directory. It lets you run a command as
`bandit20`. The password can be found in the normal `/etc/banditpass` directory.
```bash
$ ./bandit20-do cat /etc/bandit_pass/bandit20
```
GbKksEFF4yrVs6il55v6gwY5aVje5f0j

### lvl-20
There is a setuid binary in the home-directory that does the following: it makes
a connection to localhost on the port you specify as a command-line argument. It
then reads a line of text from the connection and compares it to the password in
the previous level (bandit20). If the password is correct, it will transmit the
password for the next level (bandit21).
```bash
# Each command running inside a tmux pane:
# First listen on port 5000, then connect to the same port using the program.
# Now we send the current password via `nc`:
bandit20@bandit:~$ ./suconnect 5000       │  bandit20@bandit:~$ nc -l 5000
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j    │  GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password   │  gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
```
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr

### lvl-21
A program is running automatically at regular intervals from cron, the
time-based job scheduler. Look in /etc/cron.d/ for the configuration and see
what command is being executed.
```bash
$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null

$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI
```

### lvl-22
A program is running automatically at regular intervals from cron, the
time-based job scheduler. Look in /etc/cron.d/ for the configuration and see
what command is being executed.
```bash
$ cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null

$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget

# Run the command as bandit23 to get their password
$ echo I am user bandit23 | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n
```

### lvl-23
A program is running automatically at regular intervals from cron, the
time-based job scheduler. Look in /etc/cron.d/ for the configuration and see
what command is being executed.

NOTE: Keep in mind that your shell script is removed once executed, so you may
want to keep a copy around…
```bash
$ cat /etc/cron.d/cronjob_bandit24 
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
$ cat /usr/bin/cronjob_bandit24.sh 
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
	echo "Handling $i"
	timeout -s 9 60 ./$i
	rm -f ./$i
    fi
done

# So we want a shell script that simply cats out bandit24's password

#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/sminez88_bandit24pass

# The cron runs at login so logout, log back in and cat the temp file:
$ cat /tmp/sminez88_bandit24pass
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
```

### lvl-24
A daemon is listening on port 30002 and will give you the password for bandit25
if given the password for bandit24 and a secret numeric 4-digit pincode. There
is no way to retrieve the pincode except by going through all of the 10000
combinations, called brute-forcing.
```bash
touch /tmp/sminez88_bandit24_results
COUNT=0;
for pin in $(seq -f "%04g" 0 9999); do
  if [ $(($COUNT % 100)) -eq 0 ]; then
    echo "Up to $COUNT..."
  fi;
  COUNT=$(($COUNT+1));
  resp=$(echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $pin" | nc localhost 30002);
  echo "$pin: $resp" >> /tmp/sminez88_bandit24_results;
  echo "$pin: $resp";
  if [[ ! $resp =~ .*Wrong.* ]]; then
    if [[ ! $resp == "" ]]; then
      break;
    fi;
  fi;
done;
```
uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

### lvl-25,26
Logging in to bandit26 from bandit25 should be fairly easy… The shell for user
bandit26 is not /bin/bash, but something else. Find out what it is, how it works
and how to break out of it.

We get given an SSH key to use.
```bash
# There are a couple of hidden files in the home dir
$ ls -a
.  ..  .bandit24.password  .bash_logout  .bashrc  .pin  .profile  bandit26.sshkey
$ cat .bandit24.password 
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ
$ cat .pin
5440

# /etc/passwd shows user shell config
$ cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext

# So they have a shell script set as their shell that drops us into more
$ cat /usr/bin/showtext
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0


# This one is daft. More will drop into its pager mode if the terminal window is
# small enough. After that, `v` will open the current file in vim and you can
# read in the password file to see its contents:
v
:r /etc/bandit_pass/bandit26
```
5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z

# Done!
...and that's it!
