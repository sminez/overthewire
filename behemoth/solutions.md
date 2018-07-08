Behemoth
--------

As with narnia, all binaries are in `/behemoth` and are setuid binaries that
allow you to cat the password of the next level once you crack them.
Unlike narnia, there's no source to highlight the vulnerability this time so we
need to do some actual analysis!

# lvl-1
As seems standard for these, the first level just asks for a password to be
entered, giving a shell if correct:
```bash
$ strings behemoth0
.
.
.
unixisbetterthanwindows
followthewhiterabbit
pacmanishighoncrack
# ...None of these work
```
ltrace shows a couple of interesting things:
  1) There's a call to `strlen("OK^GSYBEX^Y")` for some reason (probably a red
  herring like the three "passwords").
  2) Our input is compared to "eatmyshorts"
  Presumably this is constructed from the characters in the other strings.

```bash
behemoth0@behemoth:/behemoth$ ./behemoth0
Password: eatmyshorts
Access granted..
$ whoami
behemoth1
$ cat /etc/behemoth_pass/behemoth1
aesebootiv
```

# lvl-2
Aaaaaaaand another one.

Ah OK, It reads our input but does nothing with it: simply prints the error
message and exits...ah, but it's using `gets` so lets segfault the thing.

Right,
```bash
$ python -c 'print "A" * 66' | ./behemoth1
Password: Authentication failure.
Sorry

$ python -c 'print "A" * 67' | ./behemoth1
Password: Authentication failure.
Sorry
Segmentation fault
```

Looks like 67 is the magic number
