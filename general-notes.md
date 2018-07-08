Tips and tricks learned so far
==============================

### Programs and tools
##### Libraries
- pwntools (python library)

##### Command line tools (binaries)
- radare2 (diassembler and reverse engineering framework)
- gdb (the GNU debugger)
- strings (looks for strings in a binary)
- strace (looks at system calls made by the binary)
- ltrace (looks at library calls made by the binary)
- xxd (hex dump)

##### Command line tools (network)
- nc (netcat)
- nmap (port scanner)

##### GUI desktop apps
- Burp Suite (HTTP proxy & interception tool.)


### Assembler is king
Read up on opcodes and the general ways in which a program is run at the
assembler level. In particular:
  - Layout in memory (including how this is randomised to mitigate common
  attacks)
  - The names and functions of special registers such as the stack base pointer,
  the stack pointer, instruction pointer etc...
  - Important CPU opcodes for common architectures.
  - How to use GDB and associated debugging/disassebly tools.


### Some GDB Notes
- `set disassebly-flavour intel` makes things a little easier to read.
- As a first pass, `break main` followed by `r [INPUT]` and the `c` to continue
  step by step until you hit the segfault.
  - At that point, dump the stack in hex using `x/200x $esp` which prints 200
  bytes in hex from the stack pointer.


### Magic cat
If you read the cat manpage you'll see that cat acts as an echo when executed
without any arguments. This is useful when trying to keep a shell open if you
have created it by piping input into a binary that spawns one:
```bash
$ (echo "myawesomecrack"; cat) | ./target
```
Using a bash command group like this first passes the echo and then cat as an
argument to the spawned shell.


### Command injection
If something is taking user input and not escaping it then the easiest thing to
do is simply pass some input ending in "...;bash". (In the case of a file name
you will need to wrap the name in '' in order to not actually start a shell
yourself!)


### Buffer overflow
This is a fairly simple technique to get the hang of: if you can find a way to
create a segfault in a program then (provided ASLR and other modern protections
are not in place, so mainly for CTF/tutorials) you can find the location of the
$esp instruction pointer and redirect code flow to the address of your choice.
(See "Shell-code" below for an example of how to use this).
The general method is to determine what input length causes the segfault
(essentially play hot/cold using python to generate huge string inputs) and then
drop into `gdb` or `radare2` to determine the memory address to target. Once you
have that, you can replace your garbage padding to get to the overflow with
some malicious assembler instructions to execute.


### NOP slide
Having to work out the memory addresses exactly to hit your payload is annoying
but more than that, on modern systems the location of the stack can be
randomised as well so a common trick is to front-load your payload with a bunch
of `nop` (0x90) instructions that act as a slide to bring program execution to
your code.


### Shell-code
If you can get control of the stack pointer and you can write arbitrary bytes
onto the stack then you can find/write some shell-code to span a shell, compile
it to HEX assembly instructions and execute it directly by redirecting program
flow to the address of your injected code. It looks like there are a lot of
sites that offer tutorials on how to write the code, examples for download
(always try out on one of the overthewire servers first! Do NOT run on your own
machine without being 100% sure it will do what you think). Alternatively, the
python `pwntools` library can generate shell code for a bunch of target
systems:

```python
>>> from pwn import *
>>> asm(shellcraft.i386.linux.sh())
'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
```

As a further note, a lot of the online examples will do more that just spawn a
shell: most will actually set up a back door of some kind that can be used later
to regain access to the target system.


### Ret2libC
If you can't write your own data into the stack (or not enough to form a full
payload) then another common attack is to spawn a shell using the instructions
in the system `libc` binary itself.
NOTE: On modern systems, the location of the binary in memory is randomised so
you will need to do a bit of work to track it down before you can exploit it.
