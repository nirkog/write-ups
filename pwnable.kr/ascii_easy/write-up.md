# ascii_easy

This challenge is about constructing ascii only exploits.

## The challenge

The vulnerable program in this challenge is very simple. First, it loads libc into a fixed address:

```c
#define BASE ((void*)0x5555e000)

int main(int argc, char* argv[]) {
    ...
    size_t len_file;
    struct stat st;
    int fd = open("/home/ascii_easy/libc-2.15.so", O_RDONLY);
    if( fstat(fd,&st) < 0){
        printf("open error. tell admin!\n");
        return;
    }

    len_file = st.st_size;
    if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){
        printf("mmap error!. tell admin\n");
        return;
    }
    ...
}
```

Then, it checks that the first command line argument contains only ascii characters and copies it into a buffer, which results in a buffer overflow vulnerability.

```c
int is_ascii(int c){
    if(c>=0x20 && c<=0x7f) return 1;
    return 0;
}

void vuln(char* p){
    char buf[20];
    strcpy(buf, p);
}

int main(int argc, char* argv[]) {
    ...
	int i;
    for(i=0; i<strlen(argv[1]); i++){
        if( !is_ascii(argv[1][i]) ){
            printf("you have non-ascii byte!\n");
            return;
        }
    }

    printf("triggering bug...\n");
    vuln(argv[1]);
    ...
}
```

## The exploit

The idea here is pretty simple: redirect program execution into the dynamically loaded libc and execute a shell.

In order to do that, I fired up Ghidra and checked which interesting function is loaded into an address which contains only ascii characters. It turns out that *execv* is loaded into *0x55616740*, so we can return to it from *vuln*. Now, we need to figure out how to pass /bin/sh into the function. The address of the /bin/sh string in libc.so is *0x556bb7ec*, which contains non-ascii bytes. My solution to this program was to create a symbolic link to /bin/sh, which has a name that is located in an all ascii address in *libc.so*. I landed on the name ***files*** as address *0x556c3049* contained it. The only other problems are the *args* and *envp* arguments, which we also need to control to make sure the program doesn't segfault. The problem is we can't just pass NULL, because 0 is not in the ascii range. The solution is to pass a pointer to NULL. I found one at *0x0x5561683b* in *libc.so*.

The only thing left is to figure out how exactly we need to pass the arguments on the stack. When I just put the arguments after the return address I got a segfault. The first problem was that the environment variables are retrieved from a global that does not exist.

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/ascii_easy/execv_start.png)

In order to fix that I changed the return address to jump to after this block, so we don't segfault, which means we have to manually set *esp + local_14*, which is *esp + 8*,  to the NULL pointer. After that the *argv* and *path* arguments are passed:

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/ascii_easy/execv_argv_path.png)

This means that we need to put *argv* and *path* in *esp + local_18* and *esp + local_1c*, which are *esp + 0x20* and *esp + 0x24*.

Now, we are ready to construct the payload which looks like this: padding * 32 + *0x5561675b* (*execv*) + padding * 8 + 0x5561683b (NULL pointer) + padding * 20 + *0x556c3049* ("files") +  *0x5561683b* (NULL pointer) .

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/ascii_easy/exploit.png)

It worked!