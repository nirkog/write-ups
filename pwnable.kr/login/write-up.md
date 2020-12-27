# Login

This challenge is quite an easy one, but it can be a bit tricky to understand exactly where the vulnerability is.

## The program

We are given a program, *login*, which runs on a remote service, and we have to somehow exploit it and get the flag. When we run the program, it asks for some sort of authentication input, and then apparently prints out an md5 hash of something.

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/first_run.png)

To get a sense of what's going on under the hood, I opened up Ghidra and checked out the decompilation. The main function looks like this:

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/main_decompiled.png)

where the functions *auth* and *correct* look like this:

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/auth_decompiled.png)

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/correct_decompiled.png)

From this, we can understand the general structure and flow of the program. First, the program asks for some input from the user, which can be at most 30 characters long. Then, the input gets base64 decoded, and the decoded string's length must be less than 13 bytes. If the string is in the correct length, it is copied into a global buffer and passed into the *auth* function. What the auth function does is copying the decoded user input from the global buffer into a local variable and taking the md5 hash of a 12 byte long area on the stack, which does not seem to be user-controllable. After that, the function compares that hash to some other hash and return 0 or 1 based on the result of the comparison. If *auth* returned 1, the *correct* function is called. The function checks if the first 4 bytes of the global input variable are 0xdeadbeef and if they are it gives us a shell, which means we probably need to get there somehow.

## The vulnerability

From the the brief overview, it seems that we have no control of whether the program will get to the *correct* function or not, because the memory that is getting hashed is not under our control. This can be verified by running the program a couple of times with the same input and getting different hashes.

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/different_hash.png)

So, if we can't control the hash, how the hell are we supposed to get a shell?!? Well, if we look carefully at the *auth* function, we can spot a stack overflow vulnerability. The *v_input* array that holds the decoded user input is only 8 bytes long, and the maximum length of the string is 12 byte. This means that if we give a 12 characters long encoded string, 4 of those bytes will overflow and maybe change some interesting values. When we check where this *v_input* variable is located on the stack, we find out that it is located at *ebp - 8*, which means the overflown bytes will overflow out of the stack frame and into the pushed *ebp* of the calling function, which in this case is *main*.

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/v_input_memcpy.png)

To prove that, we can to give an input with a decoded length of 9-12 characters and see if we get a seg fault.

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/segfault.png)

## The payload

Now that we know where the vulnerability is, how do we craft the exploit? The first four bytes of the payload have to be 0xdeadbeef, so we will pass the check in *correct*. The last four bytes need to point into an address where the address of the *correct* function is stored, so that when *main* returns, it will return to *correct*. In order to create a known address which holds the *correct* address, we can use the global input buffer, which has a fixed address, and holds the decoded payload.

To sum up, our payload should look like this: First four bytes - 0xdeadbeef, Middle four bytes - Address of *correct*, Last four bytes - Address of *g_input*.

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/create_payload.png)

## Testing the exploit

After we create the exploit, the last thing left to do is trying it on the server:

![](/home/nir/Documents/vuln-research/challenges/write-ups/pwnable.kr/login/running_the_exploit.png)

And we get that flag!