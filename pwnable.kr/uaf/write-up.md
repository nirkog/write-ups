# UAF challenge write-up

As the name suggests, this challenge was about exploiting a use-after-free bug.

## Use after free

A use after free bug occurs when memory allocated on the heap gets freed, and a pointer to that memory is still used after the free. The problem with this bug stems from how the heap works. In most heap implementations, the heap manager saves a list of free holes which are free to allocate. When the program calls the free function after allocating memory, the memory chunk is added to the list of free chunks. Then, when memory is allocated again, the same check may be used. If that happens, and we can control then newly allocated data, we might be able to exploit the bug. An example of UAF bugs is shown is this code:

```
void (*a)() = malloc();
if (some_condition) {
	free(a);
}
void* b = malloc();
scanf("%s", b);
a();
```

This example is quite ridiculous, but it get the point across. In the example, the user controls the b variable, which might get allocated in the same address as the original a variable, and so the user can inject code and exploit the bug.

## The challenge

When we log in to the challenge machine and run ls, this is the output:

```
flag  uaf  uaf.cpp
```

This probably means that we need to exploit a vulnerability in uaf  and read the flag. As we can see, the program is written in C++ which might the reversing a bit tricky as the the library functions, and specifically the heap, are implemented a bit differently than in libc, but it shouldn't be too different.

When I opened uaf.cpp, I immediately noticed the very obvious bug, which is in the main function:

```
int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
    Human* w = new Woman("Jill", 21);

    size_t len;
    char* data;
    unsigned int op;
    while(1){
        cout << "1. use\n2. after\n3. free\n";
        cin >> op;

    	switch(op){
        	case 1:
                m->introduce();
                w->introduce();
                break;
 			case 2:
                len = atoi(argv[1]);
                data = new char[len];
                read(open(argv[2], O_RDONLY), data, len);
                cout << "your data is allocated" << endl;
                break;
            case 3:
                delete m;
                delete w;
                break;
            default:
                break;
        }
    }
    
	return 0;
}
```

As we can see, the variables m and w are allocated on the heap at the start of the program, using the C++ *new* operator. After that, the program enters an infinite loop, which keeps asking the user for input, and has 3 different actions it can perform.

1. Call the introduce function on *m* and *w*
2. read n bytes from a file, in which n and the file name are controlled by the user, and store them in a heap allocated memory area.
3. free *m* and *w*, using the C++ *delete* operator

In order to understand a bit better how this program works, this is the definition of Human, which both *Man* and *Woman* inherit from.

```
class Human{
private:
    virtual void give_shell(){
    	system("/bin/sh");
    }
protected:
    int age;
	string name;
public:
    virtual void introduce(){
    	cout << "My name is " << name << endl;
        cout << "I am " << age << " years old" << endl;
    }
};
```

The definitions of Man and Woman are not very interesting, as all they do is override the introduce function to print a different string and define a constructor. 

So, from all of these, we can infer that the exploit probably involves calling the delete action, which will free *m* and *w* and then somehow override the previously allocated data, and call the introduce functions, which we would probably want to somehow redirect the program to the give_shell function. **TO-DO: consider explaining the perceived exploitation method**

Now, the question that remains is how can we exploit this bug and redirect the introduce calls to the give_shell function.

## C++ virtual tables

In C++, when an instance of a class witch contains virtual functions is allocated, something called a **virtual pointer** is also allocated with it. The virtual pointer points to a **virtual table**. A virtual table is a table that contains pointers to each of the functions that a class contains. A vtable is created only for classes containing virtual classes, in order for the compiler to link each virtual function call to its correct subroutine. So, when the program calls *w->introduce()*  it actually uses the virtual pointer which points into the Woman introduce functions in the Woman class vtable. That means that if somehow we can change the *m* variable vpointer so that it points to give_shell, we can read the flag.

## Exploiting the UAF bug

The reason we **can** change that vpointer is that we can create a scenario in which the *w* and *m* variables get freed and then user allocated data is allocated on the heap, in their place. The only thing we need to know now is where exactly the vpointer is located.

After some debugging I found out that the vpointer is the first member of the Woman and Man classes, and so it is stored at offset 0 from the *w* and *m* pointers. That means that we just need to write the address of the *give_shell* function when we allocate memory after freeing the variables. **TO-DO: explain more details and add some pictures **

So, I tried to run the program with an input file that I created that contained the *give_shell* address **TO-DO: more details**.  I tried to first free the memory, then allocate with our data, and call the introduce functions after that, but I saw that the address of the newly allocated array that contained our data, was the address of the *w* variable and not the *m* variable. That makes sense because of how the heap works, containing a list of free chunks. The *w* chunk was probably the first in the list. So, I tried the same thing again, but now with allocating our data twice, and it worked! **TO-DO: explain better and more detailed and add pictures**