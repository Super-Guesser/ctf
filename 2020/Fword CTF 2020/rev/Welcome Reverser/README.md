# Welcome Pwner - 107 solves

## Analysis

I always have a habit, using the 
```bash
pwn checksec --file ./binary
```
 command (or if think differently, this is old conventions of almost pwners)  
Anyway, we can see this result (In below code snippets)  
```bash
yeon@sqrtrev:~$ pwn checksec --file ./welcome
[*] '/home/yeon/welcome'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
yeon@sqrtrev:~$
```

There are a lot of memory mitigations were used. But, we just debug reverse engineering challenge, not pwning challenge.  
Thus, we don't need to consider this mitigations.  
But to explain one interesting technique, we can debug binaries which used PIE (Position Independent Executable) just using GDB, we don't need to use IDA remote debugger.  

```bash
gdb-peda$ b *0x0
Breakpoint 1 at 0x0
gdb-peda$ r
Starting program: /home/yeon/welcome
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x0

gdb-peda$ i b
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000000000
gdb-peda$ del 1
gdb-peda$ x/3i $pc
=> 0x7ffff7dd6090:      mov    rdi,rsp
   0x7ffff7dd6093:      call   0x7ffff7dd6ea0
   0x7ffff7dd6098:      mov    r12,rax
gdb-peda$
```
If you set a breakpoint to address 0x0, and continue to run. The application started and GDB will prints 'Cannot access memory at address 0x0'.  
This message is just warning message, not error message. Thus, this application executed normally but stopped at application loaded point.  

```bash
Breakpoint 2, 0x00007ffff7dd60d4 in ?? ()
gdb-peda$ x/3i $pc
=> 0x7ffff7dd60d4:      jmp    r12
   0x7ffff7dd60d7:      nop    WORD PTR [rax+rax*1+0x0]
   0x7ffff7dd60e0:      add    DWORD PTR [rdi+0x4],0x1
gdb-peda$
```

And, we can see an assembly gadget, 'jmp r12'. Its r12 gadget have an address for entry point of ELF binaries.  

```bash
gdb-peda$ x/20i $r12
=> 0x555555555160:      endbr64
   0x555555555164:      xor    ebp,ebp
   0x555555555166:      mov    r9,rdx
   0x555555555169:      pop    rsi
   0x55555555516a:      mov    rdx,rsp
   0x55555555516d:      and    rsp,0xfffffffffffffff0
   0x555555555171:      push   rax
   0x555555555172:      push   rsp
   0x555555555173:      lea    r8,[rip+0x586]        # 0x555555555700
   0x55555555517a:      lea    rcx,[rip+0x50f]        # 0x555555555690
   0x555555555181:      lea    rdi,[rip+0x409]        # 0x555555555591
   0x555555555188:      call   QWORD PTR [rip+0x2e52]        # 0x555555557fe0
   0x55555555518e:      hlt
   0x55555555518f:      nop
   0x555555555190:      lea    rdi,[rip+0x2e79]        # 0x555555558010
   0x555555555197:      lea    rax,[rip+0x2e72]        # 0x555555558010
   0x55555555519e:      cmp    rax,rdi
   0x5555555551a1:      je     0x5555555551b8
   0x5555555551a3:      mov    rax,QWORD PTR [rip+0x2e2e]        # 0x555555557fd8
   0x5555555551aa:      test   rax,rax
gdb-peda$ x/10i 0x555555555591
   0x555555555591:      endbr64
   0x555555555595:      push   rbp
   0x555555555596:      mov    rbp,rsp
   0x555555555599:      sub    rsp,0x20
   0x55555555559d:      mov    DWORD PTR [rbp-0x14],edi
   0x5555555555a0:      mov    QWORD PTR [rbp-0x20],rsi
   0x5555555555a4:      mov    eax,0x0
   0x5555555555a9:      call   0x555555555249
   0x5555555555ae:      mov    edi,0x10
   0x5555555555b3:      call   0x555555555110 <malloc@plt>
gdb-peda$
```

We can find the main function, just by tracking the arguments.  

```c
  __asm { rep nop edx }
  v9 = a3;
  sub_1249(a4);
  LODWORD(v4) = sub_1110(16LL);
  v8 = v4;
  sub_10D0("Hello give me the secret number so i can get the flag:");
  sub_1140("%s", v8);
  if ( sub_1335(v8) )
  {
    LODWORD(v5) = sub_10E0(v8);
    if ( v5 == 16 )
    {
      v6 = sub_1391(v8);
      if ( !((v6 + sub_1421(v8)) % 10) )
      {
        sub_12AE();
        return 0LL;
      }
      sub_10D0("no thats not my number:(");
    }
  }
  sub_10D0("no Flag for u");
```

In IDA disassembler, both the function names and the PLT names were stripped.  
So we should guess the function names, just like sub_1110 is malloc().  

I guessed the function names.  
```
sub_1249() : init function for setvbuf
sub_1120() : setvbuf
sub_1110() : malloc
sub_10D0() : puts
sub_1140() : scanf
sub_10E0() : strlen
```

There are two key point functions, sub_1391(), sub_1421(), sub_12AE()  
sub_12AE() is the function for printing contents of flag.txt  
Thus, we need to make addition of outputs from calculations by sub_1391() and sub_1421() to multiples of 10.  

We don't need to consider the outputs of these two functions.  

```c
  for ( i = 0; ; i = 4 - (i ^ 2) + 2 * (i & 0xFFFFFFFD) )
  {
    LODWORD(v1) = sub_10E0(a1);
    if ( (signed int)i >= v1 )
      break;
    v4 = 2 * (*(_BYTE *)((signed int)i + a1) - 48);
    if ( (signed int)(3 * (~v4 & 0xFFFFFFF7) + 2 * ~(v4 ^ 0xFFFFFFF7) + 3 * (v4 & 8) - 2 * ~(v4 & 0xFFFFFFF7)) > 0 )
      v4 = (v4 % 10 ^ v4 / 10) + 2 * (v4 % 10 & v4 / 10);
    v3 += v4;
  }
```

This is sub_1421 function, the i variable will be changed to 0, 2, 4, 6, ...  

```c
  for ( i = 1; ; i += 2 )
  {
    LODWORD(v1) = sub_10E0(a1);
    if ( i >= v1 )
      break;
    v3 = (v3 ^ (*(_BYTE *)(i + a1) - 48)) + 2 * (~v3 | (*(_BYTE *)(i + a1) - 48)) - 2 * ~v3;
  }
```

And this is sub_1391 function, the i variable will be changed to 1, 3, 5, 7, ...  
Thus, we just assume one randomized string only consists of numerical characters, such as '1111222233334444'. Then, we just replace one character to other numerical characters.  

```yeon@sqrtrev:~$ ./welcome
Hello give me the secret number so i can get the flag:
1111222233334444
hello flag flag flag

yeon@sqrtrev:~$ ./welcome
Hello give me the secret number so i can get the flag:
1111222233334445
no thats not my number:(
no Flag for u
yeon@sqrtrev:~$
```

Flag : 
```
FwordCTF{luhn!_wh4t_a_w31rd_n4m3}
```