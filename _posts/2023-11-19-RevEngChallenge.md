---
layout: post
title: "A fun little reversing exercise..."
date: 2023-11-19 19:04:00 +0200
categories: Reverse-Engineering
---

# Start info
I was given the following information:

Flag1:
```
9f 95 98 9e c4 c0 9d 9f 9a 9f 9c ca 9a d4 9f cf 9a c8 d4 cd c9 cd cc d4 9b 98 9a cd d4 ca ca c0 ce ce c9 ca c9 9f cf c8 9a 
```

Algo 1:
```
0f 10 01 c7 44 24 08 a4 ae 9c 6f 66 49 0f 7e c1 66 0f 73 d8 08 66 48 0f 7e c2 4c 03 ca 49 3b d1 74 25 48 8d 44 24 08 41 b8 04 00 00 00 0f 1f 00 0f b6 08 48 8d 40 01 30 0a 49 83 e8 01 75 f1 48 ff c2 49 3b d1 75 db c3 cc cc cc cc cc cc cc cc
```

The challenge: decode the flag.

# Initial thoughts
First off, the algo looks like bytecode (_0xcc_ - _INT3_ : breakpoint op?). The flag couldn’t be retrieved by doing a hex to ascii conversion (the first byte is a dead giveaway, as it is not ASCII-printable). The algorithm likely decodes the flag. Let's see if the algo can be decoded into any assembly code...
Easy mode first: [online disassembler](https://defuse.ca/online-x86-assembler.htm) .

The result is legible.

__x86__:
![](https://0x0l0rd.github.io/blog/assets/img/RE1/1.png)

__x64__:
![](https://0x0l0rd.github.io/blog/assets/img/RE1/2.png)

While both x86 and x86_64 seem to suggest similar concepts, x86_64 seems to be the intended architecture. Sure, there’s a NOP with an operand in the x64 version, but in the x86 version, for one, there's a decrement of AX, but neither the RAX (nor the EAX) register are set prior.
Thus, I’ll start with the x64 assembly. If I make no progress in finding out how to decode the flag, I’ll come back to x86. Moreover, I think the value RCX must contain might be difficult to ascertain but I will come back to it once I understand what the algorithm is doing. 
I will start with static analysis, since the code is incomplete, then see if I can make out what it’s doing and rip (recreate) it.

# Reversing the x86_64 algorithm
I'm going to assume that RCX has the address of the first byte in the flag array. MOVUPS moves 16 (unpacked) bytes into an SSE register (XMM0). Then four bytes are moved into RSP+0x8. I had to re-learn what PSRLDQ is; it is basically a logical shift right for SSE registers.

Beyond that, it’s clear that I’ve got two loops (nested) to look at. I’ll focus on the inner loop first.

![](https://0x0l0rd.github.io/blog/assets/img/RE1/3.png)

At RSP+0x8, we have 0x6f9caea4 loaded into memory. The code in the above screenshot translates to: 

```
    for (int i = 0; i < 4; i++){
		buf[i] ^ dx;
	}
```
		
I note that RDX is (xmm0 / (2^8)) and R9 is (xmm0 + rdx).

The outer loop translates to:

```
	while ( r9 != rdx ){
		buf = local_ptr; // rsp+0x8
		....
	}
```	

Which, when combined with the inner loop:

```	
	while ( r9_ != rdx_ ){
		buf = char_word_ptr; // rsp+0x8
		for (int i = 0; i < 4; i++){
			buf[i] ^ dx;
		}
	}
```

Thus, the whole snippet roughly equates to:

```	
	float *float_ptr_rcx;
	float r9, rdx;
	/* 
		float_ptr_rcx is initialized.
	*/
	char buf, char_word_ptr[DWORD_SIZE] = “\xa4\xae\x9c\x6f”;
	r9 = (float)(*float_ptr_rcx);
	*float_ptr_rcx /= 256;
	rdx = (float)(*float_ptr_rcx);
	r9 += rdx;
	
	while ( r9_ != rdx_ ){
		buf = char_word_ptr; // rsp+0x8
		for (int i = 0; i < 4; i++){
			buf[i] ^ dx;
		}
	}
```

This can be further reduced to:

```	
	#include <stdio.h>
	#define DWORD_SIZE 4

	int main(){
		float *float_ptr_rcx;
		float r9, rdx;
		/* 
		    float_ptr_rcx is initialized.
		*/
		char char_word_ptr[DWORD_SIZE] = "\xa4\xae\x9c\x6f";
		r9 = (float)(*float_ptr_rcx);
		*float_ptr_rcx /= 256;
		rdx = (float)(*float_ptr_rcx);
		r9 += rdx;
		
		while ( r9 != rdx ){
		    for (int i = 0; i < 4; i++){
		        char_word_ptr[i] ^= ((long int)rdx & 0xff);
		    }
		}
	}
```

This is tentative, as it is not clear what exactly the use of the SSE register is yet.
We have a representation of the code. But, in order to solve it, we need XMM0's value (or whatever RCX is pointing to).
Let's see if Ghidra presents any new information before trying to recreate the algorithm.
I first wrote a python script to write the algorithm bytes to a file:

```
data = b"\x0f\x10\x01\xc7\x44\x24\x08\xa4\xae\x9c\x6f\x66\x49\x0f\x7e\xc1"
data += b"\x66\x0f\x73\xd8\x08\x66\x48\x0f\x7e\xc2\x4c\x03\xca\x49\x3b\xd1"
data += b"\x74\x25\x48\x8d\x44\x24\x08\x41\xb8\x04\x00\x00\x00\x0f\x1f\x00"
data += b"\x0f\xb6\x08\x48\x8d\x40\x01\x30\x0a\x49\x83\xe8\x01\x75\xf1\x48"
data += b"\xff\xc2\x49\x3b\xd1\x75\xdb\xc3\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc"

with open("bin_file", "wb+") as f:
    f.write(data)
```

![](https://0x0l0rd.github.io/blog/assets/img/RE1/5_1.png)
![](https://0x0l0rd.github.io/blog/assets/img/RE1/5_2.png)

A sanity check with Ghidra corroborates the information I have. The decompiled code hardly provides new information, so I’ll ignore it for now.

RCX's value is the most confusing part of all this. It wouldn’t be the address of the buffer which contains the flag bytes, since the XOR operation uses RDX’s value as a byte pointer (which is derived from XMM0, which itself gets its value from RCX). It couldn’t be some magic number, since the value needs to be a valid pointer. 
Furthermore, RDX’s value is going to be incremented until it reaches that of R9 (whose value is also derived from XMM0). The only thing that makes sense is if RDX initially points to the beginning of the flag buffer, and R9 points to the end of the flag buffer.

# The solution
XMM0 is going to be loaded with 16 bytes from the buffer to which RCX points. The 8 higher-order bytes will be stored in RDX, while the lower-order bits will be stored in R9. Since the PSRLDQ instruction in this code shifts the bits to the right 8 times, we can set up the stack such that the beginning address of the flag buffer is at RSP, then the end is at rsp+8, then set RCX = RSP. That way the program won't crash when the XOR operation happens.
But RDX’s value is added to that of R9, so, really, RSP+8 should be the size of the flag.  
However, since RDX is the register at which we start incrementing, it needs to be the start of the buffer. So, RSP+8 should be the start of the flag, then RSP should be the size.

Keeping in mind that flag1 is 41 bytes in size, The following assembly code should set up the registers as intended:

```
_start:
    push rbp
    mov rbp, rsp

    ; Set up stack to store addresses as discussed in walkthrough.
    push flag1
    mov rcx, 0x29
    push rcx
    mov rcx, rsp

    ; Process as explained in walkthrough. 
    movups xmm0, [rcx]
    movq r9, xmm0
    psrldq xmm0, 0x8
    movq rdx, xmm0
    add r9, rdx
```

Examining the registers in GDB, it’s clear that this setup is working, as setting a breakpoint at the INC RDX instruction shows valid ASCII text on each iteration. This would mean that my initial draft of the C representation of the algorithm was slightly off. I’ll correct it later (see accompanying code). For now, we just need to write a function to print each character as it gets decoded.

```
print_rdx:
    ; Function Prologue.
    push rbp
    mov rbp, rsp

    ; Save registers we still need.
    push rax
    push rdi
    push rsi
    push rdx

    ; SYS_WRITE
    mov rax, 1 

    ; FILENO_STD_OUT      
    mov rdi, 1

    ; Print the byte pointed to by RDX.   
    xor rsi, rsi
    movzx rsi, BYTE [rdx]
    push rsi
    mov rsi, rsp       
    mov rdx, 1   
    syscall  

    ; Remove unecessary value.
    add rsp, 8        
    
    ; Restore saved registers.
    pop rdx
    pop rsi
    pop rdi
    pop rax

    ; Safely return.
    leave
    ret
```

Then we need to call that function after the inner loop has finished execution:

```
    .innerLoop:
    movzx ecx, BYTE [rax]
    lea rax, [rax+0x1]
    xor BYTE [rdx], cl
    sub r8, 1
    jne .innerLoop

    ; Print each character as it gets decoded.
    call print_rdx
```

Finally, when compiled and executed, the result yields the flag.

![](https://0x0l0rd.github.io/blog/assets/img/RE1/6.png)

Deriving the solution in C from here is relatively easy.  

The final ASM code:
```
section .data 
    flag1 db 0x9f, 0x95, 0x98, 0x9e, 0xc4, 0xc0, 0x9d, 0x9f, 0x9a, 0x9f, 0x9c, 0xca, 0x9a, 0xd4, 0x9f, 0xcf, 0x9a, 0xc8, 0xd4, 0xcd, 0xc9, 0xcd, 0xcc, 0xd4, 0x9b, 0x98, 0x9a, 0xcd, 0xd4, 0xca, 0xca, 0xc0, 0xce, 0xce, 0xc9, 0xca, 0xc9, 0x9f, 0xcf, 0xc8, 0x9a
section .text
global _start
global print_rdx

_start:
    push rbp
    mov rbp, rsp

    ; Set up stack to store addresses as discussed in walkthrough.
    push flag1
    mov rcx, 0x29
    push rcx
    mov rcx, rsp

    ; Process as explained in walkthrough. 
    movups xmm0, [rcx]
    movq r9, xmm0
    psrldq xmm0, 0x8
    movq rdx, xmm0
    add r9, rdx
    
    ; Moved this here so that it does not interfere with the address calculation.
    mov DWORD [rsp + 0x8], 0x6f9caea4


    cmp rdx, r9
    je .end

    .outerLoop:
    lea rax, [rsp+0x8]
    xor r8, r8
    mov r8d, 0x4

    .innerLoop:
    movzx ecx, BYTE [rax]
    lea rax, [rax+0x1]
    xor BYTE [rdx], cl
    sub r8, 1
    jne .innerLoop

    ; Print each character as it gets decoded.
    call print_rdx
    
    inc rdx
    cmp rdx, r9 
    jne .outerLoop

    .end:
    ; Just exit.
    mov rax, 0x3c
    xor rdi, rdi
    syscall


print_rdx:
    ; Function Prologue.
    push rbp
    mov rbp, rsp

    ; Save registers we still need.
    push rax
    push rdi
    push rsi
    push rdx

    ; SYS_WRITE
    mov rax, 1 

    ; FILENO_STD_OUT      
    mov rdi, 1

    ; Print the byte pointed to by RDX.   
    xor rsi, rsi
    movzx rsi, BYTE [rdx]
    push rsi
    mov rsi, rsp       
    mov rdx, 1   
    syscall  

    ; Remove unecessary value.
    add rsp, 8        
    
    ; Restore saved registers.
    pop rdx
    pop rsi
    pop rdi
    pop rax

    ; Safely return.
    leave
    ret
```

And the final C code:
```
#include <stdio.h>
#define DWORD_SIZE 0x4
#define FLAG_SIZE 0x29

int main(){
    char flag_ptr[FLAG_SIZE] = "\x9f\x95\x98\x9e\xc4\xc0\x9d\x9f\x9a\x9f\x9c\xca\x9a\xd4\x9f\xcf\x9a\xc8\xd4\xcd\xc9\xcd\xcc\xd4\x9b\x98\x9a\xcd\xd4\xca\xca\xc0\xce\xce\xc9\xca\xc9\x9f\xcf\xc8\x9a";
	char *flag_end, *flag_start;

	char char_word_ptr[DWORD_SIZE] = "\xa4\xae\x9c\x6f";
	//*flag_ptr /= 256.0;
	flag_start = (char*)(flag_ptr);
	flag_end = (char *)(flag_ptr + FLAG_SIZE);
	
	while ( flag_end != flag_start ){
		for ( int i = 0; i < DWORD_SIZE; i++ ){
			//char_word_ptr[i] ^= ((long int)flag_start & 0xff);
			*flag_start ^= char_word_ptr[i];
		}
		putchar(*flag_start);
		flag_start++;
	}

	puts("\n");
}
```
