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

![](https://0x0l0rd.github.io/blog/assets/img/RE1/2.png)

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








