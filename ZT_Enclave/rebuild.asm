;
;    ZeroTrace: Oblivious Memory Primitives from Intel SGX 
;    Copyright (C) 2018  Sajin (sshsshy)
;
;    This program is free software: you can redistribute it and/or modify
;    it under the terms of the GNU General Public License as published by
;    the Free Software Foundation, version 3 of the License.
;
;    This program is distributed in the hope that it will be useful,
;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;    GNU General Public License for more details.
;
;    You should have received a copy of the GNU General Public License
;    along with this program.  If not, see <https://www.gnu.org/licenses/>.
;

BITS 64
segment .text
global oblock_move_to_bucket

oblock_move_to_bucket:
; node *iter, Block *bucket_blocks[l], dataSize, flag, *sblock_written, *posk

		; Windows: rcx,rdx,r8 ,r9 , from stack : r12, r13
		
		; node *iter   , Block *bucket_blocks[l],   dataSize, 	flag, *sblock_written, *posk
		; Linux  : RDI,		RSI,    		RDX,	 RCX,	     R8,	  R9

		;Find and store bool sblock_written from the stack to a register
		;mov r11, rsp
		;add rsp, 8*(5)
		;mov r12, qword [rsp]	; r12 holds ptr to sblock_written
		;mov r13, qword [rsp+8]	; r13 holds ptr to posk
		;mov rsp, r11

		push rbx
		push rbp
		push r12
		push r13
		push r14
		push r15
		
		;Flag moved to rbp
		mov rbp, rcx

		;Replacement for occupied flag 
		mov r15d, dword[rsi+8]
		mov r11d, dword[rdi+16]

		; Check flag (r9)
		cmp bpl, 1

		; Pointer to data's of both blocks
		mov r10, rdi		
		add r10, 24		

		mov r11, qword [rsi]

		mov rbx, 1
		mov rax, 0

		; Check flag (r9)
		cmp bpl, 1
		
		;If flag, set sblock_written flag
		cmovz rax, rbx
		mov byte [r8], al

		;If flag, increment posk
		mov rax,0
		mov rbx,1
		cmovz rax,rbx
		add dword [r9], eax

		;Because of add flag registers are lost, reset using cmp
		cmp bpl, 1

		; obliviously move id
		mov r12d, dword [rdi+16]
		mov r13d, dword [rsi+8]
		cmovz r13d, r12d
		mov dword [rsi+8], r13d

		;If flag, set stash-block's id to gN
		cmovz r15d, r11d
		mov dword[rdi+16], r15d

		;obliviously move tree label
		mov r12d, dword [rdi+20]
		mov r13d, dword [rsi+12]
		cmovz r13d, r12d
		mov dword [rsi+12], r13d

		;Set loop parameters
		mov ax, dx
		xor rdx, rdx
		mov bx, 8
		div bx
		mov cx, ax

		;Oblivious transfer to iter-block's data
		loop_stash_insert_rebuild:
			cmp bpl, 1
			mov r14, qword [r10]
			mov r15, qword [r11]
			cmovz r15, r14 				;r14 / r15 based on the compare
			mov qword [r11], r15
			add r10, 8
			add r11, 8
			loop loop_stash_insert_rebuild

		pop r15
		pop r14
		pop r13
		pop r12
		pop rbp
		pop rbx

		ret





