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

section .text
	;global_start
	global pt_settarget
	global pd_setdeepest
	global oblockcompare
	global oblock_move_on_flag
	global stash_insert
	global oassign_newlabel
	global ofix_recursion
	global ostore_deepest
	global ostore_deepest_round
	global oset_goal_source
	global omove_block
	global omove_serialized_block
    	global omove_buffer
	global oset_hold_dest
	global oset_block_as_dummy
	global pt_set_target_position
	global pt_set_src_dest
	global oset_return_value
	global oset_value
	global stash_serialized_insert
	global oincrement_value

oset_value:
		; oset_value(&dest, target[i], flag_t);
		; Linux : rdi,rsi,rdx,rcx,r8,r9

		mov r10d, [rdi]
		
		cmp edx, 1
		
		cmovz r10d, esi
		
		mov [rdi], r10d

		ret

oincrement_value:
		; oincrement_value(&value, flag_t);
		; Linux : rdi,rsi,rdx,rcx,r8,r9

		mov r10d, [rdi]
		mov r9d, r10d
		add r9d, 1

		cmp edx, 1
		
		cmovz r10d, r9d
		
		mov [rdi], r10d

		ret


oset_return_value:
		; oset_return_value(&return_value, result_block.data[k], flag_ore, &(result_block.data[pos_in_id]), newleaf_nextlevel)
		; Linux : rdi,rsi,rdx,rcx,r8,r9

		mov r10d, [rdi]
		mov r11d, [rcx]
		
		cmp edx, 1
		
		cmovz r10d, esi
		cmovz r11d, r8d		

		mov [rdi], r10d
		mov [rcx], r11d

		ret

oset_block_as_dummy:
		; oset_block_as_dummy(&block.id, gN, block.id==id)
		; Linux : rdi,rsi,rdx,rcx,r8,r9

		mov r10d, [rdi]
		
		cmp edx,1		

		cmovz r10d, esi
	
		mov [rdi], r10d		
		
		ret

pt_set_src_dest:
		; pt_set_src_dest(&src, &dest, deepest[i-1], i, flag_pt);
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		
		mov r10d, [rdi]
		mov r11d, [rsi]
		
		cmp r8d, 1
		
		mov r9d, edx
		cmovz r10d, r9d
		
		mov r9d, ecx
		cmovz r11d, r9d

		mov [rdi], r10d
		mov [rsi], r11d
	
		ret

pd_setdeepest:
		; pd_setdeepest(&(deepest[i]), src, goal>=i);	
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		; Callee-saved : RBP, RBX, and R12–R15

		;Load deepest[i]
		mov r10d, dword [rdi]		

		; Check Flag	
		cmp edx, 1
		
		; On Flag, move src to deepest[i]
		cmovz r10d, esi
		
		mov [rdi], r10d  

		ret


pt_set_target_position:
		; pt_set_target_position(&(target_pos[i]), k, &target_set, flag_stp);
		; Linux : rdi,rsi,rdx,rcx,r8,r9
	
		
		mov r10d, [rdi]
		mov r11d, [rdx]
		mov eax, 1
		
		cmp ecx , 1
		
		cmovz r10d, esi
		cmovz r11d, eax

		mov [rdi], r10d
		mov [rdx], r11d

		ret

pt_settarget:
		; pt_settarget(&(target[i]), &dest, &src, i==src);	
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		; Callee-saved : RBP, RBX, and R12–R15

		; Load target[i] to rax
		mov eax, [rdi]
	
		; Load src to r9					
		mov r9d, [rdx]

		; Load dest to r10
		mov r10d, [rsi]

		;Check flag
		cmp ecx,1


		; On Flag
		; Set target[i] = dest
		cmovz eax, r10d	
		mov [rdi], eax

		; On Flag 
		; Set src = -1
		; Set dst = -1
		mov r8d , -1
		cmovz r9d, r8d
		cmovz r10d, r8d
		mov [rdx], r9d
		mov [rsi], r10d

		ret
		
		

oset_hold_dest:		
		; Take inputs,  1 ptr to hold, 2 ptr to dest 3 ptr to flag_write, 4 flag,	
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		; Callee-saved : RBP, RBX, and R12–R15

		mov r9d, dword[rdi]
		mov r10d, dword[rsi]
		mov r11d, dword[rdx]
		mov r8d, -1
	
		;Check flag
		cmp ecx,1
					

		cmovz r9d, r8d
		cmovz r10d, r8d
		mov r8d, 1
		cmovz r11d, r8d
		
		mov dword[rdi], r9d
		mov dword[rsi], r10d
		mov dword[rdx], r11d

		ret


omove_serialized_block:
		; Take inputs,  1 ptr to dest_block, 2 ptr to source_block, 3 data_size, 4 flag
		; Linux : 	rdi,rsi,rdx,rcx->rbp

		; Callee-saved : RBP, RBX, and R12–R15

		push rbx
		push rbp
		push r12
		push r13
		push r14
		push r15

		; Move ptr to data from serialized_dest_block and serialized_source_blk
		mov R10, rdi
		mov R11, rsi

		add r10, 24
		add r11, 24
		; Extract treelabels from dest_block and source_blk
		mov R12d, dword [rdi+20]
		mov R13d, dword [rsi+20]

		;RCX will be lost for loop, store flag from rcx to rbp (1 byte , so bpl)
		mov bpl, cl

		; Oblivious evaluation of flag
		cmp bpl, 1

		; Set source_block.treelabel -> dest_block.treelabel,  if flag is set
		cmovz r12d,r13d
		mov dword [rdi+20], r12d

		; Extract id from block_hold and iter_blk
		mov R12d, dword [rdi+16]
		mov R13d, dword [rsi+16]

		; Set source_block.id -> dest_block.id if flag is set
		cmovz r12d,r13d
		mov dword [rdi+16], r12d

		;Set loop parameters
		mov ax, dx
		xor rdx, rdx
		mov bx, 8
		div bx
		mov cx, ax

		; Loop to fetch iter & res chunks till blk_size
		loopstart3:
			cmp bpl, 1
			mov r14, qword [r10]
			mov r15, qword [r11]
			cmovz r14, r15 				;r14 / r15 based on the compare
			mov qword [r10], r14
			add r10, 8
			add r11, 8
			loop loopstart3

		pop r15
		pop r14
		pop r13
		pop r12
		pop rbp
		pop rbx

		ret

omove_buffer:
		; Take inputs,  1 ptr to dest_buffer, 2 ptr to source_buffer, 3 buffer_size, 4 flag
		; Linux : 	rdi,rsi,rdx,rcx->rbp

		; Callee-saved : RBP, RBX, and R12–R15

		push rbx
		push rbp
		push r12
		push r13
		push r14
		push r15

		; Move ptr to data from serialized_dest_block and serialized_source_blk
		mov r10, rdi
		mov r11, rsi

		;RCX will be lost for loop, store flag from rcx to rbp (1 byte , so bpl)
		mov bpl, cl

		; Oblivious evaluation of flag
		cmp bpl, 1

		;Set loop parameters
		mov ax, dx
		xor rdx, rdx
		mov bx, 8
		div bx
		mov cx, ax

		; Loop to fetch iter & res chunks till blk_size
		loopstart5:
			cmp bpl, 1
			mov r14, qword [r10]
			mov r15, qword [r11]
			cmovz r14, r15 				;r14 / r15 based on the compare
			mov qword [r10], r14
			add r10, 8
			add r11, 8
			loop loopstart3

		pop r15
		pop r14
		pop r13
		pop r12
		pop rbp
		pop rbx

		ret


omove_block:
		; Take inputs,  1 ptr to dest_block, 2 ptr to source_block, 3 blk_size, 4 flag
		; Linux : 	rdi,rsi,rdx,rcx->rbp

		; Callee-saved : RBP, RBX, and R12–R15

		push rbx
		push rbp
		push r12
		push r13
		push r14
		push r15

		; Extract data ptr from dest_block and source_blk
		mov R10, qword [rdi]
		mov R11, qword [rsi]

		; Extract treelabels from dest_block and source_blk
		mov R12d, dword [rdi+12]
		mov R13d, dword [rsi+12]

		;RCX will be lost for loop, store flag from rcx to rbp (1 byte , so bpl)
		mov bpl, cl

		; Oblivious evaluation of flag
		cmp bpl, 1

		; Set source_block.treelabel -> dest_block.treelabel,  if flag is set
		cmovz r12d,r13d
		mov dword [rdi+12], r13d

		; Extract id from block_hold and iter_blk
		mov R12d, dword [rdi+8]
		mov R13d, dword [rsi+8]

		; Set source_block.id -> dest_block.id if flag is set
		cmovz r12d,r13d
		mov dword [rdi+8], r12d

		;Set loop parameters
		mov ax, dx
		xor rdx, rdx
		mov bx, 8
		div bx
		mov cx, ax

		; Loop to fetch iter & res chunks till blk_size
		loopstart4:
			cmp bpl, 1
			mov r14, qword [r10]
			mov r15, qword [r11]
			cmovz r14, r15 				;r14 / r15 based on the compare
			mov qword [r10], r14
			add r10, 8
			add r11, 8
			loop loopstart4

		pop r15
		pop r14
		pop r13
		pop r12
		pop rbp
		pop rbx

		ret


oassign_newlabel:
		; Take inputs,  1 ptr to block->label, 2 newlabel, 3 flag
		; Windows : rcx,rdx,r8 ,r9
		; Linux : rdi,rsi,rdx,rcx->rbp
		; Callee-saved : RBP, RBX, and R12–R15

		mov r9d, dword[rdi]
		cmp rdx, 1
		cmovz r9d, esi
		mov dword[rdi], r9d

		ret

ofix_recursion:
		
		; Take inputs,  1 ptr to block->data->ptr, 2 flag, 3 newlabel, 4 *nextleaf		
		; Windows : rcx,rdx,r8 ,r9
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		; Callee-saved : RBP, RBX, and R12–R15

		mov r9d, dword[rcx]
		mov r8d, dword[rdi]		
		mov eax, dword[rdi]
		cmp rsi,1
		cmovz r9d, r8d
		cmovz eax, edx

		mov dword[rcx], r9d
		mov dword[rdi], eax		

		ret

ostore_deepest:
		; Take inputs,  1 block->treelabel, 2 leaf, 3 ptr to deepest, 4 D , isDummy() flag		
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		; Callee-saved : RBP, RBX, and R12–R15
		
		mov r9d, dword [rdx]

		loop_deep:
			mov r10d, dword [rdx]
			
			;Compare labels
			cmp edi, esi
			
			;Move to r8 point where labels are same
			cmovz r10d, edi
			
			;Check if r10 > rdx
			cmp r10d, dword [rdx] 
			cmova r9d, r10d
	
			SHR edi,1
			SHR esi,1
			
			mov dword [rdx], r9d
			loop loop_deep

		ret


ostore_deepest_round:
		; Take inputs,  1 label, 2 flag, 3 ptr to deepest, 	
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		; Callee-saved : RBP, RBX, and R12–R15
		
		mov r9d, dword [rdx]
		mov r10d, dword [rdx]
		
		;Check flag
		cmp esi,1
		
		;Move to r8 point where labels are same
		cmovz r10d, edi
		
		;Check if r10 > rdx
		cmp r10d, dword [rdx] 
		cmova r9d, r10d
		
		mov dword [rdx], r9d

		ret

oset_goal_source:
		; Take inputs,  1 level_in_path, 2 value_to_put_i_goal 3 flag, 4 ptr to src, 5 ptr to goal		
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		; Callee-saved : RBP, RBX, and R12–R15

		mov r10d, dword[rcx]
		mov r11d, dword[r8]
	
		;Check flag
		cmp edx,1
		
		;
		cmovz r10d, edi
		cmovz r11d, esi
		
		mov dword[rcx], r10d
		mov dword[r8], r11d

		ret

oblock_move_on_flag:
		; Take inputs,  1 ptr to res_blk, 2 ptr to blk, 3 data_size, 4 flag
		; Windows : rcx,rdx,r8 ,r9
		; Linux : 	rdi,rsi,rdx,rcx->rbp

		; Callee-saved : RBP, RBX, and R12–R15

		push rbx
		push rbp
		push r12
		push r13
		push r14
		push r15

		; Extract data ptr from res_blk and iter_blk
		mov R10, qword [rdi]
		mov R11, qword [rsi]

		; Extract treelabels from res_blk and iter_blk
		mov R12d, dword [rdi+12]
		mov R13d, dword [rsi+12]

		;RCX will be lost for loop, store flag from rcx to rbp (1 byte , so bpl)
		mov bpl, cl

		; Oblivious evaluation of flag
		; Set iter_blk.treelabel to res_blk.treelabel if flag is set
		cmp bpl, 1
		cmovz r13d,r12d
		mov dword [rsi+12], r13d

		;Set loop parameters
		mov ax, dx
		xor rdx, rdx
		mov bx, 8
		div bx
		mov cx, ax

		; Loop to fetch iter & res chunks till data_size
		loopstart2:
			cmp bpl,1
			mov r14, qword [r10]
			mov r15, qword [r11]
			cmovz r14, r15 				;r14 / r15 based on the compare
			mov qword [r10], r14
			add r10, 8
			add r11, 8
			loop loopstart2

		pop r15
		pop r14
		pop r13
		pop r12
		pop rbp
		pop rbx

		ret

stash_insert:
		;Windows : RCX = iter->block, RDX = block, r8 = block_size, r9 = !(valid & !iter->occuppied (i.e. available) )
		;Windows:rcx,rdx,r8 ,r9 ,r12->r8
		;Linux : rdi,rsi,rdx,rcx,r8,r9
		;Calle-save registers : rbp, rbx, r12, r13, r14, r15.
		; Stash has the value of bool block_written

		; block : data, id, treelabel, r

		push rbx
		push rbp
		push r12
		push r13
		push r14
		push r15

		mov rbp,rcx

		;Linux_NOTES : r12 should hold ptr to block_written (r8 by Linux calling convention)

		; iter -> block -> data
		; Pointer to iter->block moved to r10
		mov r15, qword [rdi]
		mov r10, qword [r15]
		
		; Pointer block-data in r11		
		mov r11, qword [rsi]

		;Pointer to occupied
		add rdi, 8
		mov rax, rdi

		; pointer to occupied flag in node iter at r14
		mov r14, rax

		;Setup for transfer to written_flag
		xor rax,rax
		xor rbx,rbx

		; Check flag (r9)
		cmp bpl, 1

		; Set block_written flag if flag is valid else leave present_value unchanged
		mov al, 1
		mov bl, byte [r8]
		cmovz rbx, rax
		mov byte [r8], bl

		;Set occupied_flag if flag is true , else leave present_value unchanged;
		mov bl, byte [r14]
		cmovz rbx, rax
		mov [r14], bl

		; obliviously move id
		mov r12d, dword [r15+8]
		mov r13d, dword [rsi+8]
		cmovz r12d, r13d
		mov dword [r15+8], r12d

		;obliviously move tree label
		mov r12d, dword [r15+12]
		mov r13d, dword [rsi+12]
		cmovz r12d, r13d
		mov dword [r15+12], r12d

		;Set loop parameters
		mov ax, dx
		xor rdx, rdx
		mov bx, 8
		div bx
		mov cx, ax

		;Oblivious transfer to iter-block's data
		loop_stash_insert:
			;Check flag (r9)
			cmp bpl, 1
			mov r14, qword [r10]
			mov r15, qword [r11]
			cmovz r14, r15 				;r14 / r15 based on the compare
			mov qword [r10], r14
			add r10, 8
			add r11, 8
			loop loop_stash_insert

		pop r15
		pop r14
		pop r13
		pop r12
		pop rbp
		pop rbx

		ret


stash_serialized_insert:
		; Linux : rdi,rsi,rdx,rcx,r8,r9
		; Calle-save registers : rbp, rbx, r12, r13, r14, r15.
		; Stash has the value of bool block_written

		; block : data, id, treelabel, r

		push rbx
		push rbp
		push r12
		push r13
		push r14
		push r15

		mov rbp,rcx

		;Linux_NOTES : r12 should hold ptr to block_written (r8 by Linux calling convention)

		; Ptr to data of iter
		mov r10, rdi
		add r10, 24		

		; Pointer block-data in r11		
		mov r11, rsi
		add r11, 24

		;Setup for transfer to written_flag
		xor rax,rax
		xor rbx,rbx

		; Check flag (r9)
		cmp bpl, 1

		; Set block_written flag if flag is valid else leave present_value unchanged
		mov al, 1
		mov bl, byte [r8]
		cmovz rbx, rax
		mov byte [r8], bl

		; obliviously move id
		mov r12d, dword [rdi+16]
		mov r13d, dword [rsi+16]
		cmovz r12d, r13d
		mov dword [rdi+16], r12d

		;obliviously move tree label
		mov r12d, dword [rdi+20]
		mov r13d, dword [rsi+20]
		cmovz r12d, r13d
		mov dword [rdi+20], r12d

		;Set loop parameters
		mov ax, dx
		xor rdx, rdx
		mov bx, 8
		div bx
		mov cx, ax

		;Oblivious transfer to iter-block's data
		loop_stash_insert2:
			;Check flag (r9)
			cmp bpl, 1
			mov r14, qword [r10]
			mov r15, qword [r11]
			cmovz r14, r15 				;r14 / r15 based on the compare
			mov qword [r10], r14
			add r10, 8
			add r11, 8
			loop loop_stash_insert2

		pop r15
		pop r14
		pop r13
		pop r12
		pop rbp
		pop rbx

		ret


