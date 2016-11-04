from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
import sys

# def hook_code(uc, address, size, user_data):
#	print(">>> Tracing instruction at 0x%x, instruction size = %u" %(address, size))

def createmap( mu, address, size):
	chunk = address % 0x1000
	taddr = address - chunk
	tsize = ((0xFFF + chunk + size) / 0x1000) * 0x1000
	mu.mem_map( taddr, tsize, UC_PROT_ALL) 
 

def pHash( mu, buffer, size , hashFuncAddr ):
	r0 = 0xE0001000;
	r1 = size;
	r2 = hashFuncAddr + 1;
	mu.reg_write(UC_ARM_REG_R0, r0);
	mu.reg_write(UC_ARM_REG_R1, r1);
	mu.reg_write(UC_ARM_REG_R2, r2);

	
	mu.mem_write(r0, ''.join(str(e) for e in buffer));

	
	stub = b"\x90\x47"
	
	mu.emu_start(0x1000, 0x1000 + id(stub), 0, 0)
	

	r0 = mu.reg_read(UC_ARM_REG_R0)
	r1 = mu.reg_read(UC_ARM_REG_R1)

	ret = r1;
	ret = (ret << 32) | r0;
	
	print(">>> r0 = 0x%x" %r0)
	print(">>> r1 = 0x%x" %r1)
	print(ret)
	print(">>> ret64 = 0x%x" %ret)
	ret = ret >> 0 ^ ret >> 32
	print(ret)
	print(">>> ret32 = 0x%x" %ret)
 
 
print("Emulate Pogo Hash code")
try:
	POGO_FILENAME = "pokemongo.43.3"
	POGO_BIN_SIZE = 0x02C9C5A0 
	POGO_BIN_OFFSET = 0x0000B730
	POGO_BIN_MAX = 0x02DCA128
	POGO_FUNC  = 0x01AD7D98
	POGO_FUNC_END = 0x01ad8732 
	POGO_EXP_DATA = 0x02C9C650
	POGO_EXP_ADDR = 0x029AC000
	POGO_EXP_CNT = 0xD58D
	HASH_FUNC_ADDR = 0x01BE8290
	HASHSEED = 0x61247FBF
	
	stub = b"\x90\x47"
	# Initialize emulator in X86-32bit mode
	mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
	
	#mu.hook_add(UC_HOOK_CODE, hook_code)
	# heap and stack allocation
	createmap(mu, 0xE0000000, 0x2000)
	createmap(mu, 0xD0000000, 0x2000)
	sp = 0xD0000000 + 0x1000
	
	# stack
	mu.reg_write(UC_ARM_REG_SP, sp)

	# start code calling hash func
	createmap(mu, 0x1000, 0x1000)
	mu.mem_write(0x1000, stub)
	
	# binary mapping
	f = open(POGO_FILENAME, 'r')
	f.seek(0)
	size = POGO_BIN_SIZE
	code = f.read(size)
	
	# memory prepare
	createmap(mu, POGO_BIN_OFFSET, POGO_BIN_MAX - POGO_BIN_OFFSET)
	
	# all segment
	mu.mem_write(POGO_BIN_OFFSET, code[POGO_BIN_OFFSET:])
	
	patch = b"\x00\x20"
	
	mu.mem_write(0x01BE9D9E, patch)

	
	exportdata = POGO_EXP_DATA
	exportaddr = POGO_EXP_ADDR
	cnt = 0
	for i in range(0, POGO_EXP_CNT):
		value = (code[exportaddr + (i * 4):])

		if value == "": # before was == 0
			mu.mem_write(exportaddr + (i * 4), str(exportdata))
			cnt = cnt + 1
			
	print("changes ", cnt)
	
	buffer = [0] * 28
	buffer[0] = 0x61
	buffer[1] = 0x24
	buffer[2] = 0x7f
	buffer[3] = 0xbf
	j = 28;

	
	pHash (mu, buffer, j, HASH_FUNC_ADDR)
	
	
	buffer = [ 0x61, 0x24, 0x7f, 0xbf, 0x0a, 0x50, 0x9c, 0x93, 0x7d, 
			0x0e, 0xb0, 0xb1, 0x0c, 0xc3, 0x62, 0x86, 0xa6, 0x61, 
			0xeb, 0x6e, 0xbd, 0x64, 0x62, 0xc2, 0x17, 0xe3, 0x81, 
			0x50, 0xf0, 0x2e, 0xcf, 0x54, 0x3a, 0x56, 0x6b, 0xed, 
			0x74, 0x54, 0xb7, 0x80, 0xa9, 0x93, 0x5a, 0xd9, 0xea, 
			0xf7, 0x2d, 0xb1, 0x40, 0x1e, 0xad, 0x3e, 0xaf, 0xa9, 
			0xcf, 0x69, 0x6c, 0x74, 0x39, 0xe0, 0xe3, 0x7f, 0x17, 
			0x61, 0xa3, 0x0e, 0x61, 0x2f, 0x34, 0x32, 0x09, 0xda, 
			0xcf, 0xc4, 0x54, 0x91, 0xd9, 0xce, 0xdf, 0x29, 0x02, 
			0xae, 0x6a, 0x85, 0x10, 0x08, 0x10, 0xcc, 0x99, 0xc2, 
			0xec, 0x80, 0x2b, 0x1a, 0x10, 0x90, 0x91, 0xcf, 0xc5, 
			0xa3, 0x5e, 0xfd, 0xdf, 0x86, 0x62, 0xb3, 0xe2, 0x2c, 
			0xe0, 0x21, 0x08 ]
	j = 111
	
		
	pHash (mu, buffer, j, HASH_FUNC_ADDR)
	
	buffer = [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
	j = 24
	
	pHash (mu, buffer, j, HASH_FUNC_ADDR)
	
	buffer = [ 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
			  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 ]
	j = 24
	
	pHash (mu, buffer, j, HASH_FUNC_ADDR)
	

	newbuff = [(HASHSEED >> 24) & 0xFF, (HASHSEED >> 16) & 0xFF
		, (HASHSEED >> 8) & 0xFF, (HASHSEED >> 0) & 0xFF];
	newbuff[4:4+24] = buffer
	
	
	pHash (mu, newbuff, j, HASH_FUNC_ADDR)
	
except UcError as e:
     print("ERROR: %s" % e)
	 
	