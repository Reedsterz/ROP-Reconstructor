import os, argparse

def load_ropgadgets(file, rop_dict):
    fropgadget = open(file, 'r')

    for line in fropgadget:

        line = line.strip()

        if line == '':
            break

        if "Gadgets" in line or "====" in line:
            continue

        line_arr = line.split(' : ')
        address = line_arr[0]
        int_address = int(address, 16)
        hex_address = hex(int_address)
        instructions = line_arr[1].split(' ; ')

        rop_dict[hex_address] = instructions

    fropgadget.close()

    return rop_dict

def load_pintool_trace(file, ins_list):
    fpintool = open(file, 'r')

    for line in fpintool:

        line = line.strip()
        ins_arr = line.split()

        if(len(ins_arr) == 0):
            continue

        try:
            ins_int_address = int(ins_arr[0], 16)
            ins_hex_address = hex(ins_int_address)

            instruction = " ".join(ins_arr[1:len(ins_arr)])

            ins_list.append((ins_hex_address, instruction))

        except ValueError:
            continue

    return ins_list


def get_function_address(file, funct_dict):

	cmd = "objdump -d {} | grep \">:\"".format(file)
	output = os.popen(cmd).read()

	functions_list = output.split('\n')

   	for functions in functions_list:
   		function = functions.split()

		if function == []:
			continue

		addr, function_name = function[0], function[1]

		try:
			int_address = int(addr, 16)
			hex_address = hex(int_address)

			funct_dict[hex_address] = function_name

		except ValueError:
			continue

	return funct_dict

def get_ropchains(rop_dict, funct_dict, ins_list):

    reg_8 = ["al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
    reg_16 = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
    reg_32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
    reg_64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

    index = 0
    chain = False

    payload = []
    p_hex_ret_addr = ''
    #print("Pin tool")
    #print(ins_list)
    #print("ROPGadget")
    #print(rop_dict)
    #print('Function')
    #print(funct_dict)
    while index < len(ins_list):

	#current instruction
        addr, ins = ins_list[index][0], ins_list[index][1]

        instruction, ret_addr = ins.split()[0], ins.split()[1]

        int_ret_addr = int(ret_addr, 16)
        hex_ret_addr = hex(int_ret_addr)
	#print('current:' + hex_ret_addr)
	#previous intruction
	if (index != 0):
		p_addr, p_ins = ins_list[index - 1][0], ins_list[index - 1][1]

		p_instruction, p_ret_addr = p_ins.split()[0], p_ins.split()[1]

		p_int_ret_addr = int(p_ret_addr, 16)
		p_hex_ret_addr = hex(p_int_ret_addr)
		#print('previous:' + p_hex_ret_addr)

        if hex_ret_addr in rop_dict:

            gadgets = rop_dict[hex_ret_addr]

	    gadget_string = "{} -> {}".format(hex_ret_addr, gadgets)

	    if index != 0 and (p_hex_ret_addr in rop_dict or p_hex_ret_addr in funct_dict):
		payload.append(gadget_string)
            elif len(payload) == 0:
		payload.append(gadget_string)
	    else:
		index += 1;
		continue

	    for gadget in gadgets:
                if "pop" in gadget:
                    reg = gadget.split()[1]
                    if reg in reg_8:
                        payload.append("<token 1>")
                    elif reg in reg_16:
                        payload.append("<token 2>")
                    elif reg in reg_32:
                        payload.append("<token 4>")
                    elif reg in reg_64:
                        payload.append("<token_8>")

        elif hex_ret_addr in funct_dict:

        	funct_string = "{} -> {}".format(hex_ret_addr, funct_dict[hex_ret_addr])

		if index != 0 and (p_hex_ret_addr in rop_dict or p_hex_ret_addr in funct_dict):
		    payload.append(funct_string)
            	elif len(payload) == 0:
		    payload.append(funct_string)
	        else:
		    index += 1;
		    continue

        index += 1
    for item in payload:
	print(item)

def main():

    parser = argparse.ArgumentParser(description="ROP-Reconstructor")

    parser.add_argument('-r', help = "The path to ROPGadget output")
    parser.add_argument('-f', help = "The path to objdump output")
    parser.add_argument('-i', help = "The path to Pintool output")

    args = parser.parse_args()

    rop_dict = {}
    rop_dict = load_ropgadgets(args.r, rop_dict)

    funct_dict = {}
    funct_dict = get_function_address(args.f, funct_dict)

    ins_list = []
    ins_list = load_pintool_trace(args.i, ins_list)

    get_ropchains(rop_dict, funct_dict, ins_list)

if __name__ == "__main__":
    main()
