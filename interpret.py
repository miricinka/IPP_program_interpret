######
# File name: interpret.py
# Description: Projekt 2 do predmetu IPP 2020, FIT VUT
# Athor: Mirka Kolarikova (xkolar76)
# Date: 3.4.2020
######

from __future__ import print_function
import sys
import argparse
import re
import xml.etree.ElementTree as ET

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    
#validates order
def is_valid_order(num):
	try:
		if int(num) <= 0:
			eprint('ERROR 32: ',num, 'is not a valid instruction order')
			sys.exit(32)
	except Exception:
		eprint('ERROR 32: ',num, 'is not a valid instruction order')
		sys.exit(32)
	return int(num)

#validates number of arguments
def arg_count_check(actual, expected, opcode):
	if actual != expected:
		eprint('ERROR 32: Wrong number of arguments in instruction',opcode)
		sys.exit(32)

#converts hexadecimal sequences to string values
#returns converted string
def convert_string(string):
	string_len = len(string)
	converted_string = ''
	i = 0
	while i < string_len:
		char = string[i]
		if char.isspace() or char == "#":
			eprint('ERROR 32: Invalid string.')
			sys.exit(32)
		elif char == '\\':
			char1 = string[i+1]
			char2 = string[i+2]
			char3 = string[i+3]
			convert = ((100 * int(char1)) + (10 * int(char2)) + int(char3))
			if not(convert >= 0 and convert <= 999):
				eprint('ERROR 32: Invalid string.')
				sys.exit(32)
			i = i +3
			converted_string = converted_string + chr(convert)
		else:
			converted_string = converted_string + char
		i = i+1
	return converted_string

#valides syntax of arg1
#returns arg1
def arg1_check(args):
	arg1 = args.findall("arg1")
	if len(arg1) != 1:
		eprint('ERROR 32: Invalid arguments.')
		sys.exit(32)
	arg1 = arg1[0]
	if len(arg1.attrib) == 1:
		if 'type' not in arg1.attrib:
			eprint('ERROR 32: Invalid argument.')
			sys.exit(32)
	else: 
		eprint('ERROR 32: Invalid argument attribut.')
		sys.exit(32)
	arg1 = [arg1.attrib['type'],arg1.text]
	return arg1

#valides syntax of arg2
#return arg2
def arg2_check(args):
	arg2 = args.findall("arg2")
	if len(arg2) != 1:
		eprint('ERROR 32: Invalid arguments.')
		sys.exit(32)
	arg2 = arg2[0]
	if len(arg2.attrib) == 1:
		if 'type' not in arg2.attrib:
			eprint('ERROR 32: Invalid argument.')
			sys.exit(32)
	else: 
		eprint('ERROR 32: Invalid argument.')
		sys.exit(32)
	arg2 = [arg2.attrib['type'],arg2.text]
	return arg2

#valides syntax of arg3
#return arg3
def arg3_check(args):
	arg3 = args.findall("arg3")
	if len(arg3) != 1:
		eprint('ERROR 32: Invalid arguments.')
		sys.exit(32)
	arg3 = arg3[0]
	if len(arg3.attrib) == 1:
		if 'type' not in arg3.attrib:
			eprint('ERROR 32: Invalid argument.')
			sys.exit(32)
	else: 
		eprint('ERROR 32: Invalid argument.')
		sys.exit(32)
	arg3 = [arg3.attrib['type'],arg3.text]
	return arg3

#valides variable name
def var_name_check(variable):
	if variable[0] != 'var':
		eprint('ERROR 32: Invalid variable argument.')
		sys.exit(32)
	if variable[1] == None:
			eprint('ERROR 32: Lexical error in variable name.')
			sys.exit(32)
	var_name = re.match('^(LF|TF|GF)@([A-Za-z]|_|-|\$|&|%|\*|!|\?)([A-Za-z0-9]|_|-|\$|&|%|\*|!|\?)*$',variable[1])
	if var_name == None:
		eprint('ERROR 32: Lexical error in variable name.')
		sys.exit(32)

#valides label name
def label_name_check(variable):
	if variable[0] != 'label':
		eprint('ERROR 32: Invalid label argument.')
		sys.exit(32)
	if variable[1] == None:
			eprint('ERROR 32: Lexical error in label name.')
			sys.exit(32)
	var_name = re.match('^([A-Za-z]|_|-|\$|&|%|\*|!|\?)([A-Za-z0-9]|_|-|\$|&|%|\*|!|\?)*$',variable[1])
	if var_name == None:
		eprint('ERROR 32: Lexical error in label name.')
		sys.exit(32)

#valides type name
def type_name_check(variable):
	if variable[0] != 'type':
		eprint('ERROR 32: Invalid type argument.')
		sys.exit(32)
	if variable[1] == 'int' or variable[1] == 'string' or variable[1] == 'bool' or variable[1] == 'float':
		pass
	else:
		eprint('ERROR 32: Lexical error in type name.')
		sys.exit(32)

#valides symbol
def symbol_name_check(variable):
	#variable
	if variable[0] == 'var':
		if variable[1] == None:
			eprint('ERROR 32: Lexical error in variable name.')
			sys.exit(32)
		var_name = re.match('^(LF|TF|GF)@([A-Za-z]|_|-|\$|&|%|\*|!|\?)([A-Za-z0-9]|_|-|\$|&|%|\*|!|\?)*$',variable[1])
		if var_name == None:
			eprint('ERROR 32: Lexical error in variable name.')
			sys.exit(32)
	#bool
	elif variable[0] == 'bool':
		if variable[1] == 'true' or variable[1] == 'false':
			pass
		else:
			eprint('ERROR 32: Bool can only be true or false.')
			sys.exit(32)
	#int
	elif variable[0] == 'int':
		if variable[1] == None:
			eprint('ERROR 32: Lexical error.')
			sys.exit(32)
		number= re.match('^((\+|-)[0-9]+)$|^([0-9]+)$', variable[1])
		if number == None:
			eprint('ERROR 32: Invalid int value.')
			sys.exit(32)
	#string
	elif variable[0] == 'string':
		if variable[1] == None:
			variable[1] = ""
		else:
			string = re.match('^(\\\\[0-9]{3}|[^\\\\])*$', variable[1]) #TODO chr() cislo na znak ord() znak na cislo
			if string == None:
				eprint('ERROR 32: Invalid escape sequence in string.')
				sys.exit(32)
			else:
				variable[1] = convert_string(variable[1])
	#nil
	elif variable[0] == 'nil':
		if variable[1] == None:
			eprint('ERROR 32: Lexical error.')
			sys.exit(32)
		if variable[1] != 'nil':
			eprint('ERROR 32: Invalid nil value.')
			sys.exit(32)
	#float
	elif variable[0] == 'float':
		if variable[1] == None:
			eprint('ERROR 32: Lexical error.')
			sys.exit(32)
		try: 
			variable[1] = float.fromhex(variable[1])
		except Exception:
			eprint('ERROR 32: Invalid float value.',variable[1])
			sys.exit(32)

	else:
		eprint('ERROR 32: Invalid symbol.')
		sys.exit(32)
	return variable

#validates lexicum and syntax of instruction and its arguments
def is_valid_opcode(opcode_before, order, myroot):
	global label_dict
	opcode = opcode_before.upper()
	args = myroot[i]
	args_num = len(args)
	instruction_dict= {
  		"opcode": opcode,
 		"arg1":   None,
  		"arg2":   None,
  		"arg3":   None,
	}
	# no arguments
	if opcode == "CREATEFRAME" or opcode == "PUSHFRAME" or opcode == "CLEARS" or\
	opcode == "POPFRAME" or opcode == "RETURN" or opcode == "BREAK" or opcode == "ADDS" or \
	opcode == "SUBS" or opcode == "MULS" or opcode == "IDIVS" or opcode == "LTS" or \
	opcode == "GTS" or opcode == "EQS" or opcode == "ANDS" or opcode == "ORS" or \
	opcode == "NOTS" or opcode == "INT2CHARS" or opcode == "STRI2INTS":
		arg_count_check(args_num,0,opcode)
	#label
	elif opcode == "CALL" or opcode == "LABEL" or opcode == "JUMP" or \
	opcode == "JUMPIFEQS" or opcode == "JUMPIFNEQS":
		arg_count_check(args_num,1,opcode)
		arg1 = arg1_check(args)
		label_name_check(arg1)
		instruction_dict["arg1"]=arg1
		#fill label dictionary
		if opcode == "LABEL": 
			if arg1[1] in label_dict:
				eprint('ERROR 52: Label already exists.')
				sys.exit(52)
			label_dict[arg1[1]] = order
	#var
	elif opcode == "DEFVAR" or opcode == "POPS":
		arg_count_check(args_num,1,opcode)
		arg1  = arg1_check(args)
		var_name_check(arg1)
		instruction_dict["arg1"]=arg1
	#symb
	elif opcode == "PUSHS" or opcode == "WRITE" or opcode == "EXIT" or opcode == "DPRINT":
		arg_count_check(args_num,1,opcode)
		arg1  = arg1_check(args)
		arg1 = symbol_name_check(arg1)
		instruction_dict["arg1"]=arg1
	#var type
	elif opcode == "READ":
		arg_count_check(args_num,2,opcode)
		arg1 = arg1_check(args)
		arg2 = arg2_check(args)
		var_name_check(arg1)
		type_name_check(arg2)
		instruction_dict["arg1"]=arg1
		instruction_dict["arg2"]=arg2
	#var symb
	elif opcode == "MOVE" or opcode == "NOT" or opcode == "INT2CHAR" or \
	opcode == "STRLEN" or opcode == "TYPE" or opcode == "INT2FLOAT" or opcode == "FLOAT2INT":
		arg_count_check(args_num,2,opcode)
		arg1 = arg1_check(args)
		arg2 = arg2_check(args)
		var_name_check(arg1)
		arg2 = symbol_name_check(arg2)
		instruction_dict["arg1"]=arg1
		instruction_dict["arg2"]=arg2
	#label symb symb
	elif opcode == "JUMPIFEQ" or opcode == "JUMPIFNEQ":
		arg_count_check(args_num,3,opcode)
		arg1 = arg1_check(args)
		arg2 = arg2_check(args)
		arg3 = arg3_check(args)
		label_name_check(arg1)
		arg2 = symbol_name_check(arg2)
		arg3 = symbol_name_check(arg3)
		instruction_dict["arg1"]=arg1
		instruction_dict["arg2"]=arg2
		instruction_dict["arg3"]=arg3
	#var symb symb
	elif opcode == "ADD" or opcode == "SUB" or opcode == "MUL" or opcode == "IDIV" or \
	opcode == "LT" or opcode == "GT" or opcode == "EQ" or opcode == "AND" or \
	opcode == "OR" or opcode == "STRI2INT" or opcode == "CONCAT" or opcode == "GETCHAR" or \
	opcode == "SETCHAR" or opcode == "DIV":
		arg_count_check(args_num,3,opcode)
		arg1 = arg1_check(args)
		arg2 = arg2_check(args)
		arg3 = arg3_check(args)
		var_name_check(arg1)
		arg2 = symbol_name_check(arg2)
		arg3 = symbol_name_check(arg3)
		instruction_dict["arg1"]=arg1
		instruction_dict["arg2"]=arg2
		instruction_dict["arg3"]=arg3
	else:
		eprint('ERROR 32: Invalid operation code:',opcode_before,'.')
		sys.exit(32)
	return instruction_dict

#get variable type and val
def get_var_val(variable):
	global i
	global global_frame;
	global local_frame;
	global temp_frame;
	global TF_set;

	variable = variable.split("@")
	if variable[0] == "GF":
		if variable[1] not in global_frame:
			eprint('ERROR 54: No defined variable: GF@',variable[1],',instr:',i,'.')
			sys.exit(54)
		else:
			typ = global_frame[variable[1]]["type"]
			val = global_frame[variable[1]]["value"]
	elif variable[0] == "LF":
		if len(local_frame) == 0:
			eprint('ERROR 55: Nonexisting frame LF.')
			sys.exit(55)
		if variable[1] not in local_frame[-1]:
			eprint('ERROR 54: No defined variable: LF@',variable[1],',instr:',i,'.')
			sys.exit(54)
		else:
			typ = local_frame[-1][variable[1]]["type"]
			val = local_frame[-1][variable[1]]["value"]
	elif variable[0] == "TF":
		if TF_set == True:
			if variable[1] not in temp_frame:
				eprint('ERROR 54: No defined variable: TF@',variable[1],',instr:',i,'.')
				sys.exit(54)
			else:
				typ = temp_frame[variable[1]]["type"]
				val = temp_frame[variable[1]]["value"]
		else:
			eprint('ERROR 55: Nonexisting frame, instr:',i,'.')
			sys.exit(55)
	if typ == None or val == None:
		eprint('ERROR 56: Missing variable value, instr:',i,'.')
		sys.exit(56)
	var_to_send = [typ,val]
	return var_to_send

#saves value into variable in variable dictionary
def safe_var_val(variable, typ, val):
	global i
	global global_frame;
	global local_frame;
	global temp_frame;
	global TF_set;
	global init_var_count;

	variable = variable.split("@")
	if variable[0] == "GF":
		if variable[1] not in global_frame:
			eprint('ERROR 54: No defined variable: GF@',variable[1],',instr:',i,'.')
			sys.exit(54)
		else:
			if global_frame[variable[1]]["type"] == None:
				init_var_count = init_var_count + 1
			global_frame[variable[1]]["type"] = typ
			global_frame[variable[1]]["value"] = val
	elif variable[0] == "LF":
		if len(local_frame) == 0:
			eprint('ERROR 55: Nonexisting frame LF.')
			sys.exit(55)
		if variable[1] not in local_frame[-1]:
			eprint('ERROR 54: No defined variable: LF@',variable[1],',instr:',i,'.')
			sys.exit(54)
		else:
			if local_frame[-1][variable[1]]["type"] == None:
				init_var_count = init_var_count + 1
			local_frame[-1][variable[1]]["type"] = typ
			local_frame[-1][variable[1]]["value"] = val
	elif variable[0] == "TF":
		if TF_set == True:
			if variable[1] not in temp_frame:
				eprint('ERROR 54: No defined variable: TF@',variable[1],',instr:',i,'.')
				sys.exit(54)
			else:
				if temp_frame[variable[1]]["type"] == None:
					init_var_count = init_var_count + 1
				temp_frame[variable[1]]["type"] = typ
				temp_frame[variable[1]]["value"] = val
		else:
			eprint('ERROR 55: Nonexisting frame, instr:',i,'.')
			sys.exit(55)

#checks if label exists and returns its order
def label_ok(label):
	global label_dict
	if label not in label_dict:
		eprint('ERROR 52: Jump to nonexisting label')
		sys.exit(52)
	return label_dict[label]


###################### PARSE INSTRUCTIONS #######################
#DEFVAR
def i_defvar(arg1):
	global i;
	global global_frame;
	global local_frame;
	global temp_frame;
	global TF_set;
	var_info_dict = {
		"type": None,
		"value": None
	}
	variable = arg1[1].split("@")
	if variable[0] == "GF":
		if variable[1] in global_frame:
			eprint('ERROR 52: Redefinition of variable: GF@',variable[1],',instr:',i,'.')
			sys.exit(52)
		global_frame[variable[1]] = var_info_dict
	elif variable[0] == "LF":
		if len(local_frame) == 0:
			eprint('ERROR 55: Nonexisting frame LF.')
			sys.exit(55)
		if variable[1] in local_frame[-1]:
			eprint('ERROR 52: Redefinition of variable: LF@',variable[1],',instr:',i,'.')
			sys.exit(52)
		local_frame[-1][variable[1]] = var_info_dict
	elif variable[0] == "TF":
		if TF_set == False:
			eprint('ERROR 55: Temporary frame is nonexisting frame.')
			sys.exit(55)
		if variable[1] in temp_frame:
			eprint('ERROR 52: Redefinition of variable: TF@',variable[1],',instr:',i,'.')
			sys.exit(52)
		temp_frame[variable[1]] = var_info_dict


#MOVE
def i_move(arg1,arg2):
	global i;
	global global_frame;
	global local_frame;
	global temp_frame;
	global TF_set;
	global init_var_count;

	#je to promenna
	if arg2[0] == "var":
		variable2 = arg2[1].split("@")
		if variable2[0] == "GF":
			if variable2[1] not in global_frame:
				eprint('ERROR 54: Redefinition of variable: GF@',variable2[1],',instr:',i,'.')
				sys.exit(54)
			else:
				typ = global_frame[variable2[1]]["type"] #None osetrit
				val = global_frame[variable2[1]]["value"]
		elif variable2[0] == "LF": #predelat
			if len(local_frame) == 0:
				eprint('ERROR 55: Nonexisting frame LF.')
				sys.exit(55)
			if variable2[1] not in local_frame[-1]:
				eprint('ERROR 54: Redefinition of variable: LF@',variable2[1],',instr:',i,'.')
				sys.exit(54)
			else:
				typ = local_frame[-1][variable2[1]]["type"] #None osetrit
				val = local_frame[-1][variable2[1]]["value"]
		elif variable2[0] == "TF":
			if TF_set == True:
				if variable2[1] not in temp_frame:
					eprint('ERROR 54: Redefinition of variable: TF@',variable2[1],',instr:',i,'.')
					sys.exit(54)
				else:
					typ = temp_frame[variable2[1]]["type"] #None osetrit
					val = temp_frame[variable2[1]]["value"]
			else:
				eprint('ERROR 55: Nonexisting frame, instr:',i,'.')
				sys.exit(55)
		if typ == None or val == None:
			eprint('ERROR 56: Missing var value, instr:',i,'.')
			sys.exit(56)
	#je to symbol
	else:
		typ = arg2[0]
		val = arg2[1]

	safe_var_val(arg1[1],typ,val)

#ADD, SUB, MUL IDIV
def i_arithmetic(arg1, arg2, arg3, opcode):
	global i;
	global global_frame;
	global local_frame;
	global temp_frame;
	global TF_set;
	#get arg2 arg3 type and val
	if arg2[0] == "var":
		arg2 = get_var_val(arg2[1])
	if arg3[0] == "var":
		arg3 = get_var_val(arg3[1])
	# int int
	if arg2[0] == "int" and arg3[0] == "int":
		value1 = arg2[1]
		value2 = arg3[1]
		if opcode == "ADD":
			result = int(value1) + int(value2)
		elif opcode == "SUB":
			result = int(value1) - int(value2)
		elif opcode == "MUL":
			result = int(value1) * int(value2)
		elif opcode == "IDIV":
			if int(value2) == 0:
				eprint('ERROR 57: Division by zero!.')
				sys.exit(57)
			result = int(value1) // int(value2)
			result = int(result)
		safe_var_val(arg1[1], "int", str(result))
	#float float
	elif arg2[0] == "float" and arg3[0] == "float":
		value1 = arg2[1]
		value2 = arg3[1]
		if opcode == "ADD":
			result = value1 + value2
		elif opcode == "SUB":
			result = value1 - value2
		elif opcode == "MUL":
			result = value1 * value2
		elif opcode == "IDIV":
			eprint('ERROR 53: IDIV operations can only be done with int types.')
			sys.exit(53)
		safe_var_val(arg1[1], "float", result)
	else:
		eprint('ERROR 53: Arithmetic operations can only be done with int or float types.')
		sys.exit(53)

#PUSHS
def i_pushs(arg1):
	global zasobnik;
	if arg1[0] == "var":
		arg1 = get_var_val(arg1[1])
	zasobnik.append(arg1)

#POPS
def i_pops(arg1):
	global zasobnik;
	if len(zasobnik) == 0:
		eprint('ERROR 56: Empty stack!')
		sys.exit(56)
	last = zasobnik[-1]
	zasobnik.pop()
	safe_var_val(arg1[1], last[0], last[1])

#INT2CHAR
def i_int2char(arg1, arg2):
	if arg2[0] == "var":
		arg2_in = get_var_val(arg2[1])
		if arg2_in[0] != "int":
			eprint('ERROR 53: STRI2INT is not int!')
			sys.exit(53)
		num = int(arg2_in[1])
	elif arg2[0] != "int":
		eprint('ERROR 53: INT2CHAR is not int!')
		sys.exit(53)
		num= int(arg2[1])
	if num > 127 or num < 1:
		eprint('ERROR 58: INT2CHAR bad value!')
		sys.exit(58)
	char = chr(num)
	safe_var_val(arg1[1], "string", char)

#STRI2INT
def i_stri2int(arg1, arg2, arg3):

	if arg2[0] == "var":
		arg2_in = get_var_val(arg2[1])
		if arg2_in[0] != "string":
			eprint('ERROR 53: STRI2INT is not string!')
			sys.exit(53)
		string = arg2_in[1]
	elif arg2[0] == "string":
		string = arg2[1]
	else:
		eprint('ERROR 53: STRI2INT is not string!')
		sys.exit(53)

	if arg3[0] == "var":
		arg3_in = get_var_val(arg3[1])
		if arg3_in[0] != "int":
			eprint('ERROR 53: STRI2INT is not int!')
			sys.exit(53)
		position= arg3_in[1]
	elif arg3[0] == "int":
		position = arg3[1]
	else:
		eprint('ERROR 53: STRI2INT is not int!')
		sys.exit(53)

	if (len(string)-1) < int(position) or int(position) < 0:
		eprint('ERROR 58: STRI2INT wrong string usage!')
		sys.exit(58)
	char = ord(string[int(position)])
	safe_var_val(arg1[1], "int", str(char))

#CONCAT
def i_concat(arg1, arg2, arg3):
	if arg2[0] == "var":
		arg2_in = get_var_val(arg2[1])
		if arg2_in[0] != "string":
			eprint('ERROR 58: CONCAT is not string!')
			sys.exit(58)
		string1 = arg2_in[1]
	elif arg2[0] == "string":
		string1 = arg2[1]
	else:
		eprint('ERROR 58: CONCAT is not string!')
		sys.exit(58)

	if arg3[0] == "var":
		arg3_in = get_var_val(arg3[1])
		if arg3_in[0] != "string":
			eprint('ERROR 58: CONCAT is not string!')
			sys.exit(58)
		string2= arg3_in[1]
	elif arg3[0] == "string":
		string2 = arg3[1]
	else:
		eprint('ERROR 58: CONCAT is not string!')
		sys.exit(58)
	concatenated_string = string1 + string2
	safe_var_val(arg1[1], "string", concatenated_string)

#STRLEN
def i_strlen(arg1,arg2):
	if arg2[0] == "var":
		arg2_in = get_var_val(arg2[1])
		if arg2_in[0] != "string":
			eprint('ERROR 58: STRLEN is not string!')
			sys.exit(58)
		string1 = arg2_in[1]
	elif arg2[0] == "string":
		string1 = arg2[1]
	else:
		eprint('ERROR 58: STRLEN is not string!')
		sys.exit(58)

	num = len(string1)
	safe_var_val(arg1[1], "int", num)

#WRITE
def i_write(arg1):
	if arg1[0] == "var":
		arg1 = get_var_val(arg1[1])
	if arg1[0] == "nil":
		print("",end='')
	elif arg1[0] == "float":
		print(float.hex(arg1[1]),end='')
	else:
		print(arg1[1],end='')

#READ
def i_read(arg1,arg2):
	global i
	global s_file
	global f
	input_string = ""
	try:
		input_string = input()
	except Exception:
		safe_var_val(arg1[1], "nil", "nil")
	if not input_string or input_string == "":
		safe_var_val(arg1[1], "nil", "nil")
	else:
		#reading int
		if arg2[1] == "int":
			number= re.match('^((\+|-)[0-9]+)$|^([0-9]+)$', input_string)
			if number == None:
				input_string = "nil"
				safe_var_val(arg1[1], "nil", "nil")
			else:
				safe_var_val(arg1[1], "int", input_string)
		#reading string
		elif arg2[1] == "string":
				safe_var_val(arg1[1], "string", input_string)
		#reading bool
		elif arg2[1] == "bool":
			if input_string.upper() == "TRUE":
				safe_var_val(arg1[1], "bool", "true")
			else:
				safe_var_val(arg1[1], "bool", "false")
		#reading float
		elif arg2[1] == "float":
			try: 
				input_string = float.fromhex(input_string)
			except Exception:
				eprint('ERROR 32: Invalid float value.',input_string)
				sys.exit(32)
			safe_var_val(arg1[1], "float", input_string)

#LT GT EQ
def i_relation(arg1,arg2,arg3,opcode):
	global i;

	if arg2[0] == "var":
		arg2 = get_var_val(arg2[1])
	if arg3[0] == "var":
		arg3 = get_var_val(arg3[1])

	#nil in EQ
	if arg2[0] == "nil" or arg3[0] == "nil":
		if opcode != "EQ":
			eprint('ERROR 53: Type nil can be compared only by EQ!')
			sys.exit(53)
		if arg2[0] == "nil" and arg3[0] == "nil":
			result = True
		else:
			result = False
	elif arg2[0] == "int" and arg3[0] == "int":
		if opcode == "EQ":
			result = int(arg2[1]) == int(arg3[1])
		elif opcode == "GT":
			result = int(arg2[1]) > int(arg3[1])
		elif opcode == "LT":
			result = int(arg2[1]) < int(arg3[1])
	elif (arg2[0] == "string" and arg3[0] == "string") or (arg2[0] == "bool" and arg3[0] == "bool"):
		if opcode == "EQ":
			result = arg2[1] == arg3[1]
		elif opcode == "GT":
			result = arg2[1] > arg3[1]
		elif opcode == "LT":
			result = arg2[1] < arg3[1]
	elif arg2[0] == "float" and arg3[0] == "float":
		if opcode == "EQ":
			result = arg2[1] == arg3[1]
		elif opcode == "GT":
			result = arg2[1] > arg3[1]
		elif opcode == "LT":
			result = arg2[1] < arg3[1]
	else:
		eprint('ERROR 53: Invalid operands ',arg2[0],arg3[0],'types',opcode,'intstr:',i,'!')
		sys.exit(53)

	if result == True:
		safe_var_val(arg1[1], "bool", "true")
	else:
		safe_var_val(arg1[1], "bool", "false")

#NOT
def i_not(arg1, arg2):
	if arg2[0] == "var":
		arg2 = get_var_val(arg2[1])

	if arg2[0] != "bool":
		eprint('ERROR 53: Not operand must be bool!')
		sys.exit(53)

	if arg2[1] == "true":
		safe_var_val(arg1[1], "bool", "false")
	if arg2[1] == "false":
		safe_var_val(arg1[1], "bool", "true")

#AND OR
def i_andor(arg1,arg2,arg3,opcode):
	if arg2[0] == "var":
		arg2 = get_var_val(arg2[1])
	if arg3[0] == "var":
		arg3 = get_var_val(arg3[1])

	if arg2[0] != "bool" or arg3[0] != "bool":
		eprint('ERROR 53: Logic operations must be bool!')
		sys.exit(53)

	if arg2[1] == "true":
		value_2 = True;
	else:
		value_2 = False;

	if arg3[1] == "true":
		value_3 = True;
	else:
		value_3 = False;

	if opcode == "AND":
		result = value_2 and value_3
	elif opcode == "OR":
		result = value_2 or value_3

	if result == True:
		safe_var_val(arg1[1], "bool", "true")
	elif result == False:
		safe_var_val(arg1[1], "bool", "false")

#TYPE
def i_type(arg1,arg2):
	global i
	global global_frame;
	global local_frame;
	global temp_frame;
	global TF_set;


	if arg2[0] == "var":
		variable = arg2[1].split("@")
		if variable[0] == "GF":
			if variable[1] not in global_frame:
				eprint('ERROR 54: Nondefined var: GF@',variable[1],',instr:',i,'.')
				sys.exit(54)
			else:
				typ = global_frame[variable[1]]["type"]
				val = global_frame[variable[1]]["value"]
		elif variable[0] == "LF":
			if len(local_frame) == 0:
				eprint('ERROR 55: Nondefined vframe LF.')
				sys.exit(55)
			if variable[1] not in local_frame[-1]:
				eprint('ERROR 54: Nondefined var: LF@',variable[1],',instr:',i,'.')
				sys.exit(54)
			else:
				typ = local_frame[-1][variable[1]]["type"]
				val = local_frame[-1][variable[1]]["value"]
		elif variable[0] == "TF":
			if TF_set == True:
				if variable[1] not in temp_frame:
					eprint('ERROR 54: Nondefined var: TF@',variable[1],',instr:',i,'.')
					sys.exit(54)
				else:
					typ = temp_frame[variable[1]]["type"]
					val = temp_frame[variable[1]]["value"]
			else:
				eprint('ERROR 55: Nondefined frame, instr:',i,'.')
				sys.exit(55)
		if typ == None or val == None:
			safe_var_val(arg1[1], "string", "")
	elif arg2[0] == "int":
			safe_var_val(arg1[1], "string", "int")
	elif arg2[0] == "bool":
			safe_var_val(arg1[1], "string", "bool")
	elif arg2[0] == "string":
			safe_var_val(arg1[1], "string", "string")
	elif arg2[0] == "nil":
			safe_var_val(arg1[1], "string", "nil")
	elif arg2[0] == "float":
			safe_var_val(arg1[1], "string", "float")

#EXIT
def i_exit(arg1):
	if arg1[0] == "var":
		arg1 = get_var_val(arg1[1])
	if arg1[0] != "int":
		eprint('ERROR 53: EXIT bad value.')
		sys.exit(53)
	if int(arg1[1]) < 0 or int(arg1[1]) > 49:
		eprint('ERROR 57: EXIT bad value, must be 0 - 49.')
		sys.exit(57)

	sys.exit(int(arg1[1]))

#GETCHAR
def i_getchar(arg1,arg2,arg3):
	if arg2[0] == "var":
		arg2_in = get_var_val(arg2[1])
		if arg2_in[0] != "string":
			eprint('ERROR 53: GETCHAR is not string!')
			sys.exit(53)
		string = arg2_in[1]
	elif arg2[0] == "string":
		string = arg2[1]
	else:
		eprint('ERROR 53: GETCHAR is not string!')
		sys.exit(53)

	if arg3[0] == "var":
		arg3_in = get_var_val(arg3[1])
		if arg3_in[0] != "int":
			eprint('ERROR 53: GETCHAR is not int!')
			sys.exit(53)
		position= arg3_in[1]
	elif arg3[0] == "int":
		position = arg3[1]
	else:
		eprint('ERROR 53: GETCHAR is not int!')
		sys.exit(53)

	if (len(string)-1) < int(position) or int(position) < 0:
		eprint('ERROR 58: GETCHAR wrong string usage!')
		sys.exit(58)

	char = string[int(position)]
	safe_var_val(arg1[1], "string", str(char))

#SETCHAR
def i_setchar(arg1,arg2,arg3):
	arg1_in = get_var_val(arg1[1])
	if arg1_in[0] != "string":
		eprint('ERROR 53: arg1 in instr SETCHAR is not string!')
		sys.exit(53)
	string1 = arg1_in[1]
	if arg2[0] == "var":
		arg2 = get_var_val(arg2[1])
	if arg3[0] == "var":
		arg3 = get_var_val(arg3[1])

	if arg2[0] != "int":
		eprint('ERROR 53: arg2 in instr SETCHAR is not int!')
		sys.exit(53)
	position = arg2[1]

	if arg3[0] != "string":
		eprint('ERROR 53: arg3 in instr SETCHAR is not string!')
		sys.exit(53)

	string2 = arg3[1]
	if string2 == "":
		eprint('ERROR 58: empty string arg3 in instr SETCHAR!')
		sys.exit(58)

	if (len(string1)-1) < int(position) or int(position) < 0:
		eprint('ERROR 58: SETCHAR wrong string usage!')
		sys.exit(58)

	new = list(string1)
	new[int(position)] = string2[0]
	safe_var_val(arg1[1], "string", ''.join(new))

#JUMP
def i_jump(arg1):
	global i;
	num = label_ok(arg1[1])
	i = num - 1

#CALL
def i_call(arg1):
	global i;
	global call_stack;
	num = label_ok(arg1[1])
	call_stack.append(i)
	i = num - 1

#RETURN
def i_return():
	global i;
	global call_stack;
	if len(call_stack) == 0:
		eprint('ERROR 56: Empty call stack!')
		sys.exit(56)
	i = call_stack.pop()

#JUMPIFEQ JUMPIFNEQ
def i_jumpeq_jumpneq(arg1,arg2,arg3,opcode):
	global i;

	num = label_ok(arg1[1])
	if arg2[0] == "var":
		arg2 = get_var_val(arg2[1])
	if arg3[0] == "var":
		arg3 = get_var_val(arg3[1])

	if arg2[0] == "nil" and arg3[0] == "nil":
		result = True
	elif arg2[0] == "nil" or arg3[0] == "nil":
		result = False
	elif arg2[0] == "int" and arg3[0] == "int":
		result = int(arg2[1]) == int(arg3[1])
	elif (arg2[0] == "string" and arg3[0] == "string") or (arg2[0] == "bool" and arg3[0] == "bool"):
		result = arg2[1] == arg3[1]
	else:
		eprint('ERROR 53: Incorrect operand types in instr',opcode,'!')
		sys.exit(53)

	if opcode == "JUMPIFEQ":
		if result == True:
			i = num - 1

	elif opcode == "JUMPIFNEQ":
		if result == False:
			i = num - 1

#CREATFRAME
def i_createframe():
	global i;
	global TF_set;
	global temp_frame;
	global local_frame;
	TF_set = True
	temp_frame.clear()


#PUSHFRAME
def i_pushframe():
	global local_frame;
	global temp_frame;
	global TF_set;

	if TF_set == False:
		eprint('ERROR 55: Nonexisting TF, instr PUSHFRAME!')
		sys.exit(55)

	local_frame.append(temp_frame.copy())
	TF_set = False

#POPFRAME
def i_popframe():
	global local_frame;
	global temp_frame;
	global TF_set;
	if len(local_frame) == 0:
		eprint('ERROR 55: Nonexisting frame, instr POPFRAME.')
		sys.exit(55)


	temp_frame = local_frame[-1]
	local_frame.pop()
	TF_set = True

############STACK EXTENSION INSTRUCTIONS###########
def pop_stack():
	global zasobnik;
	if len(zasobnik) == 0:
		eprint('ERROR 56: Missing value in stack.')
		sys.exit(56)
	pop_value = zasobnik[-1]
	zasobnik.pop()
	return pop_value

def push_stack(value):
	global zasobnik;
	zasobnik.append(value)

#CLEARS
def i_clears():
	global zasobnik;
	zasobnik = []

#ADDS SUBS MULS IDIVS
def i_arithmetics(opcode):
	arg2 = pop_stack()
	arg1 = pop_stack()
	if arg1[0] != "int" or arg2[0] != "int":
		eprint('ERROR 53: Arithmetic operands must be int.')
		sys.exit(53)
	if opcode == "ADDS":
		result = int(arg1[1]) + int(arg2[1])
	elif opcode == "SUBS":
		result = int(arg1[1]) - int(arg2[1])
	elif opcode == "MULS":
		result = int(arg1[1]) * int(arg2[1])
	elif opcode == "IDIVS":
		if int(arg2[1]) == 0:
			eprint('ERROR 57: Division by zero!.')
			sys.exit(57)
		result = int(arg1[1]) // int(arg2[1])
		result = int(result)
	push_stack(["int",str(result)])

#EQS GTS LTS
def i_relations(opcode):
	arg2 = pop_stack()
	arg1 = pop_stack()

	if arg1[0] == "nil" or arg2[0] == "nil":
		if opcode != "EQS":
			eprint('ERROR 53: Type nil can only be compared by EQS!')
			sys.exit(53)
		if arg1[0] == "nil" and arg2[0] == "nil":
			result = True
		else:
			result = False
	elif arg1[0] == "int" and arg2[0] == "int":
		if opcode == "EQS":
			result = int(arg1[1]) == int(arg2[1])
		elif opcode == "GTS":
			result = int(arg1[1]) > int(arg2[1])
		elif opcode == "LTS":
			result = int(arg1[1]) < int(arg2[1])
	elif (arg1[0] == "string" and arg2[0] == "string") or (arg1[0] == "bool" and arg2[0] == "bool"):
		if opcode == "EQS":
			result = arg1[1] == arg2[1]
		elif opcode == "GTS":
			result = arg1[1] > arg2[1]
		elif opcode == "LTS":
			result = arg1[1] < arg2[1]
	else:
		eprint('ERROR 53: Incorrect operand type',opcode,'!')
		sys.exit(53)

	if result == True:
		push_stack(["bool","true"])
	else:
		push_stack(["bool","false"])

#NOTS
def i_nots():
	arg1 = pop_stack()
	if arg1[0] != "bool":
		eprint('ERROR 53: NOTS operands must be bool!')
		sys.exit(53)
	if arg1[1] == "true":
		push_stack(["bool","false"])
	if arg1[1] == "false":
		push_stack(["bool","true"])

#AND OR
def i_andors(opcode):
	arg2 = pop_stack()
	arg1 = pop_stack()

	if arg1[0] != "bool" or arg2[0] != "bool":
		eprint('ERROR 53: Logic operands must be bool!')
		sys.exit(53)
	if arg1[1] == "true":
		value_1 = True;
	else:
		value_1 = False;

	if arg2[1] == "true":
		value_2 = True;
	else:
		value_2 = False;

	if opcode == "ANDS":
		result = value_1 and value_2
	elif opcode == "ORS":
		result = value_1 or value_2

	if result == True:
		push_stack(["bool","true"])
	elif result == False:
		push_stack(["bool","false"])

#INT2CHARS
def i_int2chars():
	arg1 = pop_stack()
	###
	if arg1[0] != "int":
		eprint('ERROR 53: INT2CHARS is not int!')
		sys.exit(53)
	num= int(arg1[1])
	if num > 127 or num < 1:
		eprint('ERROR 58: INT2CHARS bad value!')
		sys.exit(58)
	char = chr(num)
	push_stack(["string",char])

#STRI2INTS
def i_stri2ints():
	arg2 = pop_stack()
	arg1 = pop_stack()

	if arg1[0] != "string":
		eprint('ERROR 53: STRI2INT is not string!')
		sys.exit(53)
	string = arg1[1]

	if arg2[0] != "int":
		eprint('ERROR 53: STRI2INT is not int!')
		sys.exit(53)
	position = arg2[1]

	if (len(string)-1) < int(position) or int(position) < 0:
		eprint('ERROR 58: STRI2INT wrong string usage!')
		sys.exit(58)
	char = ord(string[int(position)])
	push_stack(["int",str(char)])

#JUMPIFEQ JUMPIFNEQ
def i_jumpeqs_jumpneqs(label,opcode):
	global i;
	arg2 = pop_stack()
	arg1 = pop_stack()
	num = label_ok(label[1])

	if arg1[0] == "nil" and arg2[0] == "nil":
		result = True
	elif arg1[0] == "nil" or arg2[0] == "nil":
		result = False
	elif arg1[0] == "int" and arg2[0] == "int":
		result = int(arg1[1]) == int(arg2[1])
	elif (arg1[0] == "string" and arg2[0] == "string") or (arg1[0] == "bool" and arg2[0] == "bool"):
		result = arg1[1] == arg2[1]
	else:
		eprint('ERROR 53: Wrong operands ',opcode,'!')
		sys.exit(53)

	if opcode == "JUMPIFEQS":
		if result == True:
			i = num - 1

	elif opcode == "JUMPIFNEQS":
		if result == False:
			i = num - 1

########FLOAT EXTENSION
#DIV
def i_div(var,arg1,arg2):
	if arg1[0] == "var":
		arg1 = get_var_val(arg1[1])
	if arg2[0] == "var":
		arg2 = get_var_val(arg2[1])
	if arg1[0] != "float" or arg2[0] != "float":
		eprint('ERROR 53: DIV can be done only with float types!')
		sys.exit(53)
	if arg2[1] == 0:
		eprint('ERROR 57: DIV Division by zero!')
		sys.exit(57)
	result = arg1[1] / arg2[1]
	safe_var_val(var[1], "float", result)

#INT2FLOAT
def i_int2float(var, arg1):
	if arg1[0] == "var":
		arg1 = get_var_val(arg1[1])
	if arg1[0] != "int":
		eprint('ERROR 53: INT2FLOAT can be done only with int type!')
		sys.exit(53)

	value = float(arg1[1])
	safe_var_val(var[1], "float", value)

#FLOAT2INT
def i_float2int(var, arg1):
	if arg1[0] == "var":
		arg1 = get_var_val(arg1[1])
	if arg1[0] != "float":
		eprint('ERROR 53: FLOAT2INT can be done only with float type!')
		sys.exit(53)
	value = int(arg1[1])
	safe_var_val(var[1], "int", str(value))




################################ MAIN ################################
#parse arguments
parser = argparse.ArgumentParser(add_help=False,
	description="Program nacte XML reprezentaci programu a tento program s vyuzitim vstupu dle parametru prikazove radky interpretuje a generuje vystup.")
parser.add_argument('--help', action='store_true',help='show this help message and exit')
parser.add_argument('--source', dest='soubor',help="Vstupni XML soubor")
parser.add_argument('--input', dest='soubor2',help="Soubor se vstupy pro interpretaci")
parser.add_argument('--stats', dest='stats_file',help="Soubor pro vypsani statistik")
parser.add_argument('--vars',action='store_true',help="Vypsani statistik o vsech inicializovanych promennych")
parser.add_argument('--insts',action='store_true',help="Vypsani statistik o poctu instrukco")
xml_file = sys.stdin
s_file = False
stats = False

#parse arguments
try:
	args = parser.parse_args()
except Exception:
	eprint('ERROR 10: Bad arguments')
	sys.exit(10)

#help
if args.help:
	if len(sys.argv) != 2:
		eprint('ERROR 10: Bad arguments')
		sys.exit(10)
	print("-------HELP------")
	print("Program nacte XML reprezentaci programu a tento program s vyuzitim vstupu dle parametru prikazove radky interpretuje a generuje vystup.")
	print("-----------------")
	sys.exit(0)

#bad entry
if not args.soubor and not args.soubor2:
	eprint('ERROR 10:  At least one of (--source or --input) must be given.')
	sys.exit(10)

#source file
if args.soubor:
	xml_file = args.soubor
	try:
		f = open(xml_file, "r")
	except Exception:
		eprint('ERROR 11: Cannot read source file.')
		sys.exit(11)

#input file
if args.soubor2:
	input_file = args.soubor2
	try:
		sys.stdin = open(input_file, "r")
	except Exception:
		eprint('ERROR 11: Cannot read input file.')
		sys.exit(11)
	s_file = True

#stats extension
if args.vars or args.insts:
	if not args.stats_file:
		eprint('ERROR 10: Missing argument --stats.')
		sys.exit(10)

if args.stats_file:
	stats = True
	try:
		stats_file = open(args.stats_file, "w")
	except Exception:
		eprint('ERROR 12: Cannot write to stats file.')
		sys.exit(12)
	stats_file.close()

#parse XML
try:
	mytree = ET.parse(xml_file)
except Exception:
	eprint('ERROR 31: XML badly formed.')
	sys.exit(31)

myroot = mytree.getroot()

#check XML header
try:
	if myroot.tag != 'program':
		eprint('ERROR 32: Incorrect root.')
		sys.exit(32)
	if len(myroot.attrib) < 0 or len(myroot.attrib) > 3:
		eprint('ERROR 32: Wrong XML header.')
		sys.exit(32)
	if myroot.attrib['language'] != 'IPPcode20':
		eprint('ERROR 32: Missing language attrib.')
		sys.exit(32)
	if len(myroot.attrib) == 3:
		if (not ('name' in myroot.attrib) and ('description' in myroot.attrib)):
			eprint('ERROR 32: Unknown attribut.')
			sys.exit(32)
	if len(myroot.attrib) == 2:
		if (not ('name' in myroot.attrib) or ('description' in myroot.attrib)):
			eprint('ERROR 32: Unknown attribut.')
			sys.exit(32)
except Exception:
	eprint('ERROR 32: Wrong XML header.')
	sys.exit(32)


instr_dict = dict()    #dictionary containing all instructions and its arguments
label_dict = dict()    #dictionary containing labels
global_frame = dict()  #GF dictionary
local_frame = []       #LF stack
temp_frame = dict()    #TF dictionary
zasobnik = []          #stack
call_stack = []        #call stack
TF_set = False         #true if TF is set, false otherwise
max_order = 1          #value of max order

#goes trough instructions, does lexical and syntax check of XML, fill instruction dictionary
#makes label dictionary
i = 0
instruction_count = len(myroot)
while i < instruction_count:
	if myroot[i].tag != 'instruction':
		eprint('ERROR 32: Chybny instruction tag.')
		sys.exit(32)
	if len(myroot[i].attrib) !=2:
		eprint('ERROR 32: Chybny pocet atributu u instrukce.')
		sys.exit(32)
	if ('order' not in myroot[i].attrib) or ('opcode' not in myroot[i].attrib):
		eprint('ERROR 32: Neznamy atribut u instrukce.')
		sys.exit(32)
	order = is_valid_order(myroot[i].attrib['order'])
	if order > max_order:
		max_order = order
	if order in instr_dict:
		eprint('ERROR 32: Instruction order', order, 'already exists.')
		sys.exit(32)
	dictionary=is_valid_opcode(myroot[i].attrib['opcode'], order, myroot)
	instr_dict[order]=dictionary
	i = i + 1

executed_instr_count = 0 #STATI instr
init_var_count = 0       #STATI vars

print(instr_dict)

i = 1
#interprets instructions by order
while i <= max_order:
	if i not in instr_dict:
		i = i+1
		continue
	instruction = instr_dict[i]

	#calling function for each instruction
	if instruction['opcode'] == "DEFVAR":
		i_defvar(instruction['arg1'])
	elif instruction['opcode'] == "CREATEFRAME":
		i_createframe()
	elif instruction['opcode'] == "MOVE":
		i_move(instruction['arg1'],instruction['arg2'])
	elif instruction['opcode'] == "ADD" or instruction['opcode'] == "SUB" or \
	instruction['opcode'] == "MUL" or instruction['opcode'] == "IDIV":
		i_arithmetic(instruction['arg1'],instruction['arg2'],instruction['arg3'],instruction['opcode'])
	elif instruction['opcode'] == "PUSHS":
		i_pushs(instruction['arg1'])
	elif instruction['opcode'] == "POPS":
		i_pops(instruction['arg1'])
	elif instruction['opcode'] == "INT2CHAR":
		i_int2char(instruction['arg1'],instruction['arg2'])
	elif instruction['opcode'] == "STRI2INT":
		i_stri2int(instruction['arg1'],instruction['arg2'],instruction['arg3'])
	elif instruction['opcode'] == "CONCAT":
		i_concat(instruction['arg1'],instruction['arg2'],instruction['arg3'])
	elif instruction['opcode'] == "STRLEN":
		i_strlen(instruction['arg1'],instruction['arg2'])
	elif instruction['opcode'] == "WRITE":
		i_write(instruction['arg1'])
	elif instruction['opcode'] == "READ":
		i_read(instruction['arg1'],instruction['arg2'])
	elif instruction['opcode'] == "LT" or instruction['opcode'] == "GT" or \
	instruction['opcode'] == "EQ":
		i_relation(instruction['arg1'],instruction['arg2'],instruction['arg3'],instruction['opcode'])
	elif instruction['opcode'] == "NOT":
		i_not(instruction['arg1'],instruction['arg2'])
	elif instruction['opcode'] == "AND" or instruction['opcode'] == "OR":
		i_andor(instruction['arg1'],instruction['arg2'],instruction['arg3'],instruction['opcode'])
	elif instruction['opcode'] == "TYPE":
		i_type(instruction['arg1'],instruction['arg2'])
	elif instruction['opcode'] == "EXIT":
		i_exit(instruction['arg1'])
	elif instruction['opcode'] == "GETCHAR":
		i_getchar(instruction['arg1'],instruction['arg2'],instruction['arg3'])
	elif instruction['opcode'] == "SETCHAR":
		i_setchar(instruction['arg1'],instruction['arg2'],instruction['arg3'])
	elif instruction['opcode'] == "JUMP":
		i_jump(instruction['arg1'])
	elif instruction['opcode'] == "CALL":
		i_call(instruction['arg1'])
	elif instruction['opcode'] == "RETURN":
		i_return()
	elif instruction['opcode'] == "JUMPIFNEQ" or instruction['opcode'] == "JUMPIFEQ":
		i_jumpeq_jumpneq(instruction['arg1'],instruction['arg2'],instruction['arg3'],instruction['opcode'])
	elif instruction['opcode'] == "PUSHFRAME":
		i_pushframe()
	elif instruction['opcode'] == "POPFRAME":
		i_popframe()
	elif instruction['opcode'] == "CLEARS":
		i_clears()
	elif instruction['opcode'] == "ADDS" or instruction['opcode'] == "SUBS" or \
	instruction['opcode'] == "MULS" or instruction['opcode'] == "IDIVS":
		i_arithmetics(instruction['opcode'])
	elif instruction['opcode'] == "LTS" or instruction['opcode'] == "GTS" or \
	instruction['opcode'] == "EQS":
		i_relations(instruction['opcode'])
	elif instruction['opcode'] == "NOTS":
		i_nots()
	elif instruction['opcode'] == "ANDS" or instruction['opcode'] == "ORS":
		i_andors(instruction['opcode'])
	elif instruction['opcode'] == "INT2CHARS":
		i_int2chars()
	elif instruction['opcode'] == "STRI2INTS":
		i_stri2ints()
	elif instruction['opcode'] == "JUMPIFEQS" or instruction['opcode'] == "JUMPIFNEQS":
		i_jumpeqs_jumpneqs(instruction['arg1'],instruction['opcode'])
	elif instruction['opcode'] == "DIV":
		i_div(instruction['arg1'],instruction['arg2'],instruction['arg3'])
	elif instruction['opcode'] == "INT2FLOAT":
		i_int2float(instruction['arg1'],instruction['arg2'])
	elif instruction['opcode'] == "FLOAT2INT":
		i_float2int(instruction['arg1'],instruction['arg2'])

	executed_instr_count = executed_instr_count+1
	i = i+1

###STATI extension###
#prints statistics to a file
if stats == True:
	stats_file = open(args.stats_file, "a+")
	for x in sys.argv:
		if x == "--vars":
			stats_file.write("%d\n" % init_var_count) #TODO
		elif x == "--insts":
			stats_file.write("%d\n" % executed_instr_count)
"""
print("")
print("##########################")
print("Executed instructions:",executed_instr_count)
print("Max order:")
print(max_order)
print("Label dict:")
print(label_dict)
print('Global frame:')
print(global_frame)
print('Local frame:')
print(local_frame)
print('Temp frame:')
print(TF_set)
print(temp_frame)
print('Zasobnik:')
print(zasobnik)
print('Call_stack:')
print(call_stack)
print('Init var count:')
print(init_var_count)
print("##########################")
"""