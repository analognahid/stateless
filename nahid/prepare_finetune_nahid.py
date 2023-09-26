import sys
sys.path.insert(0,'/home/raisul/stateformer/')


import glob
import json
import os
import random
import re

import argparse

from capstone import *
from elftools.elf.elffile import ELFFile


from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (
    describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import (
    LocationEntry, LocationExpr, LocationParser)
import posixpath
import sys,os,pickle
from elftools.elf.segments import Segment
from elftools.dwarf.locationlists import LocationParser, LocationExpr

from collections import defaultdict

import collections
import posixpath


import ntpath
from capstone import *
from capstone.x86 import *
import collections
import magic ,hashlib
import subprocess
from subprocess import STDOUT, check_output




from command import params
# class params:
#     fields = ['static', 'inst_emb', 'inst_pos_emb', 'arch_emb', 'byte1', 'byte2', 'byte3', 'byte4', 'arg_info','op_pos_emb']

def tokenize(s):
    s = s.replace(',', ' , ')
    s = s.replace('[', ' [ ')
    s = s.replace(']', ' ] ')
    s = s.replace(':', ' : ')
    s = s.replace('*', ' * ')
    s = s.replace('(', ' ( ')
    s = s.replace(')', ' ) ')
    s = s.replace('{', ' { ')
    s = s.replace('}', ' } ')
    s = s.replace('#', '')
    s = s.replace('$', '')
    s = s.replace('!', ' ! ')

    s = re.sub(r'-(0[xX][0-9a-fA-F]+)', r'- \1', s)
    s = re.sub(r'-([0-9a-fA-F]+)', r'- \1', s)

    return s.split()


def get_function_reps(die, mapping):
    functions = []
    for child_die in die.iter_children():

        if child_die.tag.split('_')[-1] == 'subprogram':
            function = {}
            try:
                function['start_addr'] = child_die.attributes['DW_AT_low_pc'][2]
                function['end_addr'] = function['start_addr'] + child_die.attributes['DW_AT_high_pc'][2]
                function['name'] = child_die.attributes['DW_AT_name'][2].decode('utf-8')
                functions.append(function)
            except KeyError:
                continue

    return functions


def get_type(type_str, agg):
    
    
    if '*' in type_str:
        return get_type(type_str.replace('*', ''), agg)+'*'
    elif '[' in type_str and ']' in type_str:
        return 'array'
    elif agg['is_enum']:
        return 'enum'
    elif agg['is_struct']:
        return 'struct'
    elif agg['is_union']:
        return 'union'
    
    #TODO not in dict
    # elif 'void' in type_str:
    #     return 'void'

    elif 'float' in type_str:
        return 'float'
    elif 'long' in type_str and 'double' in type_str:
        return 'long_double'
    elif 'double' in type_str:
        return 'double'

    elif 'char' in type_str:
        if 'u' in type_str:
            return 'unsigned_char'
        return 'signed_char'
    elif 'short' in type_str:
        if 'u' in type_str:
            return 'unsigned_short'
        return 'signed_short'
    elif 'int' in type_str:
        if 'u' in type_str:
            return 'unsigned_int'
        return 'signed_int'
    elif 'longlong' in type_str:
        if 'u' in type_str:
            return 'unsigned_long_long'
        return 'signed_long_long'
    elif 'long' in type_str:
        if 'u' in type_str:
            return 'unsigned_long'
        return 'signed_long'


    # elif 'undefined' in type_str:
    #     return 'undefined'
    print("VALUE ERROR", type_str)
    raise ValueError
    # # #TODO fix this
    # return '?you shouldnt be seeing this?'


def test_hex(s):
    try: 
        int(s)
        return True
    except ValueError:
        return False


def get_reg(tokens):
    if tokens[-1] == ']' or test_hex(tokens[-1]):
        register = tokens[1].upper()
    else:
        register = tokens[-1].upper()
    return register


# gets the type of an instruction that has a stack xref
def get_ds_loc(loc_dict, address, funcname):
    for var in loc_dict[funcname]:
        if address in [int(i, 16) for i in loc_dict[funcname][var]['addresses']]:
            return get_type(loc_dict[funcname][var]['type'], loc_dict[funcname][var]['agg'])
    return 'no-access'


# gets the type of an argument using the register name where it's stored
def get_arg_stack_loc(loc_dict, register, funcname):
    for var in loc_dict[funcname]:
        if ('register' in loc_dict[funcname][var] 
            and register == loc_dict[funcname][var]['register']):
            return get_type(loc_dict[funcname][var]['type'], loc_dict[funcname][var]['agg'])
    return 'undefined'


# gets overall argument info for each function
def get_arg_info(loc_dict, funcname):
    arg_list = []
    for var in loc_dict[funcname]:
        if 'register' in loc_dict[funcname][var].keys():
            arg_list.append((loc_dict[funcname][var]['count'], get_type(loc_dict[funcname][var]['type'], loc_dict[funcname][var]['agg'])))
    arg_list.sort()
    leng = str(len(arg_list))

    while len(arg_list) < 3:
        arg_list.append('##')
    arg_list = [arg_type for (order, arg_type) in arg_list]

    return [leng] + arg_list[:3]


def hex2str(s, b_len=8):
    num = s.replace('0x', '')

    # handle 64-bit cases, we choose the lower 4 bytes, thus 8 numbers
    if len(num) > b_len:
        num = num[-b_len:]

    num = '0' * (b_len - len(num)) + num
    return num


def byte2seq(value_list):
    return [value_list[i:i + 2] for i in range(len(value_list) - 2)]


#TODO nahid fix
args_arch = 'x86'

output_dir = '/home/raisul/stateformer/data-src/finetune/x86-O0/' # args.output_dir[0]

stack_dir = '/media/raisul/nahid_personal/dwarf4/ghidra_types/analysis_data_state_format'


 
def is_elf_file(file_path):
    try:
        file_type = magic.from_file(file_path)
        return 'ELF' in file_type
    except Exception as e:
        return False
    

SRC_N_BIN_PATH  = '/media/raisul/nahid_personal/clones_100k_trimmed_dwarf4/'

output_dir_path = '/media/raisul/nahid_personal/dwarf4/ghidra_types/analysis_data_state_format/'

split_key = 'clones_100k_trimmed_dwarf4'

def get_fname(fpath):
    return file_path.split('/')[-1]

filtered_files = []
for path, subdirs, files in os.walk(SRC_N_BIN_PATH):
    # if len(filtered_files)>100:
    #     break
    for name in files:

        if '_elf_file_gdwarf4_O0' not in name:
            continue

        file_path = os.path.join(path, name)
        
        if is_elf_file(file_path)== False:
            continue
        filtered_files.append(file_path)








train_file = {field: open(os.path.join(output_dir, f'train.{field}'), 'w') for field in params.fields}
valid_file = {field: open(os.path.join(output_dir, f'valid.{field}'), 'w') for field in params.fields}

train_label = open(os.path.join(output_dir, 'train.label'), 'w')
valid_label = open(os.path.join(output_dir, 'valid.label'), 'w')


# filename = 'command/ghidra/ds_test_dwarf'

for file_path in filtered_files:
    filename = get_fname(file_path)

    #custom names by nahid to keep track
    unique_path = file_path.split(split_key)[1][1:]
    github_path = unique_path.split('/')[0]
    unique_file_name=github_path + '_____'+(hashlib.md5(unique_path.encode())).hexdigest()
    stack_file_path = os.path.join(output_dir_path , unique_file_name ) +'_stacks'

    # load data structure information from ghidra
    try:
        with open(stack_file_path, 'r') as f:
            loc_dict = json.loads(f.read())
    except :
        print('ERR 1')
        continue
    
    with open(file_path, 'rb') as f:
        elffile = ELFFile(f)
        dwarf = elffile.get_dwarf_info()

        # disassemble the byte code with capstone
        code = elffile.get_section_by_name('.text')
        opcodes = code.data()
        addr = code['sh_addr']
        md = Cs(CS_ARCH_X86, CS_MODE_64)

        for CU in dwarf.iter_CUs():
            function_reps = get_function_reps(CU.get_top_DIE(), None)

            for func in function_reps:
                PROB = False
                start_addr = func['start_addr']
                end_addr = func['end_addr']

                func_args = {}
                used_regs = set()

                # input
                static = []
                inst_pos = []
                op_pos = []
                arch = []
                byte1 = []
                byte2 = []
                byte3 = []
                byte4 = []

                # output
                labels = []

                inst_pos_counter = 0

                try:
                    for address, size, op_code, op_str in md.disasm_lite(opcodes, addr):

                        if start_addr <= address < end_addr:
                            tokens = tokenize(f'{op_code} {op_str}')
                            try:
                                label = get_ds_loc(loc_dict, address, func['name'])
                            except ValueError as err:
                                print('ERR 4')
                                PROB = True
                                break
                            # get the register and stack location for likely arg vars from the 
                            # op_str and label the instruction by using the register->param type
                            # mapping from Ghidra. A mapping of stack location -> type is stored
                            # for whenever else the location is seen.
                            if label == 'undefined' and '[' in tokens and op_code == 'mov':
                                reg = get_reg(tokens)

                                loc = op_str[op_str.find("[")+1:op_str.find("]")]
                                if loc in func_args:
                                    label = func_args[loc]

                                else:
                                    try:
                                        label = get_arg_stack_loc(loc_dict, reg, func['name'])
                                    except ValueError as err:
                                        print('ERR 3')
                                        PROB = True
                                        break
                                    func_args[loc] = label

                            for i, token in enumerate(tokens):
                                if '0x' in token.lower():
                                    static.append('hexvar')
                                    bytes = byte2seq(hex2str(token.lower()))
                                    byte1.append(bytes[0])
                                    byte2.append(bytes[1])
                                    byte3.append(bytes[2])
                                    byte4.append(bytes[3])

                                elif token.lower().isdigit():
                                    static.append('num')
                                    bytes = byte2seq(hex2str(hex(int(token.lower()))))
                                    byte1.append(bytes[0])
                                    byte2.append(bytes[1])
                                    byte3.append(bytes[2])
                                    byte4.append(bytes[3])
                                    
                                else:
                                    static.append(token)
                                    byte1.append('##')
                                    byte2.append('##')
                                    byte3.append('##')
                                    byte4.append('##')

                                inst_pos.append(str(inst_pos_counter))
                                op_pos.append(str(i))
                                arch.append(args_arch)

                                labels.append(label)

                            inst_pos_counter += 1

                            # print(str(address) + "\t"+ label+ "\t"+ op_code + "\t"+ op_str )

                except CsError as e:
                    print("ERROR: %s" % e)

                try:
                    arg_info = get_arg_info(loc_dict, func['name'])
                except ValueError as err:
                    print('ERR 2')
                    continue
                # skip invalid functions
                if len(labels) < 30 or len(labels) > 510 or len(set(labels)) == 1:
                    continue
                
                if PROB==True:
                    continue
                if not random.random() < 0.1:
                    train_file[params.fields[0]].write(' '.join(static) + '\n')
                    train_file[params.fields[1]].write(' '.join(inst_pos) + '\n')
                    train_file[params.fields[2]].write(' '.join(op_pos) + '\n')
                    train_file[params.fields[3]].write(' '.join(arch) + '\n')
                    train_file[params.fields[4]].write(' '.join(byte1) + '\n')
                    train_file[params.fields[5]].write(' '.join(byte2) + '\n')
                    train_file[params.fields[6]].write(' '.join(byte3) + '\n')
                    train_file[params.fields[7]].write(' '.join(byte4) + '\n')
                #    train_file[params.fields[8]].write(' '.join(arg_info) + '\n')

                    train_label.write(' '.join(labels) + '\n')


                else:
                    valid_file[params.fields[0]].write(' '.join(static) + '\n')
                    valid_file[params.fields[1]].write(' '.join(inst_pos) + '\n')
                    valid_file[params.fields[2]].write(' '.join(op_pos) + '\n')
                    valid_file[params.fields[3]].write(' '.join(arch) + '\n')
                    valid_file[params.fields[4]].write(' '.join(byte1) + '\n')
                    valid_file[params.fields[5]].write(' '.join(byte2) + '\n')
                    valid_file[params.fields[6]].write(' '.join(byte3) + '\n')
                    valid_file[params.fields[7]].write(' '.join(byte4) + '\n')
                #    valid_file[params.fields[8]].write(' '.join(arg_info) + '\n')

                    valid_label.write(' '.join(labels) + '\n')

for k in train_file:
    train_file[k].close()
for k in valid_file:
    valid_file[k].close()
train_label.close()
valid_label.close()
