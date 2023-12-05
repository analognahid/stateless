
import os
import pickle
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

# /unset GTK_PATH
SRC_N_BIN_PATH        = '/media/raisul/nahid_personal/clones_100k/'
# output_dir_path =   '/media/raisul/nahid_personal/dwarf4/ghidra_types/analysis_data_state_format_100k/'
output_dir_path =   '/media/raisul/nahid_personal/dwarf4/ghidra_types/analysis_data_state_format_100k_dwarf4_O2/'
# output_dir_path =  '/media/raisul/nahid_personal/dwarf4/ghidra_types/d4_O0/'


# /ssd/nahid/dwarf4/ghidra_types
split_key = 'clones_100k'

def is_elf_file(file_path):
    try:
        file_type = magic.from_file(file_path)
        return 'ELF' in file_type
    except Exception as e:
        return False

def analyse(  binary_path ):
    # RUN unset GTK_PATH in terminal for no symbol error

    # print(os.path.getsize(binary_path))
    # if os.path.getsize(binary_path)>(25*1024):
    #     return
    unique_path = binary_path.split(split_key)[1][1:]
    github_path = unique_path.split('/')[0]

    unique_file_name=github_path + '_____'+(hashlib.md5(unique_path.encode())).hexdigest()



    output_file_path = os.path.join(output_dir_path , unique_file_name ) +'_stacks'

    if os.path.isfile(output_file_path): #file already analysed
        return



    ghidra_path = '/home/raisul/ghidra_10.3.3_PUBLIC_20230829/ghidra_10.3.3_PUBLIC/support/analyzeHeadless  ' #'/home/tools/ghidra_10.2.3_PUBLIC/support/analyzeHeadless   '
    ghidra_proj_path = '/media/raisul/nahid_personal/dwarf4/ghidra_types/temp_proj/{}'.format(output_file_path)
    ghidra_process = "  ghidraBenchmarking_MainProcess  "
    bin_path = "-import {} -overwrite  ".format(binary_path)
    scripts = " -scriptPath /home/raisul/stateformer/command/finetune -preScript pre_script_nahid.py -postScript get_var_loc_complete.py '{}' -deleteProject".format(output_file_path)

    command = ghidra_path + ghidra_proj_path + ghidra_process + bin_path + scripts

    print(command)

    if not os.path.isdir(ghidra_proj_path):
        os.makedirs(ghidra_proj_path)
        # os.makedirs(os.path.join( ghidra_proj_path,'ghidraBenchmarking_MainProcess' ))
    
    

    cmd_process = subprocess.Popen(command, shell=True)



    (output, err) = cmd_process.communicate()  
    # #This makes the wait possible
    p_status = cmd_process.wait()
    cmd_process.kill()








filtered_files = []
# for path, subdirs, files in os.walk(SRC_N_BIN_PATH):
#     # if len(filtered_files)>100:
#     #     break
    
#     print(' DBG ->: ',len(filtered_files))
#     for name in files:

#         if '_elf_file_gdwarf4_O2' not in name:
#             continue

#         file_path = os.path.join(path, name)
        
#         if is_elf_file(file_path)== False:
#             continue
#         filtered_files.append(file_path)


# print(' DBG: ',len(filtered_files))


pkl_file_name =  '_elf_file_gdwarf4_O2.ignore_latest.pkl'
# with open(pkl_file_name, 'wb') as f:
#     pickle.dump(filtered_files , f)
    
with open(pkl_file_name, 'rb') as file:
    filtered_files  = pickle.load(file)  

# 

print(len(filtered_files))
# exit(0)
filtered_files.reverse()

import multiprocessing
from multiprocessing import active_children

if __name__ == "__main__":  # Allows for the safe importing of the main module
    print("There are {} CPUs on this machine".format( multiprocessing.cpu_count()))
    
    number_processes =  multiprocessing.cpu_count()-15
    pool = multiprocessing.Pool(number_processes)

    results = pool.map_async(analyse, filtered_files)
    pool.close()
    pool.join()
    print('\n'*5)
    print(" DONE ALL SUCCESSFULLY Alhamdulillah"*50)

