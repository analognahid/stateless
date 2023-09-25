
import os

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


SRC_N_BIN_PATH        = '/media/raisul/nahid_personal/dwarf4/state_binaries' 

output_dir_path =   '/media/raisul/nahid_personal/dwarf4/ghidra_types/analysis_data_state_format_mips/'



def is_elf_file(file_path):
    try:
        file_type = magic.from_file(file_path)
        return 'ELF' in file_type
    except Exception as e:
        return False

def analyse(  binary_path ):



    unique_file_name=binary_path.split('/')[-1]



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
for path, subdirs, files in os.walk(SRC_N_BIN_PATH):
    # if len(filtered_files)>5:
    #     break
    for name in files:

        file_path = os.path.join(path, name)
        filtered_files.append(file_path)




import multiprocessing
from multiprocessing import active_children

if __name__ == "__main__":  # Allows for the safe importing of the main module
    print("There are {} CPUs on this machine".format( multiprocessing.cpu_count()))
    
    number_processes = multiprocessing.cpu_count()-2
    pool = multiprocessing.Pool(number_processes)

    # filtered_files = filtered_files[0:200]
    results = pool.map_async(analyse, filtered_files)
    pool.close()
    pool.join()
    print('\n'*5)
    print(" DONE ALL SUCCESSFULLY Alhamdulillah"*50)

