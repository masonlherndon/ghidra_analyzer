#!/usr/bin/env python2.7
# Uses Ghidra's Jython2 API to extract functions in binary and assembly form
#
# Run in headless mode using:
# ../Ghidra/support/analyzeHeadless gproj headless -readOnly -recursive -import imports/ -postScript extract_functions.py -scriptlog script.log -max-cpu 4
# ./Ghidra/support/analyzeHeadless proj_directory proj_name -import ./data/benign/win10sys/WinHelloCPP.exe -postScript extract_functions.py -deleteProject

import os
import json
import time
import sys
import bz2
import pickle
import datetime
import struct
from ghidra.program.model.block import SimpleBlockModel

# from java.lang import System

# Logging directory
LOG_DIR = "log/script_error.log"
MEMORY_LOG_DIR = "log/script_mem.log"

# Options
JSON_VERSION = 2.3  # Format: Major.Minor: Major changes may break things. Minor changes may just add new fields.
INCLUDE_ALL_EXECUTABLE_BYTES = False  # Include all bytes from first instruction to very last. Will consume more space and take longer.


def main():
    # Workaround for Jython memory leak
    # http://blog.hillbrecht.de/2009/07/11/jython-memory-leakout-of-memory-problem/
    # prob_before = System.getProperty("python.options.internalTablesImpl")

    # get the program path
    path_str = currentProgram.getExecutablePath()

    # create json path
    json_path = create_directory(path_str, ".json.bz2")

    # Get all the categories that will be analyzed and the mnemonics within each category
    categories, category_name_lookup = read_from_config()  # []

    # get current program information
    start_time, program_json = get_program_information(path_str,
                                                       category_name_lookup)

    # prepare function information (JSON)
    program_json = prepare_function_information(program_json, categories,
                                                category_name_lookup)

    # log memory usage and json size
    # json_size = "Memory size of the JSON = " + str(float(len(str(program_json))) / 1000000.0) + " MB"
    # tot_m, used_m, free_m = map(int, os.popen('free -t -m').readlines()[-1].split()[1:])
    # memory_usage = "Total Memory:" + str(tot_m) + "  Used Memory:" + str(used_m) + "  Free Memory:" + str(free_m)
    # log(MEMORY_LOG_DIR, json_size , memory_usage)

    # compress
    '''
    Sanity check flag will ensure the compression was succefull.
    If need faster processing, set the flag to False and it will
    skip the sanity check.
    '''
    compression_sanity_check_flag = False
    compressed_data, compression_ratio, success_flag = compress_bz2(json.dumps(program_json),
                                                                    compression_sanity_check_flag)

    # sanity check if enabled
    if compression_sanity_check_flag and success_flag is False:
        println("Possible data loss when compressing")
        # handle problem here
        log(LOG_DIR, "Error while compressing", "")

    save_file(compressed_data, json_path)  # Save

    # Attempt to allow JVM to free this memory
    compressed_data = None
    json_path = None
    program_json = None
    categories = None


# =============================================================================
# Compress passed data
# =============================================================================
def compress_bz2(data, sanity_check_flag):
    try:
        success = True

        # compress
        compressed_data = bz2.compress(data)
        compression_ratio = len(data) / len(compressed_data)

        # sanity check
        if sanity_check_flag:

            # check if they are same
            if bz2.decompress(compressed_data) != data:
                success = False
    except Exception as e:
        log(LOG_DIR, "Error while compressing", e)

    return compressed_data, compression_ratio, success


# =============================================================================
# Creates the directory where the dataset for given file will go
# =============================================================================
def create_directory(path_str, extension):
    try:

        # create directory
        path = os.path.join("exports",
                            str(os.path.basename(os.path.dirname(os.path.dirname(path_str)))),  # benign\malicious
                            str(os.path.basename(os.path.dirname(path_str))))  # data source (exp:win10)
        # JSON directory
        json_path = os.path.join(path, str(currentProgram.getName()) + str(extension))
        check_path(path)
    except Exception as e:
        log(LOG_DIR, "Error while creating directory", e)
    return json_path


# =============================================================================
# Get information for the all binary-program
# =============================================================================
def get_program_information(path_str, category_name_lookup):
    try:
        # time for logging
        start_time = time.time()

        # Set label
        label = 1

        if "benign" in path_str:
            label = 0
        elif "malware" in path_str:
            label = 1
        else:
            println("Error: Path of binary is not in a folder category. Path: ")
            println(str(path_str))
            label = -1

        strings = findStrings(None, 5, 1, True, True).iterator()
        strings_list = []
        while strings.hasNext():
            string_obj = strings.next()
            start = string_obj.getAddress()
            end = string_obj.getEndAddress()
            length = end.subtract(start)
            asciibytes = getBytes(start, length)
            final_str = ''
            for item in asciibytes:
                final_str += chr(item)
            strings_list.append(final_str)

        program_json = {
            'JSON_VERSION': JSON_VERSION,  # Format: Major.Minor: Major changes could break things. Minor changes may just add new fields.
            'name': currentProgram.getName(),
            # 'len': currentProgram.getMaxAddress().subtract(currentProgram.getMinAddress()),  # This sometimes causes errors
            'max_addr': str(currentProgram.getMaxAddress()),
            'min_addr': str(currentProgram.getMinAddress()),
            'size': os.path.getsize(path_str),
            'src': os.path.basename(os.path.dirname(path_str)),
            'y': label,
            'funcs': [],
            'imprts': [x for x in currentProgram.getExternalManager().getExternalLibraryNames()],
            'hash': currentProgram.getExecutableSHA256(),
            'bs_addr': currentProgram.getImageBase().toString(),
            'inst_cat_freq_lookup': category_name_lookup,
            'lang': str(currentProgram.getLanguage()),
            'format': currentProgram.getExecutableFormat(),

            # TODO: Look at reallocation & symbol table
            'strs': strings_list
        }  # JSON for entire
    except Exception as e:
        log(LOG_DIR, "Error at get_program_information function", e)

    return start_time, program_json


# =============================================================================
# Generate list of category mnemonics
# =============================================================================
def read_from_config():
    try:

        categories = []
        category_name_lookup = []
        with open('mnemonic_categories.txt', 'r') as f:
            for line in f:
                # First, get the category name
                category = line.split()[0].replace(':', '')
                # Then, create a dictionary with all of the mnemonics under the category in question
                categories.append({'category': category, 'mnemonics': line.split()[1:]})
                category_name_lookup.append(category)
        category_name_lookup.append('unknown')
    except Exception as e:
        log(LOG_DIR, "Error while reading from config file (read_from_config) function", e)

    ##### MY CODE #####
    #log(LOG_DIR, categories, "")
    #log(LOG_DIR, "\n", "")
    #log(LOG_DIR, category_name_lookup, "")

    return categories, category_name_lookup


# =============================================================================
# Cross-reference mnemonic string with configuration file
# =============================================================================
def get_categories_from_mnemonic(mnemonic, categories):
    try:
        mnemonics = []
        # Some mnemonics may have a '.' in them. There might be multiple operations going on.
        if '.' in mnemonic:
            mnemonics = mnemonic.split('.')
        else:
            mnemonics.append(mnemonic)
        found_categories = []
        for item in mnemonics:
            found = False
            # Check all categories for the mnemonic in question
            for category in categories:
                if item in category['mnemonics']:
                    found = True
                    found_categories.append(category['category'])
            if not found:
                found_categories.append('unknown')
        final_category = found_categories[0]
        # If there were multiple mnemonics (separated by a period),
        # then both mnemonics need to have matching categories
        if all(s == final_category for s in found_categories):
            return [final_category]
        else:
            return found_categories

    except Exception as e:
        log(LOG_DIR, "Error while getting categories from mnemonic", e)


# =============================================================================
# Get all operands and types
# =============================================================================
def get_operands(instruction):
    try:
        operands_list = []
        num_operands = instruction.getNumOperands()
        for i in range(num_operands):
            # Get the integer value of the operand type
            operand_type = instruction.getOperandType(i)
            # All possible operand types
            operands = [
                'read',
                'write',
                'indirect',
                'immediate',
                'relative',
                'implicit',
                'code',
                'data',
                'port',
                'register',
                'list',
                'flag',
                'text',
                'address',
                'scalar',
                'bit',
                'byte',
                'word',
                'quadword',
                'signed',
                'float',
                'cop',
                'dynamic'
            ]
            # Get the operand type list
            operand_type_list = []
            for j in range(23):
                # Perform bitwise & operation on the integer value to determine if the last bit is 0 or 1.
                if operand_type & 1 == 1:
                    operand_type_list.append(operands[j])
                # Perform bitwise right shift to move on to the next bit in the integer value.
                operand_type = operand_type >> 1
                if operand_type == 0:
                    break

            # Get the list of operand objects
            instruction_operands = instruction.getOpObjects(i).tolist()
            string_operands = []
            # Convert the operands to usable string value
            for item in instruction_operands:
                string_operands.append(str(item))
            operands_list.append({'t': operand_type_list, 'v': string_operands})
    except Exception as e:
        log(LOG_DIR, "Error while getting operands", e)

    return operands_list


# =============================================================================
# Get registers and addresses used in individual instructions
# =============================================================================
def get_regs_and_addrs(instruction):
    try:
        operands_list = []
        num_operands = instruction.getNumOperands()
        registers, addresses = [], []
        for i in range(num_operands):
            # First, try to obtain a register. Returns None if fails
            register = instruction.getRegister(i)
            if register is not None:
                registers.append(register.toString())
            # Then, try to obtain an address. Returns None if fails
            address = instruction.getAddress(i)
            if address is not None:
                addresses.append(address.toString())
    except Exception as e:
        log(LOG_DIR, "Error while getting registers and addresses (get_regs_and_addrs)", e)

    return registers, addresses


# =============================================================================
# Get individual function's assembly code
# =============================================================================
def get_asm_information(current_function, func_len, categories, category_name_lookup, sbm):
    try:
        asm_dict = dict()
        asm_dict["asm"] = []
        asm_dict["insts"] = []
        asm_dict["op_list"] = []
        asm_dict["registers"] = []
        asm_dict["addresses"] = []
        asm_dict['instruction_info'] = []

        # Get all the categories that will be analyzed and the mnemonics within each category
        instruction_category_frequencies = [0] * len(category_name_lookup)

        current_inst = getInstructionContaining(current_function.getEntryPoint())
        # for each instruction within range of function
        while current_inst is not None and current_inst.getAddress() < current_function.getEntryPoint().add(func_len):
            # Get information about the instruction from API
            inst_str = str(current_inst)
            inst_bytes = getBytes(current_inst.getMinAddress(), current_inst.getLength())

            # Assign the current instruction's mnemonic to a reusable variable
            mnemonic = current_inst.getMnemonicString()
            # Get full assembly instruction with metadata

            # Converts improperly signed inst_bytes to unsigned array of ints
            byte_len = str(len(inst_bytes))
            inst_bytes = struct.unpack(byte_len + 'B', struct.pack(byte_len + 'b', *inst_bytes))

            inst_info_dict = {
                'inst': inst_str,
                'opcode': inst_bytes,
                'opr': get_operands(current_inst),
                # 'bbs':  # Basic block start. Does this instruction start a basic block? Only present if True (1)
            }
            if sbm.isBlockStart(current_inst):
                inst_info_dict['bbs'] = 1

            asm_dict['instruction_info'].append(inst_info_dict)
            asm_dict["insts"].append(mnemonic)

            # Get registers and addresses as their own features
            regs, addrs = get_regs_and_addrs(current_inst)
            asm_dict["registers"] += regs
            asm_dict["addresses"] += addrs
            # Increment the frequency of the category that the get_categories_from_mnemonic function returns
            cat_freqs_to_inc = get_categories_from_mnemonic(mnemonic, categories)
            for cat in cat_freqs_to_inc:
                index_to_increment = category_name_lookup.index(cat)
                instruction_category_frequencies[index_to_increment] += 1

            # Get the next instruction
            current_inst = current_inst.getNext()

        asm_dict['instruction_category_frequencies'] = instruction_category_frequencies
    except Exception as e:
        log(LOG_DIR, "Error at get_asm_information", e)

    return asm_dict


# =============================================================================
# Get information for the functions
# =============================================================================
def prepare_function_information(program_json, categories, category_name_lookup):
    try:
        # get the first function
        current_function = getFirstFunction()

        if INCLUDE_ALL_EXECUTABLE_BYTES and getLastFunction() is not None:
            # Extract all executable bytes from the first and last function (inclusive)
            final_func_len = getLastFunction().getBody().getNumAddresses()
            executable_end_address = getLastFunction().getEntryPoint().add(final_func_len)
            executable_size = executable_end_address.subtract(current_function.getEntryPoint())
            executable_bytes = getBytes(current_function.getEntryPoint(), executable_size)
            # Converts improperly signed inst_bytes to unsigned array of ints
            byte_len = str(len(executable_bytes))
            executable_bytes = struct.unpack(byte_len + 'B', struct.pack(byte_len + 'b', *executable_bytes))
            program_json["all_executable_bytes"] = executable_bytes

        sbm = SimpleBlockModel(currentProgram)

        # For each function
        while current_function is not None:
            if current_function.isThunk():
                current_function = getFunctionAfter(current_function)
                continue
            # ============= Function Bytes Extraction =============
            # function length
            func_len = current_function.getBody().getNumAddresses()
            # function bytes

            func_bytes = getBytes(current_function.getEntryPoint(), func_len)

            asm_dict = get_asm_information(current_function, func_len, categories, category_name_lookup, sbm)

            # Write instruction info to JSON
            program_json['funcs'].append({
                'func_name': str(current_function.getName()),
                'entry_pt_addr': str(current_function.getEntryPoint()),
                'exit_pt_addr': str(current_function.getEntryPoint().add(func_len)),
                # 'raw_bytes'   : [hex(func_bytes[x]) for x in range(func_len)],
                'insts': asm_dict["insts"],
                'regs': asm_dict["registers"],
                'mem_addrs': asm_dict["addresses"],
                'func_size': int(sys.getsizeof(func_bytes)),
                'func_len': int(func_len),
                'num_insts': len(asm_dict["insts"]),
                'inst_cat_freq': asm_dict["instruction_category_frequencies"],
                'inst_info': asm_dict["instruction_info"],
                'num_pars': current_function.getParameterCount()
            })

            # go to the next function in the file
            current_function = getFunctionAfter(current_function)
    except Exception as e:
        log(LOG_DIR, "Error at prepare_function_information", e)

    return program_json


# =============================================================================
# check directory path for dataset
# =============================================================================
def save_file(program, json_path):
    try:
        # Write output to file
        with open(json_path, 'w') as file:
            file.write(program)
    except Exception as e:
        log(LOG_DIR, "Error at save_file", e)


# =============================================================================
# check directory path for dataset
# =============================================================================
def check_path(new_path):
    try:

        if not os.path.exists(new_path):
            try:
                os.makedirs(new_path)
            except Exception as e:
                with open('dead.letter', 'a') as f:
                    f.write('ERROR > Failed to create directories.\n')
                    f.write(e + '\n')
                println("ERROR > Failed to create directories.")
                println(e)
    except Exception as e:
        log(LOG_DIR, "Error at check_path", e)


# =============================================================================
# log errors
# =============================================================================
def log(log_dir, message, info):
    # get time
    currentDT = datetime.datetime.now()

    # log event
    file = open(log_dir, "a+")
    file.write("Program Name: " + str(currentProgram.getName()) + "\n" + \
               "Message: " + str(message) + "\n" + \
               "Time: " + str(currentDT.strftime("%Y-%m-%d %H:%M:%S")) + "\n" + \
               "Info: " + str(info) + \
               "\n\n\n")
    file.close()


if __name__ == '__main__':
    main()
