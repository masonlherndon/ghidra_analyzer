#!/usr/bin/env python3.6
# @
import os
import datetime
import time
import subprocess
import signal
#import sys
import shutil
from subprocess import DEVNULL

'''
./ghidra/support/analyzeHeadless gproj headless -readOnly -recursive -import FOLDERHERE/ -postScript extract_functions.py -scriptlog log/script.log -log log/ghidra.log -max-cpu 8

Change instance Directory and log directory to run on another instance:
'''

###############################################################################

# Settings
BATCH_SIZE = 1  # Number of binaries per batch
MAX_INSTANCES = 1   # Maximum allowed instances
MAX_CPU_PER_INSTANCE = 2
INSTANCE_TIMEOUT = BATCH_SIZE * 5   # Number of minutes before process is killed
NEW_INSTANCES = MAX_INSTANCES   # Able to be modified to change max_instances (Modified by script, don't edit)

ENABLE_DECOMPILATION = True

# Input
DATA_DIRECTORY = "./data/malware"  # dataset root directory

# Ghidra
GHIDRA_HEADLESS = "./ghidra/support/analyzeHeadless"  # Ghidra Headless dir
GHIDRA_PARAMS = f"headless -readOnly -recursive -max-cpu {MAX_CPU_PER_INSTANCE} -import"  # Ghidra parameters
POST_SCRIPT = "./extract_functions.py"  # Ghidra Headless plugin script
PRE_SCRIPT = "./disable_decompilation.py"
COMPLETE_DIR = "./ghidra_done/"
ERR_DIR = "./ghidra_fail/"

# Logging
GHIDRA_LOG = "log/ghidra%d.log"  # Ghidra log locations
LOG_DIR = "./log/ghidra_batches.log"  # ghidra run log
log_file = open(LOG_DIR, "a+")

# Timing Measurements
T_FILES_PROCESSED = 0
T_START_TIME = datetime.datetime.now()
T_TOTAL_FILES = 0

###############################################################################

# Setup dict for processes. Each key represents one potential "slot"
# Key: index Value: (subprocess object, num files, start time)
ghidra_processes = {}
for inst in range(MAX_INSTANCES):
    ghidra_processes[inst] = None


def main():
    global MAX_INSTANCES, NEW_INSTANCES, T_TOTAL_FILES
    # get the directory tree for the instances
    dirs_inst = search_directory_tree(DATA_DIRECTORY)

    for _, binaries in dirs_inst.items():
        T_TOTAL_FILES += len(binaries)
    log("Beginning processing of %d binaries\n" % T_TOTAL_FILES, True)

    # Get all directories that have files
    for p_dir, binaries in dirs_inst.items():

        # Split files into BATCH_SIZE chunks
        file_chunks = list(divide_chunks(binaries, BATCH_SIZE))
        log("Starting %d batches * %d batch size\n" % (len(file_chunks), BATCH_SIZE), True)

        # For each chunk, find an instance to process it
        for chunk in file_chunks:
            while True:  # Repeat this chunk until it actually gets processed

                log("\nWaiting for next available process...\n")
                instance_num = find_next_avail_process()  # Find next process slot to use

                # If new instances shouldn't be created, we're in spindown_mode
                spindown_mode = NEW_INSTANCES < MAX_INSTANCES
                if spindown_mode:
                    log("Max instances decreased to %d. Processes will begin to spin down...\n" % NEW_INSTANCES, True)
                # Make sure we're ready to launch a new instance
                instance_folder = "instances/instance%d" % instance_num
                check_path(instance_folder)
                update_timing(instance_num)

                if os.listdir(instance_folder):  # If directory is not empty. (Process either finished or got killed)
                    # Process finished and is ready for new batch
                    proc_data = ghidra_processes[instance_num]
                    if proc_data is not None and proc_data[0] is not None:
                        if proc_data[0].returncode == 0:  # Finished successfully
                            move_old_files_out(instance_num)
                        elif proc_data[0].returncode == 1:  # Most likely a memory error
                            log("Ghidra instance %d returned 1. (out of memory or script error)\n" % instance_num, True)
                            move_old_files_out(instance_num, ERR_DIR)
                        elif proc_data[0].returncode == -9 or proc_data[0].returncode == -15:  # Killed
                            log("Process %d was killed." % instance_num, True)
                            delete_dir(os.path.join("projects/gproj%d/" % instance_num),
                                       err_msg=("Couldn't delete project %d folder\n" % instance_num), delete_contents=True)
                            check_path(os.path.join("./projects", "gproj%d" % instance_num))
                            move_old_files_out(instance_num, ERR_DIR)
                        else:  # Process was killed and we will recompute
                            log("Ghidra instance %d returned an error: %d" % (instance_num, proc_data[0].returncode), True)
                            log("Files are already here, but instance is new... (Re?)computing files in instance%d\n" % instance_num, True)
                            ghidra_processes[instance_num] = launch_ghidra(instance_num, len(chunk))  # Launch anyways
                            continue

                if not spindown_mode:  # Ready to launch --~~~=:>[XXXXXXXXX]>  (It's a rocket)
                    instance_num = fix_numbering(instance_num)
                    move_new_files_in(p_dir, chunk, instance_num)
                    ghidra_processes[instance_num] = launch_ghidra(instance_num, len(chunk))
                    break

                # Can't launch new instances
                log("\nProcess %d finished or attempted to start in spindown mode\n" % instance_num)
                delete_dir(os.path.join("instances/instance%d/" % instance_num),
                           err_msg=("Couldn't delete instance %d folder\n" % instance_num))
                log("Removed directory for old instance %d\n" % instance_num)
                del ghidra_processes[instance_num]
                MAX_INSTANCES -= 1
                log("Current running instances: %d/%d\n" % (MAX_INSTANCES, NEW_INSTANCES), True)

    log("\n\nWaiting for final batches to complete.\n\n", True)
    for i, proc in ghidra_processes.items():
        if proc is None or proc[0] is None:
            continue
        log("Waiting on process %d\n" % i, True)
        proc[0].wait()
        if proc[0].returncode != 0:
            log("Process %d died or something\n" % i, True)
            move_old_files_out(i, ERR_DIR)
        else:
            move_old_files_out(i)

        delete_dir("./instances/instance%d" % i, err_msg="Final execution")

    log_file.close()


def move_new_files_in(p_dir, binaries, instance_num):
    log("Moving new files in\n")
    cat_dir = os.path.basename(os.path.dirname(p_dir))  # Malicious/Benign dir name
    data_set = os.path.basename(p_dir)  # Dataset dir name
    for f in binaries:
        move_location = os.path.join("./instances/instance%d" % instance_num, cat_dir, data_set)
        check_path(move_location)
        check_path(os.path.join("./projects", "gproj%d" % instance_num))
        # print("[in] Moving file from %s to %s " % (os.path.join(p_dir, f), os.path.join(move_location, f)))
        os.rename(os.path.join(p_dir, f), os.path.join(move_location, f))


# Attempt to fix this instance's numbering which can occur after spindown
def fix_numbering(instance_num):
    if instance_num > NEW_INSTANCES:
        for i in range(NEW_INSTANCES):
            if i not in ghidra_processes.keys():
                ghidra_processes[i] = None
                del ghidra_processes[instance_num]
                delete_dir(os.path.join("instances/instance%d/" % instance_num),
                           err_msg=("Couldn't delete instance %d folder during rename" % instance_num))
                log("Process %d has been renamed to Process %d\n" % (instance_num, i))
                instance_num = i
                break
    return instance_num


def update_timing(instance_num):
    global T_FILES_PROCESSED
    if instance_num not in ghidra_processes.keys() or ghidra_processes[instance_num] is None:
        return
    num_files = ghidra_processes[instance_num][1]
    T_FILES_PROCESSED += num_files
    current_time = datetime.datetime.now()
    elapsed_time = (current_time - T_START_TIME).total_seconds()
    file_rate = T_FILES_PROCESSED / elapsed_time
    files_remaining = T_TOTAL_FILES - T_FILES_PROCESSED
    time_remaining = files_remaining / file_rate
    end_time = current_time + datetime.timedelta(seconds=time_remaining)
    log("File Rate is %.03f files per minute\n" % (file_rate*60), True)
    log("Elapsed: %s | Remaining: %s | End: %s\n" % (
        str(datetime.timedelta(seconds=elapsed_time)).split(".")[0],
        str(datetime.timedelta(seconds=time_remaining)).split(".")[0],
        end_time.strftime("%m/%d/%Y, %H:%M:%S EST")), True)


def move_old_files_out(instance_num, base_dir=COMPLETE_DIR):
    log("Moving old files out\n")
    for p_dir, mov_file in search_directory_tree("instances/instance%d" % instance_num).items():
        cat_dir = os.path.basename(os.path.dirname(p_dir))  # Malicious/Benign dir name
        data_set = os.path.basename(p_dir)  # Dataset dir name
        for f in mov_file:
            move_location = os.path.join(base_dir, cat_dir, data_set)
            check_path(move_location)  # Create directories if they don't exist
            if base_dir == ERR_DIR:
                log("[out] Moving file from %s to %s \n" % (os.path.join(p_dir, f), os.path.join(move_location, f)))
            os.rename(os.path.join(p_dir, f), os.path.join(move_location, f))
        os.rmdir(p_dir)
        delete_dir(os.path.join("instances/instance%d/" % instance_num, cat_dir), err_msg="move_old_files_out")


# Loops through each processing "slot" where each key in ghidra_processes allows one slot
def find_next_avail_process():
    global NEW_INSTANCES, MAX_INSTANCES
    while True:  # Loop until a process "slot" is available
        flag = 0
        for index, proc in ghidra_processes.items():
            if proc is not None and proc[0] is not None and proc[0].poll() is None:
                # Process is still ticking
                # Check if we've exceeded the timeout
                start_time = proc[2]

                current_time = datetime.datetime.now()
                elapsed_time = (current_time - start_time).total_seconds()
                if elapsed_time/60 > INSTANCE_TIMEOUT:
                    log("Killing pid %d\n" % proc[0].pid, True)
                    os.system("kill %d" % proc[0].pid)
                    time.sleep(1)
                    flag = index
                    break

                continue
            else:
                log("Process %d is available. Starting up next instance...\n" % index)
                return index
        else:
            time.sleep(0.5)
            # If instances has been increased or decreased -> Create more instances or setup to decrease
            if NEW_INSTANCES > MAX_INSTANCES:
                log("Max instances increased to %d! Upscaling...\n" % NEW_INSTANCES, True)
                for j in range(NEW_INSTANCES):
                    if j not in ghidra_processes.keys():
                        ghidra_processes[j] = None
                MAX_INSTANCES = NEW_INSTANCES
            continue


def delete_dir(path, err_msg, delete_contents=False):
    try:
        if delete_contents:
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.rmdir(path)
    except OSError as e:
        log(err_msg + str(e), True)
        pass


def launch_ghidra(instance_num, num_files):
    instance_dir = os.path.join("instances", f"instance{instance_num}") # this is probably overkill
    log(f"Instance dir is {instance_dir}\n")
    ghidra_proj_dir = f"projects/gproj{instance_num}"

    ######## WARNING (from Mason): THIS HACKY FIX ONLY WORKS FOR A BATCH SIZE OF 1
    dir_dict = search_directory_tree(instance_dir)
    cur_filename = ""
    for _, files in dir_dict.items():
        cur_filename = files[0]
    cur_binary_filepath = f"{os.getcwd()}/{instance_dir}/data/malware/{cur_filename}"
    file_info_str = subprocess.run(["file", cur_binary_filepath], stdout=subprocess.PIPE).stdout.decode("utf-8")
    file_bit_version = "32"
    if "PE32+" in file_info_str:
        file_bit_version = "64"
    arch_info = f"x86:LE:{file_bit_version}:default"
    ########


    args = f"{GHIDRA_HEADLESS} {ghidra_proj_dir} {GHIDRA_PARAMS} {instance_dir} -processor {arch_info} -postScript {POST_SCRIPT} -log {GHIDRA_LOG % instance_num}"

    args = f"{GHIDRA_HEADLESS} {ghidra_proj_dir} {GHIDRA_PARAMS} {instance_dir} -processor {arch_info} -preScript {PRE_SCRIPT} -postScript {POST_SCRIPT} -log {GHIDRA_LOG % instance_num}"

    args = args.split(" ")
    log(f"Started subprocess number {instance_num}")


    # Run Ghidra (and ignore SIGINTs)
    print(args)
    return (subprocess.Popen(args,
                             preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN),
                             stdout=DEVNULL, stderr=DEVNULL), num_files, datetime.datetime.now())

# =============================================================================
# Check directory path and create it if it doesn't exist
# =============================================================================
def check_path(new_path):
    try:

        if not os.path.exists(new_path):
            try:
                os.makedirs(new_path)
            except Exception as e:
                log(str(e))
    except Exception as e:
        log("Error at check_path" + str(e))


# ==============================================================================
# Recursively walks the directory tree and collect the file paths
#   Below function recursively walks the directory tree starting from the ROOT
#   directory of the dataset and returns a dictionary of file paths where key
#   is the folder name and the list that key points to is the list of files in
#   that folder:
# ==============================================================================
def search_directory_tree(ROOT_DIRECTORY):
    IGNORE_LIST = ['.DS_Store']

    # hold directories and files
    directories = dict()

    # recursively walk to directory tree and get files
    for dirName, subdirList, fileList in os.walk(ROOT_DIRECTORY):

        # remove ignore list from list
        if IGNORE_LIST:
            for ignore in IGNORE_LIST:

                # if ignore in the list
                if ignore in fileList:
                    fileList.remove(ignore)
        if len(fileList) > 0:
            directories[str(dirName)] = fileList

    return directories


# =============================================================================
# log information
# =============================================================================
def log(message, do_print=False):
    log_file.write(message)
    if do_print:
        print(message)


# =============================================================================
# create chunks from list
# =============================================================================
def divide_chunks(l, n):
    # looping till length l
    for i in range(0, len(l), n):
        yield l[i:i + n]


Ctrl_C_Once = False


def signal_handler(sig, frame):
    global Ctrl_C_Once
    global NEW_INSTANCES
    if not Ctrl_C_Once:
        log("\nCurrent max number of instances %d" % MAX_INSTANCES, True)
        log('Ctrl+C again to modify', True)
        Ctrl_C_Once = True
    else:
        if NEW_INSTANCES != MAX_INSTANCES:
            log("\nMax instances is still adjusting. Please wait.", True)
            Ctrl_C_Once = False
            return
        NEW_INSTANCES = get_int_input("\nEnter new max: ")
        Ctrl_C_Once = False
        log("Max instances set to %d" % NEW_INSTANCES, True)


def get_int_input(msg):
    while True:
        try:
            num = input(msg)
            if num == "exit":
                exit(0)
            val = int(num)
            break
        except ValueError:
            print("This is not a number. Please enter a valid number")
        except RuntimeError:
            print("Error in input. Ctrl + C Again")
    return val


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main()
