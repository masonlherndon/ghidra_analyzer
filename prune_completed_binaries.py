
import os

INPUT_DIR = "./to_be_analyzed"
OUTPUT_DIR = "./output_JSONs"
EXTENSION_ADDED_TO_OUTPUT_FILES = ".json.bz2"

# get the filenames of binaries that were successfully analyzed
completed_binaries = []
for zipped_json_filename in os.listdir(OUTPUT_DIR):
    binary_name = zipped_json_filename[:len(zipped_json_filename)-len(EXTENSION_ADDED_TO_OUTPUT_FILES)]
    completed_binaries.append(binary_name)

# remove binaries that were successfully analyzed from the input folder
for binary_name in os.listdir(INPUT_DIR):
    if (binary_name in completed_binaries):
        binary_filepath = f"{INPUT_DIR}/{binary_name}"
        os.remove(binary_filepath)
