
import os
import bz2
import json

INPUT_JSON_DIR = "./output_JSONs"
OUTPUT_JSON_DIR = "./augmented_JSONs"
ZIPPED_EXTENSION = ".bz2"

def is_compressed(filename):
    possible_file_extension = filename[len(filename)-len(ZIPPED_EXTENSION):]
    return possible_file_extension == ZIPPED_EXTENSION

json_files = os.listdir(INPUT_JSON_DIR)
print(json_files)

for filename in json_files:
    filepath = f"{INPUT_JSON_DIR}/{filename}"
    print(filepath)
