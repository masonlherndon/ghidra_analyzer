### LEVEL 2
Extract data from binaries using custom plugins and create a raw dataset in the form of JSON file.

# Function Dataset Setup
## Raw Dataset Directory Organization
```
imports/
├── benign/
│   ├── win10sys/
│   │    ├── Something.exe
│   │    └── SystemFile.exe
│   └── win7sys/
└── malicious/
    ├── ransomware/
    └── other/
```

## Post Ghidra Dataset Organization
```
exports/
├── benign/
│   ├── win10sys/
│   │    ├── Something.exe.bz2
│   │    └── SystemFile.exe.bz2
│   └── win7sys/
└── malicious/
    ├── ransomware/
    └── other/
```
## JSON Dataset Parameters
### File Information
There is one JSON per binary with main entry for file with the following parameters.
 - **name:** Name of the binary or file
 - **y:**
	 - 1 = malicious
	 - 0 = benign
 - **src:** Source of the data
 - **size:** Size or the binary or file in bytes
 - **len:** Length of the file (number of addresses)
 - **imprts:** External libraries imported by the binary
 - **hash:** SHA256 hash of the binary
 - **bs_addr:** Binary's base address
 - **strings:** List of printable strings
 - **inst_cat_freq_lookup:** Lookup list for category names and their corresponding indices in inst_cat_freq
 - **funcs:** See below
### Function Information
There is an JSON object entry for each function with the following parameters.
 - **func_name:** Function name
 - **insts:** List of  instruction mnemonics
 - **num_insts:** Number of  mnemonics
 - **entry_pt_addr** Function's entry point address
 - **exit_pt_addr:** Function's exit point address
 - **regs:** List of registers from operands
 - **mem_addrs:** List of memory addresses from operands
 - **func_size:** Function size in bytes
 - **func_len:** Function length, number of addresses
 - **num_pars:** Parameter count
 - **inst_cat_freq:** Frequency of each instruction category index, measured by number of occurrences.
 - **inst_info:** Information regarding each instruction, including the full instruction, operands, and opcode
### Instruction Information
JSON information stored under inst_info.
 - **inst:** The full instruction in question.
 - **opcode:** The instruction opcode.
 - **oprnds:** The operands referenced in the instruction.
