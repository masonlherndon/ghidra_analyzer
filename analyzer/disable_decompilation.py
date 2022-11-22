#!/usr/bin/env python2.7
# Uses Ghidra's Jython2 API to disable unneccesary analysis settings to speed up disassembly
#
# Decompiler Parameter ID - Creates parameter and local variables for a Function using Decompiler.
# Decompiler Switch Analysis - Creates switch statements for dynamic instructions using Decompiler.
# Stack - Creates stack variables for a function.
# Windows x86 PE RTTI Analyzer - This analyzer finds and creates all of the RTTI metadata structures and their associated vf tables.
# x86 Constant Reference Analyzer - x86 Constant Propagation Analyzer for constant references computed with multiple instructions.
# true	Windows x86 PE Exception Handling - Marks up exception handling data structures within a Visual Studio windows PE program.


def main():

    # setAnalysisOption(currentProgram, "x86 Constant Reference Analyzer", "false")
    # setAnalysisOption(currentProgram, "Decompiler Parameter ID", "false")
    # setAnalysisOption(currentProgram, "Stack", "false")
    # setAnalysisOption(currentProgram, "Decompiler Switch Analysis", "false")
    # setAnalysisOption(currentProgram, "Function ID", "false")
    # setAnalysisOption(currentProgram, "Demangler", "false")
    # setAnalysisOption(currentProgram, "Windows x86 PE Exception Handling", "false")

    setAnalysisOption(currentProgram, "Windows x86 PE RTTI Analyzer", "false")
    setAnalysisOption(currentProgram, "Embedded Media", "false")
    setAnalysisOption(currentProgram, "Call Convention Identification", "false")
    setAnalysisOption(currentProgram, "PDB", "false")
    setAnalysisOption(currentProgram, "Decompiler Parameter ID.Analysis Decompiler Timeout", 20)


if __name__ == '__main__':
    main()
