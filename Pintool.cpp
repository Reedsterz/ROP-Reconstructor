#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include "pin.H"

struct Instruction {
    // instruction relative virtual address (RVA)
    uintptr_t rva;
    // disassembled instruction
    std::string dis;
};

// base address of main ELF image
uintptr_t image_base_address;
// size of main ELF image
size_t image_size;
// instruction info
std::unordered_map<uintptr_t, Instruction> instructions;
// output file (stderr by default, override it with `-o` flag)
std::ostream* out = &std::cerr;

KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE,
                                 "pintool",
                                 "o",
                                 "",
                                 "specify file name for MyPinTool output");

KNOB<BOOL> KnobCount(KNOB_MODE_WRITEONCE,
                     "pintool",
                     "count",
                     "1",
                     "count control flow instructions");

INT32 Usage() {
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

VOID OnEveryInstruction(ADDRINT ins_rva_addr, ADDRINT target_addr) {
    const auto& ins = instructions[ins_rva_addr];
    *out << std::hex << ins.rva << "\t" << ins.dis << "\t"
         << "\n";
}

VOID OnCall(ADDRINT ins_rva_addr, ADDRINT target_addr) {
    const auto& item = instructions[ins_rva_addr];
    assert(ins_rva_addr == item.rva);
    *out << ins_rva_addr << "\t" << item.dis
         << target_addr << std::endl;

}

VOID OnRet(ADDRINT ins_rva_addr, ADDRINT target_addr) {
    const auto& item = instructions[ins_rva_addr];
    assert(ins_rva_addr == item.rva);
    *out << ins_rva_addr << "\t" << item.dis
         << target_addr << std::endl;
}

VOID Instruction(INS ins, VOID* v) {
    auto address = INS_Address(ins);

    // Check that instructions address is inside main ELF image
    if (address >= image_base_address &&
        address < image_base_address + image_size) {

        if (INS_IsRet(ins) || INS_IsSysret(ins)) {

            auto dis = INS_Disassemble(ins);
            auto rva = address - image_base_address;
            auto& item = instructions[rva];
            item.rva = rva;
            item.dis = dis;
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnRet, IARG_ADDRINT,
                            rva, IARG_BRANCH_TARGET_ADDR, IARG_END);
        }
    }
}

VOID Image(IMG img, VOID* v) {
    if (IMG_IsMainExecutable(img)) {
        auto name = IMG_Name(img);
        auto load_offset = IMG_LoadOffset(img);
        auto low_address = IMG_LowAddress(img);
        auto high_address = IMG_HighAddress(img);

        *out << "<<<<<<< " << name << " >>>>>>>" << std::endl;
        *out << "load offset: " << std::hex << load_offset << std::endl;
        *out << "low address: " << std::hex << low_address << std::endl;
        *out << "high address: " << std::hex << high_address << std::endl;
        *out << std::endl;

        // Store image base address and image size of the main ELF image
        image_base_address = load_offset;
        image_size = high_address - load_offset;
    }
}

VOID Fini(INT32 code, VOID* v) {

    //*out << "Trace Exited" << std::flush;
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet
 * started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[]) {
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    std::string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) {
        out = new std::ofstream(fileName.c_str());
    }

    if (KnobCount) {
        // Register function to be called to instrument instructions
        INS_AddInstrumentFunction(Instruction, 0);

        // Instrument image loading
        IMG_AddInstrumentFunction(Image, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }

    std::cerr << "===============================================" << std::endl;
    std::cerr << "This application is instrumented by MyPinTool" << std::endl;
    if (!KnobOutputFile.Value().empty()) {
        std::cerr << "See file " << KnobOutputFile.Value()
                  << " for analysis results" << std::endl;
    }
    std::cerr << "===============================================" << std::endl;

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
