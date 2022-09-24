#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <string>
#include "pin.H"

#define BEFORE_WARMUP 0
#define WARMUP_STARTED 1
#define WARMUP_RESUME 2
#define WARMUP_PAUSE 3
#define SIMULATION_STARTED 4
#define SIMULATION_RESUME 5
#define SIMULATION_PAUSE 6
#define END_OF_FILE 7


using std::string;
 std::ofstream outfile;

#include "../../../../ChampSim/inc/trace_instruction.h"

using trace_instr_format_t = input_instr;
 
trace_instr_format_t curr_instr;
trace_instr_format_t last_instr; //We will write it to the end of file

int code_state = 0; 
int count=0;
int count1=0;
int count2=0;
int count3=0;
int count4=0;
// before warmup = 0
// warmup started = 1
// warmup resume = 2
// warmup pause = 3
//simulation started = 4
// simulation resumed = 5
// simulation pause = 6
// Last instr = 7
UINT64 instrCount = 0;


/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "champsim.trace", 
        "specify file name for Champsim tracer output");

void Change_state_func(string routine_name){
    if(routine_name == "warmup_start"){
        code_state = WARMUP_STARTED;
    }
    if(routine_name == "warmup_pause"){
        code_state = WARMUP_PAUSE;
    }
    if(routine_name == "warmup_resume"){
        code_state = WARMUP_RESUME;
    }
    if(routine_name == "simulation_start"){
        code_state = SIMULATION_STARTED;
    }
    if(routine_name == "simulation_resume"){
        code_state = SIMULATION_RESUME;
    }
    if(routine_name == "simulation_pause"){
        code_state = SIMULATION_PAUSE;
    }
    
}

VOID Routine(RTN rtn, VOID* v){
    const std::string& func_name = RTN_Name(rtn);
    RTN_Open(rtn);
    // std::cout<<func_name<<std::endl;
    // std::string routine_name = func_name;
    // if(routine_name == "warmup_start"){
    //     code_state = WARMUP_STARTED;
    // }
    // if(routine_name == "warmup_pause"){
    //     code_state = WARMUP_PAUSE;
    // }
    // if(routine_name == "warmup_resume"){
    //     code_state = WARMUP_RESUME;
    // }
    // if(routine_name == "simulation_start"){
    //     code_state = SIMULATION_STARTED;
    // }
    // if(routine_name == "simulation_resume"){
    //     code_state = SIMULATION_RESUME;
    // }
    // if(routine_name == "simulation_pause"){
    //     code_state = SIMULATION_PAUSE;
    // }

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)Change_state_func, IARG_PTR, &(func_name), IARG_END); 
    RTN_Close(rtn);
}
 


INT32 Usage()
{
  std::cerr << "This tool creates a register and memory access trace" << std::endl 
        << "Specify the output trace file with -o" << std::endl 
        << "Specify the number of instructions to skip before tracing with -s" << std::endl
        << "Specify the number of instructions to trace with -t" << std::endl << std::endl;

  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

    return -1;
}

void ResetCurrentInstruction(VOID *ip)
{
    curr_instr = {};
    curr_instr.ip = (unsigned long long int)ip;
}

BOOL ShouldWrite()
{
  ++instrCount;
  return 1;
}
int flag =0;
int flag1=0;
int flag2=0;
void WriteCurrentInstruction()
{
    if((code_state == BEFORE_WARMUP )|| (code_state == WARMUP_PAUSE)){
        //Avoid writing the instruction to the file
        count++;
        return;
    }
    else if((code_state == WARMUP_STARTED) || (code_state == WARMUP_RESUME)){
        if(flag==0){
            std::cout<<count<<std::endl;
            flag++;
            }
        count1++;

        curr_instr.extra_bit = 0;
    }
    else if((code_state == SIMULATION_STARTED) || (code_state == SIMULATION_RESUME)){
        count2++;
        curr_instr.extra_bit = 1;
    }
    else if((code_state == SIMULATION_PAUSE)){
        curr_instr.extra_bit = 2;
        count3++;
    }
    else {
        count4++;
    }
    typename decltype(outfile)::char_type buf[sizeof(trace_instr_format_t)];
    std::memcpy(buf, &curr_instr, sizeof(trace_instr_format_t));
    outfile.write(buf, sizeof(trace_instr_format_t));
}

void BranchOrNot(UINT32 taken)
{
    curr_instr.is_branch = 1;
    curr_instr.branch_taken = taken;
}

template <typename T>
void WriteToSet(T* begin, T* end, UINT32 r)
{
  auto set_end = std::find(begin, end, 0);
  auto found_reg = std::find(begin, set_end, r); // check to see if this register is already in the list
  *found_reg = r;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
    // begin each instruction with this function
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ResetCurrentInstruction, IARG_INST_PTR, IARG_END);

    // instrument branch instructions
    if(INS_IsBranch(ins))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);

    // instrument register reads
    UINT32 readRegCount = INS_MaxNumRRegs(ins);
    for(UINT32 i=0; i<readRegCount; i++) 
    {
        UINT32 regNum = INS_RegR(ins, i);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned char>,
            IARG_PTR, curr_instr.source_registers, IARG_PTR, curr_instr.source_registers + NUM_INSTR_SOURCES,
            IARG_UINT32, regNum, IARG_END);
    }

    // instrument register writes
    UINT32 writeRegCount = INS_MaxNumWRegs(ins);
    for(UINT32 i=0; i<writeRegCount; i++) 
    {
        UINT32 regNum = INS_RegW(ins, i);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned char>,
            IARG_PTR, curr_instr.destination_registers, IARG_PTR, curr_instr.destination_registers + NUM_INSTR_DESTINATIONS,
            IARG_UINT32, regNum, IARG_END);
    }

    // instrument memory reads and writes
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) 
    {
        if (INS_MemoryOperandIsRead(ins, memOp)) 
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned long long int>,
                IARG_PTR, curr_instr.source_memory, IARG_PTR, curr_instr.source_memory + NUM_INSTR_SOURCES,
                IARG_MEMORYOP_EA, memOp, IARG_END);
        if (INS_MemoryOperandIsWritten(ins, memOp)) 
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned long long int>,
                IARG_PTR, curr_instr.destination_memory, IARG_PTR, curr_instr.destination_memory + NUM_INSTR_DESTINATIONS,
                IARG_MEMORYOP_EA, memOp, IARG_END);
    }
    // finalize each instruction with this function
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ShouldWrite, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteCurrentInstruction, IARG_END);
}

 
// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    std::cout<<"count: "<<count<<std::endl;
    std::cout<<"count1: "<<count1<<std::endl;
    std::cout<<"count2: "<<count2<<std::endl;
    std::cout<<"count3: "<<count3<<std::endl;
    std::cout<<"count4: "<<count4<<std::endl;


    last_instr.extra_bit = -1;
    typename decltype(outfile)::char_type buf[sizeof(trace_instr_format_t)];
    std::memcpy(buf, &last_instr, sizeof(trace_instr_format_t));
    outfile.write(buf, sizeof(trace_instr_format_t));
    outfile.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
 
int main(int argc, char* argv[])
{
    // Initialize symbol table code, needed for rtn instrumentation
    code_state=BEFORE_WARMUP;
    PIN_InitSymbols();
 
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
    
    outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile)
    {
      std::cout << "Couldn't open output trace file. Exiting." << std::endl;
        exit(1);
    }

    // Register Routine to be called to instrument rtn
    RTN_AddInstrumentFunction(Routine, 0);

    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
 
    return 0;
}