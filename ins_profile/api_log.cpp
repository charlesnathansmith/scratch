#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>

constexpr size_t MAX_INSTRUCTIONS = 1000000000;

// Output log file
KNOB<std::string> log_filename(KNOB_MODE_WRITEONCE, "pintool", "o", "log.txt", "log file");

std::ofstream logfile;
std::map<ADDRINT, std::string> api_map;

struct ins_info { size_t count; size_t last_seen; };
std::map<ADDRINT, ins_info> ins_counts;

// Count the number of times each instruction is executed
VOID log_ins(ADDRINT eip)
{
    static size_t counted = 0;

    if (++counted >= MAX_INSTRUCTIONS)
        PIN_ExitApplication(0);

    auto& it = ins_counts.find(eip);

    if (it == ins_counts.end())
        ins_counts[eip] = { 1, counted };
    else
    {
        it->second.count++;
        it->second.last_seen = counted;
    }
}

// Instrument modules on load
VOID imgInstrumentation(IMG img, VOID* val)
{
    // Instrument all APIs
    if (!IMG_IsMainExecutable(img))
    {
        logfile << IMG_Name(img) << " loaded at " << std::hex << IMG_LowAddress(img) << std::endl;

        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
            {
                ADDRINT addr = RTN_Address(rtn);
                api_map[addr] = RTN_Name(rtn);
            }
        }
    }
}

// Instrument each instruction
VOID Instruction(INS ins, VOID* v)
{
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)log_ins,
        IARG_INST_PTR,
        IARG_END);
}

VOID finished(INT32 code, VOID* v)
{
    logfile << "\nAddress\tcount\tlast_seen\tAPI name if first instruction" << std::endl;

    for (auto& e : ins_counts)
    {
        logfile << std::hex << e.first << '\t' << std::dec << e.second.count << '\t' << e.second.last_seen;
        
        auto& it = api_map.find(e.first);

        if (it != api_map.end())
            logfile << "\t\t" << it->second;

        logfile << std::endl;
    }
 
    logfile << "Finished" << std::endl;
    logfile.close();
}

int main(int argc, char* argv[])
{
    // Init PIN
    PIN_InitSymbols();

    // Parse command line
    if (PIN_Init(argc, argv))
        return -1;

    // Open log file
    logfile.open(log_filename.Value().c_str());

    // Return if unable to open log file
    // No way to record errors up to this point
    if (!logfile)
        return -1;

    // Setup PIN instrumentation callbacks
    INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(imgInstrumentation, 0);
    PIN_AddFiniFunction(finished, 0);

    // Start analysis
    logfile << "Logging to " << log_filename.Value() << "..." << std::endl;
    PIN_StartProgram();

    return 0;
}
