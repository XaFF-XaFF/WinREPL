#include "repl.h"

#undef min
#undef max
#include <asmtk/asmtk.h>

static void winrepl_fix_rip(winrepl_t *wr)
{
	// fix RIP because of \xcc
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(wr->procInfo.hThread, &ctx);

#ifdef _M_X64
	ctx.Rip = ctx.Rip - 1;
#elif defined(_M_IX86)
	ctx.Eip = ctx.Eip - 1;
#endif
	SetThreadContext(wr->procInfo.hThread, &ctx);
}

BOOL winrepl_write_shellcode(winrepl_t *wr, unsigned char *encode, size_t size)
{
	DWORD dwOldProtect = 0;
	SIZE_T nBytes;
	CONTEXT ctx = { 0 };

	winrepl_print_assembly(encode, size);

	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(wr->procInfo.hThread, &ctx))
		return FALSE;


#ifdef _M_X64
	LPVOID addr = (LPVOID)ctx.Rip;
#elif defined(_M_IX86)
	LPVOID addr = (LPVOID)ctx.Eip;
#endif

	if (!VirtualProtectEx(wr->procInfo.hProcess, (LPVOID)addr, size + 1, PAGE_READWRITE, &dwOldProtect))
		return FALSE;

	if (!WriteProcessMemory(wr->procInfo.hProcess, (LPVOID)addr, (LPCVOID)encode, size, &nBytes))
		return FALSE;

	if (!WriteProcessMemory(wr->procInfo.hProcess, (LPVOID)((LPBYTE)addr + size), (LPCVOID)"\xcc", 1, &nBytes))
		return FALSE;

	if (!VirtualProtectEx(wr->procInfo.hProcess, (LPVOID)addr, size + 1, dwOldProtect, &dwOldProtect))
		return FALSE;

	FlushInstructionCache(wr->procInfo.hProcess, (LPCVOID)addr, size + 1);

	return TRUE;
}

void winrepl_debug_shellcode(winrepl_t *wr)
{
	BOOL go = TRUE;
	while (go)
	{
		ContinueDebugEvent(wr->procInfo.dwProcessId, wr->procInfo.dwThreadId, DBG_CONTINUE);

		DEBUG_EVENT dbg = { 0 };
		if (!WaitForDebugEvent(&dbg, INFINITE))
			break;

		if (dbg.dwThreadId != wr->procInfo.dwThreadId)
		{
			ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);
			continue;
		}

		if (dbg.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && dbg.dwThreadId == wr->procInfo.dwThreadId)
		{
			go = FALSE;

			switch (dbg.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_ACCESS_VIOLATION:
				break;

			case EXCEPTION_PRIV_INSTRUCTION:
				break;

			case EXCEPTION_BREAKPOINT:
				break;
			default:
				break;
			}
		}

		if (dbg.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
		{
			if (dbg.u.LoadDll.hFile)
				CloseHandle(dbg.u.LoadDll.hFile);
		}
	}

	winrepl_fix_rip(wr);

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(wr->procInfo.hThread, &ctx);

	memcpy(&wr->prev, &wr->curr, sizeof(CONTEXT));
	memcpy(&wr->curr, &ctx, sizeof(CONTEXT));

	winrepl_print_registers(wr);
}

static BOOL winrepl_assemble(const char *instruction, std::vector<unsigned char> &data, size_t address)
{
	using namespace asmjit;
	using namespace asmtk;

#ifdef _M_X64
	ArchInfo::Type arch = ArchInfo::kTypeX64;
#elif defined(_M_IX86)
	ArchInfo::Type arch = ArchInfo::kTypeX86;
#endif

	// Setup CodeInfo
	CodeInfo codeinfo(arch, 0, address);

	// Setup CodeHolder
	CodeHolder code;
	Error err = code.init(codeinfo);
	if (err != kErrorOk)
	{
		printf("ERROR: %s\n", DebugUtils::errorAsString(err));
		return FALSE;
	}

	// Attach an assembler to the CodeHolder.
	X86Assembler a(&code);

	// Create AsmParser that will emit to X86Assembler.
	AsmParser p(&a);

	// Parse some assembly.
	err = p.parse(instruction);

	// Error handling
	if (err != kErrorOk)
	{
		printf("ERROR: %s (instruction: \"%s\")\n", DebugUtils::errorAsString(err), instruction);
		return FALSE;
	}

	// Check for unresolved relocations
	if (code._relocations.getLength())
	{
		puts("ERROR: asmjit, unresolved relocation(s)");
		return FALSE;
	}

	// If we are done, you must detach the Assembler from CodeHolder or sync
	// it, so its internal state and position is synced with CodeHolder.
	code.sync();

	// Now you can print the code, which is stored in the first section (.text).
	CodeBuffer &buffer = code.getSectionEntry(0)->getBuffer();
	for(size_t i = 0; i < buffer.getLength(); i++)
		data.push_back(buffer.getData()[i]);

	return TRUE;
}


static BOOL winrepl_run_shellcode(winrepl_t *wr, std::string assembly)
{
	std::vector<std::string> instructions = split(assembly, ";");
	std::vector<unsigned char> data;

#ifdef _M_X64
	size_t addr = wr->curr.Rip;
#elif defined(_M_IX86)
	size_t addr = wr->curr.Eip;
#endif

	for(std::string &instruction : instructions)
	{
		if (!winrepl_assemble(instruction.c_str(), data, addr + data.size()))
			return TRUE;
	}

	if (!winrepl_write_shellcode(wr, data.data(), data.size()))
		return FALSE;

	winrepl_debug_shellcode(wr);

	return TRUE;
}

BOOL winrepl_eval(winrepl_t *wr, std::string command)
{
	try
	{
		if (command.at(0) == '.')
			return winrepl_run_command(wr, command);

		return winrepl_run_shellcode(wr, command);
	}
	catch (...)
	{
		winrepl_print_error("An unhandled C++ exception occurred.");
	}

	return TRUE;
}