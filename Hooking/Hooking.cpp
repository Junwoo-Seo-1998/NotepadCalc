#include "exprtk.hpp"
#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <tlhelp32.h>


LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
    // Find Addr of WriteFile() 
    g_pfWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");

    // API Hook - WriteFile()
    // change 1st byte to 0xCC (INT 3)  
    // original byte is for backup (to unhook api)
    memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));

    std::cout << "WriteFile() Addr: " << std::hex << g_pfWriteFile << std::endl;

    ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
        &g_chOrgByte, sizeof(BYTE), NULL);
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
        &g_chINT3, sizeof(BYTE), NULL);

    return TRUE;
}

BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
    CONTEXT ctx = { 0, };
    DWORD64 dwNumOfBytesToWrite, dwAddrOfBuffer;
    PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

    // BreakPoint exception (INT 3)
    if (EXCEPTION_BREAKPOINT == per->ExceptionCode)
    {
        // if BP addr is WriteFile()
        if (g_pfWriteFile == per->ExceptionAddress)
        {
            // Unhook
            // 0xCC part to be original byte
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                &g_chOrgByte, sizeof(BYTE), NULL);

            // #2. Thread Context 구하기
            ctx.ContextFlags = CONTEXT_FULL;

            HANDLE threadH = OpenThread(THREAD_ALL_ACCESS, TRUE, pde->dwThreadId);
            GetThreadContext(threadH, &ctx);

            dwAddrOfBuffer = ctx.Rdx;
            dwNumOfBytesToWrite = ctx.R8;

            std::vector<char> str;
            str.resize(dwNumOfBytesToWrite + 1);


            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
                &str[0], dwNumOfBytesToWrite, NULL);

            //std::cout << "Input:" << str.data() << std::endl;
            //math area
            {
                typedef exprtk::symbol_table<long double> symbol_table_t;
                typedef exprtk::expression<long double>   expression_t;
                typedef exprtk::parser<long double>       parser_t;

                const std::string expression_string = str.data();

                symbol_table_t symbol_table;
                symbol_table.add_constants();

                expression_t expression;
                expression.register_symbol_table(symbol_table);

                parser_t parser;
                if (parser.compile(expression_string, expression) == false)
                {
                    std::cout << "\nSkipping (maybe windows's writing or invalid math expression) ..." << std::endl;
                }
                else
                {
                    const long double result = expression.value();
                    std::string message;
                    message += str.data();
                    message += " = ";
                    message += std::to_string(result);

                    std::cout << "\n### Result ###" << std::endl;
                    std::cout << message << std::endl;

                    std::cout << "\nAdditional info" << std::endl;
                    std::cout << "AddrOfBuffer: " << dwAddrOfBuffer << std::endl;
                    std::cout << "NumOfBytesToWrite: " << dwNumOfBytesToWrite << std::endl;
                    std::cout << "PID:" << pde->dwProcessId << std::endl;
                    std::cout << "ThreadID:" << pde->dwThreadId << std::endl;

                    MessageBoxA(0, message.c_str(), "Result", MB_OK | MB_SETFOREGROUND);
                }
            }
	            
        	// Set Thread Context RIP to be WriteFile()
        	// (current RIP is  WriteFile() + 1
            ctx.Rip = (DWORD64)g_pfWriteFile;
            SetThreadContext(threadH, &ctx);
            // Process Debuggee
            ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
            Sleep(0);

        	// API Hook
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
                &g_chINT3, sizeof(BYTE), NULL);

            return TRUE;
        }
    }

    ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
    return FALSE;
}

void DebugLoop()
{
    DEBUG_EVENT de;
    DWORD dwContinueStatus;

    while (WaitForDebugEvent(&de, INFINITE))
    {
        dwContinueStatus = DBG_CONTINUE;

        if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
        {
            OnCreateProcessDebugEvent(&de);
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
        }
        else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)
        {
            if (OnExceptionDebugEvent(&de))
                continue;
        }
        // if debuggee is terminated then debugger will be terminated
        else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
        {
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
            break;
        }
        else
        {
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
        }
    }
}

DWORD FindChildProcessByName(DWORD parentPID, const std::wstring& processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(snapshot, &entry) == TRUE) {
        do {
            if (entry.th32ParentProcessID == parentPID && _wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry) == TRUE);
    }

    CloseHandle(snapshot);
    return 0; // No matching child process found
}

int FindProcessByName(const std::wstring& processName) {

    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;

    // snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    // initializing size: needed for using Process32First
    pe.dwSize = sizeof(PROCESSENTRY32);

    // info about first process encountered in a system snapshot
    hResult = Process32First(hSnapshot, &pe);

    // retrieve information about the processes
    // and exit if unsuccessful
    while (hResult) {
        // if we find the process: return process ID
        if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }

    // closes an open handle (CreateToolhelp32Snapshot)
    CloseHandle(hSnapshot);
    return pid;
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IONBF, 0);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Path to the Notepad executable
    LPCTSTR applicationName = _T("C:\\Windows\\System32\\notepad.exe");

    //wait for notpepad launch
    DWORD notepad = FindProcessByName(_T("notepad.exe"));

    if(notepad==0)
    {
        std::cout << "There is no running Notepad Try to run new ... " << std::endl;

        // Start the Notepad process
        if (!CreateProcess(applicationName,   // Application name
            NULL,              // Command line
            NULL,              // Process handle not inheritable
            NULL,              // Thread handle not inheritable
            FALSE,             // Set handle inheritance to FALSE
            0,                 // No creation flags
            NULL,              // Use parent's environment block
            NULL,              // Use parent's starting directory 
            &si,               // Pointer to STARTUPINFO structure
            &pi)               // Pointer to PROCESS_INFORMATION structure
            ) {
            // If CreateProcess fails, print the error
            _tprintf(TEXT("CreateProcess failed (%d).\n"), GetLastError());
            return 0;
        }

        std::cout << "Waiting for notepad ... " << std::endl;
        Sleep(1000);
        while (true)
        {
            notepad = FindChildProcessByName(pi.dwProcessId, _T("notepad.exe"));
            if (notepad!=0)
                break;
        	Sleep(0);
        }

        // Close process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    std::cout << "Found PID:" << notepad << std::endl;
    // Attach Process
    if (!DebugActiveProcess(notepad))
    {
        std::cout << "Close all notepads and try to run again" << std::endl;
        printf("DebugActiveProcess(%d) failed!!!\n"
            "Error Code = %d\n", notepad, GetLastError());
        return 1;
    }

    DebugLoop();

    return 0;
}
