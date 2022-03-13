// LoveHandles
// Author: @mattsteer - matt@shadesecurity.com

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <map>

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define NT_SUCCESS(x) ((x) >= 0)

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass, 
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );

HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

int main() {

    std::wcout << L"[*] LoveHandles\n[*] Author: @mattsteer - matt@shadesecurity.com\n[!] Running...\n\n";

    while (TRUE) {

        HANDLE hProcessSnap, hProcessHandle, dupHandle;
        PROCESSENTRY32 pe32;
        THREADENTRY32 th32;
        std::map<int, std::wstring> mPrivilegedThreads;
        std::map<int, std::wstring> mPrivilegedProcessIds;
        std::map<int, std::wstring> mNonPrivilegedProcessIds;

        _NtQuerySystemInformation NtQuerySystemInformation =
            (_NtQuerySystemInformation)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQuerySystemInformation");
        _NtDuplicateObject NtDuplicateObject =
            (_NtDuplicateObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtDuplicateObject");
        _NtQueryObject NtQueryObject =
            (_NtQueryObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQueryObject");        
        _NtQueryInformationProcess NtQueryInformationProcess =
            (_NtQueryInformationProcess)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQueryInformationProcess");

        // set up to query the system for a list of all the handles present on the system.
        NTSTATUS status;
        PSYSTEM_HANDLE_INFORMATION handleInfo;
        ULONG handleInfoSize = 0x10000;
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

        // Take a snapshot of all processes and threads in the system.
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            return(FALSE);
        }

        // NtQuerySystemInformation won't give us the correct buffer size,
        //   so we guess by doubling the buffer size. 
        while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
        }

        // NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. 
        if (!NT_SUCCESS(status))
        {
            std::wcout << L"[X] NtQuerySystemInformation failed!\n";
            return 1;
        }

        // Set the size of the structure before using it.
        pe32.dwSize = sizeof(PROCESSENTRY32);
        th32.dwSize = sizeof(THREADENTRY32);
        // Retrieve information about the first process,
        // and exit if unsuccessful
        if (!Process32First(hProcessSnap, &pe32))
        {
            std::wcout << L"[X] Error enumerating processes\n";
            CloseHandle(hProcessSnap);
            return(FALSE);
        }
        // Now walk the snapshot of processes, and display information about each process in turn
        do
        {
            // if we can open the process to duplicate the handle then we aren't interested in these threads, add these to non privileged threads map
            if ((hProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pe32.th32ProcessID)))
            {
                std::wstring szExeFile = std::wstring(pe32.szExeFile);
                mNonPrivilegedProcessIds[pe32.th32ProcessID] = szExeFile;
            }
            // if we can't open the process to duplicate the handle then the process is running in another user context and we are interested in these threads, add these to the privileged threads map
            else {
                std::wstring szExeFile = std::wstring(pe32.szExeFile);
                mPrivilegedProcessIds[pe32.th32ProcessID] = szExeFile;
                // Retrieve thread information for the process
                if (!Thread32First(hProcessSnap, &th32))
                {
                    std::wcout << L"[X] Error enumerating threads\n";
                    CloseHandle(hProcessHandle);
                    continue;
                }
                do
                {
                    if (th32.th32OwnerProcessID == pe32.th32ProcessID) {
                        mPrivilegedThreads[(int)th32.th32ThreadID] = szExeFile;
                    }

                } while (Thread32Next(hProcessSnap, &th32));
            }

            CloseHandle(hProcessHandle);

        } while (Process32Next(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);

        // now we have two maps that contain threadid->processname mappings
        // loop through all the handles
        for (int i = 0; i < handleInfo->HandleCount; i++)
        {
            SYSTEM_HANDLE handle = handleInfo->Handles[i];

            // if the object type number is not process (7) or thread (8) we aren't interested
            if (handle.ObjectTypeNumber != 7 && handle.ObjectTypeNumber != 8)
                continue;

            // lookup the process id in the privileged processid map, if its there skip this handle
            if (mPrivilegedProcessIds.find((int)handle.ProcessId) != mPrivilegedProcessIds.end())
                continue;

            // if we can't open the process to duplicate the handle then we can't continue
            if (!(hProcessHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)handle.ProcessId)))
                continue;

            // handle is a process handle
            if (handle.ObjectTypeNumber == 7) {

                if (((handle.GrantedAccess & PROCESS_DUP_HANDLE) != PROCESS_DUP_HANDLE) || ((handle.GrantedAccess & PROCESS_ALL_ACCESS) != PROCESS_ALL_ACCESS) || ((handle.GrantedAccess & PROCESS_CREATE_PROCESS) != PROCESS_CREATE_PROCESS) ||
                    ((handle.GrantedAccess & PROCESS_CREATE_THREAD) != PROCESS_CREATE_THREAD) || ((handle.GrantedAccess & PROCESS_SET_INFORMATION) != PROCESS_SET_INFORMATION) || ((handle.GrantedAccess & PROCESS_VM_WRITE) != PROCESS_VM_WRITE))
                {
                    CloseHandle(hProcessHandle);
                    continue;
                }

                // Duplicate the handle so we can query it. 
                if (!NT_SUCCESS(NtDuplicateObject(hProcessHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, PROCESS_QUERY_INFORMATION, 0, 0))) {
                    CloseHandle(hProcessHandle);
                    continue;
                }

                // Query for the process information
                ULONG_PTR pbi[6]; ULONG ulSize = 0;
                if (!NT_SUCCESS(NtQueryInformationProcess(dupHandle, 0, &pbi, sizeof(pbi), &ulSize))) {
                    CloseHandle(dupHandle);
                    CloseHandle(hProcessHandle);
                    continue;
                }

                // pbi[4] contains the process id associated with the handle. If this is in the Privileged process ids the we are interested.
                if (mPrivilegedProcessIds.find((int)pbi[4]) == mPrivilegedProcessIds.end()) {
                    CloseHandle(dupHandle);
                    CloseHandle(hProcessHandle);
                    continue;
                }


                // If we have gotten this far we have a hit, print out the information
                std::wcout << L"Process " << mNonPrivilegedProcessIds[handle.ProcessId] << L" (" << handle.ProcessId << ") has handle " << handle.Handle << " to process " << mPrivilegedProcessIds[(int)pbi[4]] << L" (" << (DWORD)pbi[4] << ")\n";
                std::wcout << L"Permissions:\n";
                if ((handle.GrantedAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
                    std::wcout << L"\tPROCESS_ALL_ACCESS\n";
                if ((handle.GrantedAccess & PROCESS_CREATE_PROCESS) == PROCESS_CREATE_PROCESS)
                    std::wcout << L"\tPROCESS_CREATE_PROCESS\n";
                if ((handle.GrantedAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
                    std::wcout << L"\tPROCESS_CREATE_THREAD\n";
                if ((handle.GrantedAccess & PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE)
                    std::wcout << L"\tPROCESS_DUP_HANDLE\n";
                if ((handle.GrantedAccess & PROCESS_SET_INFORMATION) == PROCESS_SET_INFORMATION)
                    std::wcout << L"\tPROCESS_SET_INFORMATION\n";
                if ((handle.GrantedAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
                    std::wcout << L"\tPROCESS_VM_WRITE\n";
                if ((handle.GrantedAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
                    std::wcout << L"\tPROCESS_TERMINATE\n";
                std::wcout << L"\n";
                CloseHandle(dupHandle);
                CloseHandle(hProcessHandle);
            }

            if (handle.ObjectTypeNumber == 8) {

                if ((handle.GrantedAccess & THREAD_ALL_ACCESS) != THREAD_ALL_ACCESS || (handle.GrantedAccess & THREAD_DIRECT_IMPERSONATION) != THREAD_DIRECT_IMPERSONATION || (handle.GrantedAccess & THREAD_SET_CONTEXT) != THREAD_SET_CONTEXT) {
                    CloseHandle(hProcessHandle);
                    continue;
                }
                // Duplicate the handle so we can query it. 
                if (!NT_SUCCESS(NtDuplicateObject(hProcessHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, THREAD_QUERY_INFORMATION, 0, 0))) {
                    CloseHandle(hProcessHandle);
                    continue;
                }
                DWORD data = GetThreadId(dupHandle);
                if (data != 0)
                {
                    if (mPrivilegedThreads.find(data) != mPrivilegedThreads.end()) {
                        // If we have gotten this far we have a hit, print out the information
                        std::wcout << L"Process " << mNonPrivilegedProcessIds[handle.ProcessId] << L" (" << handle.ProcessId << ") has handle " << handle.Handle << " to thread " << data << " in process " << mPrivilegedThreads[data] << L"\n";
                        std::wcout << L"Permissions:\n";
                        if ((handle.GrantedAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS)
                            std::wcout << L"\tTHREAD_ALL_ACCESS\n";
                        if ((handle.GrantedAccess & THREAD_DIRECT_IMPERSONATION) == THREAD_DIRECT_IMPERSONATION)
                            std::wcout << L"\tTHREAD_DIRECT_IMPERSONATION\n";
                        if ((handle.GrantedAccess & THREAD_SET_CONTEXT) == THREAD_SET_CONTEXT)
                            std::wcout << L"\tTHREAD_SET_CONTEXT\n";
                        std::wcout << L"\n";
                    }
                }
                CloseHandle(dupHandle);
                CloseHandle(hProcessHandle);
            }
        }
        free(handleInfo);
    }
    return(TRUE);
}

