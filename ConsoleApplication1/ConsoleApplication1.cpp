//

#include <iostream>

#include <windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include "psapi.h"
#include <processthreadsapi.h>
#include <stdlib.h>
#include <time.h>
#include <timezoneapi.h>
#include <intrin.h>



typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;
typedef struct {
    int PID;
    PPROCESSENTRY32* ppe32;
    PTEB pTEB;

    //PCHAR Name;
    //PCHAR ParrentName;
    //int MemoryUsage;    
    ////threads info
    //int NumberOfThreads;





} Process;
 void GetToken()
{
     // printf("I'm in");
     HANDLE hToken;
     LUID luid;
     TOKEN_PRIVILEGES tkp;

     OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

     LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

     tkp.PrivilegeCount = 1;
     tkp.Privileges[0].Luid = luid;
     tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

     AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

     CloseHandle(hToken);
}


typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    IN	HANDLE              ProcessHandle,
    IN	PROCESSINFOCLASS    ProcessInformationClass,
    OUT	PVOID               ProcessInformation,
    IN	ULONG               ProcessInformationLength,
    OUT PULONG              ReturnLength OPTIONAL
    ); _NtQueryInformationProcess NtQueryInfoProcess;

typedef NTSTATUS(NTAPI* _NtQueryInformationThread)(
    IN	HANDLE              ThreadHandle,
    IN	THREADINFOCLASS    ThreadInformationClass,
    OUT	PVOID               ThreadInformation,
    IN	ULONG               ThreadInformationLength,
    OUT PULONG              ReturnLength
    ); _NtQueryInformationThread NtQueryInfoThread;
HANDLE GetHandle(int PID) {

    //PROCESS_QUERY_INFORMATION
    //PROCESS_QUERY_LIMITED_INFORMATION
    HANDLE h;
    h = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ, FALSE, PID);
    if (h == NULL) {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
        if (h == NULL) {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, PID);


        }

    }

    return h;
}


PVOID FindPebByHandle(HANDLE CHANDLE) {
    PROCESS_BASIC_INFORMATION pbi;

    if (_NtQueryInformationProcess NtQueryInfoProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess")) {
        NTSTATUS status = NtQueryInfoProcess(CHANDLE, (ProcessBasicInformation), &pbi, sizeof(pbi), 0);


        if (ReadProcessMemory(CHANDLE, 0, &pbi, sizeof(pbi), NULL)) {
            return pbi.PebBaseAddress;
        }
    }
    return pbi.PebBaseAddress;
}

typedef struct CPEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} CPEB, * PCPEB;


void WalkOnProcess() {
    
    HANDLE hProcessSnap;
    HANDLE hModuleSnap;
    PROCESSENTRY32 pe32;
    THREADENTRY32 le32;
    MODULEENTRY32 me32;
    PVOID pebAddress;
    PVOID rtlUserProcParamsAddress;
    UNICODE_STRING commandLine;
    WCHAR* commandLineContents;
    int OneProcess = 0;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
    le32.dwSize = sizeof(THREADENTRY32);
    me32.dwSize = sizeof(MODULEENTRY32);

    printf("PID\t\tNAME\t\t\t\tTHREADS\t\tMEMORY USAGE\tPEB VALUE\tCPU TIME\n");

    int i = 0;
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            printf("%d\t\t", pe32.th32ProcessID);
            i = 0;

            //printf("Name: %s\n", pe32.szExeFile);


            // printf("%c", pe32.szExeFile[0]);
            printf("%c", pe32.szExeFile[i]);
            while (pe32.szExeFile[i++] != '\0') {
                printf("%c", pe32.szExeFile[i]);
            }
            // printf("\t\t");
            for (int j = i; j < 32; j++) {
                printf(" ");
            }

            printf("%d \t\t", pe32.cntThreads);

            // printf("ParrentProcess: %s \t", pe32.th32ParentProcessID);


             //RAM ETC HORS STRUC PE32
            HANDLE CHANDLE = GetHandle(pe32.th32ProcessID);



            /* typedef struct _PROCESS_MEMORY_COUNTERS {
                 DWORD  cb;
                 DWORD  PageFaultCount;
                 SIZE_T PeakWorkingSetSize;
                 SIZE_T WorkingSetSize;
                 SIZE_T QuotaPeakPagedPoolUsage;
                 SIZE_T QuotaPagedPoolUsage;
                 SIZE_T QuotaPeakNonPagedPoolUsage;
                 SIZE_T QuotaNonPagedPoolUsage;
                 SIZE_T PagefileUsage;
                 SIZE_T PeakPagefileUsage;
             } PROCESS_MEMORY_COUNTERS;*/

            PROCESS_MEMORY_COUNTERS memCounter;
            BOOL result = GetProcessMemoryInfo(CHANDLE, &memCounter, sizeof(memCounter));

            if ((double)memCounter.WorkingSetSize / 1024.0 / 1024.0 < 1000.0) {
                printf("%f Mb", (double)memCounter.WorkingSetSize / 1024.0 / 1024.0);
            }
            else if (memCounter.WorkingSetSize / 1024 / 1024 / 1024 < 10.0) {
                printf("%f Gb", (double)memCounter.WorkingSetSize / 1024.0 / 1024.0 / 1024.0 / 1024.0);
            }
            else {
                printf("Cannot read :)");
            }

            printf("\t");

            PROCESS_BASIC_INFORMATION       pbi;

            BYTE                            offset;

            PWCHAR                          cmd;

            UNICODE_STRING                          LEN;

            UNICODE_STRING                   UNICODE_STR;

            PRTL_USER_PROCESS_PARAMETERS    test;

            PWSTR                           Lbuff;


            NtQueryInfoProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
            NTSTATUS status = NtQueryInfoProcess(CHANDLE, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
            if (ReadProcessMemory(CHANDLE, &pbi.PebBaseAddress->BeingDebugged, &offset, sizeof(offset), NULL)) {
                if (ReadProcessMemory(CHANDLE, &pbi.PebBaseAddress->ProcessParameters, &test, sizeof(PRTL_USER_PROCESS_PARAMETERS), NULL)) {
                    //  getchar();
                    if (ReadProcessMemory(CHANDLE, &test->CommandLine, &UNICODE_STR, sizeof(UNICODE_STRING), NULL)) {



                        printf(":: %hu\t", UNICODE_STR.Length);

                        if (ReadProcessMemory(CHANDLE, &UNICODE_STR.Buffer, &Lbuff, sizeof(PWSTR), NULL)) {
                            int p = 0;
                      //      printf("%c", Lbuff[0]);
                            while (Lbuff[p++] != '\0') {
                    //            printf("%c", Lbuff[p]);
                              //  p++;
                            }
                           // getchar();

                            

                        }

                    }

                }
            }

            //       ReadProcessMemory(CHANDLE, &pbi.PebBaseAddress->Be, &offset, sizeof(offset), NULL)
                 //  printf("ReadProcessMeory failed to read ProcessParameters offset for pid %i, Error:%i\n", pe32.th32ProcessID, GetLastError());
            if (offset == 1) {
                printf("DEBUGGED \t");

                goto LabelIsFun;
            }

       
    
          //  printf("Value in offset PEB flag is: %i\t\t", offset);
            printf("\t\t");
            LabelIsFun:
          
            
        

            if (OneProcess == 1) {
                me32.dwSize = sizeof(MODULEENTRY32);
                hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, pe32.th32ProcessID);
                if (Module32First(hModuleSnap, &me32)) {
                    do {
                        // HANDLE CTHANDLE = OpenThread(THREAD_ALL_ACCESS, FALSE, le32.th32ThreadID);

                       // printf("ME32 = %s", me32.szModule);
              /*          printf("%c", me32.szExePath[0]);
                        int w = 0;
                        while (me32.szExePath[w++] != '\0') {
                           printf("%c", me32.szExePath[w]);   //pasbo
                        }
                        printf("\n\t\t");*/

                        printf("%c", me32.szModule[0]);
                        int   w = 0;
                        while (me32.szModule[w++] != '\0') {
                            printf("%c", me32.szModule[w]);
                        }

                        printf("---");

                    } while (Module32Next(hModuleSnap, &me32));
                }
                printf("\n\t\t");
            }








   /*         pebAddress = FindPebByHandle(CHANDLE);

            printf("0x%p\t", pebAddress);

            printf("debug: %d\t", &pebAddress+0x2);

           if (ReadProcessMemory(CHANDLE, &(((_PEB*)pebAddress)->ProcessParameters), &rtlUserProcParamsAddress, sizeof(PVOID), NULL)) {
                if (ReadProcessMemory(CHANDLE, &(((_RTL_USER_PROCESS_PARAMETERS*)rtlUserProcParamsAddress)->CommandLine), &commandLine, sizeof(commandLine), NULL)) {
                    commandLineContents = (WCHAR*)malloc(commandLine.Length);
                    if (ReadProcessMemory(CHANDLE, commandLine.Buffer,
                        commandLineContents, commandLine.Length, NULL))
                    {
                        getchar();
                        commandLineContents = (WCHAR*)malloc(commandLine.Length);
                        printf("%.*S\n", commandLine.Length / 2, commandLineContents);
                        free(commandLineContents);
                    }
                }
            }*/
                    
                    



          

          //  NtQueryInfoProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

          // 
          //  CPEB *PEBcpy = (CPEB*)malloc(sizeof(CPEB));

          //  for (int i = 0; i < sizeof(PEB); i++) {
          //      NTSTATUS status = NtQueryInfoProcess(CHANDLE, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
          //      if (!ReadProcessMemory(CHANDLE, (PVOID)((uint64_t)pbi.PebBaseAddress + i), &offset, sizeof(offset), NULL)) {
          //         // printf("ReadProcessMeory failed to read ProcessParameters offset for pid %i, Error:%i\n", pe32.th32ProcessID, GetLastError());
          //      }
          //      else {
          //          printf("Value in offset PEB flag is: %i\t", offset);
          //        //  PEBcpy = (CPEB*)pbi.PebBaseAddress + i;
          //        //  printf("%i \t", PEBcpy->BeingDebugged);
          //      }

          //  }

          ////  if (PEBcpy->BeingDebugged == 0 || PEBcpy->BeingDebugged == 1) {
          //    //  printf("BeingDebug: %d", PEBcpy->BeingDebugged);
          ////  }
          //  

            FILETIME ftCreation,ftExit,ftKernel,ftUser;
            LPSYSTEMTIME lpSystemTime = (LPSYSTEMTIME)malloc(sizeof(SYSTEMTIME));
            LPSYSTEMTIME lpCurrentTime = (LPSYSTEMTIME)malloc(sizeof(SYSTEMTIME));

            GetSystemTime(lpCurrentTime);

            if(GetProcessTimes(CHANDLE, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
                if(FileTimeToSystemTime(&ftCreation, lpSystemTime)) {

                    char ret = 0;
                    int values[3];

                    for(int i = 0; i < 3; i++) {
                        size_t s = (6-i); // 6 : index of wSeconds
                        values[i] = *((WORD *)lpCurrentTime + s) - *((WORD *)lpSystemTime + s) - ret;

                        ret = values[i] < 0;
                        if (ret) values[i] = -values[i];
                    }

                    for(int i = 2; i >= 0; i--) {
                        if (values[i] < 10) printf("0");
                        printf("%ld%c", values[i], i > 0?':':'\t');
                    }
                }
            }     

            // if(GetProcessInformation(CHANDLE,))
            // printf("%s",  GetCommandLineW());




      
           // sprintf_s(procID, "%d", entry.th32ProcessID);




            //  printf("MEM: %d \t", CHANDLE);


             // NtQueryInformationProcess(CHANDLE, ProcessBasicInformation,)

          //  CreateRemoteThread(CHANDLE, )

           // cProcInfo i_Proc;
            le32.dwSize = sizeof(THREADENTRY32);
            DWORD aa;
            HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pe32.th32ProcessID);

            if (Thread32First(hThreadSnap, &le32)) {
                do {
                    HANDLE CTHANDLE = OpenThread(THREAD_ALL_ACCESS, FALSE, le32.th32ThreadID);


                    if (le32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(le32.th32OwnerProcessID)) {
                        // printf("0x%04x-", le32.th32ThreadID);
                    }

                    NT_TIB tib = { 0 };
                    THREAD_BASIC_INFORMATION tbi = { 0 };
                    ULONG BaseAddr;
                    int ThreadQuerySetWin32StartAddress;


                    if (NtQueryInfoThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread")) {
                        if (NtQueryInfoThread(CTHANDLE, (THREADINFOCLASS)0x00, &tib, sizeof(THREAD_BASIC_INFORMATION), NULL)) {
                            if (ReadProcessMemory(CTHANDLE, tbi.TebBaseAddress, &tib, sizeof(NT_TIB), NULL)) {
                                printf("yes"); getchar();
                            }
                        }
                    }
                   

                    /*thanks https://geoffchappell.com/studies/windows/km/ntoskrnl/api/ps/psquery/class.htm */

                    /*if (!ReadProcessMemory(CTHANDLE, (PVOID)((uint64_t)tbi.TebBaseAddress), &BaseAddr, sizeof(BaseAddr), NULL)) {
                         printf("ReadProcessMeory failed to read ProcessParameters offset for pid %i, Error:%i\n", pe32.th32ProcessID, GetLastError());
                    }*/

                    

                    /*   if (GetExitCodeThread(CTHANDLE, &aa)) {
                           printf(" EXIT CODE: %s\t", aa);
                       }*/
                       //else printf("%d",GetLastError());


                    le32.dwSize = sizeof(THREADENTRY32);
                } while (Thread32Next(hThreadSnap, &le32));
            }


            printf("\n");
            //  free(PEBcpy);

            CloseHandle(CHANDLE);

        } while (Process32Next(hProcessSnap, &pe32));
    }
}

int main(int argc, char* argv[]) {

    GetToken();

    WalkOnProcess();

    return 0;
}
/*struct PEB64
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;                                 //0x000
            BYTE ReadImageFileExecOptions;                              //0x001
            BYTE BeingDebugged;                                         //0x002
            BYTE _SYSTEM_DEPENDENT_01;                                  //0x003
        } flags;
        QWORD dummyalign;
    } dword0;
    QWORD                           Mutant;                             //0x0008
    QWORD                           ImageBaseAddress;                   //0x0010
    PTR64                           Ldr;                                //0x0018
    PTR64                           ProcessParameters;                  //0x0020 / pointer to RTL_USER_PROCESS_PARAMETERS64
    QWORD                           SubSystemData;                      //0x0028
    QWORD                           ProcessHeap;                        //0x0030
    QWORD                           FastPebLock;                        //0x0038
    QWORD                           _SYSTEM_DEPENDENT_02;               //0x0040
    QWORD                           _SYSTEM_DEPENDENT_03;               //0x0048
    QWORD                           _SYSTEM_DEPENDENT_04;               //0x0050
    union
    {
        QWORD                       KernelCallbackTable;                //0x0058
        QWORD                       UserSharedInfoPtr;                  //0x0058
    };
    DWORD                           SystemReserved;                     //0x0060
    DWORD                           _SYSTEM_DEPENDENT_05;               //0x0064
    QWORD                           _SYSTEM_DEPENDENT_06;               //0x0068
    QWORD                           TlsExpansionCounter;                //0x0070
    QWORD                           TlsBitmap;                          //0x0078
    DWORD                           TlsBitmapBits[2];                   //0x0080
    QWORD                           ReadOnlySharedMemoryBase;           //0x0088
    QWORD                           _SYSTEM_DEPENDENT_07;               //0x0090
    QWORD                           ReadOnlyStaticServerData;           //0x0098
    QWORD                           AnsiCodePageData;                   //0x00A0
    QWORD                           OemCodePageData;                    //0x00A8
    QWORD                           UnicodeCaseTableData;               //0x00B0
    DWORD                           NumberOfProcessors;                 //0x00B8
    union
    {
        DWORD                       NtGlobalFlag;                       //0x00BC
        DWORD                       dummy02;                            //0x00BC
    };
    LARGE_INTEGER                   CriticalSectionTimeout;             //0x00C0
    QWORD                           HeapSegmentReserve;                 //0x00C8
    QWORD                           HeapSegmentCommit;                  //0x00D0
    QWORD                           HeapDeCommitTotalFreeThreshold;     //0x00D8
    QWORD                           HeapDeCommitFreeBlockThreshold;     //0x00E0
    DWORD                           NumberOfHeaps;                      //0x00E8
    DWORD                           MaximumNumberOfHeaps;               //0x00EC
    QWORD                           ProcessHeaps;                       //0x00F0
    QWORD                           GdiSharedHandleTable;               //0x00F8
    QWORD                           ProcessStarterHelper;               //0x0100
    QWORD                           GdiDCAttributeList;                 //0x0108
    QWORD                           LoaderLock;                         //0x0110
    DWORD                           OSMajorVersion;                     //0x0118
    DWORD                           OSMinorVersion;                     //0x011C
    WORD                            OSBuildNumber;                      //0x0120
    WORD                            OSCSDVersion;                       //0x0122
    DWORD                           OSPlatformId;                       //0x0124
    DWORD                           ImageSubsystem;                     //0x0128
    DWORD                           ImageSubsystemMajorVersion;         //0x012C
    QWORD                           ImageSubsystemMinorVersion;         //0x0130
    union
    {
        QWORD                       ImageProcessAffinityMask;           //0x0138
        QWORD                       ActiveProcessAffinityMask;          //0x0138
    };
    QWORD                           GdiHandleBuffer[30];                //0x0140
    QWORD                           PostProcessInitRoutine;             //0x0230
    QWORD                           TlsExpansionBitmap;                 //0x0238
    DWORD                           TlsExpansionBitmapBits[32];         //0x0240
    QWORD                           SessionId;                          //0x02C0
    ULARGE_INTEGER                  AppCompatFlags;                     //0x02C8
    ULARGE_INTEGER                  AppCompatFlagsUser;                 //0x02D0
    QWORD                           pShimData;                          //0x02D8
    QWORD                           AppCompatInfo;                      //0x02E0
    UNICODE_STRING64                CSDVersion;                         //0x02E8
    QWORD                           ActivationContextData;              //0x02F8
    QWORD                           ProcessAssemblyStorageMap;          //0x0300
    QWORD                           SystemDefaultActivationContextData; //0x0308
    QWORD                           SystemAssemblyStorageMap;           //0x0310
    QWORD                           MinimumStackCommit;                 //0x0318

}; //struct PEB64*/