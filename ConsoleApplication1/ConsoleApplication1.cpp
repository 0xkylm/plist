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
#include <winnt.h>

/*************************WMI for fun and profite*******************************************/
#define _WIN32_DCOM
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

/************https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer\*********/

//typedef struct CUS_CONTEXT {
//    DWORD64 P1Home;
//    DWORD64 P2Home;
//    DWORD64 P3Home;
//    DWORD64 P4Home;
//    DWORD64 P5Home;
//    DWORD64 P6Home;
//    DWORD   ContextFlags;
//    DWORD   MxCsr;
//    WORD    SegCs;
//    WORD    SegDs;
//    WORD    SegEs;
//    WORD    SegFs;
//    WORD    SegGs;
//    WORD    SegSs;
//    DWORD   EFlags;
//    DWORD64 Dr0;
//    DWORD64 Dr1;
//    DWORD64 Dr2;
//    DWORD64 Dr3;
//    DWORD64 Dr6;
//    DWORD64 Dr7;
//    DWORD64 Rax;
//    DWORD64 Rcx;
//    DWORD64 Rdx;
//    DWORD64 Rbx;
//    DWORD64 Rsp;
//    DWORD64 Rbp;
//    DWORD64 Rsi;
//    DWORD64 Rdi;
//    DWORD64 R8;
//    DWORD64 R9;
//    DWORD64 R10;
//    DWORD64 R11;
//    DWORD64 R12;
//    DWORD64 R13;
//    DWORD64 R14;
//    DWORD64 R15;
//    DWORD64 Rip;
//    union {
//        XMM_SAVE_AREA32 FltSave;
//        DWORD64         Q[16];
//        ULONGLONG       D[32];
//        struct {
//            M128A Header[2];
//            M128A Legacy[8];
//            M128A Xmm0;
//            M128A Xmm1;
//            M128A Xmm2;
//            M128A Xmm3;
//            M128A Xmm4;
//            M128A Xmm5;
//            M128A Xmm6;
//            M128A Xmm7;
//            M128A Xmm8;
//            M128A Xmm9;
//            M128A Xmm10;
//            M128A Xmm11;
//            M128A Xmm12;
//            M128A Xmm13;
//            M128A Xmm14;
//            M128A Xmm15;
//        } DUMMYSTRUCTNAME;
//        DWORD           S[32];
//    } DUMMYUNIONNAME;
//    M128A   VectorRegister[26];
//    DWORD64 VectorControl;
//    DWORD64 DebugControl;
//    DWORD64 LastBranchToRip;
//    DWORD64 LastBranchFromRip;
//    DWORD64 LastExceptionToRip;
//    DWORD64 LastExceptionFromRip;
//} CUS_CONTEXT, * PCUS_CONTEXT;

//typedef struct _SYSTEM_PROCESS_INFORMATION {
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    BYTE Reserved1[48];
//    UNICODE_STRING ImageName;
//    KPRIORITY BasePriority;
//    HANDLE UniqueProcessId;
//    PVOID Reserved2;
//    ULONG HandleCount;
//    ULONG SessionId;
//    PVOID Reserved3;
//    SIZE_T PeakVirtualSize;
//    SIZE_T VirtualSize;
//    ULONG Reserved4;
//    SIZE_T PeakWorkingSetSize;
//    SIZE_T WorkingSetSize;
//    PVOID Reserved5;
//    SIZE_T QuotaPagedPoolUsage;
//    PVOID Reserved6;
//    SIZE_T QuotaNonPagedPoolUsage;
//    SIZE_T PagefileUsage;
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//    LARGE_INTEGER Reserved7[6];
//} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


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
// void GetToken()
//{
//     // printf("I'm in");
//     HANDLE hToken;
//     LUID luid;
//     TOKEN_PRIVILEGES tkp;
//
//     OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
//
//     LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
//
//     tkp.PrivilegeCount = 1;
//     tkp.Privileges[0].Luid = luid;
//     tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//
//     AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
//
//     CloseHandle(hToken);
//}


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

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    IN      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT     PVOID                    SystemInformation,
    IN      ULONG                    SystemInformationLength,
    OUT     PULONG                   ReturnLength OPTIONAL
    ); _NtQuerySystemInformation NtQueryySystemInfo;






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

//typedef struct CPEB {
//    BYTE                          Reserved1[2];
//    BYTE                          BeingDebugged;
//    BYTE                          Reserved2[1];
//    PVOID                         Reserved3[2];
//    PPEB_LDR_DATA                 Ldr;
//    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
//    PVOID                         Reserved4[3];
//    PVOID                         AtlThunkSListPtr;
//    PVOID                         Reserved5;
//    ULONG                         Reserved6;
//    PVOID                         Reserved7;
//    ULONG                         Reserved8;
//    ULONG                         AtlThunkSListPtr32;
//    PVOID                         Reserved9[45];
//    BYTE                          Reserved10[96];
//    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
//    BYTE                          Reserved11[128];
//    PVOID                         Reserved12[1];
//    ULONG                         SessionId;
//} CPEB, * PCPEB;
//





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


    PROCESS_BASIC_INFORMATION       pbi;

    BYTE                            offset;

    PWCHAR                          cmd;

    UNICODE_STRING                   LEN;

    UNICODE_STRING                   UNICODE_STR;

    PRTL_USER_PROCESS_PARAMETERS    test;

    PWSTR                           Lbuff;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
    le32.dwSize = sizeof(THREADENTRY32);
    me32.dwSize = sizeof(MODULEENTRY32);

    printf("PID\t\tNAME\t\t\t\tTHREADS\t\tMEMORY USAGE\tPEB VALUE\tELAPSED TIME\n");

    int i = 0;
    if (Process32First(hProcessSnap, &pe32)) {
        do {

            /***********************************PID + NAME*******************************************************/
            printf("%d\t\n", pe32.th32ProcessID);
            i = 0;;
            printf("%c", pe32.szExeFile[i]);
            while (pe32.szExeFile[i++] != '\0') {
                printf("%c", pe32.szExeFile[i]);
            }
            for (int j = i; j < 32; j++) {
                printf(" ");
            }

            printf("%d \t\t", pe32.cntThreads);

            HANDLE CHANDLE = GetHandle(pe32.th32ProcessID);

            /**************************************Memory Usage***************************************************/

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

            //    pbi = { 0 };


            NtQueryInfoProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
            NTSTATUS status = NtQueryInfoProcess(CHANDLE, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
            /***************************************ARE DEBUGGED ?*********************************************************************************/

            if (ReadProcessMemory(CHANDLE, &pbi.PebBaseAddress->BeingDebugged, &offset, sizeof(offset), NULL)) {
                /****************************************Process Name + argument**************************************/


                PPEB ppeb = (PPEB)((PVOID*)&pbi)[1];
                PPEB ppebCopy = (PPEB)malloc(sizeof(PEB));
                if (ReadProcessMemory(CHANDLE, ppeb, ppebCopy, sizeof(PEB), NULL)) {
                    PRTL_USER_PROCESS_PARAMETERS pRtlProcParam = ppebCopy->ProcessParameters;
                    PRTL_USER_PROCESS_PARAMETERS pRtlProcParamCopy = (PRTL_USER_PROCESS_PARAMETERS)malloc(sizeof(RTL_USER_PROCESS_PARAMETERS));
                    if (ReadProcessMemory(CHANDLE, pRtlProcParam, pRtlProcParamCopy, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
                        PWSTR wBuffer = pRtlProcParamCopy->CommandLine.Buffer;
                        USHORT len = pRtlProcParamCopy->CommandLine.Length;
                        PWSTR wBufferCopy = (PWSTR)malloc(len);
                        if (ReadProcessMemory(CHANDLE, wBuffer, wBufferCopy, len, NULL)) {
                            printf("%ls\t", wBufferCopy);
                        }
                    }
                }
                  /*thanks https://geoffchappell.com/studies/windows/km/ntoskrnl/api/ps/psquery/class.htm */

            }
            if (offset == 1) {
                printf("DEBUGGED \t");

                goto LabelIsFun; //    :)
            }
            printf("\t\t");
        LabelIsFun:


            /***********************************************LOADDED DLL / MODULE same?*******************************************************************/
              //  OneProcess = 1;
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

                        printf("\n");

                    } while (Module32Next(hModuleSnap, &me32));
                }
                printf("\n\t\t");
            }

            /*********************************ELAPSED TIME***************************************************/

            FILETIME ftCreation, ftExit, ftKernel, ftUser;
            LPSYSTEMTIME lpSystemTime = (LPSYSTEMTIME)malloc(sizeof(SYSTEMTIME));
            LPSYSTEMTIME lpCurrentTime = (LPSYSTEMTIME)malloc(sizeof(SYSTEMTIME));

            GetSystemTime(lpCurrentTime);

            if (GetProcessTimes(CHANDLE, &ftCreation, &ftExit, &ftKernel, &ftUser)) {
                if (FileTimeToSystemTime(&ftCreation, lpSystemTime)) {

                    char ret = 0;
                    int values[3];

                    for (int i = 0; i < 3; i++) {
                        size_t s = (6 - i); // 6 : index of wSeconds
                        values[i] = *((WORD*)lpCurrentTime + s) - *((WORD*)lpSystemTime + s) - ret;

                        ret = values[i] < 0;
                        if (ret) values[i] = -values[i];
                    }

                    for (int i = 2; i >= 0; i--) {
                        if (values[i] < 10) printf("0");
                        printf("%ld%c", values[i], i > 0 ? ':' : '\t');
                    }
                }
            }
            printf("\n");

            /******************************************THREAD INFO***************************************************************/
            le32.dwSize = sizeof(THREADENTRY32);
            DWORD aa;
            HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pe32.th32ProcessID);

            if (Thread32First(hThreadSnap, &le32) && pe32.th32ProcessID != GetCurrentProcessId()) {
                do {


                    if (le32.th32OwnerProcessID == pe32.th32ProcessID && pe32.th32ProcessID != GetCurrentProcessId()) {
                        HANDLE CTHANDLE = OpenThread(THREAD_ALL_ACCESS, FALSE, le32.th32ThreadID);

                        if (CTHANDLE != NULL) {
                            //if (le32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(le32.th32OwnerProcessID)) {
                            //    // printf("0x%04x-", le32.th32ThreadID);
                            //}














                            /*****************************FIND TEB FOR FUN AND PROFITE************************************************************/

                            THREAD_BASIC_INFORMATION tbi;
                            KPRIORITY CheckRead;
                            PVOID addr;
                            NT_TIB nt_tib;

                            NtQueryInfoThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread");

                            if (NtQueryInfoThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread"))
                            {
                                NT_TIB tib = { 0 };
                                THREAD_BASIC_INFORMATION tbi = { 0 };

                                NTSTATUS status = NtQueryInfoThread(CTHANDLE, (THREADINFOCLASS)0, &tbi, sizeof(tbi), nullptr);
                             //   printf("%d", status);
                                if (status >= 0)
                                {


                                    NTSTATUS status2 = NtQueryInfoThread(CTHANDLE, (THREADINFOCLASS)9, &addr, sizeof(addr), nullptr);
                                    if (status >= 0)
                                    {
                                        printf("ThreadQuerySetWin32StartAddress:: 0x%p\n", addr);
                                    }

                                    _SYSTEM_THREAD_INFORMATION idk;

                                    _SYSTEM_THREAD_INFORMATION idk_cpy;


                                    ULONG state;
                                    //typedef enum _KTHREAD_STATE
                                    //{
                                    //    Initialized,
                                    //    Ready,
                                    //    Running,
                                    //    Standby,
                                    //    Terminated,
                                    //    Waiting,
                                    //    Transition,
                                    //    DeferredReady,
                                    //    GateWaitObsolete,
                                    //    WaitingForProcessInSwap,
                                    //    MaximumThreadState
                                    //} KTHREAD_STATE, * PKTHREAD_STATE;

                                    NTSTATUS status3 = NtQueryInfoThread(CTHANDLE, (THREADINFOCLASS)0x28, &idk, sizeof(idk), nullptr);

                                 //   ReadProcessMemory(CHANDLE, &idk.Reserved2, &state, sizeof(state), nullptr);
                                    // printf("status3:: %X\n", status3);
                                    if (status3 >= 0) {
                                       // printf("from var:: %i\n", state);

                                       // printf("NtQueryInfoThreadfrom :: %i\n", &idk);
                                        switch(idk.ThreadState){
                                        case 1:
                                            printf("Initialized\n");
                                            break;
                                        case 2:
                                            printf("Ready\n");
                                            break;
                                        case 3:
                                            printf("Running\n");
                                            break;
                                        case 4:
                                            printf("Standby\n");
                                            break;
                                        case 5:
                                            printf("Terminated\n"); //Tous marqué terminated ?????????????????????????
                                            break;
                                        case 6:
                                            printf("Waiting\n");
                                            break;
                                        case 7:
                                            printf("Transition\n");
                                            break;
                                        case 8:
                                            printf("DeferredReady\n");
                                            break;
                                        case 9:
                                            printf("GateWaitObsolete\n");
                                            break;
                                        case 10:
                                            printf("WaitingForProcessInSwap\n");
                                            break;
                                        case 11:
                                            printf("MaximumThreadState\n");
                                            break;
                                        default:
                                            printf("surement quelquechose\n");
                                            break;
                                        }
                                    }
                                   





                                    /***************************TEB GOESSSSSS BRRRRRRRRRRRRRR**********************************/
                                    ReadProcessMemory(CHANDLE, tbi.TebBaseAddress, &tib, sizeof(tbi), nullptr);


                                   

                                    PTEB pteb = (PTEB)((PVOID*)&pbi)[1];
                                    PTEB ptebCopy = (PTEB)malloc(sizeof(TEB));

                                  //  printf("TEB STACKABE %p\n", ptebCopy->ProcessEnvironmentBlock);


                                    if (ReadProcessMemory(CHANDLE, pteb, ptebCopy, sizeof(TEB), NULL)) {
                                            printf("PTEB  ADD:%p\n", ptebCopy);

                                            PPEB peb_1 = (PPEB)((PVOID*)&ptebCopy->ProcessEnvironmentBlock);
                                            PPEB pebCopy_1 = (PPEB)malloc(sizeof(PEB));
                                            if (ReadProcessMemory(CHANDLE, peb_1, pebCopy_1, sizeof(TEB), NULL)) {
                                                //printf("Addr Being Debugged :)%p\n", pebCopy_1->BeingDebugged);
                                                /*To FIX*/
                                            }
                                    }
                                }
                            }
                            /****************************Thread Id + EntryPoint:)************************************/

                            if (le32.th32OwnerProcessID != GetCurrentProcessId()) {
                                DWORD FLAGS = 0;
                                if (le32.th32OwnerProcessID != GetCurrentProcessId()) {
                                    if (SuspendThread(CTHANDLE) != -1) {
                                        CONTEXT context = { 0 };
                                        context.ContextFlags = CONTEXT_FULL;
                                        if (GetThreadContext(CTHANDLE, &context)) {
                                           ResumeThread(CTHANDLE);
                                            if ((void*)context.Rip != 0) {

                                                printf("THREAD ID %i :: Thread Rip:: 0x%p\n", le32.th32ThreadID, (void*)context.Rip);


                                                



                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    le32.dwSize = sizeof(THREADENTRY32);
                } while (Thread32Next(hThreadSnap, &le32));
            }
            else


                printf("\n");
            CloseHandle(CHANDLE);
            //Closes Handle et freee si on a des truc a free

        } while (Process32Next(hProcessSnap, &pe32));
    }
}

int main(int argc, char* argv[]) {

    // GetToken();

    WalkOnProcess();

   // WmiQuery();

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
