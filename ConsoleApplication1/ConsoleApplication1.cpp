//

#include <iostream>

#include <windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include "psapi.h"


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


HANDLE GetHandle(int PID) {


    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);



}


void WalkOnProcess() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    PVOID pebAddress;
    PVOID rtlUserProcParamsAddress;
    UNICODE_STRING commandLine;
    WCHAR* commandLineContents;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);

    int i = 0;
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            printf("PID: %d\t", pe32.th32ProcessID);
            i = 0;

            //printf("Name: %s\n", pe32.szExeFile);


               // printf("%c", pe32.szExeFile[0]);
            printf("NAME: %c", pe32.szExeFile[i]);
            while (pe32.szExeFile[i++] != '\0') {
                printf("%c", pe32.szExeFile[i]);
            }
            printf("\t");

            printf("NumberOfThreads: %d \t", pe32.cntThreads);

            // printf("ParrentProcess: %s \t", pe32.th32ParentProcessID);


             //RAM ETC HORS STRUC PE32
            HANDLE CHANDLE = GetHandle(pe32.th32ProcessID);

            PROCESS_MEMORY_COUNTERS memCounter;
            BOOL result = GetProcessMemoryInfo(CHANDLE,&memCounter,sizeof(memCounter));

            if (memCounter.WorkingSetSize / 1024 / 1024 < 10000000) {
                printf("MEMORY USAGE: %lld Mb", memCounter.WorkingSetSize / 1024 / 1024);
            }
            else {
                printf("Cannot read SeDebug Seem Not Be Activated plz use it :)");
            }

      
           // sprintf_s(procID, "%d", entry.th32ProcessID);




            //  printf("MEM: %d \t", CHANDLE);


             // NtQueryInformationProcess(CHANDLE, ProcessBasicInformation,)

          //  CreateRemoteThread(CHANDLE, )
            


                printf("\n");

            CloseHandle(CHANDLE);

        } while (Process32Next(hProcessSnap, &pe32));
    }
}

int main(int argc, char* argv[]) {

    WalkOnProcess();

    return 0;
}
