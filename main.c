//if used for remote process, you need to duplicate handles (and close them after)
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef LONG NTSTATUS;

typedef struct _SYSTEM_HANDLE {
    DWORD       ProcessId;
    BYTE        ObjectTypeNumber;
    BYTE        Flags;
    WORD        Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (WINAPI *NtQueryObject_t)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

#define SystemHandleInformation 16

int main() {
	printf("starting\n");
    NtQuerySystemInformation_t NtQuerySystemInformation = 
        (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    NtQueryObject_t NtQueryObject = 
        (NtQueryObject_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

    if (!NtQuerySystemInformation || !NtQueryObject) {
        printf("Failed to get NtQuerySystemInformation or NtQueryObject\n");
        return 1;
    }

    ULONG bufferSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
    NTSTATUS status;
	//finding the proper size
    while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, bufferSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize *= 2;
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, bufferSize);
    }

    if (status != 0) {
        printf("NtQuerySystemInformation failed: 0x%X\n", status);
        free(handleInfo);
        return 1;
    }
		printf("getting PID\n");

    DWORD currentPID = GetCurrentProcessId();

    for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
		//printf("handle # %d\n",i);

        SYSTEM_HANDLE handleEntry = handleInfo->Handles[i];

        if (handleEntry.ProcessId != currentPID)
            continue;

        //HANDLE Hduplicated = NULL;
		
        HANDLE hSource = (HANDLE)(uintptr_t)handleEntry.Handle;
		//if (!DuplicateHandle(GetCurrentProcess(), hSource, GetCurrentProcess(), &Hduplicated, 0, FALSE, DUPLICATE_SAME_ACCESS)) {continue;}
        BYTE objTypeInfoBuffer[0x1000] = {0};
        BYTE objNameInfoBuffer[0x1000] = {0};

        status = NtQueryObject(hSource, ObjectTypeInformation, objTypeInfoBuffer, sizeof(objTypeInfoBuffer), NULL);
        if (status != 0) {
         //   CloseHandle(Hduplicated);
            continue;
        }

        PUNICODE_STRING objTypeName = (PUNICODE_STRING)objTypeInfoBuffer;

        status = NtQueryObject(hSource, ObjectNameInformation, objNameInfoBuffer, sizeof(objNameInfoBuffer), NULL);
        if (status != 0) {
            //CloseHandle(Hduplicated);
            continue;
        }

        PUNICODE_STRING objName = (PUNICODE_STRING)objNameInfoBuffer;

        wprintf(L"Handle: 0x%04X\n", handleEntry.Handle);
        wprintf(L"Type  : %S\n",  objTypeName->Buffer);

        if (objName->Length > 0)
            wprintf(L"Name  : %S\n",objName->Buffer);
        else
            wprintf(L"Name  : N/A\n");
        printf("-----------------\n\n");

       // CloseHandle(Hduplicated);
    }

    free(handleInfo);
    return 0;
}
