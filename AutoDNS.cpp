// AutoDNS.xex 1.1, a DashLaunch plugin.
//
// The console keeps a dead DNS server (10.255.255.1) in its stored network
// settings, so the dashboard that runs before the exploit cannot resolve any
// Xbox Live hostname. Once the exploit chain has loaded us, we decrypt the
// stored settings with XnpLoadConfigParams, put real DNS servers in, and apply
// them with XnpConfig. XnpConfig changes the live stack only. Storage keeps the
// dead DNS, so the next boot starts offline again without any extra work.
//
// Log goes to Usb:\AutoDNS.log. One-time console setup: Network Settings,
// DNS Manual, 10.255.255.1 for both servers.

#include <xtl.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// ponytail: the knobs. Nothing below these should need editing.
// ---------------------------------------------------------------------------

#define DEAD_DNS   0x0AFFFF01u   // 10.255.255.1
#define GOOD_DNS1  0x01010101u   // 1.1.1.1
#define GOOD_DNS2  0x08080808u   // 8.8.8.8
#define BOOT_WAIT  90000         // ms to wait for Wi-Fi association and DHCP at boot
#define SWAP_WAIT  30000         // ms to wait for DHCP to finish after XnpConfig
#define LOG_PATH   "\\Device\\Mass0\\AutoDNS.log"

// ---------------------------------------------------------------------------
// Kernel imports (xboxkrnl.lib)
// ---------------------------------------------------------------------------

typedef LONG NTSTATUS;

typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } STR;
typedef struct { HANDLE Root; STR *Name; ULONG Attr; }         OA;
typedef struct { NTSTATUS Status; ULONG_PTR Info; }            IOSB;

extern "C" {
    NTSTATUS NtCreateFile(PHANDLE, ACCESS_MASK, OA *, IOSB *, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG);
    NTSTATUS NtWriteFile(HANDLE, HANDLE, PVOID, PVOID, IOSB *, PVOID, ULONG, PLARGE_INTEGER);
    NTSTATUS NtClose(HANDLE);
    NTSTATUS ExCreateThread(PHANDLE, DWORD, LPDWORD, PVOID, LPTHREAD_START_ROUTINE, LPVOID, DWORD);
    NTSTATUS XexGetModuleHandle(PCHAR, PHANDLE);
    NTSTATUS XexGetProcedureAddress(HANDLE, DWORD, PVOID *);
}

// ---------------------------------------------------------------------------
// xam.xex structures and exports, resolved by ordinal at runtime
// ---------------------------------------------------------------------------

#define SYSAPP 2   // XNCALLER_SYSAPP: we run in the system context

#pragma pack(push, 1)
typedef struct {
    DWORD ina, inaOnline;
    WORD  port;
    BYTE  enet[6], online[20];
} XNADDR_;

// XNetConfigParams. 492 bytes, layout from xkelib.
typedef struct {
    BYTE  hash[0x14], confounder[8];
    WORD  name[0x18], flags;
    BYTE  enet[6];
    DWORD ina, mask, gw, dns[2];
    char  host[0x28], pppoe[0x40 + 0x40 + 0x28 + 0x28];
    LARGE_INTEGER leaseTime;
    DWORD leaseSecs, rest[3 + 4 + 4];
    BYTE  tail[0x44 + 16];
} CFG;
#pragma pack(pop)
C_ASSERT(sizeof(CFG) == 492);

typedef struct { INT status; UINT n; DWORD a[8]; } XNDNS_;

static int   (*pXNetStartup)(int, BYTE *);
static int   (*pXNetCleanup)(int);
static DWORD (*pXNetGetTitleXnAddr)(int, XNADDR_ *);
static INT   (*pXNetDnsLookup)(int, const char *, HANDLE, XNDNS_ **);
static INT   (*pXNetDnsRelease)(int, XNDNS_ *);
static int   (*pXnpConfig)(int, CFG *, DWORD);
static int   (*pXnpLoadConfigParams)(int, CFG *, DWORD, DWORD);

static BOOL Resolve()
{
    HANDLE xam;
    if (XexGetModuleHandle("xam.xex", &xam) < 0)
        return FALSE;

    struct { DWORD ord; PVOID *fn; } table[] = {
        {  51, (PVOID *)&pXNetStartup         },
        {  52, (PVOID *)&pXNetCleanup         },
        {  67, (PVOID *)&pXNetDnsLookup       },
        {  68, (PVOID *)&pXNetDnsRelease      },
        {  73, (PVOID *)&pXNetGetTitleXnAddr  },
        { 101, (PVOID *)&pXnpLoadConfigParams },
        { 104, (PVOID *)&pXnpConfig           },
    };
    for (int i = 0; i < 7; i++) {
        if (XexGetProcedureAddress(xam, table[i].ord, table[i].fn) < 0 || *table[i].fn == NULL)
            return FALSE;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

static HANDLE   g_log;
static LONGLONG g_off;
static DWORD    g_t0;

static void Log(const char *fmt, ...)
{
    char    line[256];
    va_list ap;

    va_start(ap, fmt);
    int n = _snprintf(line, sizeof(line) - 1, "[%5u ms] ", (unsigned)(GetTickCount() - g_t0));
    n += _vsnprintf(line + n, sizeof(line) - n - 3, fmt, ap);
    va_end(ap);
    line[n++] = '\r';
    line[n++] = '\n';

    if (g_log == NULL) {
        static char path[] = LOG_PATH;
        STR  name = { sizeof(path) - 1, sizeof(path), path };
        OA   oa   = { NULL, &name, 0x40 };
        IOSB io;
        if (NtCreateFile(&g_log, GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL, 0x80, 1, 5, 0x60) < 0) {
            g_log = NULL;
            return;
        }
    }

    IOSB          io;
    LARGE_INTEGER off;
    off.QuadPart = g_off;
    if (NtWriteFile(g_log, NULL, NULL, NULL, &io, line, n, &off) >= 0)
        g_off += io.Info;
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

#define IP4(a) (unsigned)((a) >> 24) & 0xFF, (unsigned)((a) >> 16) & 0xFF, \
               (unsigned)((a) >> 8) & 0xFF,  (unsigned)(a) & 0xFF

#define DEAD(c) ((c).dns[0] == DEAD_DNS || (c).dns[1] == DEAD_DNS)

// Polls XNetGetTitleXnAddr until the console has an address. Logs only when
// the flags change, so a long wait is a few lines, not a few hundred.
static BOOL WaitForAddress(DWORD ms, const char *tag)
{
    DWORD t0        = GetTickCount();
    DWORD lastFlags = ~0u;

    for (;;) {
        XNADDR_ a;
        memset(&a, 0, sizeof(a));
        DWORD flags = pXNetGetTitleXnAddr(SYSAPP, &a);

        if (flags != lastFlags) {
            Log("%s: addr=0x%04X ip=%u.%u.%u.%u", tag, (unsigned)flags, IP4(a.ina));
            lastFlags = flags;
        }

        BOOL configured = (flags & 0xC) != 0;   // STATIC or DHCP
        BOOL none       = (flags & 0x1) != 0;   // NONE
        if (configured && !none && a.ina != 0)
            return TRUE;

        if (GetTickCount() - t0 > ms) {
            Log("%s: timeout", tag);
            return FALSE;
        }
        Sleep(500);
    }
}

// One DNS query. If the swap did not take, this is what fails.
static BOOL DnsWorks()
{
    XNDNS_ *d  = NULL;
    DWORD   t0 = GetTickCount();

    if (pXNetDnsLookup(SYSAPP, "example.com", NULL, &d) != 0 || d == NULL)
        return FALSE;

    while (d->status == 10036 /* WSAEINPROGRESS */ && GetTickCount() - t0 < 10000)
        Sleep(100);

    BOOL ok = d->status == 0 && d->n > 0;
    Log("probe: %s (status %d)", ok ? "DNS OK" : "DNS FAILED", d->status);
    pXNetDnsRelease(SYSAPP, d);
    return ok;
}

// Decrypts the stored network settings into c. Undecrypted data shows up as
// a 70-year lease and random flags, which is what the plausibility check
// catches.
static BOOL Load(CFG *c, const char *tag)
{
    memset(c, 0, sizeof(*c));
    int  rc = pXnpLoadConfigParams(SYSAPP, c, 0, 0);
    BOOL ok = c->leaseSecs <= 30u * 24 * 3600 && c->flags < 0x1000;

    Log("%s: rc=%d dns=%u.%u.%u.%u,%u.%u.%u.%u%s",
        tag, rc, IP4(c->dns[0]), IP4(c->dns[1]), ok ? "" : " IMPLAUSIBLE");
    return ok;
}

// ---------------------------------------------------------------------------
// The job
// ---------------------------------------------------------------------------

static void Run()
{
    CFG c;

    if (!WaitForAddress(BOOT_WAIT, "boot")) {
        Log("no network");
        return;
    }
    if (!Load(&c, "stored")) {
        Log("bad params");
        return;
    }
    if (!DEAD(c)) {
        Log("stored DNS normal, nothing to do");
        return;
    }

    c.dns[0] = GOOD_DNS1;
    c.dns[1] = GOOD_DNS2;
    Log("swap: XnpConfig rc=%d", pXnpConfig(SYSAPP, &c, 0));

    if (!WaitForAddress(SWAP_WAIT, "swap")) {
        Log("no address after swap");
        return;
    }
    if (!DnsWorks()) {
        Log("DNS still failing");
        return;
    }
    Log("online with working DNS");

    // ponytail: no write-back. XnpConfig never persisted across five boots. If
    // this ever logs LOST, set the dead DNS in the dashboard again.
    if (Load(&c, "storage") && DEAD(c))
        Log("storage still armed");
    else
        Log("storage LOST dead DNS. Set it in the dashboard again");
}

static DWORD WINAPI Worker(LPVOID)
{
    g_t0 = GetTickCount();
    Log("AutoDNS 1.1");

    if (!Resolve()) {
        Log("resolve failed");
        return 0;
    }

    BYTE startup[13] = { 13 };   // XNetStartupParams: size byte, rest default
    pXNetStartup(SYSAPP, startup);

    Run();

    Log("done");
    if (g_log != NULL)
        NtClose(g_log);
    pXNetCleanup(SYSAPP);
    return 0;
}

extern "C" BOOL WINAPI DllMain(HANDLE, DWORD reason, LPVOID)
{
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    HANDLE h = NULL;
    if (ExCreateThread(&h, 0, NULL, NULL, Worker, NULL, 2) >= 0 && h != NULL)
        CloseHandle(h);
    return TRUE;
}
