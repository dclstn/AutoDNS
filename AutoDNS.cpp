// AutoDNS.xex 1.0.0, a DashLaunch plugin.
//
// The console's stored network settings point at a DNS server that doesn't
// exist (10.255.255.1). The dashboard that runs before the exploit therefore
// can't resolve a single Xbox Live hostname. Once the exploit chain has loaded
// this plugin, it decrypts those settings with XnpLoadConfigParams, swaps in
// working DNS servers, and applies them with XnpConfig. XnpConfig only changes
// the running stack. Storage still holds the dead server, so the next boot
// starts offline again on its own.
//
// Set this up once in the dashboard. Network Settings, DNS Manual, 10.255.255.1
// for both servers.

#include <xtl.h>
#include <string.h>

#define DEAD_DNS   0x0AFFFF01u   // 10.255.255.1
#define GOOD_DNS1  0x01010101u   // 1.1.1.1
#define GOOD_DNS2  0x01000001u   // 1.0.0.1
#define BOOT_WAIT  90000         // ms to wait for Wi-Fi association and DHCP at boot

typedef LONG NTSTATUS;

extern "C" {
    NTSTATUS ExCreateThread(PHANDLE, DWORD, LPDWORD, PVOID, LPTHREAD_START_ROUTINE, LPVOID, DWORD);
    NTSTATUS XexGetModuleHandle(PCHAR, PHANDLE);
    NTSTATUS XexGetProcedureAddress(HANDLE, DWORD, PVOID *);
}

#define SYSAPP 2   // XNCALLER_SYSAPP. Plugins run in the system context.

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

static int   (*pXNetStartup)(int, BYTE *);
static int   (*pXNetCleanup)(int);
static DWORD (*pXNetGetTitleXnAddr)(int, XNADDR_ *);
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
        {  73, (PVOID *)&pXNetGetTitleXnAddr  },
        { 101, (PVOID *)&pXnpLoadConfigParams },
        { 104, (PVOID *)&pXnpConfig           },
    };
    for (int i = 0; i < 5; i++) {
        if (XexGetProcedureAddress(xam, table[i].ord, table[i].fn) < 0 || *table[i].fn == NULL)
            return FALSE;
    }
    return TRUE;
}

// Polls XNetGetTitleXnAddr until the console has an address.
static BOOL WaitForAddress(DWORD ms)
{
    DWORD t0 = GetTickCount();

    for (;;) {
        XNADDR_ a;
        memset(&a, 0, sizeof(a));
        DWORD flags = pXNetGetTitleXnAddr(SYSAPP, &a);

        BOOL configured = (flags & 0xC) != 0;   // STATIC or DHCP
        BOOL none       = (flags & 0x1) != 0;   // NONE
        if (configured && !none && a.ina != 0)
            return TRUE;

        if (GetTickCount() - t0 > ms)
            return FALSE;
        Sleep(500);
    }
}

// Decrypts the stored network settings into c. If decryption didn't happen,
// the lease reads as 70 years and the flags are noise, so that's the check.
static BOOL Load(CFG *c)
{
    memset(c, 0, sizeof(*c));
    pXnpLoadConfigParams(SYSAPP, c, 0, 0);
    return c->leaseSecs <= 30u * 24 * 3600 && c->flags < 0x1000;
}

static void Run()
{
    CFG c;

    if (!WaitForAddress(BOOT_WAIT))
        return;
    if (!Load(&c))
        return;
    if (c.dns[0] != DEAD_DNS && c.dns[1] != DEAD_DNS)
        return;

    c.dns[0] = GOOD_DNS1;
    c.dns[1] = GOOD_DNS2;
    pXnpConfig(SYSAPP, &c, 0);
}

static DWORD WINAPI Worker(LPVOID)
{
    if (!Resolve())
        return 0;

    BYTE startup[13] = { 13 };   // XNetStartupParams. First byte is the size, zeros mean defaults.
    pXNetStartup(SYSAPP, startup);

    Run();

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
