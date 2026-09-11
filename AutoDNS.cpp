// AutoDNS.xex 1.0.3 (Modificado para Blind Boot + Delay de Segurança)
//
// The console's stored network settings point at a DNS server that doesn't
// exist: 192.0.2.1, from the RFC 5737 documentation range. The dashboard that
// runs before the exploit therefore can't resolve a single Xbox Live hostname.
// Once the exploit chain has loaded this plugin, it decrypts those settings
// with XnpLoadConfigParams, swaps in working DNS servers, and applies them
// with XnpConfig. 
//
// MODIFICAÇÃO: Agora aplica o DNS em duas fases. Primeiro no SYSAPP (Dashboard),
// aguarda um tempo de segurança para plugins subsequentes (ex: xbGuard) armarem
// seus hooks de proteção, e só então aplica no TITLE (Jogos e Aplicativos).
//
// Set this up once in the dashboard. Network Settings, DNS Manual, 192.0.2.1
// for both servers.

#include <xtl.h>
#include <stddef.h>
#include <string.h>

#define DEAD_DNS   0xC0000201u   // 192.0.2.1 (RFC 5737 TEST-NET-1, never assigned)
#define GOOD_DNS1  0x01010101u   // 1.1.1.1 (Cloudflare)
#define GOOD_DNS2  0x01000001u   // 1.0.0.1 (Cloudflare)
#define BOOT_WAIT  90000         // ms to wait for Wi-Fi association and DHCP at boot
#define SWAP_WAIT  30000         // ms to wait for DHCP to finish after XnpConfig

typedef LONG NTSTATUS;

extern "C" {
    NTSTATUS ExCreateThread(PHANDLE, DWORD, LPDWORD, PVOID, LPTHREAD_START_ROUTINE, LPVOID, DWORD);
    NTSTATUS XexGetModuleHandle(PCHAR, PHANDLE);
    NTSTATUS XexGetProcedureAddress(HANDLE, DWORD, PVOID *);
}

// Definição dos contextos de chamada do XAM
#define SYSAPP 2   // XNCALLER_SYSAPP. Usado pela Dashboard e sistema base.
#define TITLE  1   // XNCALLER_TITLE. Usado por Jogos e Aplicativos.

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

// Asserts de segurança para garantir que a estrutura não corrompa a memória
C_ASSERT(sizeof(CFG) == 492);
C_ASSERT(offsetof(CFG, flags) == 0x4C);      
C_ASSERT(offsetof(CFG, dns) == 0x60);        
C_ASSERT(offsetof(CFG, leaseSecs) == 0x168); 

// xam.xex exports by ordinal (Xenia xam_table.inc and xkelib xamext.def agree):
//   51 NetDll_XNetStartup   73 NetDll_XNetGetTitleXnAddr
//  101 NetDll_XnpLoadConfigParams   104 NetDll_XnpConfig
static int   (*pXNetStartup)(int, BYTE *);
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
        {  73, (PVOID *)&pXNetGetTitleXnAddr  },
        { 101, (PVOID *)&pXnpLoadConfigParams },
        { 104, (PVOID *)&pXnpConfig           },
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
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
    pXnpLoadConfigParams(SYSAPP, c, 0, 0);   // returns 1 on hardware; meaning undocumented
    return c->leaseSecs <= 30u * 24 * 3600 && c->flags < 0x1000;
}

// XnpConfig returns at once and reconfigures in the background. 
// The params live in a static so they outlive this call.
static CFG g_cfg;

static void Run()
{
    // 1. Espera o console pegar um IP válido na rede local (Wi-Fi ou Cabo)
    if (!WaitForAddress(BOOT_WAIT))
        return;
        
    // 2. Lê as configurações de rede salvas no NAND
    if (!Load(&g_cfg))
        return;
        
    // 3. Só executa a troca se o DNS estiver "morto" (192.0.2.1)
    if (g_cfg.dns[0] != DEAD_DNS && g_cfg.dns[1] != DEAD_DNS)
        return;

    // Define os servidores DNS válidos na estrutura em memória
    g_cfg.dns[0] = GOOD_DNS1;
    g_cfg.dns[1] = GOOD_DNS2;

    // ==========================================
    // FASE 1: Acordar a Dashboard (SYSAPP = 2)
    // ==========================================
    pXnpConfig(SYSAPP, &g_cfg, 0);
    
    // Aguarda a Dashboard se estabilizar e conseguir logar na Xbox Live
    WaitForAddress(SWAP_WAIT);

    // ==========================================
    // FASE 2: A Mágica do Tempo (Sleep de Segurança)
    // ==========================================
    // O DashLaunch carrega os plugins na ordem do launch.ini.
    // Como o xbGuard.xex é o plugin3, ele está carregando agora.
    // Precisamos dar tempo para ele injetar os hooks de proteção no xam.xex
    // antes de liberarmos o tráfego de jogos e aplicativos.
    // 10 segundos (10000 ms) é uma margem de segurança robusta.
    Sleep(10000);

    // ==========================================
    // FASE 3: Acordar Jogos e Aplicativos (TITLE = 1)
    // ==========================================
    // Agora o xbGuard já está ativo e protegendo as chamadas de rede.
    // Podemos aplicar o DNS válido para o contexto dos aplicativos.
    pXnpConfig(TITLE, &g_cfg, 0);

    // Aguarda a rede do contexto TITLE se estabilizar
    WaitForAddress(SWAP_WAIT);
}

// No XNetCleanup: the plugin stays resident for the console's uptime, and
// tearing down a context under xam's own caller id is the one call here whose
// refcount semantics aren't documented. A held reference costs nothing.
static DWORD WINAPI Worker(LPVOID)
{
    if (!Resolve())
        return 0;

    BYTE startup[13] = { 13 };   // XNetStartupParams. First byte is the size, zeros mean defaults.
    if (pXNetStartup(SYSAPP, startup) != 0)
        return 0;

    Run();
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
