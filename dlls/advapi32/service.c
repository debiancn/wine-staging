/*
 * Win32 advapi functions
 *
 * Copyright 1995 Sven Verdoolaege
 * Copyright 2005 Mike McCormack
 * Copyright 2007 Rolf Kalbermatter
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"
#include "wine/port.h"

#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "windef.h"
#include "winbase.h"
#include "winsvc.h"
#include "winerror.h"
#include "winreg.h"
#include "wine/unicode.h"
#include "wine/debug.h"
#include "winternl.h"
#include "lmcons.h"
#include "lmserver.h"

#include "svcctl.h"

#include "wine/exception.h"

WINE_DEFAULT_DEBUG_CHANNEL(service);

static const WCHAR szLocalSystem[] = {'L','o','c','a','l','S','y','s','t','e','m',0};
static const WCHAR szServiceManagerKey[] = { 'S','y','s','t','e','m','\\',
      'C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
      'S','e','r','v','i','c','e','s',0 };
static const WCHAR  szSCMLock[] = {'A','D','V','A','P','I','_','S','C','M',
                                   'L','O','C','K',0};

void  __RPC_FAR * __RPC_USER MIDL_user_allocate(size_t len)
{
    return HeapAlloc(GetProcessHeap(), 0, len);
}

void __RPC_USER MIDL_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

static const GENERIC_MAPPING scm_generic = {
    (STANDARD_RIGHTS_READ | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS),
    (STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG),
    (STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK),
    SC_MANAGER_ALL_ACCESS
};

static const GENERIC_MAPPING svc_generic = {
    (STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS),
    (STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG),
    (STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL),
    SERVICE_ALL_ACCESS
};

typedef struct service_data_t
{
    LPHANDLER_FUNCTION_EX handler;
    LPVOID context;
    HANDLE thread;
    SC_HANDLE handle;
    BOOL unicode : 1;
    union {
        LPSERVICE_MAIN_FUNCTIONA a;
        LPSERVICE_MAIN_FUNCTIONW w;
    } proc;
    LPWSTR args;
    WCHAR name[1];
} service_data;

static CRITICAL_SECTION service_cs;
static CRITICAL_SECTION_DEBUG service_cs_debug =
{
    0, 0, &service_cs,
    { &service_cs_debug.ProcessLocksList, 
      &service_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": service_cs") }
};
static CRITICAL_SECTION service_cs = { &service_cs_debug, -1, 0, 0, 0, 0 };

static service_data **services;
static unsigned int nb_services;
static HANDLE service_event;

extern HANDLE __wine_make_process_system(void);

/******************************************************************************
 * SC_HANDLEs
 */

#define MAX_SERVICE_NAME 256

typedef enum { SC_HTYPE_MANAGER, SC_HTYPE_SERVICE } SC_HANDLE_TYPE;

struct sc_handle;
typedef VOID (*sc_handle_destructor)(struct sc_handle *);

struct sc_handle
{
    SC_HANDLE_TYPE htype;
    DWORD ref_count;
    sc_handle_destructor destroy;
    SC_RPC_HANDLE server_handle;     /* server-side handle */
};

struct sc_manager       /* service control manager handle */
{
    struct sc_handle hdr;
    HKEY   hkey;   /* handle to services database in the registry */
    DWORD  dwAccess;
};

struct sc_service       /* service handle */
{
    struct sc_handle hdr;
    HKEY   hkey;          /* handle to service entry in the registry (under hkey) */
    DWORD  dwAccess;
    struct sc_manager *scm;  /* pointer to SCM handle */
    WCHAR  name[1];
};

static void *sc_handle_alloc(SC_HANDLE_TYPE htype, DWORD size,
                             sc_handle_destructor destroy)
{
    struct sc_handle *hdr;

    hdr = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, size );
    if (hdr)
    {
        hdr->htype = htype;
        hdr->ref_count = 1;
        hdr->destroy = destroy;
    }
    TRACE("sc_handle type=%d -> %p\n", htype, hdr);
    return hdr;
}

static void *sc_handle_get_handle_data(SC_HANDLE handle, DWORD htype)
{
    struct sc_handle *hdr = (struct sc_handle *) handle;

    if (!hdr)
        return NULL;
    if (hdr->htype != htype)
        return NULL;
    return hdr;
}

static void sc_handle_free(struct sc_handle* hdr)
{
    if (!hdr)
        return;
    if (--hdr->ref_count)
        return;
    hdr->destroy(hdr);
    HeapFree(GetProcessHeap(), 0, hdr);
}

static void sc_handle_destroy_manager(struct sc_handle *handle)
{
    struct sc_manager *mgr = (struct sc_manager*) handle;

    TRACE("destroying SC Manager %p\n", mgr);
    if (mgr->hkey)
        RegCloseKey(mgr->hkey);
}

static void sc_handle_destroy_service(struct sc_handle *handle)
{
    struct sc_service *svc = (struct sc_service*) handle;
    
    TRACE("destroying service %p\n", svc);
    if (svc->hkey)
        RegCloseKey(svc->hkey);
    svc->hkey = NULL;
    sc_handle_free(&svc->scm->hdr);
    svc->scm = NULL;
}

/******************************************************************************
 * String management functions (same behaviour as strdup)
 * NOTE: the caller of those functions is responsible for calling HeapFree
 * in order to release the memory allocated by those functions.
 */
static inline LPWSTR SERV_dup( LPCSTR str )
{
    UINT len;
    LPWSTR wstr;

    if( !str )
        return NULL;
    len = MultiByteToWideChar( CP_ACP, 0, str, -1, NULL, 0 );
    wstr = HeapAlloc( GetProcessHeap(), 0, len*sizeof (WCHAR) );
    MultiByteToWideChar( CP_ACP, 0, str, -1, wstr, len );
    return wstr;
}

static inline LPWSTR SERV_dupmulti(LPCSTR str)
{
    UINT len = 0, n = 0;
    LPWSTR wstr;

    if( !str )
        return NULL;
    do {
        len += MultiByteToWideChar( CP_ACP, 0, &str[n], -1, NULL, 0 );
        n += (strlen( &str[n] ) + 1);
    } while (str[n]);
    len++;
    n++;

    wstr = HeapAlloc( GetProcessHeap(), 0, len*sizeof (WCHAR) );
    MultiByteToWideChar( CP_ACP, 0, str, n, wstr, len );
    return wstr;
}

static inline DWORD multisz_cb(LPCWSTR wmultisz)
{
    const WCHAR *wptr = wmultisz;

    if (wmultisz == NULL)
        return 0;

    while (*wptr)
        wptr += lstrlenW(wptr)+1;
    return (wptr - wmultisz + 1)*sizeof(WCHAR);
}

/******************************************************************************
 * RPC connection with services.exe
 */

handle_t __RPC_USER MACHINE_HANDLEW_bind(MACHINE_HANDLEW MachineName)
{
    WCHAR transport[] = SVCCTL_TRANSPORT;
    WCHAR endpoint[] = SVCCTL_ENDPOINT;
    RPC_WSTR binding_str;
    RPC_STATUS status;
    handle_t rpc_handle;

    status = RpcStringBindingComposeW(NULL, transport, (RPC_WSTR)MachineName, endpoint, NULL, &binding_str);
    if (status != RPC_S_OK)
    {
        ERR("RpcStringBindingComposeW failed (%d)\n", (DWORD)status);
        return NULL;
    }

    status = RpcBindingFromStringBindingW(binding_str, &rpc_handle);
    RpcStringFreeW(&binding_str);

    if (status != RPC_S_OK)
    {
        ERR("Couldn't connect to services.exe: error code %u\n", (DWORD)status);
        return NULL;
    }

    return rpc_handle;
}

void __RPC_USER MACHINE_HANDLEW_unbind(MACHINE_HANDLEW MachineName, handle_t h)
{
    RpcBindingFree(&h);
}

static LONG WINAPI rpc_filter(EXCEPTION_POINTERS *eptr)
{
    return I_RpcExceptionFilter(eptr->ExceptionRecord->ExceptionCode);
}

static DWORD map_exception_code(DWORD exception_code)
{
    switch (exception_code)
    {
    case RPC_X_NULL_REF_POINTER:
    case RPC_X_ENUM_VALUE_OUT_OF_RANGE:
    case RPC_X_BYTE_COUNT_TOO_SMALL:
        return ERROR_INVALID_PARAMETER;
    default:
        return exception_code;
    }
}

/******************************************************************************
 * Service IPC functions
 */
static LPWSTR service_get_pipe_name(void)
{
    static const WCHAR format[] = { '\\','\\','.','\\','p','i','p','e','\\',
        'n','e','t','\\','N','t','C','o','n','t','r','o','l','P','i','p','e','%','u',0};
    static const WCHAR service_current_key_str[] = { 'S','Y','S','T','E','M','\\',
        'C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
        'C','o','n','t','r','o','l','\\',
        'S','e','r','v','i','c','e','C','u','r','r','e','n','t',0};
    LPWSTR name;
    DWORD len;
    HKEY service_current_key;
    DWORD service_current;
    LONG ret;
    DWORD type;

    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, service_current_key_str, 0,
        KEY_QUERY_VALUE, &service_current_key);
    if (ret != ERROR_SUCCESS)
        return NULL;
    len = sizeof(service_current);
    ret = RegQueryValueExW(service_current_key, NULL, NULL, &type,
        (BYTE *)&service_current, &len);
    RegCloseKey(service_current_key);
    if (ret != ERROR_SUCCESS || type != REG_DWORD)
        return NULL;
    len = sizeof(format)/sizeof(WCHAR) + 10 /* strlenW("4294967295") */;
    name = HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
    if (!name)
        return NULL;
    snprintfW(name, len, format, service_current);
    return name;
}

static HANDLE service_open_pipe(void)
{
    LPWSTR szPipe = service_get_pipe_name();
    HANDLE handle = INVALID_HANDLE_VALUE;

    do {
        handle = CreateFileW(szPipe, GENERIC_READ|GENERIC_WRITE,
                         0, NULL, OPEN_ALWAYS, 0, NULL);
        if (handle != INVALID_HANDLE_VALUE)
            break;
        if (GetLastError() != ERROR_PIPE_BUSY)
            break;
    } while (WaitNamedPipeW(szPipe, NMPWAIT_WAIT_FOREVER));
    HeapFree(GetProcessHeap(), 0, szPipe);

    return handle;
}

static service_data *find_service_by_name( const WCHAR *name )
{
    unsigned int i;

    if (nb_services == 1)  /* only one service (FIXME: should depend on OWN_PROCESS etc.) */
        return services[0];
    for (i = 0; i < nb_services; i++)
        if (!strcmpiW( name, services[i]->name )) return services[i];
    return NULL;
}

/******************************************************************************
 * service_thread
 *
 * Call into the main service routine provided by StartServiceCtrlDispatcher.
 */
static DWORD WINAPI service_thread(LPVOID arg)
{
    service_data *info = arg;
    LPWSTR str = info->args;
    DWORD argc = 0, len = 0;

    TRACE("%p\n", arg);

    while (str[len])
    {
        len += strlenW(&str[len]) + 1;
        argc++;
    }

    if (!argc)
    {
        if (info->unicode)
            info->proc.w(0, NULL);
        else
            info->proc.a(0, NULL);
        return 0;
    }
    
    if (info->unicode)
    {
        LPWSTR *argv, p;

        argv = HeapAlloc(GetProcessHeap(), 0, (argc+1)*sizeof(LPWSTR));
        for (argc=0, p=str; *p; p += strlenW(p) + 1)
            argv[argc++] = p;
        argv[argc] = NULL;

        info->proc.w(argc, argv);
        HeapFree(GetProcessHeap(), 0, argv);
    }
    else
    {
        LPSTR strA, *argv, p;
        DWORD lenA;
        
        lenA = WideCharToMultiByte(CP_ACP,0, str, len, NULL, 0, NULL, NULL);
        strA = HeapAlloc(GetProcessHeap(), 0, lenA);
        WideCharToMultiByte(CP_ACP,0, str, len, strA, lenA, NULL, NULL);

        argv = HeapAlloc(GetProcessHeap(), 0, (argc+1)*sizeof(LPSTR));
        for (argc=0, p=strA; *p; p += strlen(p) + 1)
            argv[argc++] = p;
        argv[argc] = NULL;

        info->proc.a(argc, argv);
        HeapFree(GetProcessHeap(), 0, argv);
        HeapFree(GetProcessHeap(), 0, strA);
    }
    return 0;
}

/******************************************************************************
 * service_handle_start
 */
static DWORD service_handle_start(service_data *service, const WCHAR *data, DWORD count)
{
    TRACE("%s argsize %u\n", debugstr_w(service->name), count);

    if (service->thread)
    {
        WARN("service is not stopped\n");
        return ERROR_SERVICE_ALREADY_RUNNING;
    }

    HeapFree(GetProcessHeap(), 0, service->args);
    service->args = HeapAlloc(GetProcessHeap(), 0, count * sizeof(WCHAR));
    memcpy( service->args, data, count * sizeof(WCHAR) );
    service->thread = CreateThread( NULL, 0, service_thread,
                                    service, 0, NULL );
    SetEvent( service_event );  /* notify the main loop */
    return 0;
}

/******************************************************************************
 * service_handle_control
 */
static DWORD service_handle_control(service_data *service, DWORD dwControl)
{
    DWORD ret = ERROR_INVALID_SERVICE_CONTROL;

    TRACE("%s control %u\n", debugstr_w(service->name), dwControl);

    if (service->handler)
        ret = service->handler(dwControl, 0, NULL, service->context);
    return ret;
}

/******************************************************************************
 * service_control_dispatcher
 */
static DWORD WINAPI service_control_dispatcher(LPVOID arg)
{
    SC_HANDLE manager;
    HANDLE pipe;

    if (!(manager = OpenSCManagerW( NULL, NULL, SC_MANAGER_CONNECT )))
    {
        ERR("failed to open service manager error %u\n", GetLastError());
        return 0;
    }

    pipe = service_open_pipe();

    if (pipe==INVALID_HANDLE_VALUE)
    {
        ERR("failed to create control pipe error = %d\n", GetLastError());
        return 0;
    }

    /* dispatcher loop */
    while (1)
    {
        service_data *service;
        service_start_info info;
        WCHAR *data = NULL;
        BOOL r;
        DWORD data_size = 0, count, result;

        r = ReadFile( pipe, &info, FIELD_OFFSET(service_start_info,data), &count, NULL );
        if (!r)
        {
            if (GetLastError() != ERROR_BROKEN_PIPE)
                ERR( "pipe read failed error %u\n", GetLastError() );
            break;
        }
        if (count != FIELD_OFFSET(service_start_info,data))
        {
            ERR( "partial pipe read %u\n", count );
            break;
        }
        if (count < info.total_size)
        {
            data_size = info.total_size - FIELD_OFFSET(service_start_info,data);
            data = HeapAlloc( GetProcessHeap(), 0, data_size );
            r = ReadFile( pipe, data, data_size, &count, NULL );
            if (!r)
            {
                if (GetLastError() != ERROR_BROKEN_PIPE)
                    ERR( "pipe read failed error %u\n", GetLastError() );
                break;
            }
            if (count != data_size)
            {
                ERR( "partial pipe read %u/%u\n", count, data_size );
                break;
            }
        }

        /* find the service */

        if (!(service = find_service_by_name( data )))
        {
            FIXME( "got request %u for unknown service %s\n", info.cmd, debugstr_w(data));
            result = ERROR_INVALID_PARAMETER;
            goto done;
        }

        TRACE( "got request %u for service %s\n", info.cmd, debugstr_w(data) );

        /* handle the request */
        switch (info.cmd)
        {
        case WINESERV_STARTINFO:
            if (!service->handle)
            {
                if (!(service->handle = OpenServiceW( manager, data, SERVICE_SET_STATUS )))
                    FIXME( "failed to open service %s\n", debugstr_w(data) );
            }
            result = service_handle_start(service, data + info.name_size,
                                          data_size / sizeof(WCHAR) - info.name_size );
            break;
        case WINESERV_SENDCONTROL:
            result = service_handle_control(service, info.control);
            break;
        default:
            ERR("received invalid command %u\n", info.cmd);
            result = ERROR_INVALID_PARAMETER;
            break;
        }

    done:
        WriteFile(pipe, &result, sizeof(result), &count, NULL);
        HeapFree( GetProcessHeap(), 0, data );
    }

    CloseHandle(pipe);
    CloseServiceHandle( manager );
    return 1;
}

/******************************************************************************
 * service_run_main_thread
 */
static BOOL service_run_main_thread(void)
{
    DWORD i, n, ret;
    HANDLE wait_handles[MAXIMUM_WAIT_OBJECTS];
    UINT wait_services[MAXIMUM_WAIT_OBJECTS];

    service_event = CreateEventW( NULL, FALSE, FALSE, NULL );

    /* FIXME: service_control_dispatcher should be merged into the main thread */
    wait_handles[0] = __wine_make_process_system();
    wait_handles[1] = CreateThread( NULL, 0, service_control_dispatcher, NULL, 0, NULL );
    wait_handles[2] = service_event;

    TRACE("Starting %d services running as process %d\n",
          nb_services, GetCurrentProcessId());

    /* wait for all the threads to pack up and exit */
    for (;;)
    {
        EnterCriticalSection( &service_cs );
        for (i = 0, n = 3; i < nb_services && n < MAXIMUM_WAIT_OBJECTS; i++)
        {
            if (!services[i]->thread) continue;
            wait_services[n] = i;
            wait_handles[n++] = services[i]->thread;
        }
        LeaveCriticalSection( &service_cs );

        ret = WaitForMultipleObjects( n, wait_handles, FALSE, INFINITE );
        if (!ret)  /* system process event */
        {
            TRACE( "last user process exited, shutting down\n" );
            /* FIXME: we should maybe send a shutdown control to running services */
            ExitProcess(0);
        }
        else if (ret == 1)
        {
            TRACE( "control dispatcher exited, shutting down\n" );
            /* FIXME: we should maybe send a shutdown control to running services */
            ExitProcess(0);
        }
        else if (ret == 2)
        {
            continue;  /* rebuild the list */
        }
        else if (ret < n)
        {
            services[wait_services[ret]]->thread = 0;
            CloseHandle( wait_handles[ret] );
            if (n == 4) return TRUE; /* it was the last running thread */
        }
        else return FALSE;
    }
}

/******************************************************************************
 * StartServiceCtrlDispatcherA [ADVAPI32.@]
 *
 * See StartServiceCtrlDispatcherW.
 */
BOOL WINAPI StartServiceCtrlDispatcherA( const SERVICE_TABLE_ENTRYA *servent )
{
    service_data *info;
    unsigned int i;
    BOOL ret = TRUE;

    TRACE("%p\n", servent);

    if (nb_services)
    {
        SetLastError( ERROR_SERVICE_ALREADY_RUNNING );
        return FALSE;
    }
    while (servent[nb_services].lpServiceName) nb_services++;
    services = HeapAlloc( GetProcessHeap(), 0, nb_services * sizeof(*services) );

    for (i = 0; i < nb_services; i++)
    {
        DWORD len = MultiByteToWideChar(CP_ACP, 0, servent[i].lpServiceName, -1, NULL, 0);
        DWORD sz = FIELD_OFFSET( service_data, name[len] );
        info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz );
        MultiByteToWideChar(CP_ACP, 0, servent[i].lpServiceName, -1, info->name, len);
        info->proc.a = servent[i].lpServiceProc;
        info->unicode = FALSE;
        services[i] = info;
    }

    service_run_main_thread();

    return ret;
}

/******************************************************************************
 * StartServiceCtrlDispatcherW [ADVAPI32.@]
 *
 *  Connects a process containing one or more services to the service control
 * manager.
 *
 * PARAMS
 *   servent [I]  A list of the service names and service procedures
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE.
 */
BOOL WINAPI StartServiceCtrlDispatcherW( const SERVICE_TABLE_ENTRYW *servent )
{
    service_data *info;
    unsigned int i;
    BOOL ret = TRUE;

    TRACE("%p\n", servent);

    if (nb_services)
    {
        SetLastError( ERROR_SERVICE_ALREADY_RUNNING );
        return FALSE;
    }
    while (servent[nb_services].lpServiceName) nb_services++;
    services = HeapAlloc( GetProcessHeap(), 0, nb_services * sizeof(*services) );

    for (i = 0; i < nb_services; i++)
    {
        DWORD len = strlenW(servent[i].lpServiceName) + 1;
        DWORD sz = FIELD_OFFSET( service_data, name[len] );
        info = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz );
        strcpyW(info->name, servent[i].lpServiceName);
        info->proc.w = servent[i].lpServiceProc;
        info->unicode = TRUE;
        services[i] = info;
    }

    service_run_main_thread();

    return ret;
}

/******************************************************************************
 * LockServiceDatabase  [ADVAPI32.@]
 */
SC_LOCK WINAPI LockServiceDatabase (SC_HANDLE hSCManager)
{
    struct sc_manager *hscm;
    SC_RPC_LOCK hLock = NULL;
    DWORD err;

    TRACE("%p\n",hSCManager);

    hscm = sc_handle_get_handle_data( hSCManager, SC_HTYPE_MANAGER );
    if (!hscm)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return NULL;
    }

    __TRY
    {
        err = svcctl_LockServiceDatabase(hscm->hdr.server_handle, &hLock);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return NULL;
    }
    return hLock;
}

/******************************************************************************
 * UnlockServiceDatabase  [ADVAPI32.@]
 */
BOOL WINAPI UnlockServiceDatabase (SC_LOCK ScLock)
{
    DWORD err;
    SC_RPC_LOCK hRpcLock = ScLock;

    TRACE("%p\n",ScLock);

    __TRY
    {
        err = svcctl_UnlockServiceDatabase(&hRpcLock);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }
    return TRUE;
}

/******************************************************************************
 * SetServiceStatus [ADVAPI32.@]
 *
 * PARAMS
 *   hService []
 *   lpStatus []
 */
BOOL WINAPI
SetServiceStatus( SERVICE_STATUS_HANDLE hService, LPSERVICE_STATUS lpStatus )
{
    struct sc_service *hsvc;
    DWORD err;

    TRACE("%p %x %x %x %x %x %x %x\n", hService,
          lpStatus->dwServiceType, lpStatus->dwCurrentState,
          lpStatus->dwControlsAccepted, lpStatus->dwWin32ExitCode,
          lpStatus->dwServiceSpecificExitCode, lpStatus->dwCheckPoint,
          lpStatus->dwWaitHint);

    hsvc = sc_handle_get_handle_data((SC_HANDLE)hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }

    __TRY
    {
        err = svcctl_SetServiceStatus( hsvc->hdr.server_handle, lpStatus );
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }

    if (lpStatus->dwCurrentState == SERVICE_STOPPED)
        CloseServiceHandle((SC_HANDLE)hService);

    return TRUE;
}


/******************************************************************************
 * OpenSCManagerA [ADVAPI32.@]
 *
 * Establish a connection to the service control manager and open its database.
 *
 * PARAMS
 *   lpMachineName   [I] Pointer to machine name string
 *   lpDatabaseName  [I] Pointer to database name string
 *   dwDesiredAccess [I] Type of access
 *
 * RETURNS
 *   Success: A Handle to the service control manager database
 *   Failure: NULL
 */
SC_HANDLE WINAPI OpenSCManagerA( LPCSTR lpMachineName, LPCSTR lpDatabaseName,
                                 DWORD dwDesiredAccess )
{
    LPWSTR lpMachineNameW, lpDatabaseNameW;
    SC_HANDLE ret;

    lpMachineNameW = SERV_dup(lpMachineName);
    lpDatabaseNameW = SERV_dup(lpDatabaseName);
    ret = OpenSCManagerW(lpMachineNameW, lpDatabaseNameW, dwDesiredAccess);
    HeapFree(GetProcessHeap(), 0, lpDatabaseNameW);
    HeapFree(GetProcessHeap(), 0, lpMachineNameW);
    return ret;
}

/******************************************************************************
 * OpenSCManagerW [ADVAPI32.@]
 *
 * See OpenSCManagerA.
 */
SC_HANDLE WINAPI OpenSCManagerW( LPCWSTR lpMachineName, LPCWSTR lpDatabaseName,
                                 DWORD dwDesiredAccess )
{
    struct sc_manager *manager;
    HKEY hReg;
    LONG r;
    DWORD new_mask = dwDesiredAccess;

    TRACE("(%s,%s,0x%08x)\n", debugstr_w(lpMachineName),
          debugstr_w(lpDatabaseName), dwDesiredAccess);

    manager = sc_handle_alloc( SC_HTYPE_MANAGER, sizeof (struct sc_manager),
                               sc_handle_destroy_manager );
    if (!manager)
         return NULL;

    __TRY
    {
        r = svcctl_OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess, &manager->hdr.server_handle);
    }
    __EXCEPT(rpc_filter)
    {
        r = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    if (r!=ERROR_SUCCESS)
        goto error;

    r = RegConnectRegistryW(lpMachineName,HKEY_LOCAL_MACHINE,&hReg);
    if (r!=ERROR_SUCCESS)
        goto error;

    r = RegCreateKeyW(hReg, szServiceManagerKey, &manager->hkey);
    RegCloseKey( hReg );
    if (r!=ERROR_SUCCESS)
        goto error;

    RtlMapGenericMask(&new_mask, &scm_generic);
    manager->dwAccess = new_mask;
    TRACE("returning %p (access : 0x%08x)\n", manager, manager->dwAccess);

    return (SC_HANDLE) &manager->hdr;

error:
    sc_handle_free( &manager->hdr );
    SetLastError( r);
    return NULL;
}

/******************************************************************************
 * ControlService [ADVAPI32.@]
 *
 * Send a control code to a service.
 *
 * PARAMS
 *   hService        [I] Handle of the service control manager database
 *   dwControl       [I] Control code to send (SERVICE_CONTROL_* flags from "winsvc.h")
 *   lpServiceStatus [O] Destination for the status of the service, if available
 *
 * RETURNS
 *   Success: TRUE.
 *   Failure: FALSE.
 *
 * BUGS
 *   Unlike M$' implementation, control requests are not serialized and may be
 *   processed asynchronously.
 */
BOOL WINAPI ControlService( SC_HANDLE hService, DWORD dwControl,
                            LPSERVICE_STATUS lpServiceStatus )
{
    struct sc_service *hsvc;
    DWORD err;

    TRACE("%p %d %p\n", hService, dwControl, lpServiceStatus);

    hsvc = sc_handle_get_handle_data(hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }

    __TRY
    {
        err = svcctl_ControlService(hsvc->hdr.server_handle, dwControl, lpServiceStatus);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }

    return TRUE;
}

/******************************************************************************
 * CloseServiceHandle [ADVAPI32.@]
 * 
 * Close a handle to a service or the service control manager database.
 *
 * PARAMS
 *   hSCObject [I] Handle to service or service control manager database
 *
 * RETURNS
 *  Success: TRUE
 *  Failure: FALSE
 */
BOOL WINAPI
CloseServiceHandle( SC_HANDLE hSCObject )
{
    struct sc_handle *obj;
    DWORD err;

    TRACE("%p\n", hSCObject);
    if (hSCObject == NULL)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    obj = (struct sc_handle *)hSCObject;
    __TRY
    {
        err = svcctl_CloseServiceHandle(&obj->server_handle);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    sc_handle_free( obj );

    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }
    return TRUE;
}


/******************************************************************************
 * OpenServiceA [ADVAPI32.@]
 *
 * Open a handle to a service.
 *
 * PARAMS
 *   hSCManager      [I] Handle of the service control manager database
 *   lpServiceName   [I] Name of the service to open
 *   dwDesiredAccess [I] Access required to the service
 *
 * RETURNS
 *    Success: Handle to the service
 *    Failure: NULL
 */
SC_HANDLE WINAPI OpenServiceA( SC_HANDLE hSCManager, LPCSTR lpServiceName,
                               DWORD dwDesiredAccess )
{
    LPWSTR lpServiceNameW;
    SC_HANDLE ret;

    TRACE("%p %s %d\n", hSCManager, debugstr_a(lpServiceName), dwDesiredAccess);

    lpServiceNameW = SERV_dup(lpServiceName);
    ret = OpenServiceW( hSCManager, lpServiceNameW, dwDesiredAccess);
    HeapFree(GetProcessHeap(), 0, lpServiceNameW);
    return ret;
}


/******************************************************************************
 * OpenServiceW [ADVAPI32.@]
 *
 * See OpenServiceA.
 */
SC_HANDLE WINAPI OpenServiceW( SC_HANDLE hSCManager, LPCWSTR lpServiceName,
                               DWORD dwDesiredAccess)
{
    struct sc_manager *hscm;
    struct sc_service *hsvc;
    DWORD err;
    DWORD len;
    DWORD new_mask = dwDesiredAccess;

    TRACE("%p %s %d\n", hSCManager, debugstr_w(lpServiceName), dwDesiredAccess);

    hscm = sc_handle_get_handle_data( hSCManager, SC_HTYPE_MANAGER );
    if (!hscm)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }

    if (!lpServiceName)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return NULL;
    }
    
    len = strlenW(lpServiceName)+1;
    hsvc = sc_handle_alloc( SC_HTYPE_SERVICE,
                            sizeof (struct sc_service) + len*sizeof(WCHAR),
                            sc_handle_destroy_service );
    if (!hsvc)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    strcpyW( hsvc->name, lpServiceName );

    /* add reference to SCM handle */
    hscm->hdr.ref_count++;
    hsvc->scm = hscm;

    __TRY
    {
        err = svcctl_OpenServiceW(hscm->hdr.server_handle, lpServiceName, dwDesiredAccess, &hsvc->hdr.server_handle);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY

    if (err != ERROR_SUCCESS)
    {
        sc_handle_free(&hsvc->hdr);
        SetLastError(err);
        return NULL;
    }

    /* for parts of advapi32 not using services.exe yet */
    RtlMapGenericMask(&new_mask, &svc_generic);
    hsvc->dwAccess = new_mask;

    err = RegOpenKeyExW( hscm->hkey, lpServiceName, 0, KEY_ALL_ACCESS, &hsvc->hkey );
    if (err != ERROR_SUCCESS)
        ERR("Shouldn't hapen - service key for service validated by services.exe doesn't exist\n");

    TRACE("returning %p\n",hsvc);

    return (SC_HANDLE) &hsvc->hdr;
}

/******************************************************************************
 * CreateServiceW [ADVAPI32.@]
 */
SC_HANDLE WINAPI
CreateServiceW( SC_HANDLE hSCManager, LPCWSTR lpServiceName,
                  LPCWSTR lpDisplayName, DWORD dwDesiredAccess,
                  DWORD dwServiceType, DWORD dwStartType,
                  DWORD dwErrorControl, LPCWSTR lpBinaryPathName,
                  LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId,
                  LPCWSTR lpDependencies, LPCWSTR lpServiceStartName,
                  LPCWSTR lpPassword )
{
    struct sc_manager *hscm;
    struct sc_service *hsvc = NULL;
    DWORD new_mask = dwDesiredAccess;
    DWORD len, err;
    SIZE_T passwdlen;

    TRACE("%p %s %s\n", hSCManager, 
          debugstr_w(lpServiceName), debugstr_w(lpDisplayName));

    hscm = sc_handle_get_handle_data( hSCManager, SC_HTYPE_MANAGER );
    if (!hscm)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return NULL;
    }

    if (!lpServiceName || !lpBinaryPathName)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return NULL;
    }

    if (lpPassword)
        passwdlen = (strlenW(lpPassword) + 1) * sizeof(WCHAR);
    else
        passwdlen = 0;

    len = strlenW(lpServiceName)+1;
    len = sizeof (struct sc_service) + len*sizeof(WCHAR);
    hsvc = sc_handle_alloc( SC_HTYPE_SERVICE, len, sc_handle_destroy_service );
    if( !hsvc )
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    lstrcpyW( hsvc->name, lpServiceName );

    hsvc->scm = hscm;
    hscm->hdr.ref_count++;

    __TRY
    {
        err = svcctl_CreateServiceW(hscm->hdr.server_handle, lpServiceName,
                lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl,
                lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, (LPBYTE)lpDependencies,
                multisz_cb(lpDependencies), lpServiceStartName, (LPBYTE)lpPassword, passwdlen,
                &hsvc->hdr.server_handle);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY

    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        sc_handle_free(&hsvc->hdr);
        return NULL;
    }

    /* for parts of advapi32 not using services.exe yet */
    err = RegOpenKeyW(hscm->hkey, lpServiceName, &hsvc->hkey);
    if (err != ERROR_SUCCESS)
        WINE_ERR("Couldn't open key that should have been created by services.exe\n");

    RtlMapGenericMask(&new_mask, &svc_generic);
    hsvc->dwAccess = new_mask;

    return (SC_HANDLE) &hsvc->hdr;
}


/******************************************************************************
 * CreateServiceA [ADVAPI32.@]
 */
SC_HANDLE WINAPI
CreateServiceA( SC_HANDLE hSCManager, LPCSTR lpServiceName,
                  LPCSTR lpDisplayName, DWORD dwDesiredAccess,
                  DWORD dwServiceType, DWORD dwStartType,
                  DWORD dwErrorControl, LPCSTR lpBinaryPathName,
                  LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId,
                  LPCSTR lpDependencies, LPCSTR lpServiceStartName,
                  LPCSTR lpPassword )
{
    LPWSTR lpServiceNameW, lpDisplayNameW, lpBinaryPathNameW,
        lpLoadOrderGroupW, lpDependenciesW, lpServiceStartNameW, lpPasswordW;
    SC_HANDLE r;

    TRACE("%p %s %s\n", hSCManager,
          debugstr_a(lpServiceName), debugstr_a(lpDisplayName));

    lpServiceNameW = SERV_dup( lpServiceName );
    lpDisplayNameW = SERV_dup( lpDisplayName );
    lpBinaryPathNameW = SERV_dup( lpBinaryPathName );
    lpLoadOrderGroupW = SERV_dup( lpLoadOrderGroup );
    lpDependenciesW = SERV_dupmulti( lpDependencies );
    lpServiceStartNameW = SERV_dup( lpServiceStartName );
    lpPasswordW = SERV_dup( lpPassword );

    r = CreateServiceW( hSCManager, lpServiceNameW, lpDisplayNameW,
            dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl,
            lpBinaryPathNameW, lpLoadOrderGroupW, lpdwTagId,
            lpDependenciesW, lpServiceStartNameW, lpPasswordW );

    HeapFree( GetProcessHeap(), 0, lpServiceNameW );
    HeapFree( GetProcessHeap(), 0, lpDisplayNameW );
    HeapFree( GetProcessHeap(), 0, lpBinaryPathNameW );
    HeapFree( GetProcessHeap(), 0, lpLoadOrderGroupW );
    HeapFree( GetProcessHeap(), 0, lpDependenciesW );
    HeapFree( GetProcessHeap(), 0, lpServiceStartNameW );
    HeapFree( GetProcessHeap(), 0, lpPasswordW );

    return r;
}


/******************************************************************************
 * DeleteService [ADVAPI32.@]
 *
 * Delete a service from the service control manager database.
 *
 * PARAMS
 *    hService [I] Handle of the service to delete
 *
 * RETURNS
 *  Success: TRUE
 *  Failure: FALSE
 */
BOOL WINAPI DeleteService( SC_HANDLE hService )
{
    struct sc_service *hsvc;
    DWORD err;

    hsvc = sc_handle_get_handle_data(hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }

    __TRY
    {
        err = svcctl_DeleteService(hsvc->hdr.server_handle);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    if (err != 0)
    {
        SetLastError(err);
        return FALSE;
    }

    /* Close the key to the service */
    RegCloseKey(hsvc->hkey);
    hsvc->hkey = NULL;
    return TRUE;
}


/******************************************************************************
 * StartServiceA [ADVAPI32.@]
 *
 * Start a service
 *
 * PARAMS
 *   hService            [I] Handle of service
 *   dwNumServiceArgs    [I] Number of arguments
 *   lpServiceArgVectors [I] Address of array of argument strings
 *
 * NOTES
 *  - NT implements this function using an obscure RPC call.
 *  - You might need to do a "setenv SystemRoot \\WINNT" in your .cshrc
 *    to get things like "%SystemRoot%\\System32\\service.exe" to load.
 *  - This will only work for shared address space. How should the service
 *    args be transferred when address spaces are separated?
 *  - Can only start one service at a time.
 *  - Has no concept of privilege.
 *
 * RETURNS
 *   Success: TRUE.
 *   Failure: FALSE
 */
BOOL WINAPI StartServiceA( SC_HANDLE hService, DWORD dwNumServiceArgs,
                           LPCSTR *lpServiceArgVectors )
{
    LPWSTR *lpwstr=NULL;
    unsigned int i;
    BOOL r;

    TRACE("(%p,%d,%p)\n",hService,dwNumServiceArgs,lpServiceArgVectors);

    if (dwNumServiceArgs)
        lpwstr = HeapAlloc( GetProcessHeap(), 0,
                                   dwNumServiceArgs*sizeof(LPWSTR) );

    for(i=0; i<dwNumServiceArgs; i++)
        lpwstr[i]=SERV_dup(lpServiceArgVectors[i]);

    r = StartServiceW(hService, dwNumServiceArgs, (LPCWSTR *)lpwstr);

    if (dwNumServiceArgs)
    {
        for(i=0; i<dwNumServiceArgs; i++)
            HeapFree(GetProcessHeap(), 0, lpwstr[i]);
        HeapFree(GetProcessHeap(), 0, lpwstr);
    }

    return r;
}


/******************************************************************************
 * StartServiceW [ADVAPI32.@]
 * 
 * See StartServiceA.
 */
BOOL WINAPI StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs,
                          LPCWSTR *lpServiceArgVectors)
{
    struct sc_service *hsvc;
    DWORD err;

    TRACE("%p %d %p\n", hService, dwNumServiceArgs, lpServiceArgVectors);

    hsvc = sc_handle_get_handle_data(hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    __TRY
    {
        err = svcctl_StartServiceW(hsvc->hdr.server_handle, dwNumServiceArgs, lpServiceArgVectors);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }

    return TRUE;
}

/******************************************************************************
 * QueryServiceStatus [ADVAPI32.@]
 *
 * PARAMS
 *   hService        [I] Handle to service to get information about
 *   lpservicestatus [O] buffer to receive the status information for the service
 *
 */
BOOL WINAPI QueryServiceStatus(SC_HANDLE hService,
                               LPSERVICE_STATUS lpservicestatus)
{
    SERVICE_STATUS_PROCESS SvcStatusData;
    BOOL ret;
    DWORD dummy;

    TRACE("%p %p\n", hService, lpservicestatus);

    ret = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&SvcStatusData,
                                sizeof(SERVICE_STATUS_PROCESS), &dummy);
    if (ret) memcpy(lpservicestatus, &SvcStatusData, sizeof(SERVICE_STATUS)) ;
    return ret;
}


/******************************************************************************
 * QueryServiceStatusEx [ADVAPI32.@]
 *
 * Get information about a service.
 *
 * PARAMS
 *   hService       [I] Handle to service to get information about
 *   InfoLevel      [I] Level of information to get
 *   lpBuffer       [O] Destination for requested information
 *   cbBufSize      [I] Size of lpBuffer in bytes
 *   pcbBytesNeeded [O] Destination for number of bytes needed, if cbBufSize is too small
 *
 * RETURNS
 *  Success: TRUE
 *  FAILURE: FALSE
 */
BOOL WINAPI QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE InfoLevel,
                        LPBYTE lpBuffer, DWORD cbBufSize,
                        LPDWORD pcbBytesNeeded)
{
    struct sc_service *hsvc;
    DWORD err;

    TRACE("%p %d %p %d %p\n", hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);

    hsvc = sc_handle_get_handle_data(hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }

    __TRY
    {
        err = svcctl_QueryServiceStatusEx(hsvc->hdr.server_handle, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY
    if (err != ERROR_SUCCESS)
    {
        SetLastError(err);
        return FALSE;
    }

    return TRUE;
}

/******************************************************************************
 * QueryServiceConfigA [ADVAPI32.@]
 */
BOOL WINAPI QueryServiceConfigA( SC_HANDLE hService, LPQUERY_SERVICE_CONFIGA config,
                                 DWORD size, LPDWORD needed )
{
    DWORD n;
    LPSTR p, buffer;
    BOOL ret;
    QUERY_SERVICE_CONFIGW *configW;

    TRACE("%p %p %d %p\n", hService, config, size, needed);

    if (!(buffer = HeapAlloc( GetProcessHeap(), 0, 2 * size )))
    {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return FALSE;
    }
    configW = (QUERY_SERVICE_CONFIGW *)buffer;
    ret = QueryServiceConfigW( hService, configW, 2 * size, needed );
    if (!ret) goto done;

    config->dwServiceType      = configW->dwServiceType;
    config->dwStartType        = configW->dwStartType;
    config->dwErrorControl     = configW->dwErrorControl;
    config->lpBinaryPathName   = NULL;
    config->lpLoadOrderGroup   = NULL;
    config->dwTagId            = configW->dwTagId;
    config->lpDependencies     = NULL;
    config->lpServiceStartName = NULL;
    config->lpDisplayName      = NULL;

    p = (LPSTR)(config + 1);
    n = size - sizeof(*config);
    ret = FALSE;

#define MAP_STR(str) \
    do { \
        if (configW->str) \
        { \
            DWORD sz = WideCharToMultiByte( CP_ACP, 0, configW->str, -1, p, n, NULL, NULL ); \
            if (!sz) goto done; \
            config->str = p; \
            p += sz; \
            n -= sz; \
        } \
    } while (0)

    MAP_STR( lpBinaryPathName );
    MAP_STR( lpLoadOrderGroup );
    MAP_STR( lpDependencies );
    MAP_STR( lpServiceStartName );
    MAP_STR( lpDisplayName );
#undef MAP_STR

    *needed = p - (LPSTR)config;
    ret = TRUE;

done:
    HeapFree( GetProcessHeap(), 0, buffer );
    return ret;
}

static DWORD move_string_to_buffer(BYTE **buf, LPWSTR *string_ptr)
{
    DWORD cb;

    if (!*string_ptr)
    {
        cb = sizeof(WCHAR);
        memset(*buf, 0, cb);
    }
    else
    {
        cb = (strlenW(*string_ptr) + 1)*sizeof(WCHAR);
        memcpy(*buf, *string_ptr, cb);
        MIDL_user_free(*string_ptr);
    }

    *string_ptr = (LPWSTR)*buf;
    *buf += cb;

    return cb;
}

static DWORD size_string(LPWSTR string)
{
    return (string ? (strlenW(string) + 1)*sizeof(WCHAR) : sizeof(WCHAR));
}

/******************************************************************************
 * QueryServiceConfigW [ADVAPI32.@]
 */
BOOL WINAPI 
QueryServiceConfigW( SC_HANDLE hService,
                     LPQUERY_SERVICE_CONFIGW lpServiceConfig,
                     DWORD cbBufSize, LPDWORD pcbBytesNeeded)
{
    QUERY_SERVICE_CONFIGW config;
    struct sc_service *hsvc;
    DWORD total;
    DWORD err;
    BYTE *bufpos;

    TRACE("%p %p %d %p\n", hService, lpServiceConfig,
           cbBufSize, pcbBytesNeeded);

    hsvc = sc_handle_get_handle_data(hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }

    memset(&config, 0, sizeof(config));

    __TRY
    {
        err = svcctl_QueryServiceConfigW(hsvc->hdr.server_handle, &config);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY

    if (err != ERROR_SUCCESS)
    {
        TRACE("services.exe: error %u\n", err);
        SetLastError(err);
        return FALSE;
    }

    /* calculate the size required first */
    total = sizeof (QUERY_SERVICE_CONFIGW);
    total += size_string(config.lpBinaryPathName);
    total += size_string(config.lpLoadOrderGroup);
    total += size_string(config.lpDependencies);
    total += size_string(config.lpServiceStartName);
    total += size_string(config.lpDisplayName);

    *pcbBytesNeeded = total;

    /* if there's not enough memory, return an error */
    if( total > cbBufSize )
    {
        SetLastError( ERROR_INSUFFICIENT_BUFFER );
        MIDL_user_free(config.lpBinaryPathName);
        MIDL_user_free(config.lpLoadOrderGroup);
        MIDL_user_free(config.lpDependencies);
        MIDL_user_free(config.lpServiceStartName);
        MIDL_user_free(config.lpDisplayName);
        return FALSE;
    }

    *lpServiceConfig = config;
    bufpos = ((BYTE *)lpServiceConfig) + sizeof(QUERY_SERVICE_CONFIGW);
    move_string_to_buffer(&bufpos, &lpServiceConfig->lpBinaryPathName);
    move_string_to_buffer(&bufpos, &lpServiceConfig->lpLoadOrderGroup);
    move_string_to_buffer(&bufpos, &lpServiceConfig->lpDependencies);
    move_string_to_buffer(&bufpos, &lpServiceConfig->lpServiceStartName);
    move_string_to_buffer(&bufpos, &lpServiceConfig->lpDisplayName);

    if (bufpos - (LPBYTE)lpServiceConfig > cbBufSize)
        ERR("Buffer overflow!\n");

    TRACE("Image path           = %s\n", debugstr_w(lpServiceConfig->lpBinaryPathName) );
    TRACE("Group                = %s\n", debugstr_w(lpServiceConfig->lpLoadOrderGroup) );
    TRACE("Dependencies         = %s\n", debugstr_w(lpServiceConfig->lpDependencies) );
    TRACE("Service account name = %s\n", debugstr_w(lpServiceConfig->lpServiceStartName) );
    TRACE("Display name         = %s\n", debugstr_w(lpServiceConfig->lpDisplayName) );

    return TRUE;
}

/******************************************************************************
 * QueryServiceConfig2A [ADVAPI32.@]
 *
 * Note
 *   observed under win2k:
 *   The functions QueryServiceConfig2A and QueryServiceConfig2W return the same
 *   required buffer size (in byte) at least for dwLevel SERVICE_CONFIG_DESCRIPTION
 */
BOOL WINAPI QueryServiceConfig2A(SC_HANDLE hService, DWORD dwLevel, LPBYTE buffer,
                                 DWORD size, LPDWORD needed)
{
    BOOL ret;
    LPBYTE bufferW = NULL;

    if(buffer && size)
        bufferW = HeapAlloc( GetProcessHeap(), 0, size);

    ret = QueryServiceConfig2W(hService, dwLevel, bufferW, size, needed);
    if(!ret) goto cleanup;

    switch(dwLevel) {
        case SERVICE_CONFIG_DESCRIPTION:
            {   LPSERVICE_DESCRIPTIONA configA = (LPSERVICE_DESCRIPTIONA) buffer;
                LPSERVICE_DESCRIPTIONW configW = (LPSERVICE_DESCRIPTIONW) bufferW;
                if (configW->lpDescription) {
                    DWORD sz;
                    configA->lpDescription = (LPSTR)(configA + 1);
                    sz = WideCharToMultiByte( CP_ACP, 0, configW->lpDescription, -1,
                             configA->lpDescription, size - sizeof(SERVICE_DESCRIPTIONA), NULL, NULL );
                    if (!sz) {
                        FIXME("WideCharToMultiByte failed for configW->lpDescription\n");
                        ret = FALSE;
                        configA->lpDescription = NULL;
                    }
                }
                else configA->lpDescription = NULL;
            }
        break;
        default:
            FIXME("conversation W->A not implemented for level %d\n", dwLevel);
            ret = FALSE;
    }

cleanup:
    HeapFree( GetProcessHeap(), 0, bufferW);
    return ret;
}

/******************************************************************************
 * QueryServiceConfig2W [ADVAPI32.@]
 */
BOOL WINAPI QueryServiceConfig2W(SC_HANDLE hService, DWORD dwLevel, LPBYTE buffer,
                                 DWORD size, LPDWORD needed)
{
    DWORD sz, type;
    HKEY hKey;
    LONG r;
    struct sc_service *hsvc;

    if(dwLevel != SERVICE_CONFIG_DESCRIPTION) {
        if((dwLevel == SERVICE_CONFIG_DELAYED_AUTO_START_INFO) ||
           (dwLevel == SERVICE_CONFIG_FAILURE_ACTIONS) ||
           (dwLevel == SERVICE_CONFIG_FAILURE_ACTIONS_FLAG) ||
           (dwLevel == SERVICE_CONFIG_PRESHUTDOWN_INFO) ||
           (dwLevel == SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO) ||
           (dwLevel == SERVICE_CONFIG_SERVICE_SID_INFO))
            FIXME("Level %d not implemented\n", dwLevel);
        SetLastError(ERROR_INVALID_LEVEL);
        return FALSE;
    }
    if(!needed || (!buffer && size)) {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

    TRACE("%p 0x%d %p 0x%d %p\n", hService, dwLevel, buffer, size, needed);

    hsvc = sc_handle_get_handle_data(hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    hKey = hsvc->hkey;

    switch(dwLevel) {
        case SERVICE_CONFIG_DESCRIPTION: {
            static const WCHAR szDescription[] = {'D','e','s','c','r','i','p','t','i','o','n',0};
            LPSERVICE_DESCRIPTIONW config = (LPSERVICE_DESCRIPTIONW) buffer;
            LPBYTE strbuf = NULL;
            *needed = sizeof (SERVICE_DESCRIPTIONW);
            sz = size - *needed;
            if(config && (*needed <= size))
                strbuf = (LPBYTE) (config + 1);
            r = RegQueryValueExW( hKey, szDescription, 0, &type, strbuf, &sz );
            if((r == ERROR_SUCCESS) && ( type != REG_SZ)) {
                FIXME("SERVICE_CONFIG_DESCRIPTION: don't know how to handle type %d\n", type);
                return FALSE;
            }
            *needed += sz;
            if(config) {
                if(r == ERROR_SUCCESS)
                    config->lpDescription = (LPWSTR) (config + 1);
                else
                    config->lpDescription = NULL;
            }
        }
        break;
    }
    if(*needed > size)
        SetLastError(ERROR_INSUFFICIENT_BUFFER);

    return (*needed <= size);
}

/******************************************************************************
 * EnumServicesStatusA [ADVAPI32.@]
 */
BOOL WINAPI
EnumServicesStatusA( SC_HANDLE hSCManager, DWORD dwServiceType,
                     DWORD dwServiceState, LPENUM_SERVICE_STATUSA lpServices,
                     DWORD cbBufSize, LPDWORD pcbBytesNeeded,
                     LPDWORD lpServicesReturned, LPDWORD lpResumeHandle )
{
    FIXME("%p type=%x state=%x %p %x %p %p %p\n", hSCManager,
          dwServiceType, dwServiceState, lpServices, cbBufSize,
          pcbBytesNeeded, lpServicesReturned,  lpResumeHandle);
    SetLastError (ERROR_ACCESS_DENIED);
    return FALSE;
}

/******************************************************************************
 * EnumServicesStatusW [ADVAPI32.@]
 */
BOOL WINAPI
EnumServicesStatusW( SC_HANDLE hSCManager, DWORD dwServiceType,
                     DWORD dwServiceState, LPENUM_SERVICE_STATUSW lpServices,
                     DWORD cbBufSize, LPDWORD pcbBytesNeeded,
                     LPDWORD lpServicesReturned, LPDWORD lpResumeHandle )
{
    FIXME("%p type=%x state=%x %p %x %p %p %p\n", hSCManager,
          dwServiceType, dwServiceState, lpServices, cbBufSize,
          pcbBytesNeeded, lpServicesReturned,  lpResumeHandle);
    SetLastError (ERROR_ACCESS_DENIED);
    return FALSE;
}

/******************************************************************************
 * EnumServicesStatusExA [ADVAPI32.@]
 */
BOOL WINAPI
EnumServicesStatusExA(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType,
                      DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded,
                      LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName)
{
    FIXME("%p level=%d type=%x state=%x %p %x %p %p %p %s\n", hSCManager, InfoLevel,
          dwServiceType, dwServiceState, lpServices, cbBufSize,
          pcbBytesNeeded, lpServicesReturned,  lpResumeHandle, debugstr_a(pszGroupName));
    *lpServicesReturned = 0;
    SetLastError (ERROR_ACCESS_DENIED);
    return FALSE;
}

/******************************************************************************
 * EnumServicesStatusExW [ADVAPI32.@]
 */
BOOL WINAPI
EnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType,
                      DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded,
                      LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName)
{
    FIXME("%p level=%d type=%x state=%x %p %x %p %p %p %s\n", hSCManager, InfoLevel,
          dwServiceType, dwServiceState, lpServices, cbBufSize,
          pcbBytesNeeded, lpServicesReturned,  lpResumeHandle, debugstr_w(pszGroupName));
    SetLastError (ERROR_ACCESS_DENIED);
    return FALSE;
}

/******************************************************************************
 * GetServiceKeyNameA [ADVAPI32.@]
 */
BOOL WINAPI GetServiceKeyNameA( SC_HANDLE hSCManager, LPCSTR lpDisplayName,
                                LPSTR lpServiceName, LPDWORD lpcchBuffer )
{
    LPWSTR lpDisplayNameW, lpServiceNameW;
    DWORD sizeW;
    BOOL ret = FALSE;

    TRACE("%p %s %p %p\n", hSCManager,
          debugstr_a(lpDisplayName), lpServiceName, lpcchBuffer);

    lpDisplayNameW = SERV_dup(lpDisplayName);
    if (lpServiceName)
        lpServiceNameW = HeapAlloc(GetProcessHeap(), 0, *lpcchBuffer * sizeof(WCHAR));
    else
        lpServiceNameW = NULL;

    sizeW = *lpcchBuffer;
    if (!GetServiceKeyNameW(hSCManager, lpDisplayNameW, lpServiceNameW, &sizeW))
    {
        if (*lpcchBuffer && lpServiceName)
            lpServiceName[0] = 0;
        *lpcchBuffer = sizeW*2;  /* we can only provide an upper estimation of string length */
        goto cleanup;
    }

    if (!WideCharToMultiByte(CP_ACP, 0, lpServiceNameW, (sizeW + 1), lpServiceName,
                        *lpcchBuffer, NULL, NULL ))
    {
        if (*lpcchBuffer && lpServiceName)
            lpServiceName[0] = 0;
        *lpcchBuffer = WideCharToMultiByte(CP_ACP, 0, lpServiceNameW, -1, NULL, 0, NULL, NULL);
        goto cleanup;
    }

    /* lpcchBuffer not updated - same as in GetServiceDisplayNameA */
    ret = TRUE;

cleanup:
    HeapFree(GetProcessHeap(), 0, lpServiceNameW);
    HeapFree(GetProcessHeap(), 0, lpDisplayNameW);
    return ret;
}

/******************************************************************************
 * GetServiceKeyNameW [ADVAPI32.@]
 */
BOOL WINAPI GetServiceKeyNameW( SC_HANDLE hSCManager, LPCWSTR lpDisplayName,
                                LPWSTR lpServiceName, LPDWORD lpcchBuffer )
{
    struct sc_manager *hscm;
    DWORD err;

    TRACE("%p %s %p %p\n", hSCManager,
          debugstr_w(lpServiceName), lpDisplayName, lpcchBuffer);

    hscm = sc_handle_get_handle_data(hSCManager, SC_HTYPE_MANAGER);
    if (!hscm)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (!lpDisplayName)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

    __TRY
    {
        err = svcctl_GetServiceKeyNameW(hscm->hdr.server_handle,
                lpDisplayName, lpServiceName, lpServiceName ? *lpcchBuffer : 0, lpcchBuffer);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY

    if (err)
        SetLastError(err);
    return err == ERROR_SUCCESS;
}

/******************************************************************************
 * QueryServiceLockStatusA [ADVAPI32.@]
 */
BOOL WINAPI QueryServiceLockStatusA( SC_HANDLE hSCManager,
                                     LPQUERY_SERVICE_LOCK_STATUSA lpLockStatus,
                                     DWORD cbBufSize, LPDWORD pcbBytesNeeded)
{
    FIXME("%p %p %08x %p\n", hSCManager, lpLockStatus, cbBufSize, pcbBytesNeeded);

    return FALSE;
}

/******************************************************************************
 * QueryServiceLockStatusW [ADVAPI32.@]
 */
BOOL WINAPI QueryServiceLockStatusW( SC_HANDLE hSCManager,
                                     LPQUERY_SERVICE_LOCK_STATUSW lpLockStatus,
                                     DWORD cbBufSize, LPDWORD pcbBytesNeeded)
{
    FIXME("%p %p %08x %p\n", hSCManager, lpLockStatus, cbBufSize, pcbBytesNeeded);

    return FALSE;
}

/******************************************************************************
 * GetServiceDisplayNameA  [ADVAPI32.@]
 */
BOOL WINAPI GetServiceDisplayNameA( SC_HANDLE hSCManager, LPCSTR lpServiceName,
  LPSTR lpDisplayName, LPDWORD lpcchBuffer)
{
    LPWSTR lpServiceNameW, lpDisplayNameW;
    DWORD sizeW;
    BOOL ret = FALSE;

    TRACE("%p %s %p %p\n", hSCManager,
          debugstr_a(lpServiceName), lpDisplayName, lpcchBuffer);

    lpServiceNameW = SERV_dup(lpServiceName);
    if (lpDisplayName)
        lpDisplayNameW = HeapAlloc(GetProcessHeap(), 0, *lpcchBuffer * sizeof(WCHAR));
    else
        lpDisplayNameW = NULL;

    sizeW = *lpcchBuffer;
    if (!GetServiceDisplayNameW(hSCManager, lpServiceNameW, lpDisplayNameW, &sizeW))
    {
        if (*lpcchBuffer && lpDisplayName)
            lpDisplayName[0] = 0;
        *lpcchBuffer = sizeW*2;  /* we can only provide an upper estimation of string length */
        goto cleanup;
    }

    if (!WideCharToMultiByte(CP_ACP, 0, lpDisplayNameW, (sizeW + 1), lpDisplayName,
                        *lpcchBuffer, NULL, NULL ))
    {
        if (*lpcchBuffer && lpDisplayName)
            lpDisplayName[0] = 0;
        *lpcchBuffer = WideCharToMultiByte(CP_ACP, 0, lpDisplayNameW, -1, NULL, 0, NULL, NULL);
        goto cleanup;
    }

    /* probably due to a bug GetServiceDisplayNameA doesn't modify lpcchBuffer on success.
     * (but if the function succeeded it means that is a good upper estimation of the size) */
    ret = TRUE;

cleanup:
    HeapFree(GetProcessHeap(), 0, lpDisplayNameW);
    HeapFree(GetProcessHeap(), 0, lpServiceNameW);
    return ret;
}

/******************************************************************************
 * GetServiceDisplayNameW  [ADVAPI32.@]
 */
BOOL WINAPI GetServiceDisplayNameW( SC_HANDLE hSCManager, LPCWSTR lpServiceName,
  LPWSTR lpDisplayName, LPDWORD lpcchBuffer)
{
    struct sc_manager *hscm;
    DWORD err;

    TRACE("%p %s %p %p\n", hSCManager,
          debugstr_w(lpServiceName), lpDisplayName, lpcchBuffer);

    hscm = sc_handle_get_handle_data(hSCManager, SC_HTYPE_MANAGER);
    if (!hscm)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (!lpServiceName)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

    __TRY
    {
        err = svcctl_GetServiceDisplayNameW(hscm->hdr.server_handle,
                lpServiceName, lpDisplayName, lpDisplayName ? *lpcchBuffer : 0, lpcchBuffer);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY

    if (err)
        SetLastError(err);
    return err == ERROR_SUCCESS;
}

/******************************************************************************
 * ChangeServiceConfigW  [ADVAPI32.@]
 */
BOOL WINAPI ChangeServiceConfigW( SC_HANDLE hService, DWORD dwServiceType,
  DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName,
  LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies,
  LPCWSTR lpServiceStartName, LPCWSTR lpPassword, LPCWSTR lpDisplayName)
{
    struct sc_service *hsvc;
    DWORD cb_pwd;
    DWORD err;

    TRACE("%p %d %d %d %s %s %p %p %s %s %s\n",
          hService, dwServiceType, dwStartType, dwErrorControl, 
          debugstr_w(lpBinaryPathName), debugstr_w(lpLoadOrderGroup),
          lpdwTagId, lpDependencies, debugstr_w(lpServiceStartName),
          debugstr_w(lpPassword), debugstr_w(lpDisplayName) );

    hsvc = sc_handle_get_handle_data(hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }

    cb_pwd = lpPassword ? (strlenW(lpPassword) + 1)*sizeof(WCHAR) : 0;

    __TRY
    {
        err = svcctl_ChangeServiceConfigW(hsvc->hdr.server_handle, dwServiceType,
                dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId,
                (const BYTE *)lpDependencies, multisz_cb(lpDependencies), lpServiceStartName,
                (const BYTE *)lpPassword, cb_pwd, lpDisplayName);
    }
    __EXCEPT(rpc_filter)
    {
        err = map_exception_code(GetExceptionCode());
    }
    __ENDTRY

    if (err != ERROR_SUCCESS)
        SetLastError(err);

    return err == ERROR_SUCCESS;
}

/******************************************************************************
 * ChangeServiceConfigA  [ADVAPI32.@]
 */
BOOL WINAPI ChangeServiceConfigA( SC_HANDLE hService, DWORD dwServiceType,
  DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName,
  LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies,
  LPCSTR lpServiceStartName, LPCSTR lpPassword, LPCSTR lpDisplayName)
{
    LPWSTR wBinaryPathName, wLoadOrderGroup, wDependencies;
    LPWSTR wServiceStartName, wPassword, wDisplayName;
    BOOL r;

    TRACE("%p %d %d %d %s %s %p %p %s %s %s\n",
          hService, dwServiceType, dwStartType, dwErrorControl, 
          debugstr_a(lpBinaryPathName), debugstr_a(lpLoadOrderGroup),
          lpdwTagId, lpDependencies, debugstr_a(lpServiceStartName),
          debugstr_a(lpPassword), debugstr_a(lpDisplayName) );

    wBinaryPathName = SERV_dup( lpBinaryPathName );
    wLoadOrderGroup = SERV_dup( lpLoadOrderGroup );
    wDependencies = SERV_dupmulti( lpDependencies );
    wServiceStartName = SERV_dup( lpServiceStartName );
    wPassword = SERV_dup( lpPassword );
    wDisplayName = SERV_dup( lpDisplayName );

    r = ChangeServiceConfigW( hService, dwServiceType,
            dwStartType, dwErrorControl, wBinaryPathName,
            wLoadOrderGroup, lpdwTagId, wDependencies,
            wServiceStartName, wPassword, wDisplayName);

    HeapFree( GetProcessHeap(), 0, wBinaryPathName );
    HeapFree( GetProcessHeap(), 0, wLoadOrderGroup );
    HeapFree( GetProcessHeap(), 0, wDependencies );
    HeapFree( GetProcessHeap(), 0, wServiceStartName );
    HeapFree( GetProcessHeap(), 0, wPassword );
    HeapFree( GetProcessHeap(), 0, wDisplayName );

    return r;
}

/******************************************************************************
 * ChangeServiceConfig2A  [ADVAPI32.@]
 */
BOOL WINAPI ChangeServiceConfig2A( SC_HANDLE hService, DWORD dwInfoLevel, 
    LPVOID lpInfo)
{
    BOOL r = FALSE;

    TRACE("%p %d %p\n",hService, dwInfoLevel, lpInfo);

    if (dwInfoLevel == SERVICE_CONFIG_DESCRIPTION)
    {
        LPSERVICE_DESCRIPTIONA sd = (LPSERVICE_DESCRIPTIONA) lpInfo;
        SERVICE_DESCRIPTIONW sdw;

        sdw.lpDescription = SERV_dup( sd->lpDescription );

        r = ChangeServiceConfig2W( hService, dwInfoLevel, &sdw );

        HeapFree( GetProcessHeap(), 0, sdw.lpDescription );
    }
    else if (dwInfoLevel == SERVICE_CONFIG_FAILURE_ACTIONS)
    {
        LPSERVICE_FAILURE_ACTIONSA fa = (LPSERVICE_FAILURE_ACTIONSA) lpInfo;
        SERVICE_FAILURE_ACTIONSW faw;

        faw.dwResetPeriod = fa->dwResetPeriod;
        faw.lpRebootMsg = SERV_dup( fa->lpRebootMsg );
        faw.lpCommand = SERV_dup( fa->lpCommand );
        faw.cActions = fa->cActions;
        faw.lpsaActions = fa->lpsaActions;

        r = ChangeServiceConfig2W( hService, dwInfoLevel, &faw );

        HeapFree( GetProcessHeap(), 0, faw.lpRebootMsg );
        HeapFree( GetProcessHeap(), 0, faw.lpCommand );
    }
    else
        SetLastError( ERROR_INVALID_PARAMETER );

    return r;
}

/******************************************************************************
 * ChangeServiceConfig2W  [ADVAPI32.@]
 */
BOOL WINAPI ChangeServiceConfig2W( SC_HANDLE hService, DWORD dwInfoLevel, 
    LPVOID lpInfo)
{
    HKEY hKey;
    struct sc_service *hsvc;

    hsvc = sc_handle_get_handle_data(hService, SC_HTYPE_SERVICE);
    if (!hsvc)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }
    hKey = hsvc->hkey;

    if (dwInfoLevel == SERVICE_CONFIG_DESCRIPTION)
    {
        static const WCHAR szDescription[] = {'D','e','s','c','r','i','p','t','i','o','n',0};
        LPSERVICE_DESCRIPTIONW sd = (LPSERVICE_DESCRIPTIONW)lpInfo;
        if (sd->lpDescription)
        {
            TRACE("Setting Description to %s\n",debugstr_w(sd->lpDescription));
            if (sd->lpDescription[0] == 0)
                RegDeleteValueW(hKey,szDescription);
            else
                RegSetValueExW(hKey, szDescription, 0, REG_SZ,
                                        (LPVOID)sd->lpDescription,
                                 sizeof(WCHAR)*(strlenW(sd->lpDescription)+1));
        }
    }
    else   
        FIXME("STUB: %p %d %p\n",hService, dwInfoLevel, lpInfo);
    return TRUE;
}

/******************************************************************************
 * QueryServiceObjectSecurity [ADVAPI32.@]
 */
BOOL WINAPI QueryServiceObjectSecurity(SC_HANDLE hService,
       SECURITY_INFORMATION dwSecurityInformation,
       PSECURITY_DESCRIPTOR lpSecurityDescriptor,
       DWORD cbBufSize, LPDWORD pcbBytesNeeded)
{
    SECURITY_DESCRIPTOR descriptor;
    DWORD size;
    BOOL succ;
    ACL acl;

    FIXME("%p %d %p %u %p - semi-stub\n", hService, dwSecurityInformation,
          lpSecurityDescriptor, cbBufSize, pcbBytesNeeded);

    if (dwSecurityInformation != DACL_SECURITY_INFORMATION)
        FIXME("information %d not supported\n", dwSecurityInformation);

    InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);

    InitializeAcl(&acl, sizeof(ACL), ACL_REVISION);
    SetSecurityDescriptorDacl(&descriptor, TRUE, &acl, TRUE);

    size = cbBufSize;
    succ = MakeSelfRelativeSD(&descriptor, lpSecurityDescriptor, &size);
    *pcbBytesNeeded = size;
    return succ;
}

/******************************************************************************
 * SetServiceObjectSecurity [ADVAPI32.@]
 */
BOOL WINAPI SetServiceObjectSecurity(SC_HANDLE hService,
       SECURITY_INFORMATION dwSecurityInformation,
       PSECURITY_DESCRIPTOR lpSecurityDescriptor)
{
    FIXME("%p %d %p\n", hService, dwSecurityInformation, lpSecurityDescriptor);
    return TRUE;
}

/******************************************************************************
 * SetServiceBits [ADVAPI32.@]
 */
BOOL WINAPI SetServiceBits( SERVICE_STATUS_HANDLE hServiceStatus,
        DWORD dwServiceBits,
        BOOL bSetBitsOn,
        BOOL bUpdateImmediately)
{
    FIXME("%p %08x %x %x\n", hServiceStatus, dwServiceBits,
          bSetBitsOn, bUpdateImmediately);
    return TRUE;
}

/* thunk for calling the RegisterServiceCtrlHandler handler function */
static DWORD WINAPI ctrl_handler_thunk( DWORD control, DWORD type, void *data, void *context )
{
    LPHANDLER_FUNCTION func = context;

    func( control );
    return ERROR_SUCCESS;
}

/******************************************************************************
 * RegisterServiceCtrlHandlerA [ADVAPI32.@]
 */
SERVICE_STATUS_HANDLE WINAPI RegisterServiceCtrlHandlerA( LPCSTR name, LPHANDLER_FUNCTION handler )
{
    return RegisterServiceCtrlHandlerExA( name, ctrl_handler_thunk, handler );
}

/******************************************************************************
 * RegisterServiceCtrlHandlerW [ADVAPI32.@]
 */
SERVICE_STATUS_HANDLE WINAPI RegisterServiceCtrlHandlerW( LPCWSTR name, LPHANDLER_FUNCTION handler )
{
    return RegisterServiceCtrlHandlerExW( name, ctrl_handler_thunk, handler );
}

/******************************************************************************
 * RegisterServiceCtrlHandlerExA [ADVAPI32.@]
 */
SERVICE_STATUS_HANDLE WINAPI RegisterServiceCtrlHandlerExA( LPCSTR name, LPHANDLER_FUNCTION_EX handler, LPVOID context )
{
    LPWSTR nameW;
    SERVICE_STATUS_HANDLE ret;

    nameW = SERV_dup(name);
    ret = RegisterServiceCtrlHandlerExW( nameW, handler, context );
    HeapFree( GetProcessHeap(), 0, nameW );
    return ret;
}

/******************************************************************************
 * RegisterServiceCtrlHandlerExW [ADVAPI32.@]
 */
SERVICE_STATUS_HANDLE WINAPI RegisterServiceCtrlHandlerExW( LPCWSTR lpServiceName,
        LPHANDLER_FUNCTION_EX lpHandlerProc, LPVOID lpContext )
{
    service_data *service;
    SC_HANDLE hService = 0;
    BOOL found = FALSE;

    TRACE("%s %p %p\n", debugstr_w(lpServiceName), lpHandlerProc, lpContext);

    EnterCriticalSection( &service_cs );
    if ((service = find_service_by_name( lpServiceName )))
    {
        service->handler = lpHandlerProc;
        service->context = lpContext;
        hService = service->handle;
        found = TRUE;
    }
    LeaveCriticalSection( &service_cs );

    if (!found) SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);

    return (SERVICE_STATUS_HANDLE)hService;
}

/******************************************************************************
 * EnumDependentServicesA [ADVAPI32.@]
 */
BOOL WINAPI EnumDependentServicesA( SC_HANDLE hService, DWORD dwServiceState,
                                    LPENUM_SERVICE_STATUSA lpServices, DWORD cbBufSize,
        LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned )
{
    FIXME("%p 0x%08x %p 0x%08x %p %p - stub\n", hService, dwServiceState,
          lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned);

    *lpServicesReturned = 0;
    return TRUE;
}

/******************************************************************************
 * EnumDependentServicesW [ADVAPI32.@]
 */
BOOL WINAPI EnumDependentServicesW( SC_HANDLE hService, DWORD dwServiceState,
                                    LPENUM_SERVICE_STATUSW lpServices, DWORD cbBufSize,
                                    LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned )
{
    FIXME("%p 0x%08x %p 0x%08x %p %p - stub\n", hService, dwServiceState,
          lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned);

    *lpServicesReturned = 0;
    return TRUE;
}
