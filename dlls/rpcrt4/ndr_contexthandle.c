/*
 * NDR data marshalling
 *
 * Copyright 2006 Mike McCormack (for CodeWeavers)
 * Copyright 2006-2007 Robert Shearman (for CodeWeavers)
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

#include "ndr_misc.h"
#include "rpc_assoc.h"
#include "rpcndr.h"

#include "wine/rpcfc.h"

#include "wine/debug.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(ole);

#define NDR_CONTEXT_HANDLE_MAGIC 0x4352444e

typedef struct ndr_context_handle
{
    ULONG      attributes;
    GUID       uuid;
} ndr_context_handle;

struct context_handle_entry
{
    struct list entry;
    DWORD magic;
    RPC_BINDING_HANDLE handle;
    ndr_context_handle wire_data;
};

static struct list context_handle_list = LIST_INIT(context_handle_list);

static CRITICAL_SECTION ndr_context_cs;
static CRITICAL_SECTION_DEBUG ndr_context_debug =
{
    0, 0, &ndr_context_cs,
    { &ndr_context_debug.ProcessLocksList, &ndr_context_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": ndr_context") }
};
static CRITICAL_SECTION ndr_context_cs = { &ndr_context_debug, -1, 0, 0, 0, 0 };

static struct context_handle_entry *get_context_entry(NDR_CCONTEXT CContext)
{
    struct context_handle_entry *che = (struct context_handle_entry*) CContext;

    if (che->magic != NDR_CONTEXT_HANDLE_MAGIC)
        return NULL;
    return che;
}

static struct context_handle_entry *context_entry_from_guid(LPCGUID uuid)
{
    struct context_handle_entry *che;
    LIST_FOR_EACH_ENTRY(che, &context_handle_list, struct context_handle_entry, entry)
        if (IsEqualGUID(&che->wire_data.uuid, uuid))
            return che;
    return NULL;
}

RPC_BINDING_HANDLE WINAPI NDRCContextBinding(NDR_CCONTEXT CContext)
{
    struct context_handle_entry *che;
    RPC_BINDING_HANDLE handle = NULL;

    TRACE("%p\n", CContext);

    EnterCriticalSection(&ndr_context_cs);
    che = get_context_entry(CContext);
    if (che)
        handle = che->handle;
    LeaveCriticalSection(&ndr_context_cs);

    if (!handle)
        RpcRaiseException(ERROR_INVALID_HANDLE);
    return handle;
}

void WINAPI NDRCContextMarshall(NDR_CCONTEXT CContext, void *pBuff)
{
    struct context_handle_entry *che;

    TRACE("%p %p\n", CContext, pBuff);

    if (CContext)
    {
        EnterCriticalSection(&ndr_context_cs);
        che = get_context_entry(CContext);
        memcpy(pBuff, &che->wire_data, sizeof (ndr_context_handle));
        LeaveCriticalSection(&ndr_context_cs);
    }
    else
    {
        ndr_context_handle *wire_data = (ndr_context_handle *)pBuff;
        wire_data->attributes = 0;
        wire_data->uuid = GUID_NULL;
    }
}

/***********************************************************************
 *           RpcSmDestroyClientContext [RPCRT4.@]
 */
RPC_STATUS WINAPI RpcSmDestroyClientContext(void **ContextHandle)
{
    RPC_STATUS status = RPC_X_SS_CONTEXT_MISMATCH;
    struct context_handle_entry *che = NULL;

    TRACE("(%p)\n", ContextHandle);

    EnterCriticalSection(&ndr_context_cs);
    che = get_context_entry(*ContextHandle);
    *ContextHandle = NULL;
    if (che)
    {
        status = RPC_S_OK;
        list_remove(&che->entry);
    }

    LeaveCriticalSection(&ndr_context_cs);

    if (che)
    {
        RpcBindingFree(&che->handle);
        HeapFree(GetProcessHeap(), 0, che);
    }

    return status;
}

/***********************************************************************
 *           RpcSsDestroyClientContext [RPCRT4.@]
 */
void WINAPI RpcSsDestroyClientContext(void **ContextHandle)
{
    RPC_STATUS status = RpcSmDestroyClientContext(ContextHandle);
    if (status != RPC_S_OK)
        RpcRaiseException(status);
}

static UINT ndr_update_context_handle(NDR_CCONTEXT *CContext,
                                      RPC_BINDING_HANDLE hBinding,
                                      const ndr_context_handle *chi)
{
    struct context_handle_entry *che = NULL;

    /* a null UUID means we should free the context handle */
    if (IsEqualGUID(&chi->uuid, &GUID_NULL))
    {
        if (*CContext)
        {
            che = get_context_entry(*CContext);
            if (!che)
                return ERROR_INVALID_HANDLE;
            list_remove(&che->entry);
            RpcBindingFree(&che->handle);
            HeapFree(GetProcessHeap(), 0, che);
            che = NULL;
        }
    }
    /* if there's no existing entry matching the GUID, allocate one */
    else if (!(che = context_entry_from_guid(&chi->uuid)))
    {
        che = HeapAlloc(GetProcessHeap(), 0, sizeof *che);
        if (!che)
            return ERROR_NOT_ENOUGH_MEMORY;
        che->magic = NDR_CONTEXT_HANDLE_MAGIC;
        RpcBindingCopy(hBinding, &che->handle);
        list_add_tail(&context_handle_list, &che->entry);
        memcpy(&che->wire_data, chi, sizeof *chi);
    }

    *CContext = che;

    return ERROR_SUCCESS;
}

/***********************************************************************
 *           NDRCContextUnmarshall [RPCRT4.@]
 */
void WINAPI NDRCContextUnmarshall(NDR_CCONTEXT *CContext,
                                  RPC_BINDING_HANDLE hBinding,
                                  void *pBuff, ULONG DataRepresentation)
{
    UINT r;

    TRACE("*%p=(%p) %p %p %08x\n",
          CContext, *CContext, hBinding, pBuff, DataRepresentation);

    EnterCriticalSection(&ndr_context_cs);
    r = ndr_update_context_handle(CContext, hBinding, pBuff);
    LeaveCriticalSection(&ndr_context_cs);
    if (r)
        RpcRaiseException(r);
}

/***********************************************************************
 *           NDRSContextMarshall [RPCRT4.@]
 */
void WINAPI NDRSContextMarshall(NDR_SCONTEXT SContext,
                               void *pBuff,
                               NDR_RUNDOWN userRunDownIn)
{
    TRACE("(%p %p %p)\n", SContext, pBuff, userRunDownIn);
    NDRSContextMarshall2(I_RpcGetCurrentCallHandle(), SContext, pBuff, userRunDownIn, NULL, 0);
}

/***********************************************************************
 *           NDRSContextMarshallEx [RPCRT4.@]
 */
void WINAPI NDRSContextMarshallEx(RPC_BINDING_HANDLE hBinding,
                                  NDR_SCONTEXT SContext,
                                  void *pBuff,
                                  NDR_RUNDOWN userRunDownIn)
{
    TRACE("(%p %p %p %p)\n", hBinding, SContext, pBuff, userRunDownIn);
    NDRSContextMarshall2(hBinding, SContext, pBuff, userRunDownIn, NULL, 0);
}

/***********************************************************************
 *           NDRSContextMarshall2 [RPCRT4.@]
 */
void WINAPI NDRSContextMarshall2(RPC_BINDING_HANDLE hBinding,
                                 NDR_SCONTEXT SContext,
                                 void *pBuff,
                                 NDR_RUNDOWN userRunDownIn,
                                 void *CtxGuard, ULONG Flags)
{
    RpcBinding *binding = hBinding;
    RPC_STATUS status;
    ndr_context_handle *ndr = pBuff;

    TRACE("(%p %p %p %p %p %u)\n",
          hBinding, SContext, pBuff, userRunDownIn, CtxGuard, Flags);

    if (!binding->server || !binding->Assoc)
        RpcRaiseException(ERROR_INVALID_HANDLE);

    if (SContext->userContext)
    {
        status = RpcServerAssoc_UpdateContextHandle(binding->Assoc, SContext, CtxGuard, userRunDownIn);
        if (status != RPC_S_OK)
            RpcRaiseException(status);
        ndr->attributes = 0;
        RpcContextHandle_GetUuid(SContext, &ndr->uuid);
    }
    else
    {
        if (!RpcContextHandle_IsGuardCorrect(SContext, CtxGuard))
            RpcRaiseException(ERROR_INVALID_HANDLE);
        memset(ndr, 0, sizeof(*ndr));
        /* Note: release the context handle twice in this case to release
         * one ref being kept around for the data and one ref for the
         * unmarshall/marshall sequence */
        if (!RpcServerAssoc_ReleaseContextHandle(binding->Assoc, SContext, FALSE))
            return; /* this is to cope with the case of the data not being valid
                     * before and so not having a further reference */
    }
    RpcServerAssoc_ReleaseContextHandle(binding->Assoc, SContext, TRUE);
}

/***********************************************************************
 *           NDRSContextUnmarshall [RPCRT4.@]
 */
NDR_SCONTEXT WINAPI NDRSContextUnmarshall(void *pBuff,
                                          ULONG DataRepresentation)
{
    TRACE("(%p %08x)\n", pBuff, DataRepresentation);
    return NDRSContextUnmarshall2(I_RpcGetCurrentCallHandle(), pBuff, DataRepresentation, NULL, 0);
}

/***********************************************************************
 *           NDRSContextUnmarshallEx [RPCRT4.@]
 */
NDR_SCONTEXT WINAPI NDRSContextUnmarshallEx(RPC_BINDING_HANDLE hBinding,
                                            void *pBuff,
                                            ULONG DataRepresentation)
{
    TRACE("(%p %p %08x)\n", hBinding, pBuff, DataRepresentation);
    return NDRSContextUnmarshall2(hBinding, pBuff, DataRepresentation, NULL, 0);
}

/***********************************************************************
 *           NDRSContextUnmarshall2 [RPCRT4.@]
 */
NDR_SCONTEXT WINAPI NDRSContextUnmarshall2(RPC_BINDING_HANDLE hBinding,
                                           void *pBuff,
                                           ULONG DataRepresentation,
                                           void *CtxGuard, ULONG Flags)
{
    RpcBinding *binding = hBinding;
    NDR_SCONTEXT SContext;
    RPC_STATUS status;

    TRACE("(%p %p %08x %p %u)\n",
          hBinding, pBuff, DataRepresentation, CtxGuard, Flags);

    if (!binding->server || !binding->Assoc)
        RpcRaiseException(ERROR_INVALID_HANDLE);

    if (!pBuff)
        status = RpcServerAssoc_AllocateContextHandle(binding->Assoc, CtxGuard,
                                                      &SContext);
    else
    {
        const ndr_context_handle *context_ndr = pBuff;
        if (context_ndr->attributes)
        {
            ERR("non-null attributes 0x%x\n", context_ndr->attributes);
            status = ERROR_INVALID_HANDLE;
        }
        else
            status = RpcServerAssoc_FindContextHandle(binding->Assoc,
                                                      &context_ndr->uuid,
                                                      CtxGuard, Flags,
                                                      &SContext);
    }

    if (status != RPC_S_OK)
        RpcRaiseException(status);

    return SContext;
}
