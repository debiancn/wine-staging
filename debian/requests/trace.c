/*
 * Server request tracing
 *
 * Copyright (C) 1999 Alexandre Julliard
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

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wincon.h"
#include "winternl.h"
#include "winuser.h"
#include "winioctl.h"
#include "ddk/wdm.h"
#define USE_WS_PREFIX
#include "winsock2.h"
#include "file.h"
#include "request.h"
#include "unicode.h"

static const void *cur_data;
static data_size_t cur_size;

static const char *get_status_name( unsigned int status );

/* utility functions */

static inline void remove_data( data_size_t size )
{
    cur_data = (const char *)cur_data + size;
    cur_size -= size;
}

static void dump_uints( const int *ptr, int len )
{
    fputc( '{', stderr );
    while (len > 0)
    {
        fprintf( stderr, "%08x", *ptr++ );
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
}

static void dump_handles( const char *prefix, const obj_handle_t *data, data_size_t size )
{
    data_size_t len = size / sizeof(*data);

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        fprintf( stderr, "%04x", *data++ );
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
}

static void dump_timeout( const char *prefix, const timeout_t *time )
{
    fprintf( stderr, "%s%s", prefix, get_timeout_str(*time) );
}

static void dump_uint64( const char *prefix, const unsigned __int64 *val )
{
    if ((unsigned int)*val != *val)
        fprintf( stderr, "%s%x%08x", prefix, (unsigned int)(*val >> 32), (unsigned int)*val );
    else
        fprintf( stderr, "%s%08x", prefix, (unsigned int)*val );
}

static void dump_rectangle( const char *prefix, const rectangle_t *rect )
{
    fprintf( stderr, "%s{%d,%d;%d,%d}", prefix,
             rect->left, rect->top, rect->right, rect->bottom );
}

static void dump_char_info( const char *prefix, const char_info_t *info )
{
    fprintf( stderr, "%s{'", prefix );
    dump_strW( &info->ch, 1, stderr, "\'\'" );
    fprintf( stderr, "',%04x}", info->attr );
}

static void dump_ioctl_code( const char *prefix, const ioctl_code_t *code )
{
    switch(*code)
    {
#define CASE(c) case c: fprintf( stderr, "%s%s", prefix, #c ); break
        CASE(FSCTL_DISMOUNT_VOLUME);
        CASE(FSCTL_PIPE_DISCONNECT);
        CASE(FSCTL_PIPE_LISTEN);
        CASE(FSCTL_PIPE_WAIT);
        CASE(WS_SIO_ADDRESS_LIST_CHANGE);
        default: fprintf( stderr, "%s%08x", prefix, *code ); break;
#undef CASE
    }
}

static void dump_cpu_type( const char *prefix, const cpu_type_t *code )
{
    switch (*code)
    {
#define CASE(c) case CPU_##c: fprintf( stderr, "%s%s", prefix, #c ); break
        CASE(x86);
        CASE(x86_64);
        CASE(POWERPC);
        CASE(ARM);
        CASE(ARM64);
        default: fprintf( stderr, "%s%u", prefix, *code ); break;
#undef CASE
    }
}

static void dump_apc_call( const char *prefix, const apc_call_t *call )
{
    fprintf( stderr, "%s{", prefix );
    switch(call->type)
    {
    case APC_NONE:
        fprintf( stderr, "APC_NONE" );
        break;
    case APC_USER:
        dump_uint64( "APC_USER,func=", &call->user.func );
        dump_uint64( ",args={", &call->user.args[0] );
        dump_uint64( ",", &call->user.args[1] );
        dump_uint64( ",", &call->user.args[2] );
        fputc( '}', stderr );
        break;
    case APC_TIMER:
        dump_timeout( "APC_TIMER,time=", &call->timer.time );
        dump_uint64( ",arg=", &call->timer.arg );
        break;
    case APC_ASYNC_IO:
        dump_uint64( "APC_ASYNC_IO,func=", &call->async_io.func );
        dump_uint64( ",user=", &call->async_io.user );
        dump_uint64( ",sb=", &call->async_io.sb );
        fprintf( stderr, ",status=%s", get_status_name(call->async_io.status) );
        break;
    case APC_VIRTUAL_ALLOC:
        dump_uint64( "APC_VIRTUAL_ALLOC,addr==", &call->virtual_alloc.addr );
        dump_uint64( ",size=", &call->virtual_alloc.size );
        fprintf( stderr, ",zero_bits=%u,op_type=%x,prot=%x",
                 call->virtual_alloc.zero_bits, call->virtual_alloc.op_type,
                 call->virtual_alloc.prot );
        break;
    case APC_VIRTUAL_FREE:
        dump_uint64( "APC_VIRTUAL_FREE,addr=", &call->virtual_free.addr );
        dump_uint64( ",size=", &call->virtual_free.size );
        fprintf( stderr, ",op_type=%x", call->virtual_free.op_type );
        break;
    case APC_VIRTUAL_QUERY:
        dump_uint64( "APC_VIRTUAL_QUERY,addr=", &call->virtual_query.addr );
        break;
    case APC_VIRTUAL_PROTECT:
        dump_uint64( "APC_VIRTUAL_PROTECT,addr=", &call->virtual_protect.addr );
        dump_uint64( ",size=", &call->virtual_protect.size );
        fprintf( stderr, ",prot=%x", call->virtual_protect.prot );
        break;
    case APC_VIRTUAL_FLUSH:
        dump_uint64( "APC_VIRTUAL_FLUSH,addr=", &call->virtual_flush.addr );
        dump_uint64( ",size=", &call->virtual_flush.size );
        break;
    case APC_VIRTUAL_LOCK:
        dump_uint64( "APC_VIRTUAL_LOCK,addr=", &call->virtual_lock.addr );
        dump_uint64( ",size=", &call->virtual_lock.size );
        break;
    case APC_VIRTUAL_UNLOCK:
        dump_uint64( "APC_VIRTUAL_UNLOCK,addr=", &call->virtual_unlock.addr );
        dump_uint64( ",size=", &call->virtual_unlock.size );
        break;
    case APC_MAP_VIEW:
        fprintf( stderr, "APC_MAP_VIEW,handle=%04x", call->map_view.handle );
        dump_uint64( ",addr=", &call->map_view.addr );
        dump_uint64( ",size=", &call->map_view.size );
        dump_uint64( ",offset=", &call->map_view.offset );
        fprintf( stderr, ",zero_bits=%u,alloc_type=%x,prot=%x",
                 call->map_view.zero_bits, call->map_view.alloc_type, call->map_view.prot );
        break;
    case APC_UNMAP_VIEW:
        dump_uint64( "APC_UNMAP_VIEW,addr=", &call->unmap_view.addr );
        break;
    case APC_CREATE_THREAD:
        dump_uint64( "APC_CREATE_THREAD,func=", &call->create_thread.func );
        dump_uint64( ",arg=", &call->create_thread.arg );
        dump_uint64( ",reserve=", &call->create_thread.reserve );
        dump_uint64( ",commit=", &call->create_thread.commit );
        fprintf( stderr, ",suspend=%u", call->create_thread.suspend );
        break;
    default:
        fprintf( stderr, "type=%u", call->type );
        break;
    }
    fputc( '}', stderr );
}

static void dump_apc_result( const char *prefix, const apc_result_t *result )
{
    fprintf( stderr, "%s{", prefix );
    switch(result->type)
    {
    case APC_NONE:
        break;
    case APC_ASYNC_IO:
        fprintf( stderr, "APC_ASYNC_IO,status=%s,total=%u",
                 get_status_name( result->async_io.status ), result->async_io.total );
        dump_uint64( ",apc=", &result->async_io.apc );
        dump_uint64( ",arg=", &result->async_io.arg );
        break;
    case APC_VIRTUAL_ALLOC:
        fprintf( stderr, "APC_VIRTUAL_ALLOC,status=%s",
                 get_status_name( result->virtual_alloc.status ));
        dump_uint64( ",addr=", &result->virtual_alloc.addr );
        dump_uint64( ",size=", &result->virtual_alloc.size );
        break;
    case APC_VIRTUAL_FREE:
        fprintf( stderr, "APC_VIRTUAL_FREE,status=%s",
                 get_status_name( result->virtual_free.status ));
        dump_uint64( ",addr=", &result->virtual_free.addr );
        dump_uint64( ",size=", &result->virtual_free.size );
        break;
    case APC_VIRTUAL_QUERY:
        fprintf( stderr, "APC_VIRTUAL_QUERY,status=%s",
                 get_status_name( result->virtual_query.status ));
        dump_uint64( ",base=", &result->virtual_query.base );
        dump_uint64( ",alloc_base=", &result->virtual_query.alloc_base );
        dump_uint64( ",size=", &result->virtual_query.size );
        fprintf( stderr, ",state=%x,prot=%x,alloc_prot=%x,alloc_type=%x",
                 result->virtual_query.state, result->virtual_query.prot,
                 result->virtual_query.alloc_prot, result->virtual_query.alloc_type );
        break;
    case APC_VIRTUAL_PROTECT:
        fprintf( stderr, "APC_VIRTUAL_PROTECT,status=%s",
                 get_status_name( result->virtual_protect.status ));
        dump_uint64( ",addr=", &result->virtual_protect.addr );
        dump_uint64( ",size=", &result->virtual_protect.size );
        fprintf( stderr, ",prot=%x", result->virtual_protect.prot );
        break;
    case APC_VIRTUAL_FLUSH:
        fprintf( stderr, "APC_VIRTUAL_FLUSH,status=%s",
                 get_status_name( result->virtual_flush.status ));
        dump_uint64( ",addr=", &result->virtual_flush.addr );
        dump_uint64( ",size=", &result->virtual_flush.size );
        break;
    case APC_VIRTUAL_LOCK:
        fprintf( stderr, "APC_VIRTUAL_LOCK,status=%s",
                 get_status_name( result->virtual_lock.status ));
        dump_uint64( ",addr=", &result->virtual_lock.addr );
        dump_uint64( ",size=", &result->virtual_lock.size );
        break;
    case APC_VIRTUAL_UNLOCK:
        fprintf( stderr, "APC_VIRTUAL_UNLOCK,status=%s",
                 get_status_name( result->virtual_unlock.status ));
        dump_uint64( ",addr=", &result->virtual_unlock.addr );
        dump_uint64( ",size=", &result->virtual_unlock.size );
        break;
    case APC_MAP_VIEW:
        fprintf( stderr, "APC_MAP_VIEW,status=%s",
                 get_status_name( result->map_view.status ));
        dump_uint64( ",addr=", &result->map_view.addr );
        dump_uint64( ",size=", &result->map_view.size );
        break;
    case APC_UNMAP_VIEW:
        fprintf( stderr, "APC_UNMAP_VIEW,status=%s",
                 get_status_name( result->unmap_view.status ) );
        break;
    case APC_CREATE_THREAD:
        fprintf( stderr, "APC_CREATE_THREAD,status=%s,tid=%04x,handle=%04x",
                 get_status_name( result->create_thread.status ),
                 result->create_thread.tid, result->create_thread.handle );
        break;
    default:
        fprintf( stderr, "type=%u", result->type );
        break;
    }
    fputc( '}', stderr );
}

static void dump_async_data( const char *prefix, const async_data_t *data )
{
    fprintf( stderr, "%s{handle=%04x,event=%04x", prefix, data->handle, data->event );
    dump_uint64( ",callback=", &data->callback );
    dump_uint64( ",iosb=", &data->iosb );
    dump_uint64( ",arg=", &data->arg );
    dump_uint64( ",cvalue=", &data->cvalue );
    fputc( '}', stderr );
}

static void dump_irp_params( const char *prefix, const irp_params_t *data )
{
    switch (data->major)
    {
    case IRP_MJ_CREATE:
        fprintf( stderr, "%s{major=CREATE,access=%08x,sharing=%08x,options=%08x",
                 prefix, data->create.access, data->create.sharing, data->create.options );
        dump_uint64( ",device=", &data->create.device );
        fputc( '}', stderr );
        break;
    case IRP_MJ_CLOSE:
        fprintf( stderr, "%s{major=CLOSE", prefix );
        dump_uint64( ",file=", &data->close.file );
        fputc( '}', stderr );
        break;
    case IRP_MJ_READ:
        fprintf( stderr, "%s{major=READ,key=%08x", prefix, data->read.key );
        dump_uint64( ",pos=", &data->read.pos );
        dump_uint64( ",file=", &data->read.file );
        fputc( '}', stderr );
        break;
    case IRP_MJ_WRITE:
        fprintf( stderr, "%s{major=WRITE,key=%08x", prefix, data->write.key );
        dump_uint64( ",pos=", &data->write.pos );
        dump_uint64( ",file=", &data->write.file );
        fputc( '}', stderr );
        break;
    case IRP_MJ_FLUSH_BUFFERS:
        fprintf( stderr, "%s{major=FLUSH_BUFFERS", prefix );
        dump_uint64( ",file=", &data->flush.file );
        fputc( '}', stderr );
        break;
    case IRP_MJ_DEVICE_CONTROL:
        fprintf( stderr, "%s{major=DEVICE_CONTROL", prefix );
        dump_ioctl_code( ",code=", &data->ioctl.code );
        dump_uint64( ",file=", &data->ioctl.file );
        fputc( '}', stderr );
        break;
    case IRP_MJ_MAXIMUM_FUNCTION + 1: /* invalid */
        fprintf( stderr, "%s{}", prefix );
        break;
    default:
        fprintf( stderr, "%s{major=%u}", prefix, data->major );
        break;
    }
}

static void dump_hw_input( const char *prefix, const hw_input_t *input )
{
    switch (input->type)
    {
    case INPUT_MOUSE:
        fprintf( stderr, "%s{type=MOUSE,x=%d,y=%d,data=%08x,flags=%08x,time=%u",
                 prefix, input->mouse.x, input->mouse.y, input->mouse.data, input->mouse.flags,
                 input->mouse.time );
        dump_uint64( ",info=", &input->mouse.info );
        fputc( '}', stderr );
        break;
    case INPUT_KEYBOARD:
        fprintf( stderr, "%s{type=KEYBOARD,vkey=%04hx,scan=%04hx,flags=%08x,time=%u",
                 prefix, input->kbd.vkey, input->kbd.scan, input->kbd.flags, input->kbd.time );
        dump_uint64( ",info=", &input->kbd.info );
        fputc( '}', stderr );
        break;
    case INPUT_HARDWARE:
        fprintf( stderr, "%s{type=HARDWARE,msg=%04x", prefix, input->hw.msg );
        dump_uint64( ",lparam=", &input->hw.lparam );
        fputc( '}', stderr );
        break;
    default:
        fprintf( stderr, "%s{type=%04x}", prefix, input->type );
        break;
    }
}

static void dump_luid( const char *prefix, const luid_t *luid )
{
    fprintf( stderr, "%s%d.%u", prefix, luid->high_part, luid->low_part );
}

static void dump_varargs_ints( const char *prefix, data_size_t size )
{
    const int *data = cur_data;
    data_size_t len = size / sizeof(*data);

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        fprintf( stderr, "%d", *data++ );
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_uints64( const char *prefix, data_size_t size )
{
    const unsigned __int64 *data = cur_data;
    data_size_t len = size / sizeof(*data);

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        dump_uint64( "", data++ );
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_apc_result( const char *prefix, data_size_t size )
{
    const apc_result_t *result = cur_data;

    if (size >= sizeof(*result))
    {
        dump_apc_result( prefix, result );
        size = sizeof(*result);
    }
    remove_data( size );
}

static void dump_varargs_select_op( const char *prefix, data_size_t size )
{
    select_op_t data;

    if (!size)
    {
        fprintf( stderr, "%s{}", prefix );
        return;
    }
    memset( &data, 0, sizeof(data) );
    memcpy( &data, cur_data, min( size, sizeof(data) ));

    fprintf( stderr, "%s{", prefix );
    switch (data.op)
    {
    case SELECT_NONE:
        fprintf( stderr, "NONE" );
        break;
    case SELECT_WAIT:
    case SELECT_WAIT_ALL:
        fprintf( stderr, "%s", data.op == SELECT_WAIT ? "WAIT" : "WAIT_ALL" );
        if (size > offsetof( select_op_t, wait.handles ))
            dump_handles( ",handles=", data.wait.handles,
                          min( size, sizeof(data.wait) ) - offsetof( select_op_t, wait.handles ));
        break;
    case SELECT_SIGNAL_AND_WAIT:
        fprintf( stderr, "SIGNAL_AND_WAIT,signal=%04x,wait=%04x",
                 data.signal_and_wait.signal, data.signal_and_wait.wait );
        break;
    case SELECT_KEYED_EVENT_WAIT:
    case SELECT_KEYED_EVENT_RELEASE:
        fprintf( stderr, "KEYED_EVENT_%s,handle=%04x",
                 data.op == SELECT_KEYED_EVENT_WAIT ? "WAIT" : "RELEASE",
                 data.keyed_event.handle );
        dump_uint64( ",key=", &data.keyed_event.key );
        break;
    default:
        fprintf( stderr, "op=%u", data.op );
        break;
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_user_handles( const char *prefix, data_size_t size )
{
    const user_handle_t *data = cur_data;
    data_size_t len = size / sizeof(*data);

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        fprintf( stderr, "%08x", *data++ );
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_bytes( const char *prefix, data_size_t size )
{
    const unsigned char *data = cur_data;
    data_size_t len = min( 1024, size );

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        fprintf( stderr, "%02x", *data++ );
        if (--len) fputc( ',', stderr );
    }
    if (size > 1024) fprintf( stderr, "...(total %u)", size );
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_string( const char *prefix, data_size_t size )
{
    fprintf( stderr, "%s\"%.*s\"", prefix, (int)size, (const char *)cur_data );
    remove_data( size );
}

static void dump_varargs_unicode_str( const char *prefix, data_size_t size )
{
    fprintf( stderr, "%sL\"", prefix );
    dump_strW( cur_data, size / sizeof(WCHAR), stderr, "\"\"" );
    fputc( '\"', stderr );
    remove_data( size );
}

static void dump_varargs_context( const char *prefix, data_size_t size )
{
    const context_t *context = cur_data;
    context_t ctx;
    unsigned int i;

    if (!size)
    {
        fprintf( stderr, "%s{}", prefix );
        return;
    }
    size = min( size, sizeof(ctx) );
    memset( &ctx, 0, sizeof(ctx) );
    memcpy( &ctx, context, size );

    fprintf( stderr,"%s{", prefix );
    dump_cpu_type( "cpu=", &ctx.cpu );
    switch (ctx.cpu)
    {
    case CPU_x86:
        if (ctx.flags & SERVER_CTX_CONTROL)
            fprintf( stderr, ",eip=%08x,esp=%08x,ebp=%08x,eflags=%08x,cs=%04x,ss=%04x",
                     ctx.ctl.i386_regs.eip, ctx.ctl.i386_regs.esp, ctx.ctl.i386_regs.ebp,
                     ctx.ctl.i386_regs.eflags, ctx.ctl.i386_regs.cs, ctx.ctl.i386_regs.ss );
        if (ctx.flags & SERVER_CTX_SEGMENTS)
            fprintf( stderr, ",ds=%04x,es=%04x,fs=%04x,gs=%04x",
                     ctx.seg.i386_regs.ds, ctx.seg.i386_regs.es,
                     ctx.seg.i386_regs.fs, ctx.seg.i386_regs.gs );
        if (ctx.flags & SERVER_CTX_INTEGER)
            fprintf( stderr, ",eax=%08x,ebx=%08x,ecx=%08x,edx=%08x,esi=%08x,edi=%08x",
                     ctx.integer.i386_regs.eax, ctx.integer.i386_regs.ebx, ctx.integer.i386_regs.ecx,
                     ctx.integer.i386_regs.edx, ctx.integer.i386_regs.esi, ctx.integer.i386_regs.edi );
        if (ctx.flags & SERVER_CTX_DEBUG_REGISTERS)
            fprintf( stderr, ",dr0=%08x,dr1=%08x,dr2=%08x,dr3=%08x,dr6=%08x,dr7=%08x",
                     ctx.debug.i386_regs.dr0, ctx.debug.i386_regs.dr1, ctx.debug.i386_regs.dr2,
                     ctx.debug.i386_regs.dr3, ctx.debug.i386_regs.dr6, ctx.debug.i386_regs.dr7 );
        if (ctx.flags & SERVER_CTX_FLOATING_POINT)
        {
            fprintf( stderr, ",fp.ctrl=%08x,fp.status=%08x,fp.tag=%08x,fp.err_off=%08x,fp.err_sel=%08x",
                     ctx.fp.i386_regs.ctrl, ctx.fp.i386_regs.status, ctx.fp.i386_regs.tag,
                     ctx.fp.i386_regs.err_off, ctx.fp.i386_regs.err_sel );
            fprintf( stderr, ",fp.data_off=%08x,fp.data_sel=%08x,fp.cr0npx=%08x",
                     ctx.fp.i386_regs.data_off, ctx.fp.i386_regs.data_sel, ctx.fp.i386_regs.cr0npx );
            for (i = 0; i < 8; i++)
                fprintf( stderr, ",fp.reg%u=%Lg", i, *(long double *)&ctx.fp.i386_regs.regs[10*i] );
        }
        if (ctx.flags & SERVER_CTX_EXTENDED_REGISTERS)
        {
            fprintf( stderr, ",extended=" );
            dump_uints( (const int *)ctx.ext.i386_regs, sizeof(ctx.ext.i386_regs) / sizeof(int) );
        }
        break;
    case CPU_x86_64:
        if (ctx.flags & SERVER_CTX_CONTROL)
        {
            dump_uint64( ",rip=", &ctx.ctl.x86_64_regs.rip );
            dump_uint64( ",rbp=", &ctx.ctl.x86_64_regs.rbp );
            dump_uint64( ",rsp=", &ctx.ctl.x86_64_regs.rsp );
            fprintf( stderr, ",cs=%04x,ss=%04x,flags=%08x",
                     ctx.ctl.x86_64_regs.cs, ctx.ctl.x86_64_regs.ss, ctx.ctl.x86_64_regs.flags );
        }
        if (ctx.flags & SERVER_CTX_INTEGER)
        {
            dump_uint64( ",rax=", &ctx.integer.x86_64_regs.rax );
            dump_uint64( ",rbx=", &ctx.integer.x86_64_regs.rbx );
            dump_uint64( ",rcx=", &ctx.integer.x86_64_regs.rcx );
            dump_uint64( ",rdx=", &ctx.integer.x86_64_regs.rdx );
            dump_uint64( ",rsi=", &ctx.integer.x86_64_regs.rsi );
            dump_uint64( ",rdi=", &ctx.integer.x86_64_regs.rdi );
            dump_uint64( ",r8=",  &ctx.integer.x86_64_regs.r8 );
            dump_uint64( ",r9=",  &ctx.integer.x86_64_regs.r9 );
            dump_uint64( ",r10=", &ctx.integer.x86_64_regs.r10 );
            dump_uint64( ",r11=", &ctx.integer.x86_64_regs.r11 );
            dump_uint64( ",r12=", &ctx.integer.x86_64_regs.r12 );
            dump_uint64( ",r13=", &ctx.integer.x86_64_regs.r13 );
            dump_uint64( ",r14=", &ctx.integer.x86_64_regs.r14 );
            dump_uint64( ",r15=", &ctx.integer.x86_64_regs.r15 );
        }
        if (ctx.flags & SERVER_CTX_SEGMENTS)
            fprintf( stderr, ",ds=%04x,es=%04x,fs=%04x,gs=%04x",
                     ctx.seg.x86_64_regs.ds, ctx.seg.x86_64_regs.es,
                     ctx.seg.x86_64_regs.fs, ctx.seg.x86_64_regs.gs );
        if (ctx.flags & SERVER_CTX_DEBUG_REGISTERS)
        {
            dump_uint64( ",dr0=", &ctx.debug.x86_64_regs.dr0 );
            dump_uint64( ",dr1=", &ctx.debug.x86_64_regs.dr1 );
            dump_uint64( ",dr2=", &ctx.debug.x86_64_regs.dr2 );
            dump_uint64( ",dr3=", &ctx.debug.x86_64_regs.dr3 );
            dump_uint64( ",dr6=", &ctx.debug.x86_64_regs.dr6 );
            dump_uint64( ",dr7=", &ctx.debug.x86_64_regs.dr7 );
        }
        if (ctx.flags & SERVER_CTX_FLOATING_POINT)
        {
            for (i = 0; i < 32; i++)
                fprintf( stderr, ",fp%u=%08x%08x%08x%08x", i,
                         (unsigned int)(ctx.fp.x86_64_regs.fpregs[i].high >> 32),
                         (unsigned int)ctx.fp.x86_64_regs.fpregs[i].high,
                         (unsigned int)(ctx.fp.x86_64_regs.fpregs[i].low >> 32),
                         (unsigned int)ctx.fp.x86_64_regs.fpregs[i].low );
        }
        break;
    case CPU_POWERPC:
        if (ctx.flags & SERVER_CTX_CONTROL)
            fprintf( stderr, ",iar=%08x,msr=%08x,ctr=%08x,lr=%08x,dar=%08x,dsisr=%08x,trap=%08x",
                     ctx.ctl.powerpc_regs.iar, ctx.ctl.powerpc_regs.msr, ctx.ctl.powerpc_regs.ctr,
                     ctx.ctl.powerpc_regs.lr, ctx.ctl.powerpc_regs.dar, ctx.ctl.powerpc_regs.dsisr,
                     ctx.ctl.powerpc_regs.trap );
        if (ctx.flags & SERVER_CTX_INTEGER)
        {
            for (i = 0; i < 32; i++) fprintf( stderr, ",gpr%u=%08x", i, ctx.integer.powerpc_regs.gpr[i] );
            fprintf( stderr, ",cr=%08x,xer=%08x",
                     ctx.integer.powerpc_regs.cr, ctx.integer.powerpc_regs.xer );
        }
        if (ctx.flags & SERVER_CTX_DEBUG_REGISTERS)
            for (i = 0; i < 8; i++) fprintf( stderr, ",dr%u=%08x", i, ctx.debug.powerpc_regs.dr[i] );
        if (ctx.flags & SERVER_CTX_FLOATING_POINT)
        {
            for (i = 0; i < 32; i++) fprintf( stderr, ",fpr%u=%g", i, ctx.fp.powerpc_regs.fpr[i] );
            fprintf( stderr, ",fpscr=%g", ctx.fp.powerpc_regs.fpscr );
        }
        break;
    case CPU_ARM:
        if (ctx.flags & SERVER_CTX_CONTROL)
            fprintf( stderr, ",sp=%08x,lr=%08x,pc=%08x,cpsr=%08x",
                     ctx.ctl.arm_regs.sp, ctx.ctl.arm_regs.lr,
                     ctx.ctl.arm_regs.pc, ctx.ctl.arm_regs.cpsr );
        if (ctx.flags & SERVER_CTX_INTEGER)
            for (i = 0; i < 13; i++) fprintf( stderr, ",r%u=%08x", i, ctx.integer.arm_regs.r[i] );
        break;
    case CPU_ARM64:
        if (ctx.flags & SERVER_CTX_CONTROL)
        {
            dump_uint64( ",sp=", &ctx.ctl.arm64_regs.sp );
            dump_uint64( ",pc=", &ctx.ctl.arm64_regs.pc );
            dump_uint64( ",pstate=", &ctx.ctl.arm64_regs.pstate );
        }
        if (ctx.flags & SERVER_CTX_INTEGER)
        {
            dump_uint64( ",x0=",  &ctx.integer.arm64_regs.x[0] );
            dump_uint64( ",x1=",  &ctx.integer.arm64_regs.x[1] );
            dump_uint64( ",x2=",  &ctx.integer.arm64_regs.x[2] );
            dump_uint64( ",x3=",  &ctx.integer.arm64_regs.x[3] );
            dump_uint64( ",x4=",  &ctx.integer.arm64_regs.x[4] );
            dump_uint64( ",x5=",  &ctx.integer.arm64_regs.x[5] );
            dump_uint64( ",x6=",  &ctx.integer.arm64_regs.x[6] );
            dump_uint64( ",x7=",  &ctx.integer.arm64_regs.x[7] );
            dump_uint64( ",x8=",  &ctx.integer.arm64_regs.x[8] );
            dump_uint64( ",x9=",  &ctx.integer.arm64_regs.x[9] );
            dump_uint64( ",x10=", &ctx.integer.arm64_regs.x[10] );
            dump_uint64( ",x11=", &ctx.integer.arm64_regs.x[11] );
            dump_uint64( ",x12=", &ctx.integer.arm64_regs.x[12] );
            dump_uint64( ",x13=", &ctx.integer.arm64_regs.x[13] );
            dump_uint64( ",x14=", &ctx.integer.arm64_regs.x[14] );
            dump_uint64( ",x15=", &ctx.integer.arm64_regs.x[15] );
            dump_uint64( ",x16=", &ctx.integer.arm64_regs.x[16] );
            dump_uint64( ",x17=", &ctx.integer.arm64_regs.x[17] );
            dump_uint64( ",x18=", &ctx.integer.arm64_regs.x[18] );
            dump_uint64( ",x19=", &ctx.integer.arm64_regs.x[19] );
            dump_uint64( ",x20=", &ctx.integer.arm64_regs.x[20] );
            dump_uint64( ",x21=", &ctx.integer.arm64_regs.x[21] );
            dump_uint64( ",x22=", &ctx.integer.arm64_regs.x[22] );
            dump_uint64( ",x23=", &ctx.integer.arm64_regs.x[23] );
            dump_uint64( ",x24=", &ctx.integer.arm64_regs.x[24] );
            dump_uint64( ",x25=", &ctx.integer.arm64_regs.x[25] );
            dump_uint64( ",x26=", &ctx.integer.arm64_regs.x[26] );
            dump_uint64( ",x27=", &ctx.integer.arm64_regs.x[27] );
            dump_uint64( ",x28=", &ctx.integer.arm64_regs.x[28] );
            dump_uint64( ",x29=", &ctx.integer.arm64_regs.x[29] );
            dump_uint64( ",x30=", &ctx.integer.arm64_regs.x[30] );
        }
        break;
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_debug_event( const char *prefix, data_size_t size )
{
    debug_event_t event;
    unsigned int i;

    if (!size)
    {
        fprintf( stderr, "%s{}", prefix );
        return;
    }
    size = min( size, sizeof(event) );
    memset( &event, 0, sizeof(event) );
    memcpy( &event, cur_data, size );

    switch(event.code)
    {
    case EXCEPTION_DEBUG_EVENT:
        fprintf( stderr, "%s{exception,first=%d,exc_code=%08x,flags=%08x", prefix,
                 event.exception.first, event.exception.exc_code, event.exception.flags );
        dump_uint64( ",record=", &event.exception.record );
        dump_uint64( ",address=", &event.exception.address );
        fprintf( stderr, ",params={" );
        event.exception.nb_params = min( event.exception.nb_params, EXCEPTION_MAXIMUM_PARAMETERS );
        for (i = 0; i < event.exception.nb_params; i++)
        {
            dump_uint64( "", &event.exception.params[i] );
            if (i < event.exception.nb_params) fputc( ',', stderr );
        }
        fprintf( stderr, "}}" );
        break;
    case CREATE_THREAD_DEBUG_EVENT:
        fprintf( stderr, "%s{create_thread,thread=%04x", prefix, event.create_thread.handle );
        dump_uint64( ",teb=", &event.create_thread.teb );
        dump_uint64( ",start=", &event.create_thread.start );
        fputc( '}', stderr );
        break;
    case CREATE_PROCESS_DEBUG_EVENT:
        fprintf( stderr, "%s{create_process,file=%04x,process=%04x,thread=%04x", prefix,
                 event.create_process.file, event.create_process.process,
                 event.create_process.thread );
        dump_uint64( ",base=", &event.create_process.base );
        fprintf( stderr, ",offset=%d,size=%d",
                 event.create_process.dbg_offset, event.create_process.dbg_size );
        dump_uint64( ",teb=", &event.create_process.teb );
        dump_uint64( ",start=", &event.create_process.start );
        dump_uint64( ",name=", &event.create_process.name );
        fprintf( stderr, ",unicode=%d}", event.create_process.unicode );
        break;
    case EXIT_THREAD_DEBUG_EVENT:
        fprintf( stderr, "%s{exit_thread,code=%d}", prefix, event.exit.exit_code );
        break;
    case EXIT_PROCESS_DEBUG_EVENT:
        fprintf( stderr, "%s{exit_process,code=%d}", prefix, event.exit.exit_code );
        break;
    case LOAD_DLL_DEBUG_EVENT:
        fprintf( stderr, "%s{load_dll,file=%04x", prefix, event.load_dll.handle );
        dump_uint64( ",base=", &event.load_dll.base );
        fprintf( stderr, ",offset=%d,size=%d",
                 event.load_dll.dbg_offset, event.load_dll.dbg_size );
        dump_uint64( ",name=", &event.load_dll.name );
        fprintf( stderr, ",unicode=%d}", event.load_dll.unicode );
        break;
    case UNLOAD_DLL_DEBUG_EVENT:
        fprintf( stderr, "%s{unload_dll", prefix );
        dump_uint64( ",base=", &event.unload_dll.base );
        fputc( '}', stderr );
        break;
    case 0:  /* zero is the code returned on timeouts */
        fprintf( stderr, "%s{}", prefix );
        break;
    default:
        fprintf( stderr, "%s{code=??? (%d)}", prefix, event.code );
        break;
    }
    remove_data( size );
}

/* dump a unicode string contained in a buffer; helper for dump_varargs_startup_info */
static data_size_t dump_inline_unicode_string( const char *prefix, data_size_t pos, data_size_t len, data_size_t total_size )
{
    fputs( prefix, stderr );
    if (pos >= total_size) return pos;
    if (len > total_size - pos) len = total_size - pos;
    len /= sizeof(WCHAR);
    dump_strW( (const WCHAR *)cur_data + pos/sizeof(WCHAR), len, stderr, "\"\"" );
    return pos + len * sizeof(WCHAR);
}

static void dump_varargs_startup_info( const char *prefix, data_size_t size )
{
    startup_info_t info;
    data_size_t pos = sizeof(info);

    memset( &info, 0, sizeof(info) );
    memcpy( &info, cur_data, min( size, sizeof(info) ));

    fprintf( stderr,
             "%s{debug_flags=%x,console_flags=%x,console=%04x,hstdin=%04x,hstdout=%04x,hstderr=%04x,"
             "x=%u,y=%u,xsize=%u,ysize=%u,xchars=%u,ychars=%u,attribute=%02x,flags=%x,show=%u",
             prefix, info.debug_flags, info.console_flags, info.console,
             info.hstdin, info.hstdout, info.hstderr, info.x, info.y, info.xsize, info.ysize,
             info.xchars, info.ychars, info.attribute, info.flags, info.show );
    pos = dump_inline_unicode_string( ",curdir=L\"", pos, info.curdir_len, size );
    pos = dump_inline_unicode_string( "\",dllpath=L\"", pos, info.dllpath_len, size );
    pos = dump_inline_unicode_string( "\",imagepath=L\"", pos, info.imagepath_len, size );
    pos = dump_inline_unicode_string( "\",cmdline=L\"", pos, info.cmdline_len, size );
    pos = dump_inline_unicode_string( "\",title=L\"", pos, info.title_len, size );
    pos = dump_inline_unicode_string( "\",desktop=L\"", pos, info.desktop_len, size );
    pos = dump_inline_unicode_string( "\",shellinfo=L\"", pos, info.shellinfo_len, size );
    pos = dump_inline_unicode_string( "\",runtime=L\"", pos, info.runtime_len, size );
    fprintf( stderr, "\"}" );
    remove_data( size );
}

static void dump_varargs_input_records( const char *prefix, data_size_t size )
{
    const INPUT_RECORD *rec = cur_data;
    data_size_t len = size / sizeof(*rec);

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        fprintf( stderr, "{%04x,...}", rec->EventType );
        rec++;
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_rectangles( const char *prefix, data_size_t size )
{
    const rectangle_t *rect = cur_data;
    data_size_t len = size / sizeof(*rect);

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        dump_rectangle( "", rect++ );
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_message_data( const char *prefix, data_size_t size )
{
    /* FIXME: dump the structured data */
    dump_varargs_bytes( prefix, size );
}

static void dump_varargs_properties( const char *prefix, data_size_t size )
{
    const property_data_t *prop = cur_data;
    data_size_t len = size / sizeof(*prop);

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        fprintf( stderr, "{atom=%04x,str=%d", prop->atom, prop->string );
        dump_uint64( ",data=", &prop->data );
        fputc( '}', stderr );
        prop++;
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_varargs_LUID_AND_ATTRIBUTES( const char *prefix, data_size_t size )
{
    const LUID_AND_ATTRIBUTES *lat = cur_data;
    data_size_t len = size / sizeof(*lat);

    fprintf( stderr,"%s{", prefix );
    while (len > 0)
    {
        fprintf( stderr, "{luid=%08x%08x,attr=%x}",
                 lat->Luid.HighPart, lat->Luid.LowPart, lat->Attributes );
        lat++;
        if (--len) fputc( ',', stderr );
    }
    fputc( '}', stderr );
    remove_data( size );
}

static void dump_inline_sid( const char *prefix, const SID *sid, data_size_t size )
{
    DWORD i;

    /* security check */
    if ((FIELD_OFFSET(SID, SubAuthority[0]) > size) ||
        (FIELD_OFFSET(SID, SubAuthority[sid->SubAuthorityCount]) > size))
    {
        fprintf( stderr, "<invalid sid>" );
        return;
    }

    fprintf( stderr,"%s{", prefix );
    fprintf( stderr, "S-%u-%u", sid->Revision, MAKELONG(
        MAKEWORD( sid->IdentifierAuthority.Value[5],
                  sid->IdentifierAuthority.Value[4] ),
        MAKEWORD( sid->IdentifierAuthority.Value[3],
                  sid->IdentifierAuthority.Value[2] ) ) );
    for (i = 0; i < sid->SubAuthorityCount; i++)
        fprintf( stderr, "-%u", sid->SubAuthority[i] );
    fputc( '}', stderr );
}

static void dump_varargs_SID( const char *prefix, data_size_t size )
{
    const SID *sid = cur_data;
    dump_inline_sid( prefix, sid, size );
    remove_data( size );
}

static void dump_inline_acl( const char *prefix, const ACL *acl, data_size_t size )
{
    const ACE_HEADER *ace;
    ULONG i;

    fprintf( stderr,"%s{", prefix );
    if (size)
    {
        if (size < sizeof(ACL))
        {
            fprintf( stderr, "<invalid acl>}" );
            return;
        }
        size -= sizeof(ACL);
        ace = (const ACE_HEADER *)(acl + 1);
        for (i = 0; i < acl->AceCount; i++)
        {
            const SID *sid = NULL;
            data_size_t sid_size = 0;

            if (size < sizeof(ACE_HEADER) || size < ace->AceSize) break;
            size -= ace->AceSize;
            if (i != 0) fputc( ',', stderr );
            fprintf( stderr, "{AceType=" );
            switch (ace->AceType)
            {
            case ACCESS_DENIED_ACE_TYPE:
                sid = (const SID *)&((const ACCESS_DENIED_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(ACCESS_DENIED_ACE, SidStart);
                fprintf( stderr, "ACCESS_DENIED_ACE_TYPE,Mask=%x",
                         ((const ACCESS_DENIED_ACE *)ace)->Mask );
                break;
            case ACCESS_ALLOWED_ACE_TYPE:
                sid = (const SID *)&((const ACCESS_ALLOWED_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
                fprintf( stderr, "ACCESS_ALLOWED_ACE_TYPE,Mask=%x",
                         ((const ACCESS_ALLOWED_ACE *)ace)->Mask );
                break;
            case SYSTEM_AUDIT_ACE_TYPE:
                sid = (const SID *)&((const SYSTEM_AUDIT_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(SYSTEM_AUDIT_ACE, SidStart);
                fprintf( stderr, "SYSTEM_AUDIT_ACE_TYPE,Mask=%x",
                         ((const SYSTEM_AUDIT_ACE *)ace)->Mask );
                break;
            case SYSTEM_ALARM_ACE_TYPE:
                sid = (const SID *)&((const SYSTEM_ALARM_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(SYSTEM_ALARM_ACE, SidStart);
                fprintf( stderr, "SYSTEM_ALARM_ACE_TYPE,Mask=%x",
                         ((const SYSTEM_ALARM_ACE *)ace)->Mask );
                break;
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                sid = (const SID *)&((const SYSTEM_MANDATORY_LABEL_ACE *)ace)->SidStart;
                sid_size = ace->AceSize - FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart);
                fprintf( stderr, "SYSTEM_MANDATORY_LABEL_ACE_TYPE,Mask=%x",
                         ((const SYSTEM_MANDATORY_LABEL_ACE *)ace)->Mask );
                break;
            default:
                fprintf( stderr, "unknown<%d>", ace->AceType );
                break;
            }
            fprintf( stderr, ",AceFlags=%x", ace->AceFlags );
            if (sid)
                dump_inline_sid( ",Sid=", sid, sid_size );
            ace = (const ACE_HEADER *)((const char *)ace + ace->AceSize);
            fputc( '}', stderr );
        }
    }
    fputc( '}', stderr );
}

static void dump_varargs_ACL( const char *prefix, data_size_t size )
{
    const ACL *acl = cur_data;
    dump_inline_acl( prefix, acl, size );
    remove_data( size );
}

static void dump_inline_security_descriptor( const char *prefix, const struct security_descriptor *sd, data_size_t size )
{
    fprintf( stderr,"%s{", prefix );
    if (size >= sizeof(struct security_descriptor))
    {
        size_t offset = sizeof(struct security_descriptor);
        fprintf( stderr, "control=%08x", sd->control );
        if ((sd->owner_len > FIELD_OFFSET(SID, SubAuthority[255])) || (offset + sd->owner_len > size))
            return;
        if (sd->owner_len)
            dump_inline_sid( ",owner=", (const SID *)((const char *)sd + offset), sd->owner_len );
        else
            fprintf( stderr, ",owner=<not present>" );
        offset += sd->owner_len;
        if ((sd->group_len > FIELD_OFFSET(SID, SubAuthority[255])) || (offset + sd->group_len > size))
            return;
        if (sd->group_len)
            dump_inline_sid( ",group=", (const SID *)((const char *)sd + offset), sd->group_len );
        else
            fprintf( stderr, ",group=<not present>" );
        offset += sd->group_len;
        if ((sd->sacl_len >= MAX_ACL_LEN) || (offset + sd->sacl_len > size))
            return;
        dump_inline_acl( ",sacl=", (const ACL *)((const char *)sd + offset), sd->sacl_len );
        offset += sd->sacl_len;
        if ((sd->dacl_len >= MAX_ACL_LEN) || (offset + sd->dacl_len > size))
            return;
        dump_inline_acl( ",dacl=", (const ACL *)((const char *)sd + offset), sd->dacl_len );
        offset += sd->dacl_len;
    }
    fputc( '}', stderr );
}

static void dump_varargs_security_descriptor( const char *prefix, data_size_t size )
{
    const struct security_descriptor *sd = cur_data;
    dump_inline_security_descriptor( prefix, sd, size );
    remove_data( size );
}

static void dump_varargs_token_groups( const char *prefix, data_size_t size )
{
    const struct token_groups *tg = cur_data;

    fprintf( stderr,"%s{", prefix );
    if (size >= sizeof(struct token_groups))
    {
        size_t offset = sizeof(*tg);
        fprintf( stderr, "count=%08x,", tg->count );
        if (tg->count * sizeof(unsigned int) <= size)
        {
            unsigned int i;
            const unsigned int *attr = (const unsigned int *)(tg + 1);

            offset += tg->count * sizeof(unsigned int);

            fputc( '[', stderr );
            for (i = 0; i < tg->count; i++)
            {
                const SID *sid = (const SID *)((const char *)cur_data + offset);
                if (i != 0)
                    fputc( ',', stderr );
                fputc( '{', stderr );
                fprintf( stderr, "attributes=%08x", attr[i] );
                dump_inline_sid( ",sid=", sid, size - offset );
                if ((offset + FIELD_OFFSET(SID, SubAuthority[0]) > size) ||
                    (offset + FIELD_OFFSET(SID, SubAuthority[sid->SubAuthorityCount]) > size))
                    break;
                offset += FIELD_OFFSET(SID, SubAuthority[sid->SubAuthorityCount]);
                fputc( '}', stderr );
            }
            fputc( ']', stderr );
        }
    }
    fputc( '}', stderr );
}

static void dump_varargs_object_attributes( const char *prefix, data_size_t size )
{
    const struct object_attributes *objattr = cur_data;

    fprintf( stderr,"%s{", prefix );
    if (size >= sizeof(struct object_attributes))
    {
        const WCHAR *str;
        fprintf( stderr, "rootdir=%04x", objattr->rootdir );
        if (objattr->sd_len > size - sizeof(*objattr) ||
            objattr->name_len > size - sizeof(*objattr) - objattr->sd_len)
            return;
        dump_inline_security_descriptor( ",sd=", (const struct security_descriptor *)(objattr + 1), objattr->sd_len );
        str = (const WCHAR *)objattr + (sizeof(*objattr) + objattr->sd_len) / sizeof(WCHAR);
        fprintf( stderr, ",name=L\"" );
        dump_strW( str, objattr->name_len / sizeof(WCHAR), stderr, "\"\"" );
        fputc( '\"', stderr );
        remove_data( ((sizeof(*objattr) + objattr->sd_len) / sizeof(WCHAR)) * sizeof(WCHAR) +
                     objattr->name_len );
    }
    fputc( '}', stderr );
}

static void dump_varargs_filesystem_event( const char *prefix, data_size_t size )
{
    static const char * const actions[] = {
        NULL,
        "ADDED",
        "REMOVED",
        "MODIFIED",
        "RENAMED_OLD_NAME",
        "RENAMED_NEW_NAME",
        "ADDED_STREAM",
        "REMOVED_STREAM",
        "MODIFIED_STREAM"
    };

    fprintf( stderr,"%s{", prefix );
    while (size)
    {
        const struct filesystem_event *event = cur_data;
        data_size_t len = (offsetof( struct filesystem_event, name[event->len] ) + sizeof(int)-1)
                           / sizeof(int) * sizeof(int);
        if (size < len) break;
        if (event->action < sizeof(actions)/sizeof(actions[0]) && actions[event->action])
            fprintf( stderr, "{action=%s", actions[event->action] );
        else
            fprintf( stderr, "{action=%u", event->action );
        fprintf( stderr, ",name=\"%.*s\"}", event->len, event->name );
        size -= len;
        remove_data( len );
        if (size)fputc( ',', stderr );
    }
    fputc( '}', stderr );
}

static void dump_varargs_rawinput_devices(const char *prefix, data_size_t size )
{
    const struct rawinput_device *device;

    fprintf( stderr, "%s{", prefix );
    while (size >= sizeof(*device))
    {
        device = cur_data;
        fprintf( stderr, "{usage_page=%04x,usage=%04x,flags=%08x,target=%08x}",
                 device->usage_page, device->usage, device->flags, device->target );
        size -= sizeof(*device);
        remove_data( sizeof(*device) );
        if (size) fputc( ',', stderr );
    }
    fputc( '}', stderr );
}

typedef void (*dump_func)( const void *req );

/* Everything below this line is generated automatically by tools/make_requests */
/* ### make_requests begin ### */
/* ### make_requests end ### */
/* Everything above this line is generated automatically by tools/make_requests */

static const char *get_status_name( unsigned int status )
{
    int i;
    static char buffer[10];

    if (status)
    {
        for (i = 0; status_names[i].name; i++)
            if (status_names[i].value == status) return status_names[i].name;
    }
    sprintf( buffer, "%x", status );
    return buffer;
}

void trace_request(void)
{
    enum request req = current->req.request_header.req;
    if (req < REQ_NB_REQUESTS)
    {
        fprintf( stderr, "%04x: %s(", current->id, req_names[req] );
        if (req_dumpers[req])
        {
            cur_data = get_req_data();
            cur_size = get_req_data_size();
            req_dumpers[req]( &current->req );
        }
        fprintf( stderr, " )\n" );
    }
    else fprintf( stderr, "%04x: %d(?)\n", current->id, req );
}

void trace_reply( enum request req, const union generic_reply *reply )
{
    if (req < REQ_NB_REQUESTS)
    {
        fprintf( stderr, "%04x: %s() = %s",
                 current->id, req_names[req], get_status_name(current->error) );
        if (reply_dumpers[req])
        {
            fprintf( stderr, " {" );
            cur_data = current->reply_data;
            cur_size = reply->reply_header.reply_size;
            reply_dumpers[req]( reply );
            fprintf( stderr, " }" );
        }
        fputc( '\n', stderr );
    }
    else fprintf( stderr, "%04x: %d() = %s\n",
                  current->id, req, get_status_name(current->error) );
}
