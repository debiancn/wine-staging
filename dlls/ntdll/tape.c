/*
 * TAPE support
 *
 * Copyright 2006 Hans Leidekker
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
#include <stdio.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_MTIO_H
#include <sys/mtio.h>
#endif

#if !defined(MTCOMPRESSION) && defined(MTCOMP)
#define MTCOMPRESSION MTCOMP
#endif
#if !defined(MTSETBLK) && defined(MTSETBSIZ)
#define MTSETBLK MTSETBSIZ
#endif
#if !defined(MTSETBLK) && defined(MTSRSZ)
#define MTSETBLK MTSRSZ
#endif
#ifndef MT_ST_BLKSIZE_MASK
#define MT_ST_BLKSIZE_MASK 0xffffff
#endif

/* Darwin 7.9.0 has MTSETBSIZ instead of MTSETBLK */
#if !defined(MTSETBLK) && defined(MTSETBSIZ)
#define MTSETBLK MTSETBSIZ
#endif

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winioctl.h"
#include "ddk/ntddtape.h"
#include "ntdll_misc.h"
#include "wine/server.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(tape);

static const char *io2str( DWORD io )
{
    switch (io)
    {
#define X(x)    case (x): return #x;
    X(IOCTL_TAPE_CHECK_VERIFY);
    X(IOCTL_TAPE_CREATE_PARTITION);
    X(IOCTL_TAPE_ERASE);
    X(IOCTL_TAPE_FIND_NEW_DEVICES);
    X(IOCTL_TAPE_GET_DRIVE_PARAMS);
    X(IOCTL_TAPE_GET_MEDIA_PARAMS);
    X(IOCTL_TAPE_GET_POSITION);
    X(IOCTL_TAPE_GET_STATUS);
    X(IOCTL_TAPE_PREPARE);
    X(IOCTL_TAPE_SET_DRIVE_PARAMS);
    X(IOCTL_TAPE_SET_MEDIA_PARAMS);
    X(IOCTL_TAPE_SET_POSITION);
    X(IOCTL_TAPE_WRITE_MARKS);
#undef X
    default: { static char tmp[32]; sprintf(tmp, "IOCTL_TAPE_%d\n", io); return tmp; }
    }
}

/******************************************************************
 *      TAPE_GetStatus
 */
static NTSTATUS TAPE_GetStatus( int error )
{
    if (!error) return STATUS_SUCCESS;
    return FILE_GetNtStatus();
}

/******************************************************************
 *      TAPE_CreatePartition
 */
static NTSTATUS TAPE_CreatePartition( int fd, const TAPE_CREATE_PARTITION *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtop cmd;

    TRACE( "fd: %d method: 0x%08x count: 0x%08x size: 0x%08x\n",
           fd, data->Method, data->Count, data->Size );

    if (data->Count > 1)
    {
        WARN( "Creating more than 1 partition is not supported\n" );
        return STATUS_INVALID_PARAMETER;
    }

    switch (data->Method)
    {
#ifdef MTMKPART
    case TAPE_FIXED_PARTITIONS:
    case TAPE_SELECT_PARTITIONS:
        cmd.mt_op = MTMKPART;
        cmd.mt_count = 0;
        break;
    case TAPE_INITIATOR_PARTITIONS:
        cmd.mt_op = MTMKPART;
        cmd.mt_count = data->Size;
        break;
#endif
    default:
        ERR( "Unhandled method: 0x%08x\n", data->Method );
        return STATUS_INVALID_PARAMETER;
    }

    return TAPE_GetStatus( ioctl( fd, MTIOCTOP, &cmd ) );
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}

/******************************************************************
 *      TAPE_Erase
 */
static NTSTATUS TAPE_Erase( int fd, const TAPE_ERASE *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtop cmd;

    TRACE( "fd: %d type: 0x%08x immediate: 0x%02x\n",
           fd, data->Type, data->Immediate );

    switch (data->Type)
    {
    case TAPE_ERASE_LONG:
        cmd.mt_op = MTERASE;
        cmd.mt_count = 1;
        break;
    case TAPE_ERASE_SHORT:
        cmd.mt_op = MTERASE;
        cmd.mt_count = 0;
        break;
    default:
        ERR( "Unhandled type: 0x%08x\n", data->Type );
        return STATUS_INVALID_PARAMETER;
    }

    return TAPE_GetStatus( ioctl( fd, MTIOCTOP, &cmd ) );
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}

/******************************************************************
 *      TAPE_GetDriveParams
 */
static NTSTATUS TAPE_GetDriveParams( int fd, TAPE_GET_DRIVE_PARAMETERS *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtget get;
    NTSTATUS status;

    TRACE( "fd: %d\n", fd );

    memset( data, 0, sizeof(TAPE_GET_DRIVE_PARAMETERS) );

    status = TAPE_GetStatus( ioctl( fd, MTIOCGET, &get ) );
    if (status != STATUS_SUCCESS)
        return status;

    data->ECC = FALSE;
    data->Compression = FALSE;
    data->DataPadding = FALSE;
    data->ReportSetmarks = FALSE;
#ifdef HAVE_STRUCT_MTGET_MT_BLKSIZ
    data->DefaultBlockSize = get.mt_blksiz;
#else
    data->DefaultBlockSize = get.mt_dsreg & MT_ST_BLKSIZE_MASK;
#endif
    data->MaximumBlockSize = data->DefaultBlockSize;
    data->MinimumBlockSize = data->DefaultBlockSize;
    data->MaximumPartitionCount = 1;

    return status;
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}

/******************************************************************
 *      TAPE_GetMediaParams
 */
static NTSTATUS TAPE_GetMediaParams( int fd, TAPE_GET_MEDIA_PARAMETERS *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtget get;
    NTSTATUS status;

    TRACE( "fd: %d\n", fd );

    memset( data, 0, sizeof(TAPE_GET_MEDIA_PARAMETERS) );

    status = TAPE_GetStatus( ioctl( fd, MTIOCGET, &get ) );
    if (status != STATUS_SUCCESS)
        return status;

    data->Capacity.u.LowPart = 1024 * 1024 * 1024;
    data->Remaining.u.LowPart = 1024 * 1024 * 1024;
#ifdef HAVE_STRUCT_MTGET_MT_BLKSIZ
    data->BlockSize = get.mt_blksiz;
#else
    data->BlockSize = get.mt_dsreg & MT_ST_BLKSIZE_MASK;
#endif
    data->PartitionCount = 1;
#ifdef HAVE_STRUCT_MTGET_MT_GSTAT
    data->WriteProtected = (GMT_WR_PROT(get.mt_gstat) != 0);
#else
    data->WriteProtected = 0;
#endif

    return status;
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}

/******************************************************************
 *      TAPE_GetPosition
 */
static NTSTATUS TAPE_GetPosition( int fd, ULONG type, TAPE_GET_POSITION *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtget get;
#ifndef HAVE_STRUCT_MTGET_MT_BLKNO
    struct mtpos pos;
#endif
    NTSTATUS status;

    TRACE( "fd: %d type: 0x%08x\n", fd, type );

    memset( data, 0, sizeof(TAPE_GET_POSITION) );

    status = TAPE_GetStatus( ioctl( fd, MTIOCGET, &get ) );
    if (status != STATUS_SUCCESS)
        return status;

#ifndef HAVE_STRUCT_MTGET_MT_BLKNO
    status = TAPE_GetStatus( ioctl( fd, MTIOCPOS, &pos ) );
    if (status != STATUS_SUCCESS)
        return status;
#endif

    switch (type)
    {
    case TAPE_ABSOLUTE_BLOCK:
        data->Type = type;
        data->Partition = get.mt_resid;
#ifdef HAVE_STRUCT_MTGET_MT_BLKNO
        data->OffsetLow = get.mt_blkno;
#else
        data->OffsetLow = pos.mt_blkno;
#endif
        break;
    case TAPE_LOGICAL_BLOCK:
    case TAPE_PSEUDO_LOGICAL_BLOCK:
        WARN( "Positioning type not supported\n" );
        break;
    default:
        ERR( "Unhandled type: 0x%08x\n", type );
        return STATUS_INVALID_PARAMETER;
    }

    return status;
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}

/******************************************************************
 *      TAPE_Prepare
 */
static NTSTATUS TAPE_Prepare( int fd, const TAPE_PREPARE *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtop cmd;

    TRACE( "fd: %d type: 0x%08x immediate: 0x%02x\n",
           fd, data->Operation, data->Immediate );

    switch (data->Operation)
    {
#ifdef MTLOAD
    case TAPE_LOAD:
        cmd.mt_op = MTLOAD;
        break;
#endif
#ifdef MTUNLOAD
    case TAPE_UNLOAD:
        cmd.mt_op = MTUNLOAD;
        break;
#endif
#ifdef MTRETEN
    case TAPE_TENSION:
        cmd.mt_op = MTRETEN;
        break;
#endif
#ifdef MTLOCK
    case TAPE_LOCK:
        cmd.mt_op = MTLOCK;
        break;
#endif
#ifdef MTUNLOCK
    case TAPE_UNLOCK:
        cmd.mt_op = MTUNLOCK;
        break;
#endif
    case TAPE_FORMAT:
        /* Native ignores this if the drive doesn't support it */
        return STATUS_SUCCESS;
    default:
        ERR( "Unhandled operation: 0x%08x\n", data->Operation );
        return STATUS_INVALID_PARAMETER;
    }

    return TAPE_GetStatus( ioctl( fd, MTIOCTOP, &cmd ) );
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}

/******************************************************************
 *      TAPE_SetDriveParams
 */
static NTSTATUS TAPE_SetDriveParams( int fd, const TAPE_SET_DRIVE_PARAMETERS *data )
{
#if defined(HAVE_SYS_MTIO_H) && defined(MTCOMPRESSION)
    struct mtop cmd;

    TRACE( "fd: %d ECC: 0x%02x, compression: 0x%02x padding: 0x%02x\n",
            fd, data->ECC, data->Compression, data->DataPadding );
    TRACE( "setmarks: 0x%02x zonesize: 0x%08x\n",
           data->ReportSetmarks, data->EOTWarningZoneSize );

    if (data->ECC || data->DataPadding || data->ReportSetmarks ||
        data->EOTWarningZoneSize ) WARN( "Setting not supported\n" );

    cmd.mt_op = MTCOMPRESSION;
    cmd.mt_count = data->Compression;

    return TAPE_GetStatus( ioctl( fd, MTIOCTOP, &cmd ) );
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}
        
/******************************************************************
 *      TAPE_SetMediaParams
 */
static NTSTATUS TAPE_SetMediaParams( int fd, const TAPE_SET_MEDIA_PARAMETERS *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtop cmd;

    TRACE( "fd: %d blocksize: 0x%08x\n", fd, data->BlockSize );
    
    cmd.mt_op = MTSETBLK;
    cmd.mt_count = data->BlockSize;

    return TAPE_GetStatus( ioctl( fd, MTIOCTOP, &cmd ) );
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}
        
/******************************************************************
 *      TAPE_SetPosition
 */
static NTSTATUS TAPE_SetPosition( int fd, const TAPE_SET_POSITION *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtop cmd;

    TRACE( "fd: %d method: 0x%08x partition: 0x%08x offset: 0x%x%08x immediate: 0x%02x\n",
           fd, data->Method, data->Partition, (DWORD)(data->Offset.QuadPart >> 32),
           (DWORD)data->Offset.QuadPart, data->Immediate );

    if (sizeof(cmd.mt_count) < sizeof(data->Offset.QuadPart) &&
        (int)data->Offset.QuadPart != data->Offset.QuadPart)
    {
        ERR("Offset too large or too small\n");
        return STATUS_INVALID_PARAMETER;
    }

    switch (data->Method)
    {
    case TAPE_REWIND:
        cmd.mt_op = MTREW;
        break;
#ifdef MTSEEK
    case TAPE_ABSOLUTE_BLOCK:
        cmd.mt_op = MTSEEK;
        cmd.mt_count = data->Offset.QuadPart;
        break;
#endif
#ifdef MTEOM
    case TAPE_SPACE_END_OF_DATA:
        cmd.mt_op = MTEOM;
        break;
#endif
    case TAPE_SPACE_FILEMARKS:
        if (data->Offset.QuadPart >= 0) {
            cmd.mt_op = MTFSF;
            cmd.mt_count = data->Offset.QuadPart;
        }
        else {
            cmd.mt_op = MTBSF;
            cmd.mt_count = -data->Offset.QuadPart;
        }
        break;
#if defined(MTFSS) && defined(MTBSS)
    case TAPE_SPACE_SETMARKS:
        if (data->Offset.QuadPart >= 0) {
            cmd.mt_op = MTFSS;
            cmd.mt_count = data->Offset.QuadPart;
        }
        else {
            cmd.mt_op = MTBSS;
            cmd.mt_count = -data->Offset.QuadPart;
        }
        break;
#endif
    case TAPE_LOGICAL_BLOCK:
    case TAPE_PSEUDO_LOGICAL_BLOCK:
    case TAPE_SPACE_RELATIVE_BLOCKS:
    case TAPE_SPACE_SEQUENTIAL_FMKS:
    case TAPE_SPACE_SEQUENTIAL_SMKS:
        WARN( "Positioning method not supported\n" );
        return STATUS_INVALID_PARAMETER;
    default:
        ERR( "Unhandled method: 0x%08x\n", data->Method );
        return STATUS_INVALID_PARAMETER;
    }

    return TAPE_GetStatus( ioctl( fd, MTIOCTOP, &cmd ) );
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}

/******************************************************************
 *      TAPE_WriteMarks
 */
static NTSTATUS TAPE_WriteMarks( int fd, const TAPE_WRITE_MARKS *data )
{
#ifdef HAVE_SYS_MTIO_H
    struct mtop cmd;

    TRACE( "fd: %d type: 0x%08x count: 0x%08x immediate: 0x%02x\n",
           fd, data->Type, data->Count, data->Immediate );

    switch (data->Type)
    {
#ifdef MTWSM
    case TAPE_SETMARKS:
        cmd.mt_op = MTWSM;
        cmd.mt_count = data->Count;
        break;
#endif
    case TAPE_FILEMARKS:
    case TAPE_SHORT_FILEMARKS:
    case TAPE_LONG_FILEMARKS:
        cmd.mt_op = MTWEOF;
        cmd.mt_count = data->Count;
        break;
    default:
        ERR( "Unhandled type: 0x%08x\n", data->Type );
        return STATUS_INVALID_PARAMETER;
    }

    return TAPE_GetStatus( ioctl( fd, MTIOCTOP, &cmd ) );
#else
    FIXME( "Not implemented.\n" );
    return STATUS_NOT_SUPPORTED;
#endif
}

/******************************************************************
 *		TAPE_DeviceIoControl
 *
 * SEE ALSO
 *   NtDeviceIoControl.
 */
NTSTATUS TAPE_DeviceIoControl( HANDLE device, HANDLE event,
    PIO_APC_ROUTINE apc, PVOID apc_user, PIO_STATUS_BLOCK io_status,
    ULONG io_control, LPVOID in_buffer, DWORD in_size,
    LPVOID out_buffer, DWORD out_size )
{
    DWORD sz = 0;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    int fd, needs_close;

    TRACE( "%p %s %p %d %p %d %p\n", device, io2str(io_control),
           in_buffer, in_size, out_buffer, out_size, io_status );

    io_status->Information = 0;

    if ((status = server_get_unix_fd( device, 0, &fd, &needs_close, NULL, NULL )))
        goto error;

    switch (io_control)
    {
    case IOCTL_TAPE_CREATE_PARTITION:
        status = TAPE_CreatePartition( fd, (TAPE_CREATE_PARTITION *)in_buffer );
        break;
    case IOCTL_TAPE_ERASE:
        status = TAPE_Erase( fd, (TAPE_ERASE *)in_buffer );
        break;
    case IOCTL_TAPE_GET_DRIVE_PARAMS:
        status = TAPE_GetDriveParams( fd, (TAPE_GET_DRIVE_PARAMETERS *)out_buffer );
        break;
    case IOCTL_TAPE_GET_MEDIA_PARAMS:
        status = TAPE_GetMediaParams( fd, (TAPE_GET_MEDIA_PARAMETERS *)out_buffer );
        break;
    case IOCTL_TAPE_GET_POSITION:
        status = TAPE_GetPosition( fd, ((TAPE_GET_POSITION *)in_buffer)->Type,
                                   (TAPE_GET_POSITION *)out_buffer );
        break;
    case IOCTL_TAPE_GET_STATUS:
        status = FILE_GetNtStatus();
        break;
    case IOCTL_TAPE_PREPARE:
        status = TAPE_Prepare( fd, (TAPE_PREPARE *)in_buffer );
        break;
    case IOCTL_TAPE_SET_DRIVE_PARAMS:
        status = TAPE_SetDriveParams( fd, (TAPE_SET_DRIVE_PARAMETERS *)in_buffer );
        break;
    case IOCTL_TAPE_SET_MEDIA_PARAMS:
        status = TAPE_SetMediaParams( fd, (TAPE_SET_MEDIA_PARAMETERS *)in_buffer );
        break;
    case IOCTL_TAPE_SET_POSITION:
        status = TAPE_SetPosition( fd, (TAPE_SET_POSITION *)in_buffer );
        break;
    case IOCTL_TAPE_WRITE_MARKS:
        status = TAPE_WriteMarks( fd, (TAPE_WRITE_MARKS *)in_buffer );
        break;

    case IOCTL_TAPE_CHECK_VERIFY:
    case IOCTL_TAPE_FIND_NEW_DEVICES:
        break;
    default:
        FIXME( "Unsupported IOCTL %x (type=%x access=%x func=%x meth=%x)\n",
               io_control, io_control >> 16, (io_control >> 14) & 3,
               (io_control >> 2) & 0xfff, io_control & 3 );
        break;
    }

    if (needs_close) close( fd );

error:
    io_status->u.Status = status;
    io_status->Information = sz;
    if (event) NtSetEvent( event, NULL );
    return status;
}
