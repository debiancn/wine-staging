/*
 * Copyright 2007 Tim Schwartz
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

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <lm.h>
#include "resources.h"

#define NET_START 0001
#define NET_STOP  0002

int output_string(int msg, ...)
{
    char msg_buffer[8192];
    va_list arguments;

    LoadString(GetModuleHandle(NULL), msg, msg_buffer, sizeof(msg_buffer));
    va_start(arguments, msg);
    vprintf(msg_buffer, arguments);
    va_end(arguments);
    return 0;
}

BOOL output_error_string(DWORD error)
{
    LPSTR pBuffer;
    if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            NULL, error, 0, (LPSTR)&pBuffer, 0, NULL))
    {
        fputs(pBuffer, stdout);
        LocalFree(pBuffer);
        return TRUE;
    }
    return FALSE;
}

static BOOL net_use(int argc, char *argv[])
{
    USE_INFO_2 *buffer, *connection;
    DWORD read, total, resume_handle, rc, i;
    const char *status_description[] = { "OK", "Paused", "Disconnected", "An error occurred",
                                         "A network error occurred", "Connection is being made",
					 "Reconnecting" };
    resume_handle = 0;
    buffer = NULL;

    if(argc<3)
    {
        do {
            rc = NetUseEnum(NULL, 2, (BYTE **) &buffer, 2048, &read, &total, &resume_handle);
            if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS)
            {
                break;
            }

	    if(total == 0)
	    {
	        output_string(STRING_NO_ENTRIES);
		break;
	    }

            output_string(STRING_USE_HEADER);
            for (i = 0, connection = buffer; i < read; ++i, ++connection)
                output_string(STRING_USE_ENTRY, status_description[connection->ui2_status], connection->ui2_local,
				connection->ui2_remote, connection->ui2_refcount);

            if (buffer != NULL) NetApiBufferFree(buffer);
        } while (rc == ERROR_MORE_DATA);

	return TRUE;
    }

    return FALSE;
}

static BOOL StopService(SC_HANDLE SCManager, SC_HANDLE serviceHandle)
{
    LPENUM_SERVICE_STATUS dependencies = NULL;
    DWORD buffer_size = 0;
    DWORD count = 0, counter;
    BOOL result;
    SC_HANDLE dependent_serviceHandle;
    SERVICE_STATUS_PROCESS ssp;

    result = EnumDependentServices(serviceHandle, SERVICE_ACTIVE, dependencies, buffer_size, &buffer_size, &count);

    if(!result && (GetLastError() == ERROR_MORE_DATA))
    {
        dependencies = HeapAlloc(GetProcessHeap(), 0, buffer_size);
        if(EnumDependentServices(serviceHandle, SERVICE_ACTIVE, dependencies, buffer_size, &buffer_size, &count))
        {
            for(counter = 0; counter < count; counter++)
            {
                output_string(STRING_STOP_DEP, dependencies[counter].lpDisplayName);
                dependent_serviceHandle = OpenService(SCManager, dependencies[counter].lpServiceName, SC_MANAGER_ALL_ACCESS);
                if(dependent_serviceHandle) result = StopService(SCManager, dependent_serviceHandle);
                CloseServiceHandle(dependent_serviceHandle);
                if(!result) output_string(STRING_CANT_STOP, dependencies[counter].lpDisplayName);
           }
        }
    }

    if(result) result = ControlService(serviceHandle, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
    HeapFree(GetProcessHeap(), 0, dependencies);
    return result;
}

static BOOL net_service(int operation, char *service_name)
{
    SC_HANDLE SCManager, serviceHandle;
    BOOL result = 0;
    char service_display_name[4096];
    DWORD buffer_size = sizeof(service_display_name);

    SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(!SCManager)
    {
        output_string(STRING_NO_SCM);
        return FALSE;
    }
    serviceHandle = OpenService(SCManager, service_name, SC_MANAGER_ALL_ACCESS);
    if(!serviceHandle)
    {
        output_string(STRING_NO_SVCHANDLE);
        CloseServiceHandle(SCManager);
        return FALSE;
    }


    GetServiceDisplayName(SCManager, service_name, service_display_name, &buffer_size);
    if (!service_display_name[0]) strcpy(service_display_name, service_name);

    switch(operation)
    {
    case NET_START:
        output_string(STRING_START_SVC, service_display_name);
        result = StartService(serviceHandle, 0, NULL);

        if(result) output_string(STRING_START_SVC_SUCCESS, service_display_name);
        else
        {
            if (!output_error_string(GetLastError()))
                output_string(STRING_START_SVC_FAIL, service_display_name);
        }
        break;
    case NET_STOP:
        output_string(STRING_STOP_SVC, service_display_name);
        result = StopService(SCManager, serviceHandle);

        if(result) output_string(STRING_STOP_SVC_SUCCESS, service_display_name);
        else
        {
            if (!output_error_string(GetLastError()))
                output_string(STRING_STOP_SVC_FAIL, service_display_name);
        }
        break;
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(SCManager);
    return result;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        output_string(STRING_USAGE);
        return 1;
    }

    if(!strcasecmp(argv[1], "help"))
    {
        output_string(STRING_HELP_USAGE);
    }

    if(!strcasecmp(argv[1], "start"))
    {
        if(argc < 3)
        {
            output_string(STRING_START_USAGE);
            return 1;
        }

        if(!net_service(NET_START, argv[2]))
        {
            return 1;
        }
        return 0;
    }

    if(!strcasecmp(argv[1], "stop"))
    {
        if(argc < 3)
        {
            output_string(STRING_STOP_USAGE);
            return 1;
        }

        if(!net_service(NET_STOP, argv[2]))
        {
            return 1;
        }
        return 0;
    }

    if(!strcasecmp(argv[1], "use"))
    {
        if(!net_use(argc, argv)) return 1;
    }

    return 0;
}
