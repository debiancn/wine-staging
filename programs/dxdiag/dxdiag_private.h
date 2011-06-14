/*
 * Private definitions for the DirectX Diagnostic Tool
 *
 * Copyright 2011 Andrew Nguyen
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

/* Output backend definitions. */
enum output_type
{
    OUTPUT_NONE,
    OUTPUT_TEXT,
    OUTPUT_XML,
};

static inline const char *debugstr_output_type(enum output_type type)
{
    switch (type)
    {
    case OUTPUT_NONE:
        return "(none)";
    case OUTPUT_TEXT:
        return "Plain-text output";
    case OUTPUT_XML:
        return "XML output";
    default:
        return "(unknown)";
    }
}

const WCHAR *get_output_extension(enum output_type type);
BOOL output_dxdiag_information(const WCHAR *filename, enum output_type type);
