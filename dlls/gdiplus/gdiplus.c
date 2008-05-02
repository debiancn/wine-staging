/*
 * Copyright (C) 2007 Google (Evan Stade)
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

#include <stdarg.h>
#include <math.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "wine/debug.h"
#include "gdiplus.h"
#include "gdiplus_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(gdiplus);

/*****************************************************
 *      DllMain
 */
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    TRACE("(%p, %d, %p)\n", hinst, reason, reserved);

    switch(reason)
    {
    case DLL_WINE_PREATTACH:
        return FALSE;  /* prefer native version */

    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls( hinst );
        break;
    }
    return TRUE;
}

/*****************************************************
 *      GdiplusStartup [GDIPLUS.@]
 */
Status WINAPI GdiplusStartup(ULONG_PTR *token, const struct GdiplusStartupInput *input,
                             struct GdiplusStartupOutput *output)
{
    if(!token)
        return InvalidParameter;

    if(input->GdiplusVersion != 1) {
        return UnsupportedGdiplusVersion;
    } else if ((input->DebugEventCallback) ||
        (input->SuppressBackgroundThread) || (input->SuppressExternalCodecs)){
        FIXME("Unimplemented for non-default GdiplusStartupInput\n");
        return NotImplemented;
    } else if(output) {
        FIXME("Unimplemented for non-null GdiplusStartupOutput\n");
        return NotImplemented;
    }

    return Ok;
}

/*****************************************************
 *      GdiplusShutdown [GDIPLUS.@]
 */
void WINAPI GdiplusShutdown(ULONG_PTR token)
{
    /* FIXME: no object tracking */
}

/*****************************************************
 *      GdipAlloc [GDIPLUS.@]
 */
void* WINGDIPAPI GdipAlloc(SIZE_T size)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

/*****************************************************
 *      GdipFree [GDIPLUS.@]
 */
void WINGDIPAPI GdipFree(void* ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}

/* Calculates the bezier points needed to fill in the arc portion starting at
 * angle start and ending at end.  These two angles should be no more than 90
 * degrees from each other.  x1, y1, x2, y2 describes the bounding box (upper
 * left and width and height).  Angles must be in radians. write_first indicates
 * that the first bezier point should be written out (usually this is false).
 * pt is the array of GpPointFs that gets written to.
 **/
static void add_arc_part(GpPointF * pt, REAL x1, REAL y1, REAL x2, REAL y2,
    REAL start, REAL end, BOOL write_first)
{
    REAL center_x, center_y, rad_x, rad_y, cos_start, cos_end,
        sin_start, sin_end, a, half;
    INT i;

    rad_x = x2 / 2.0;
    rad_y = y2 / 2.0;
    center_x = x1 + rad_x;
    center_y = y1 + rad_y;

    cos_start = cos(start);
    cos_end = cos(end);
    sin_start = sin(start);
    sin_end = sin(end);

    half = (end - start) / 2.0;
    a = 4.0 / 3.0 * (1 - cos(half)) / sin(half);

    if(write_first){
        pt[0].X = cos_start;
        pt[0].Y = sin_start;
    }
    pt[1].X = cos_start - a * sin_start;
    pt[1].Y = sin_start + a * cos_start;

    pt[3].X = cos_end;
    pt[3].Y = sin_end;
    pt[2].X = cos_end + a * sin_end;
    pt[2].Y = sin_end - a * cos_end;

    /* expand the points back from the unit circle to the ellipse */
    for(i = (write_first ? 0 : 1); i < 4; i ++){
        pt[i].X = pt[i].X * rad_x + center_x;
        pt[i].Y = pt[i].Y * rad_y + center_y;
    }
}

/* We plot the curve as if it is on a circle then stretch the points.  This
 * adjusts the angles so that when we stretch the points they will end in the
 * right place. This is only complicated because atan and atan2 do not behave
 * conveniently. */
static void unstretch_angle(REAL * angle, REAL rad_x, REAL rad_y)
{
    REAL stretched;
    INT revs_off;

    *angle = deg2rad(*angle);

    if(cos(*angle) == 0 || sin(*angle) == 0)
        return;

    stretched = atan2(sin(*angle) / rad_y, cos(*angle) / rad_x);
    revs_off = roundr(*angle / (2.0 * M_PI)) - roundr(stretched / (2.0 * M_PI));
    stretched += ((REAL)revs_off) * M_PI * 2.0;
    *angle = stretched;
}

/* Stores the bezier points that correspond to the arc in points.  If points is
 * null, just return the number of points needed to represent the arc. */
INT arc2polybezier(GpPointF * points, REAL x1, REAL y1, REAL x2, REAL y2,
    REAL startAngle, REAL sweepAngle)
{
    INT i, count;
    REAL end_angle, start_angle, endAngle;

    endAngle = startAngle + sweepAngle;
    unstretch_angle(&startAngle, x2 / 2.0, y2 / 2.0);
    unstretch_angle(&endAngle, x2 / 2.0, y2 / 2.0);

    count = ceilf(fabs(endAngle - startAngle) / M_PI_2) * 3 + 1;
    /* don't make more than a full circle */
    count = min(MAX_ARC_PTS, count);

    if(count == 1)
        return 0;
    if(!points)
        return count;

    /* start_angle and end_angle are the iterative variables */
    start_angle = startAngle;

    for(i = 0; i < count - 1; i += 3){
        /* check if we've overshot the end angle */
        if( sweepAngle > 0.0 )
            end_angle = min(start_angle + M_PI_2, endAngle);
        else
            end_angle = max(start_angle - M_PI_2, endAngle);

        add_arc_part(&points[i], x1, y1, x2, y2, start_angle, end_angle, i == 0);

        start_angle += M_PI_2 * (sweepAngle < 0.0 ? -1.0 : 1.0);
    }

    return count;
}

COLORREF ARGB2COLORREF(ARGB color)
{
    /*
    Packing of these color structures:
    COLORREF:   00bbggrr
    ARGB:       aarrggbb
    FIXME:doesn't handle alpha channel
    */
    return (COLORREF)
        ((color & 0x0000ff) << 16) +
         (color & 0x00ff00) +
        ((color & 0xff0000) >> 16);
}
