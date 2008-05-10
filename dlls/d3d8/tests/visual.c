/*
 * Copyright (C) 2005 Henri Verbeet
 * Copyright (C) 2007 Stefan D�singer(for CodeWeavers)
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

/* See comment in dlls/d3d9/tests/visual.c for general guidelines */

#define COBJMACROS
#include <d3d8.h>
#include <dxerr8.h>
#include "wine/test.h"

static HMODULE d3d8_handle = 0;

static HWND create_window(void)
{
    WNDCLASS wc = {0};
    HWND ret;
    wc.lpfnWndProc = &DefWindowProc;
    wc.lpszClassName = "d3d8_test_wc";
    RegisterClass(&wc);

    ret = CreateWindow("d3d8_test_wc", "d3d8_test",
                        WS_MAXIMIZE | WS_VISIBLE | WS_CAPTION , 0, 0, 640, 480, 0, 0, 0, 0);
    return ret;
}

static DWORD getPixelColor(IDirect3DDevice8 *device, UINT x, UINT y)
{
    DWORD ret;
    IDirect3DSurface8 *surf;
    IDirect3DTexture8 *tex;
    HRESULT hr;
    D3DLOCKED_RECT lockedRect;
    RECT rectToLock = {x, y, x+1, y+1};

    hr = IDirect3DDevice8_CreateTexture(device, 640, 480, 1 /* Levels */, 0 /* usage */, D3DFMT_A8R8G8B8, D3DPOOL_SYSTEMMEM, &tex);
    if(FAILED(hr) || !tex )  /* This is not a test */
    {
        trace("Can't create an offscreen plain surface to read the render target data, hr=%#08x\n", hr);
        return 0xdeadbeef;
    }
    hr = IDirect3DTexture8_GetSurfaceLevel(tex, 0, &surf);
    if(FAILED(hr) || !tex )  /* This is not a test */
    {
        trace("Can't get surface from texture, hr=%#08x\n", hr);
        ret = 0xdeadbeee;
        goto out;
    }

    hr = IDirect3DDevice8_GetFrontBuffer(device, surf);
    if(FAILED(hr))
    {
        trace("Can't read the front buffer data, hr=%#08x\n", hr);
        ret = 0xdeadbeed;
        goto out;
    }

    hr = IDirect3DSurface8_LockRect(surf, &lockedRect, &rectToLock, D3DLOCK_READONLY);
    if(FAILED(hr))
    {
        trace("Can't lock the offscreen surface, hr=%#08x\n", hr);
        ret = 0xdeadbeec;
        goto out;
    }
    /* Remove the X channel for now. DirectX and OpenGL have different ideas how to treat it apparently, and it isn't
     * really important for these tests
     */
    ret = ((DWORD *) lockedRect.pBits)[0] & 0x00ffffff;
    hr = IDirect3DSurface8_UnlockRect(surf);
    if(FAILED(hr))
    {
        trace("Can't unlock the offscreen surface, hr=%#08x\n", hr);
    }

out:
    if(surf) IDirect3DSurface8_Release(surf);
    if(tex) IDirect3DTexture8_Release(tex);
    return ret;
}

static IDirect3DDevice8 *init_d3d8(void)
{
    IDirect3D8 * (__stdcall * d3d8_create)(UINT SDKVersion) = 0;
    IDirect3D8 *d3d8_ptr = 0;
    IDirect3DDevice8 *device_ptr = 0;
    D3DPRESENT_PARAMETERS present_parameters;
    HRESULT hr;

    d3d8_create = (void *)GetProcAddress(d3d8_handle, "Direct3DCreate8");
    ok(d3d8_create != NULL, "Failed to get address of Direct3DCreate8\n");
    if (!d3d8_create) return NULL;

    d3d8_ptr = d3d8_create(D3D_SDK_VERSION);
    ok(d3d8_ptr != NULL, "Failed to create IDirect3D8 object\n");
    if (!d3d8_ptr) return NULL;

    ZeroMemory(&present_parameters, sizeof(present_parameters));
    present_parameters.Windowed = FALSE;
    present_parameters.hDeviceWindow = create_window();
    present_parameters.SwapEffect = D3DSWAPEFFECT_DISCARD;
    present_parameters.BackBufferWidth = 640;
    present_parameters.BackBufferHeight = 480;
    present_parameters.BackBufferFormat = D3DFMT_X8R8G8B8;
    present_parameters.EnableAutoDepthStencil = TRUE;
    present_parameters.AutoDepthStencilFormat = D3DFMT_D16;

    hr = IDirect3D8_CreateDevice(d3d8_ptr, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, present_parameters.hDeviceWindow, D3DCREATE_SOFTWARE_VERTEXPROCESSING, &present_parameters, &device_ptr);
    ok(hr == D3D_OK || hr == D3DERR_INVALIDCALL, "IDirect3D_CreateDevice returned: %#08x\n", hr);

    return device_ptr;
}

struct vertex
{
    float x, y, z;
    DWORD diffuse;
};

struct nvertex
{
    float x, y, z;
    float nx, ny, nz;
    DWORD diffuse;
};

static void lighting_test(IDirect3DDevice8 *device)
{
    HRESULT hr;
    DWORD fvf = D3DFVF_XYZ | D3DFVF_DIFFUSE;
    DWORD nfvf = D3DFVF_XYZ | D3DFVF_DIFFUSE | D3DFVF_NORMAL;
    DWORD color;

    float mat[16] = { 1.0f, 0.0f, 0.0f, 0.0f,
                      0.0f, 1.0f, 0.0f, 0.0f,
                      0.0f, 0.0f, 1.0f, 0.0f,
                      0.0f, 0.0f, 0.0f, 1.0f };

    struct vertex unlitquad[] =
    {
        {-1.0f, -1.0f,   0.1f,                          0xffff0000},
        {-1.0f,  0.0f,   0.1f,                          0xffff0000},
        { 0.0f,  0.0f,   0.1f,                          0xffff0000},
        { 0.0f, -1.0f,   0.1f,                          0xffff0000},
    };
    struct vertex litquad[] =
    {
        {-1.0f,  0.0f,   0.1f,                          0xff00ff00},
        {-1.0f,  1.0f,   0.1f,                          0xff00ff00},
        { 0.0f,  1.0f,   0.1f,                          0xff00ff00},
        { 0.0f,  0.0f,   0.1f,                          0xff00ff00},
    };
    struct nvertex unlitnquad[] =
    {
        { 0.0f, -1.0f,   0.1f,  1.0f,   1.0f,   1.0f,   0xff0000ff},
        { 0.0f,  0.0f,   0.1f,  1.0f,   1.0f,   1.0f,   0xff0000ff},
        { 1.0f,  0.0f,   0.1f,  1.0f,   1.0f,   1.0f,   0xff0000ff},
        { 1.0f, -1.0f,   0.1f,  1.0f,   1.0f,   1.0f,   0xff0000ff},
    };
    struct nvertex litnquad[] =
    {
        { 0.0f,  0.0f,   0.1f,  1.0f,   1.0f,   1.0f,   0xffffff00},
        { 0.0f,  1.0f,   0.1f,  1.0f,   1.0f,   1.0f,   0xffffff00},
        { 1.0f,  1.0f,   0.1f,  1.0f,   1.0f,   1.0f,   0xffffff00},
        { 1.0f,  0.0f,   0.1f,  1.0f,   1.0f,   1.0f,   0xffffff00},
    };
    WORD Indices[] = {0, 1, 2, 2, 3, 0};

    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xffffffff, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed with %#08x\n", hr);

    /* Setup some states that may cause issues */
    hr = IDirect3DDevice8_SetTransform(device, D3DTS_WORLDMATRIX(0), (D3DMATRIX *) mat);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetTransform returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetTransform(device, D3DTS_VIEW, (D3DMATRIX *)mat);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetTransform returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetTransform(device, D3DTS_PROJECTION, (D3DMATRIX *) mat);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetTransform returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_CLIPPING, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ZENABLE, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGENABLE, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_STENCILENABLE, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ALPHATESTENABLE, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ALPHABLENDENABLE, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_CULLMODE, D3DCULL_NONE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed with %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_COLORWRITEENABLE, D3DCOLORWRITEENABLE_RED | D3DCOLORWRITEENABLE_GREEN | D3DCOLORWRITEENABLE_BLUE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed with %#08x\n", hr);

    hr = IDirect3DDevice8_SetVertexShader(device, fvf);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetVertexShader returned %#08x\n", hr);

    hr = IDirect3DDevice8_BeginScene(device);
    ok(hr == D3D_OK, "IDirect3DDevice8_BeginScene failed with %#08x\n", hr);
    if(hr == D3D_OK)
    {
        /* No lights are defined... That means, lit vertices should be entirely black */
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_LIGHTING, FALSE);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
        hr = IDirect3DDevice8_DrawIndexedPrimitiveUP(device, D3DPT_TRIANGLELIST, 0 /* MinIndex */, 4 /* NumVerts */,
                                                    2 /*PrimCount */, Indices, D3DFMT_INDEX16, unlitquad, sizeof(unlitquad[0]));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawIndexedPrimitiveUP failed with %#08x\n", hr);

        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_LIGHTING, TRUE);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
        hr = IDirect3DDevice8_DrawIndexedPrimitiveUP(device, D3DPT_TRIANGLELIST, 0 /* MinIndex */, 4 /* NumVerts */,
                                                    2 /*PrimCount */, Indices, D3DFMT_INDEX16, litquad, sizeof(litquad[0]));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawIndexedPrimitiveUP failed with %#08x\n", hr);

        hr = IDirect3DDevice8_SetVertexShader(device, nfvf);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetVertexShader failed with %#08x\n", hr);

        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_LIGHTING, FALSE);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
        hr = IDirect3DDevice8_DrawIndexedPrimitiveUP(device, D3DPT_TRIANGLELIST, 0 /* MinIndex */, 4 /* NumVerts */,
                                                    2 /*PrimCount */, Indices, D3DFMT_INDEX16, unlitnquad, sizeof(unlitnquad[0]));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawIndexedPrimitiveUP failed with %#08x\n", hr);

        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_LIGHTING, TRUE);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
        hr = IDirect3DDevice8_DrawIndexedPrimitiveUP(device, D3DPT_TRIANGLELIST, 0 /* MinIndex */, 4 /* NumVerts */,
                                                    2 /*PrimCount */, Indices, D3DFMT_INDEX16, litnquad, sizeof(litnquad[0]));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawIndexedPrimitiveUP failed with %#08x\n", hr);

        IDirect3DDevice8_EndScene(device);
        ok(hr == D3D_OK, "IDirect3DDevice8_EndScene failed with %#08x\n", hr);
    }

    IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);

    color = getPixelColor(device, 160, 360); /* lower left quad - unlit without normals */
    ok(color == 0x00ff0000, "Unlit quad without normals has color %08x\n", color);
    color = getPixelColor(device, 160, 120); /* upper left quad - lit without normals */
    ok(color == 0x00000000, "Lit quad without normals has color %08x\n", color);
    color = getPixelColor(device, 480, 360); /* lower left quad - unlit width normals */
    ok(color == 0x000000ff, "Unlit quad width normals has color %08x\n", color);
    color = getPixelColor(device, 480, 120); /* upper left quad - lit width normals */
    ok(color == 0x00000000, "Lit quad width normals has color %08x\n", color);

    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_LIGHTING, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %#08x\n", hr);
}

static void clear_test(IDirect3DDevice8 *device)
{
    /* Tests the correctness of clearing parameters */
    HRESULT hr;
    D3DRECT rect[2];
    D3DRECT rect_negneg;
    DWORD color;

    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xffffffff, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed with %#08x\n", hr);

    /* Positive x, negative y */
    rect[0].x1 = 0;
    rect[0].y1 = 480;
    rect[0].x2 = 320;
    rect[0].y2 = 240;

    /* Positive x, positive y */
    rect[1].x1 = 0;
    rect[1].y1 = 0;
    rect[1].x2 = 320;
    rect[1].y2 = 240;
    /* Clear 2 rectangles with one call. Shows that a positive value is returned, but the negative rectangle
     * is ignored, the positive is still cleared afterwards
     */
    hr = IDirect3DDevice8_Clear(device, 2, rect, D3DCLEAR_TARGET, 0xffff0000, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed with %#08x\n", hr);

    /* negative x, negative y */
    rect_negneg.x1 = 640;
    rect_negneg.x1 = 240;
    rect_negneg.x2 = 320;
    rect_negneg.y2 = 0;
    hr = IDirect3DDevice8_Clear(device, 1, &rect_negneg, D3DCLEAR_TARGET, 0xff00ff00, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed with %#08x\n", hr);

    IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);

    color = getPixelColor(device, 160, 360); /* lower left quad */
    ok(color == 0x00ffffff, "Clear rectangle 3(pos, neg) has color %08x\n", color);
    color = getPixelColor(device, 160, 120); /* upper left quad */
    ok(color == 0x00ff0000, "Clear rectangle 1(pos, pos) has color %08x\n", color);
    color = getPixelColor(device, 480, 360); /* lower right quad  */
    ok(color == 0x00ffffff, "Clear rectangle 4(NULL) has color %08x\n", color);
    color = getPixelColor(device, 480, 120); /* upper right quad */
    ok(color == 0x00ffffff, "Clear rectangle 4(neg, neg) has color %08x\n", color);
}

struct sVertex {
    float x, y, z;
    DWORD diffuse;
    DWORD specular;
};

struct sVertexT {
    float x, y, z, rhw;
    DWORD diffuse;
    DWORD specular;
};

static void fog_test(IDirect3DDevice8 *device)
{
    HRESULT hr;
    DWORD color;
    float start = 0.0, end = 1.0;

    /* Gets full z based fog with linear fog, no fog with specular color */
    struct sVertex unstransformed_1[] = {
        {-1,    -1,   0.1f,         0xFFFF0000,     0xFF000000  },
        {-1,     0,   0.1f,         0xFFFF0000,     0xFF000000  },
        { 0,     0,   0.1f,         0xFFFF0000,     0xFF000000  },
        { 0,    -1,   0.1f,         0xFFFF0000,     0xFF000000  },
    };
    /* Ok, I am too lazy to deal with transform matrices */
    struct sVertex unstransformed_2[] = {
        {-1,     0,   1.0f,         0xFFFF0000,     0xFF000000  },
        {-1,     1,   1.0f,         0xFFFF0000,     0xFF000000  },
        { 0,     1,   1.0f,         0xFFFF0000,     0xFF000000  },
        { 0,     0,   1.0f,         0xFFFF0000,     0xFF000000  },
    };
    /* Untransformed ones. Give them a different diffuse color to make the test look
     * nicer. It also makes making sure that they are drawn correctly easier.
     */
    struct sVertexT transformed_1[] = {
        {320,    0,   1.0f, 1.0f,   0xFFFFFF00,     0xFF000000  },
        {640,    0,   1.0f, 1.0f,   0xFFFFFF00,     0xFF000000  },
        {640,  240,   1.0f, 1.0f,   0xFFFFFF00,     0xFF000000  },
        {320,  240,   1.0f, 1.0f,   0xFFFFFF00,     0xFF000000  },
    };
    struct sVertexT transformed_2[] = {
        {320,  240,   1.0f, 1.0f,   0xFFFFFF00,     0xFF000000  },
        {640,  240,   1.0f, 1.0f,   0xFFFFFF00,     0xFF000000  },
        {640,  480,   1.0f, 1.0f,   0xFFFFFF00,     0xFF000000  },
        {320,  480,   1.0f, 1.0f,   0xFFFFFF00,     0xFF000000  },
    };
    WORD Indices[] = {0, 1, 2, 2, 3, 0};

    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xffff00ff, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear returned %#08x\n", hr);

    /* Setup initial states: No lighting, fog on, fog color */
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_LIGHTING, FALSE);
    ok(hr == D3D_OK, "Turning off lighting returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGENABLE, TRUE);
    ok(hr == D3D_OK, "Turning on fog calculations returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGCOLOR, 0xFF00FF00 /* A nice green */);
    ok(hr == D3D_OK, "Turning on fog calculations returned %#08x\n", hr);

    /* First test: Both table fog and vertex fog off */
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGTABLEMODE, D3DFOG_NONE);
    ok(hr == D3D_OK, "Turning off table fog returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGVERTEXMODE, D3DFOG_NONE);
    ok(hr == D3D_OK, "Turning off table fog returned %#08x\n", hr);

    /* Start = 0, end = 1. Should be default, but set them */
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGSTART, *((DWORD *) &start));
    ok(hr == D3D_OK, "Setting fog start returned %#08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGEND, *((DWORD *) &end));
    ok(hr == D3D_OK, "Setting fog start returned %#08x\n", hr);

    if(IDirect3DDevice8_BeginScene(device) == D3D_OK)
    {
        hr = IDirect3DDevice8_SetVertexShader(device, D3DFVF_XYZ | D3DFVF_DIFFUSE | D3DFVF_SPECULAR);
        ok( hr == D3D_OK, "SetVertexShader returned %#08x\n", hr);
        /* Untransformed, vertex fog = NONE, table fog = NONE: Read the fog weighting from the specular color */
        hr = IDirect3DDevice8_DrawIndexedPrimitiveUP(device, D3DPT_TRIANGLELIST, 0 /* MinIndex */, 4 /* NumVerts */,
                                                     2 /*PrimCount */, Indices, D3DFMT_INDEX16, unstransformed_1,
                                                     sizeof(unstransformed_1[0]));
        ok(hr == D3D_OK, "DrawIndexedPrimitiveUP returned %#08x\n", hr);

        /* That makes it use the Z value */
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGVERTEXMODE, D3DFOG_LINEAR);
        ok(hr == D3D_OK, "Turning off table fog returned %#08x\n", hr);
        /* Untransformed, vertex fog != none (or table fog != none):
         * Use the Z value as input into the equation
         */
        hr = IDirect3DDevice8_DrawIndexedPrimitiveUP(device, D3DPT_TRIANGLELIST, 0 /* MinIndex */, 4 /* NumVerts */,
                                                     2 /*PrimCount */, Indices, D3DFMT_INDEX16, unstransformed_2,
                                                     sizeof(unstransformed_1[0]));
        ok(hr == D3D_OK, "DrawIndexedPrimitiveUP returned %#08x\n", hr);

        /* transformed verts */
        hr = IDirect3DDevice8_SetVertexShader(device, D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_SPECULAR);
        ok( hr == D3D_OK, "SetVertexShader returned %#08x\n", hr);
        /* Transformed, vertex fog != NONE, pixel fog == NONE: Use specular color alpha component */
        hr = IDirect3DDevice8_DrawIndexedPrimitiveUP(device, D3DPT_TRIANGLELIST, 0 /* MinIndex */, 4 /* NumVerts */,
                                                     2 /*PrimCount */, Indices, D3DFMT_INDEX16, transformed_1,
                                                     sizeof(transformed_1[0]));
        ok(hr == D3D_OK, "DrawIndexedPrimitiveUP returned %#08x\n", hr);

        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGTABLEMODE, D3DFOG_LINEAR);
        ok( hr == D3D_OK, "Setting fog table mode to D3DFOG_LINEAR returned %#08x\n", hr);
        /* Transformed, table fog != none, vertex anything: Use Z value as input to the fog
         * equation
         */
        hr = IDirect3DDevice8_DrawIndexedPrimitiveUP(device, D3DPT_TRIANGLELIST, 0 /* MinIndex */, 4 /* NumVerts */,
                                                     2 /*PrimCount */, Indices, D3DFMT_INDEX16, transformed_2,
                                                     sizeof(transformed_2[0]));

        hr = IDirect3DDevice8_EndScene(device);
        ok(hr == D3D_OK, "EndScene returned %#08x\n", hr);
    }
    else
    {
        ok(FALSE, "BeginScene failed\n");
    }

    IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);
    color = getPixelColor(device, 160, 360);
    ok(color == 0x00FF0000, "Untransformed vertex with no table or vertex fog has color %08x\n", color);
    color = getPixelColor(device, 160, 120);
    ok(color == 0x0000FF00, "Untransformed vertex with linear vertex fog has color %08x\n", color);
    color = getPixelColor(device, 480, 120);
    ok(color == 0x00FFFF00, "Transformed vertex with linear vertex fog has color %08x\n", color);
    color = getPixelColor(device, 480, 360);
    ok(color == 0x0000FF00, "Transformed vertex with linear table fog has color %08x\n", color);

    /* Turn off the fog master switch to avoid confusing other tests */
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_FOGENABLE, FALSE);
    ok(hr == D3D_OK, "Turning off fog calculations returned %#08x\n", hr);
}

static void present_test(IDirect3DDevice8 *device)
{
    struct vertex quad[] =
    {
        {-1.0f, -1.0f,   0.9f,                          0xffff0000},
        {-1.0f,  1.0f,   0.9f,                          0xffff0000},
        { 1.0f, -1.0f,   0.1f,                          0xffff0000},
        { 1.0f,  1.0f,   0.1f,                          0xffff0000},
    };
    HRESULT hr;
    DWORD color;

    /* Does the Present clear the depth stencil? Clear the depth buffer with some value != 0,
    * then call Present. Then clear the color buffer to make sure it has some defined content
    * after the Present with D3DSWAPEFFECT_DISCARD. After that draw a plane that is somewhere cut
    * by the depth value.
    */
    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0xffffffff, 0.75, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear returned %s\n", DXGetErrorString8(hr));
    hr = IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);
    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xffffffff, 0.4, 0);

    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ZENABLE, D3DZB_TRUE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %s\n", DXGetErrorString8(hr));
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ZFUNC, D3DCMP_GREATER);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %s\n", DXGetErrorString8(hr));
    hr = IDirect3DDevice8_SetVertexShader(device, D3DFVF_XYZ | D3DFVF_DIFFUSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetFVF returned %s\n", DXGetErrorString8(hr));

    hr = IDirect3DDevice8_BeginScene(device);
    ok(hr == D3D_OK, "IDirect3DDevice8_BeginScene failed with %s\n", DXGetErrorString8(hr));
    if(hr == D3D_OK)
    {
        /* No lights are defined... That means, lit vertices should be entirely black */
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2 /*PrimCount */, quad, sizeof(quad[0]));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawIndexedPrimitiveUP failed with %s\n", DXGetErrorString8(hr));

        hr = IDirect3DDevice8_EndScene(device);
        ok(hr == D3D_OK, "IDirect3DDevice8_EndScene failed with %s\n", DXGetErrorString8(hr));
    }

    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ZENABLE, D3DZB_FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %s\n", DXGetErrorString8(hr));

    hr = IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);
    ok(SUCCEEDED(hr), "Present failed (%#08x)\n", hr);
    color = getPixelColor(device, 512, 240);
    ok(color == 0x00ffffff, "Present failed: Got color 0x%08x, expected 0x00ffffff.\n", color);
    color = getPixelColor(device, 64, 240);
    ok(color == 0x00ff0000, "Present failed: Got color 0x%08x, expected 0x00ff0000.\n", color);
}

static void test_rcp_rsq(IDirect3DDevice8 *device)
{
    HRESULT hr;
    DWORD shader;
    DWORD color;
    unsigned char c1, c2, c3;
    float constant[4] = {1.0, 1.0, 1.0, 2.0};

    static const float quad[][3] = {
        {-1.0f, -1.0f, 0.0f},
        {-1.0f,  1.0f, 0.0f},
        { 1.0f, -1.0f, 0.0f},
        { 1.0f,  1.0f, 0.0f},
    };

    const DWORD rcp_test[] = {
        0xfffe0101,                                         /* vs.1.1 */

        0x0009fffe, 0x30303030, 0x30303030,                 /* Shaders have to have a minimal size. */
        0x30303030, 0x30303030, 0x30303030,                 /* Add a filler comment. Usually D3DX8's*/
        0x30303030, 0x30303030, 0x30303030,                 /* version comment makes the shader big */
        0x00303030,                                         /* enough to make windows happy         */

        0x00000001, 0xc00f0000, 0x90e40000,                 /* mov oPos, v0 */
        0x00000006, 0xd00f0000, 0xa0e40000,                 /* rcp oD0, c0 */
        0x0000ffff                                          /* END */
    };

    const DWORD rsq_test[] = {
        0xfffe0101,                                         /* vs.1.1 */

        0x0009fffe, 0x30303030, 0x30303030,                 /* Shaders have to have a minimal size. */
        0x30303030, 0x30303030, 0x30303030,                 /* Add a filler comment. Usually D3DX8's*/
        0x30303030, 0x30303030, 0x30303030,                 /* version comment makes the shader big */
        0x00303030,                                         /* enough to make windows happy         */

        0x00000001, 0xc00f0000, 0x90e40000,                 /* mov oPos, v0 */
        0x00000007, 0xd00f0000, 0xa0e40000,                 /* rsq oD0, c0 */
        0x0000ffff                                          /* END */
    };

    DWORD decl[] =
    {
        D3DVSD_STREAM(0),
        D3DVSD_REG(D3DVSDE_POSITION, D3DVSDT_FLOAT3),  /* D3DVSDE_POSITION, Register v0 */
        D3DVSD_END()
    };

    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0xff800080, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed with %#08x\n", hr);

    hr = IDirect3DDevice8_CreateVertexShader(device, decl, rcp_test, &shader, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_CreateVertexShader returned with %#08x\n", hr);

    IDirect3DDevice8_SetVertexShader(device, shader);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetVertexShader returned %#08x\n", hr);
    IDirect3DDevice8_SetVertexShaderConstant(device, 0, constant, 1);

    hr = IDirect3DDevice8_BeginScene(device);
    ok(hr == D3D_OK, "IDirect3DDevice8_BeginScene returned %#08x\n", hr);
    if(SUCCEEDED(hr))
    {
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, &quad[0], 3 * sizeof(float));
        ok(SUCCEEDED(hr), "DrawPrimitiveUP failed (%#08x)\n", hr);
        hr = IDirect3DDevice8_EndScene(device);
        ok(hr == D3D_OK, "IDirect3DDevice8_EndScene returned %#08x\n", hr);
    }

    hr = IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);
    ok(SUCCEEDED(hr), "Present failed (%#08x)\n", hr);
    color = getPixelColor(device, 320, 240);
    c1 = (color & 0x00ff0000 )>> 16;
    c2 = (color & 0x0000ff00 )>>  8;
    c3 = (color & 0x000000ff )>>  0;
    ok(c1 == c2 && c2 == c3, "Color components differ: c1 = %02x, c2 = %02x, c3 = %02x\n",
       c1, c2, c3);
    ok(c1 >= 0x7c && c1 <= 0x84, "Color component value is %02x\n", c1);

    IDirect3DDevice8_SetVertexShader(device, 0);
    IDirect3DDevice8_DeleteVertexShader(device, shader);

    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0xff800080, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed with %#08x\n", hr);

    hr = IDirect3DDevice8_CreateVertexShader(device, decl, rsq_test, &shader, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_CreateVertexShader returned with %#08x\n", hr);

    IDirect3DDevice8_SetVertexShader(device, shader);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetVertexShader returned %#08x\n", hr);
    IDirect3DDevice8_SetVertexShaderConstant(device, 0, constant, 1);

    hr = IDirect3DDevice8_BeginScene(device);
    ok(hr == D3D_OK, "IDirect3DDevice8_BeginScene returned %#08x\n", hr);
    if(SUCCEEDED(hr))
    {
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, &quad[0], 3 * sizeof(float));
        ok(SUCCEEDED(hr), "DrawPrimitiveUP failed (%#08x)\n", hr);
        hr = IDirect3DDevice8_EndScene(device);
        ok(hr == D3D_OK, "IDirect3DDevice8_EndScene returned %#08x\n", hr);
    }

    hr = IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);
    ok(SUCCEEDED(hr), "Present failed (%#08x)\n", hr);
    color = getPixelColor(device, 320, 240);
    c1 = (color & 0x00ff0000 )>> 16;
    c2 = (color & 0x0000ff00 )>>  8;
    c3 = (color & 0x000000ff )>>  0;
    ok(c1 == c2 && c2 == c3, "Color components differ: c1 = %02x, c2 = %02x, c3 = %02x\n",
       c1, c2, c3);
    ok(c1 >= 0xb0 && c1 <= 0xb8, "Color component value is %02x\n", c1);

    IDirect3DDevice8_SetVertexShader(device, 0);
    IDirect3DDevice8_DeleteVertexShader(device, shader);
}

static void offscreen_test(IDirect3DDevice8 *device)
{
    HRESULT hr;
    IDirect3DTexture8 *offscreenTexture = NULL;
    IDirect3DSurface8 *backbuffer = NULL, *offscreen = NULL, *depthstencil = NULL;
    DWORD color;

    static const float quad[][5] = {
        {-0.5f, -0.5f, 0.1f, 0.0f, 0.0f},
        {-0.5f,  0.5f, 0.1f, 0.0f, 1.0f},
        { 0.5f, -0.5f, 0.1f, 1.0f, 0.0f},
        { 0.5f,  0.5f, 0.1f, 1.0f, 1.0f},
    };

    hr = IDirect3DDevice8_GetDepthStencilSurface(device, &depthstencil);
    ok(hr == D3D_OK, "IDirect3DDevice8_GetDepthStencilSurface failed, hr = %#08x\n", hr);

    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xffff0000, 0.0, 0);
    ok(hr == D3D_OK, "Clear failed, hr = %#08x\n", hr);

    hr = IDirect3DDevice8_CreateTexture(device, 128, 128, 1, D3DUSAGE_RENDERTARGET, D3DFMT_X8R8G8B8, D3DPOOL_DEFAULT, &offscreenTexture);
    ok(hr == D3D_OK || D3DERR_INVALIDCALL, "Creating the offscreen render target failed, hr = %#08x\n", hr);
    if(!offscreenTexture) {
        trace("Failed to create an X8R8G8B8 offscreen texture, trying R5G6B5\n");
        hr = IDirect3DDevice8_CreateTexture(device, 128, 128, 1, D3DUSAGE_RENDERTARGET, D3DFMT_R5G6B5, D3DPOOL_DEFAULT, &offscreenTexture);
        ok(hr == D3D_OK || D3DERR_INVALIDCALL, "Creating the offscreen render target failed, hr = %#08x\n", hr);
        if(!offscreenTexture) {
            skip("Cannot create an offscreen render target\n");
            goto out;
        }
    }

    hr = IDirect3DDevice8_GetBackBuffer(device, 0, D3DBACKBUFFER_TYPE_MONO, &backbuffer);
    ok(hr == D3D_OK, "Can't get back buffer, hr = %#08x\n", hr);
    if(!backbuffer) {
        goto out;
    }

    hr = IDirect3DTexture8_GetSurfaceLevel(offscreenTexture, 0, &offscreen);
    ok(hr == D3D_OK, "Can't get offscreen surface, hr = %#08x\n", hr);
    if(!offscreen) {
        goto out;
    }

    hr = IDirect3DDevice8_SetVertexShader(device, D3DFVF_XYZ | D3DFVF_TEX1);
    ok(hr == D3D_OK, "SetVertexShader failed, hr = %#08x\n", hr);

    hr = IDirect3DDevice8_SetTextureStageState(device, 0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    ok(hr == D3D_OK, "SetTextureStageState failed, hr = %#08x\n", hr);
    hr = IDirect3DDevice8_SetTextureStageState(device, 0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
    ok(hr == D3D_OK, "SetTextureStageState failed, hr = %#08x\n", hr);
    hr = IDirect3DDevice8_SetTextureStageState(device, 0, D3DTSS_MINFILTER, D3DTEXF_NONE);
    ok(SUCCEEDED(hr), "SetTextureStageState D3DSAMP_MINFILTER failed (%#08x)\n", hr);
    hr = IDirect3DDevice8_SetTextureStageState(device, 0, D3DTSS_MAGFILTER, D3DTEXF_NONE);
    ok(SUCCEEDED(hr), "SetTextureStageState D3DSAMP_MAGFILTER failed (%#08x)\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_LIGHTING, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %s\n", DXGetErrorString8(hr));

    if(IDirect3DDevice8_BeginScene(device) == D3D_OK) {
        hr = IDirect3DDevice8_SetRenderTarget(device, offscreen, depthstencil);
        ok(hr == D3D_OK, "SetRenderTarget failed, hr = %#08x\n", hr);
        hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xffff00ff, 0.0, 0);
        ok(hr == D3D_OK, "Clear failed, hr = %#08x\n", hr);

        /* Draw without textures - Should result in a white quad */
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(quad[0]));
        ok(hr == D3D_OK, "DrawPrimitiveUP failed, hr = %#08x\n", hr);

        hr = IDirect3DDevice8_SetRenderTarget(device, backbuffer, depthstencil);
        ok(hr == D3D_OK, "SetRenderTarget failed, hr = %#08x\n", hr);
        hr = IDirect3DDevice8_SetTexture(device, 0, (IDirect3DBaseTexture8 *) offscreenTexture);
        ok(hr == D3D_OK, "SetTexture failed, %s\n", DXGetErrorString8(hr));

        /* This time with the texture */
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad, sizeof(quad[0]));
        ok(hr == D3D_OK, "DrawPrimitiveUP failed, hr = %#08x\n", hr);

        IDirect3DDevice8_EndScene(device);
    }

    IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);

    /* Center quad - should be white */
    color = getPixelColor(device, 320, 240);
    ok(color == 0x00ffffff, "Offscreen failed: Got color 0x%08x, expected 0x00ffffff.\n", color);
    /* Some quad in the cleared part of the texture */
    color = getPixelColor(device, 170, 240);
    ok(color == 0x00ff00ff, "Offscreen failed: Got color 0x%08x, expected 0x00ff00ff.\n", color);
    /* Part of the originally cleared back buffer */
    color = getPixelColor(device, 10, 10);
    ok(color == 0x00ff0000, "Offscreen failed: Got color 0x%08x, expected 0x00ff0000.\n", color);
    if(0) {
        /* Lower left corner of the screen, where back buffer offscreen rendering draws the offscreen texture.
        * It should be red, but the offscreen texture may leave some junk there. Not tested yet. Depending on
        * the offscreen rendering mode this test would succeed or fail
        */
        color = getPixelColor(device, 10, 470);
        ok(color == 0x00ff0000, "Offscreen failed: Got color 0x%08x, expected 0x00ff0000.\n", color);
    }

out:
    hr = IDirect3DDevice8_SetTexture(device, 0, NULL);

    /* restore things */
    if(backbuffer) {
        hr = IDirect3DDevice8_SetRenderTarget(device, backbuffer, depthstencil);
        IDirect3DSurface8_Release(backbuffer);
    }
    if(offscreenTexture) {
        IDirect3DTexture8_Release(offscreenTexture);
    }
    if(offscreen) {
        IDirect3DSurface8_Release(offscreen);
    }
    if(depthstencil) {
        IDirect3DSurface8_Release(depthstencil);
    }
}

static void alpha_test(IDirect3DDevice8 *device)
{
    HRESULT hr;
    IDirect3DTexture8 *offscreenTexture;
    IDirect3DSurface8 *backbuffer = NULL, *offscreen = NULL, *depthstencil = NULL;
    DWORD color, red, green, blue;

    struct vertex quad1[] =
    {
        {-1.0f, -1.0f,   0.1f,                          0x4000ff00},
        {-1.0f,  0.0f,   0.1f,                          0x4000ff00},
        { 1.0f, -1.0f,   0.1f,                          0x4000ff00},
        { 1.0f,  0.0f,   0.1f,                          0x4000ff00},
    };
    struct vertex quad2[] =
    {
        {-1.0f,  0.0f,   0.1f,                          0xc00000ff},
        {-1.0f,  1.0f,   0.1f,                          0xc00000ff},
        { 1.0f,  0.0f,   0.1f,                          0xc00000ff},
        { 1.0f,  1.0f,   0.1f,                          0xc00000ff},
    };
    static const float composite_quad[][5] = {
        { 0.0f, -1.0f, 0.1f, 0.0f, 1.0f},
        { 0.0f,  1.0f, 0.1f, 0.0f, 0.0f},
        { 1.0f, -1.0f, 0.1f, 1.0f, 1.0f},
        { 1.0f,  1.0f, 0.1f, 1.0f, 0.0f},
    };

    /* Clear the render target with alpha = 0.5 */
    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0x80ff0000, 0.0, 0);
    ok(hr == D3D_OK, "Clear failed, hr = %08x\n", hr);

    hr = IDirect3DDevice8_CreateTexture(device, 128, 128, 1, D3DUSAGE_RENDERTARGET, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT, &offscreenTexture);
    ok(hr == D3D_OK || D3DERR_INVALIDCALL, "Creating the offscreen render target failed, hr = %#08x\n", hr);

    hr = IDirect3DDevice8_GetDepthStencilSurface(device, &depthstencil);
    ok(hr == D3D_OK, "IDirect3DDevice8_GetDepthStencilSurface failed, hr = %#08x\n", hr);

    hr = IDirect3DDevice8_GetBackBuffer(device, 0, D3DBACKBUFFER_TYPE_MONO, &backbuffer);
    ok(hr == D3D_OK, "Can't get back buffer, hr = %#08x\n", hr);
    if(!backbuffer) {
        goto out;
    }
    hr = IDirect3DTexture8_GetSurfaceLevel(offscreenTexture, 0, &offscreen);
    ok(hr == D3D_OK, "Can't get offscreen surface, hr = %#08x\n", hr);
    if(!offscreen) {
        goto out;
    }

    hr = IDirect3DDevice8_SetVertexShader(device, D3DFVF_XYZ | D3DFVF_DIFFUSE);
    ok(hr == D3D_OK, "SetVertexShader failed, hr = %#08x\n", hr);

    hr = IDirect3DDevice8_SetTextureStageState(device, 0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    ok(hr == D3D_OK, "SetTextureStageState failed, hr = %#08x\n", hr);
    hr = IDirect3DDevice8_SetTextureStageState(device, 0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
    ok(hr == D3D_OK, "SetTextureStageState failed, hr = %#08x\n", hr);
    hr = IDirect3DDevice8_SetTextureStageState(device, 0, D3DTSS_MINFILTER, D3DTEXF_NONE);
    ok(SUCCEEDED(hr), "SetTextureStageState D3DSAMP_MINFILTER failed (%#08x)\n", hr);
    hr = IDirect3DDevice8_SetTextureStageState(device, 0, D3DTSS_MAGFILTER, D3DTEXF_NONE);
    ok(SUCCEEDED(hr), "SetTextureStageState D3DSAMP_MAGFILTER failed (%#08x)\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_LIGHTING, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState returned %s\n", DXGetErrorString8(hr));

    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ALPHABLENDENABLE, TRUE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
    if(IDirect3DDevice8_BeginScene(device) == D3D_OK) {

        /* Draw two quads, one with src alpha blending, one with dest alpha blending. The
         * SRCALPHA / INVSRCALPHA blend doesn't give any surprises. Colors are blended based on
         * the input alpha
         *
         * The DESTALPHA / INVDESTALPHA do not "work" on the regular buffer because there is no alpha.
         * They give essentially ZERO and ONE blend factors
         */
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad1, sizeof(quad1[0]));
        ok(hr == D3D_OK, "DrawPrimitiveUP failed, hr = %#08x\n", hr);

        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_SRCBLEND, D3DBLEND_DESTALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_DESTBLEND, D3DBLEND_INVDESTALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad2, sizeof(quad2[0]));
        ok(hr == D3D_OK, "DrawPrimitiveUP failed, hr = %#08x\n", hr);

        /* Switch to the offscreen buffer, and redo the testing. SRCALPHA and DESTALPHA. The offscreen buffer
         * has a alpha channel on its own. Clear the offscreen buffer with alpha = 0.5 again, then draw the
         * quads again. The SRCALPHA/INVSRCALPHA doesn't give any surprises, but the DESTALPHA/INVDESTALPHA
         * blending works as supposed now - blend factor is 0.5 in both cases, not 0.75 as from the input
         * vertices
         */
        hr = IDirect3DDevice8_SetRenderTarget(device, offscreen, 0);
        ok(hr == D3D_OK, "Can't get back buffer, hr = %08x\n", hr);
        hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0x80ff0000, 0.0, 0);
        ok(hr == D3D_OK, "Clear failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad1, sizeof(quad1[0]));
        ok(hr == D3D_OK, "DrawPrimitiveUP failed, hr = %#08x\n", hr);

        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_SRCBLEND, D3DBLEND_DESTALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_DESTBLEND, D3DBLEND_INVDESTALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad2, sizeof(quad2[0]));
        ok(hr == D3D_OK, "DrawPrimitiveUP failed, hr = %#08x\n", hr);

        hr = IDirect3DDevice8_SetRenderTarget(device, backbuffer, depthstencil);
        ok(hr == D3D_OK, "Can't get back buffer, hr = %08x\n", hr);

        /* Render the offscreen texture onto the frame buffer to be able to compare it regularly.
         * Disable alpha blending for the final composition
         */
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ALPHABLENDENABLE, FALSE);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_SetVertexShader(device, D3DFVF_XYZ | D3DFVF_TEX1);
        ok(hr == D3D_OK, "SetVertexShader failed, hr = %#08x\n", hr);

        hr = IDirect3DDevice8_SetTexture(device, 0, (IDirect3DBaseTexture8 *) offscreenTexture);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetTexture failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, composite_quad, sizeof(float) * 5);
        ok(hr == D3D_OK, "DrawPrimitiveUP failed, hr = %#08x\n", hr);
        hr = IDirect3DDevice8_SetTexture(device, 0, NULL);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetTexture failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_EndScene(device);
        ok(hr == D3D_OK, "IDirect3DDevice7_EndScene failed, hr = %08x\n", hr);
    }

    IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);

    color = getPixelColor(device, 160, 360);
    red =   (color & 0x00ff0000) >> 16;
    green = (color & 0x0000ff00) >>  8;
    blue =  (color & 0x000000ff);
    ok(red >= 0xbe && red <= 0xc0 && green >= 0x39 && green <= 0x41 && blue == 0x00,
       "SRCALPHA on frame buffer returned color %08x, expected 0x00bf4000\n", color);

    color = getPixelColor(device, 160, 120);
    red =   (color & 0x00ff0000) >> 16;
    green = (color & 0x0000ff00) >>  8;
    blue =  (color & 0x000000ff);
    ok(red == 0x00 && green == 0x00 && blue >= 0xfe && blue <= 0xff ,
       "DSTALPHA on frame buffer returned color %08x, expected 0x00ff0000\n", color);

    color = getPixelColor(device, 480, 360);
    red =   (color & 0x00ff0000) >> 16;
    green = (color & 0x0000ff00) >>  8;
    blue =  (color & 0x000000ff);
    ok(red >= 0xbe && red <= 0xc0 && green >= 0x39 && green <= 0x41 && blue == 0x00,
       "SRCALPHA on texture returned color %08x, expected bar\n", color);

    color = getPixelColor(device, 480, 120);
    red =   (color & 0x00ff0000) >> 16;
    green = (color & 0x0000ff00) >>  8;
    blue =  (color & 0x000000ff);
    ok(red >= 0x7e && red <= 0x81 && green == 0x00 && blue >= 0x7e && blue <= 0x81,
       "DSTALPHA on texture returned color %08x, expected foo\n", color);

    out:
    /* restore things */
    if(backbuffer) {
        IDirect3DSurface8_Release(backbuffer);
    }
    if(offscreenTexture) {
        IDirect3DTexture8_Release(offscreenTexture);
    }
    if(offscreen) {
        IDirect3DSurface8_Release(offscreen);
    }
    if(depthstencil) {
        IDirect3DSurface8_Release(depthstencil);
    }
}

static void p8_texture_test(IDirect3DDevice8 *device)
{
    IDirect3D8 *d3d = NULL;
    HRESULT hr;
    IDirect3DTexture8 *texture = NULL, *texture2 = NULL;
    D3DLOCKED_RECT lr;
    unsigned char *data;
    DWORD color, red, green, blue;
    PALETTEENTRY table[256];
    D3DCAPS8 caps;
    UINT i;
    float quad[] = {
       -1.0,       0,       0.1,     0.0,    0.0,
       -1.0,       1.0,     0.1,     0.0,    1.0,
        1.0,       0,       0.1,     1.0,    0.0,
        1.0,       1.0,     0.1,     1.0,    1.0,
    };
    float quad2[] = {
       -1.0,       -1.0,    0.1,     0.0,    0.0,
       -1.0,       0,       0.1,     0.0,    1.0,
        1.0,       -1.0,    0.1,     1.0,    0.0,
        1.0,       0,       0.1,     1.0,    1.0,
    };

    IDirect3DDevice8_GetDirect3D(device, &d3d);

    if(IDirect3D8_CheckDeviceFormat(d3d, 0, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0,
       D3DRTYPE_TEXTURE, D3DFMT_P8) != D3D_OK) {
           skip("D3DFMT_P8 textures not supported\n");
           goto out;
    }

    hr = IDirect3DDevice8_CreateTexture(device, 1, 1, 1, 0, D3DFMT_P8,
                                        D3DPOOL_MANAGED, &texture2);
    ok(hr == D3D_OK, "IDirect3DDevice8_CreateTexture failed, hr = %08x\n", hr);
    if(!texture2) {
        skip("Failed to create D3DFMT_P8 texture\n");
        goto out;
    }

    memset(&lr, 0, sizeof(lr));
    hr = IDirect3DTexture8_LockRect(texture2, 0, &lr, NULL, 0);
    ok(hr == D3D_OK, "IDirect3DTexture8_LockRect failed, hr = %08x\n", hr);
    data = lr.pBits;
    *data = 1;

    hr = IDirect3DTexture8_UnlockRect(texture2, 0);
    ok(hr == D3D_OK, "IDirect3DTexture8_UnlockRect failed, hr = %08x\n", hr);

    hr = IDirect3DDevice8_CreateTexture(device, 1, 1, 1, 0, D3DFMT_P8,
                                        D3DPOOL_MANAGED, &texture);
    ok(hr == D3D_OK, "IDirect3DDevice8_CreateTexture failed, hr = %08x\n", hr);
    if(!texture) {
        skip("Failed to create D3DFMT_P8 texture\n");
        goto out;
    }

    memset(&lr, 0, sizeof(lr));
    hr = IDirect3DTexture8_LockRect(texture, 0, &lr, NULL, 0);
    ok(hr == D3D_OK, "IDirect3DTexture8_LockRect failed, hr = %08x\n", hr);
    data = lr.pBits;
    *data = 1;

    hr = IDirect3DTexture8_UnlockRect(texture, 0);
    ok(hr == D3D_OK, "IDirect3DTexture8_UnlockRect failed, hr = %08x\n", hr);

    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xff000000, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed, hr = %08x\n", hr);

    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ALPHABLENDENABLE, TRUE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);

    /* The first part of the test should work both with and without D3DPTEXTURECAPS_ALPHAPALETTE;
       alpha of every entry is set to 1.0, which MS says is required when there's no
       D3DPTEXTURECAPS_ALPHAPALETTE capability */
    for (i = 0; i < 256; i++) {
        table[i].peRed = table[i].peGreen = table[i].peBlue = 0;
        table[i].peFlags = 0xff;
    }
    table[1].peRed = 0xff;
    hr = IDirect3DDevice8_SetPaletteEntries(device, 0, table);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetPaletteEntries failed, hr = %08x\n", hr);

    table[1].peRed = 0;
    table[1].peBlue = 0xff;
    hr = IDirect3DDevice8_SetPaletteEntries(device, 1, table);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetPaletteEntries failed, hr = %08x\n", hr);

    hr = IDirect3DDevice8_BeginScene(device);
    ok(hr == D3D_OK, "IDirect3DDevice8_BeginScene failed, hr = %08x\n", hr);
    if(SUCCEEDED(hr)) {
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_SetVertexShader(device, D3DFVF_XYZ | D3DFVF_TEX1);
        ok(hr == D3D_OK, "SetVertexShader failed, hr = %#08x\n", hr);

        hr = IDirect3DDevice8_SetCurrentTexturePalette(device, 0);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetCurrentTexturePalette failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_SetTexture(device, 0, (IDirect3DBaseTexture8 *) texture2);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetTexture failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad, 5 * sizeof(float));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawPrimitiveUP failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_SetTexture(device, 0, (IDirect3DBaseTexture8 *) texture);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetTexture failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad, 5 * sizeof(float));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawPrimitiveUP failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_SetCurrentTexturePalette(device, 1);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetCurrentTexturePalette failed, hr = %08x\n", hr);
        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad2, 5 * sizeof(float));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawPrimitiveUP failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_EndScene(device);
        ok(hr == D3D_OK, "IDirect3DDevice8_EndScene failed, hr = %08x\n", hr);
    }

    hr = IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);
    ok(hr == D3D_OK, "IDirect3DDevice8_Present failed, hr = %08x\n", hr);

    color = getPixelColor(device, 32, 32);
    red   = (color & 0x00ff0000) >> 16;
    green = (color & 0x0000ff00) >>  8;
    blue  = (color & 0x000000ff) >>  0;
    ok(red == 0xff && blue == 0 && green == 0,
       "got color %08x, expected 0x00ff0000\n", color);

    color = getPixelColor(device, 32, 320);
    red   = (color & 0x00ff0000) >> 16;
    green = (color & 0x0000ff00) >>  8;
    blue  = (color & 0x000000ff) >>  0;
    ok(red == 0 && blue == 0xff && green == 0,
    "got color %08x, expected 0x000000ff\n", color);

    hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xff000000, 0.0, 0);
    ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed, hr = %08x\n", hr);

    hr = IDirect3DDevice8_BeginScene(device);
    ok(hr == D3D_OK, "IDirect3DDevice8_BeginScene failed, hr = %08x\n", hr);
    if(SUCCEEDED(hr)) {
        hr = IDirect3DDevice8_SetTexture(device, 0, (IDirect3DBaseTexture8 *) texture2);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetTexture failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad, 5 * sizeof(float));
        ok(hr == D3D_OK, "IDirect3DDevice8_DrawPrimitiveUP failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_EndScene(device);
        ok(hr == D3D_OK, "IDirect3DDevice8_EndScene failed, hr = %08x\n", hr);
    }

    hr = IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);
    ok(hr == D3D_OK, "IDirect3DDevice8_Present failed, hr = %08x\n", hr);

    color = getPixelColor(device, 32, 32);
    red   = (color & 0x00ff0000) >> 16;
    green = (color & 0x0000ff00) >>  8;
    blue  = (color & 0x000000ff) >>  0;
    ok(red == 0 && blue == 0xff && green == 0,
    "got color %08x, expected 0x000000ff\n", color);

    /* Test palettes with alpha */
    IDirect3DDevice8_GetDeviceCaps(device, &caps);
    if (!(caps.TextureCaps & D3DPTEXTURECAPS_ALPHAPALETTE)) {
        skip("no D3DPTEXTURECAPS_ALPHAPALETTE capability, tests with alpha in palette will be skipped\n");
    } else {
        hr = IDirect3DDevice8_Clear(device, 0, NULL, D3DCLEAR_TARGET, 0xff000000, 0.0, 0);
        ok(hr == D3D_OK, "IDirect3DDevice8_Clear failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ALPHABLENDENABLE, TRUE);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);

        for (i = 0; i < 256; i++) {
            table[i].peRed = table[i].peGreen = table[i].peBlue = 0;
            table[i].peFlags = 0xff;
        }
        table[1].peRed = 0xff;
        table[1].peFlags = 0x80;
        hr = IDirect3DDevice8_SetPaletteEntries(device, 0, table);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetPaletteEntries failed, hr = %08x\n", hr);

        table[1].peRed = 0;
        table[1].peBlue = 0xff;
        table[1].peFlags = 0x80;
        hr = IDirect3DDevice8_SetPaletteEntries(device, 1, table);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetPaletteEntries failed, hr = %08x\n", hr);

        hr = IDirect3DDevice8_BeginScene(device);
        ok(hr == D3D_OK, "IDirect3DDevice8_BeginScene failed, hr = %08x\n", hr);
        if(SUCCEEDED(hr)) {
            hr = IDirect3DDevice8_SetRenderState(device, D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
            ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);
            hr = IDirect3DDevice8_SetRenderState(device, D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
            ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);

            hr = IDirect3DDevice8_SetVertexShader(device, D3DFVF_XYZ | D3DFVF_TEX1);
            ok(hr == D3D_OK, "SetVertexShader failed, hr = %#08x\n", hr);

            hr = IDirect3DDevice8_SetCurrentTexturePalette(device, 0);
            ok(hr == D3D_OK, "IDirect3DDevice8_SetCurrentTexturePalette failed, hr = %08x\n", hr);

            hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad, 5 * sizeof(float));
            ok(hr == D3D_OK, "IDirect3DDevice8_DrawPrimitiveUP failed, hr = %08x\n", hr);

            hr = IDirect3DDevice8_SetCurrentTexturePalette(device, 1);
            ok(hr == D3D_OK, "IDirect3DDevice8_SetCurrentTexturePalette failed, hr = %08x\n", hr);

            hr = IDirect3DDevice8_DrawPrimitiveUP(device, D3DPT_TRIANGLESTRIP, 2, quad2, 5 * sizeof(float));
            ok(hr == D3D_OK, "IDirect3DDevice8_DrawPrimitiveUP failed, hr = %08x\n", hr);

            hr = IDirect3DDevice8_EndScene(device);
            ok(hr == D3D_OK, "IDirect3DDevice8_EndScene failed, hr = %08x\n", hr);
        }

        hr = IDirect3DDevice8_Present(device, NULL, NULL, NULL, NULL);
        ok(hr == D3D_OK, "IDirect3DDevice8_Present failed, hr = %08x\n", hr);

        color = getPixelColor(device, 32, 32);
        red   = (color & 0x00ff0000) >> 16;
        green = (color & 0x0000ff00) >>  8;
        blue  = (color & 0x000000ff) >>  0;
        ok(red >= 0x7e && red <= 0x81 && blue == 0 && green == 0,
        "got color %08x, expected 0x00800000 or near\n", color);

        color = getPixelColor(device, 32, 320);
        red   = (color & 0x00ff0000) >> 16;
        green = (color & 0x0000ff00) >>  8;
        blue  = (color & 0x000000ff) >>  0;
        ok(red == 0 && blue >= 0x7e && blue <= 0x81 && green == 0,
        "got color %08x, expected 0x00000080 or near\n", color);
    }

    hr = IDirect3DDevice8_SetTexture(device, 0, NULL);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetTexture failed, hr = %08x\n", hr);
    hr = IDirect3DDevice8_SetRenderState(device, D3DRS_ALPHABLENDENABLE, FALSE);
    ok(hr == D3D_OK, "IDirect3DDevice8_SetRenderState failed, hr = %08x\n", hr);

out:
    if(texture) IDirect3DTexture8_Release(texture);
    if(texture2) IDirect3DTexture8_Release(texture2);
    IDirect3D8_Release(d3d);
}

START_TEST(visual)
{
    IDirect3DDevice8 *device_ptr;
    HRESULT hr;
    DWORD color;
    D3DCAPS8 caps;

    d3d8_handle = LoadLibraryA("d3d8.dll");
    if (!d3d8_handle)
    {
        skip("Could not load d3d8.dll\n");
        return;
    }

    device_ptr = init_d3d8();
    if (!device_ptr)
    {
        skip("Could not initialize direct3d\n");
        return;
    }

    IDirect3DDevice8_GetDeviceCaps(device_ptr, &caps);

    /* Check for the reliability of the returned data */
    hr = IDirect3DDevice8_Clear(device_ptr, 0, NULL, D3DCLEAR_TARGET, 0xffff0000, 0.0, 0);
    if(FAILED(hr))
    {
        trace("Clear failed, can't assure correctness of the test results, skipping\n");
        goto cleanup;
    }
    IDirect3DDevice8_Present(device_ptr, NULL, NULL, NULL, NULL);

    color = getPixelColor(device_ptr, 1, 1);
    if(color !=0x00ff0000)
    {
        trace("Sanity check returned an incorrect color(%08x), can't assure the correctness of the tests, skipping\n", color);
        goto cleanup;
    }

    hr = IDirect3DDevice8_Clear(device_ptr, 0, NULL, D3DCLEAR_TARGET, 0xff00ddee, 0.0, 0);
    if(FAILED(hr))
    {
        trace("Clear failed, can't assure correctness of the test results, skipping\n");
        goto cleanup;
    }
    IDirect3DDevice8_Present(device_ptr, NULL, NULL, NULL, NULL);

    color = getPixelColor(device_ptr, 639, 479);
    if(color != 0x0000ddee)
    {
        trace("Sanity check returned an incorrect color(%08x), can't assure the correctness of the tests, skipping\n", color);
        goto cleanup;
    }

    /* Now run the real test */
    lighting_test(device_ptr);
    clear_test(device_ptr);
    fog_test(device_ptr);
    present_test(device_ptr);
    offscreen_test(device_ptr);
    alpha_test(device_ptr);

    if (caps.VertexShaderVersion >= D3DVS_VERSION(1, 1))
    {
        test_rcp_rsq(device_ptr);
    }
    else
    {
        skip("No vs.1.1 support\n");
    }

    p8_texture_test(device_ptr);

cleanup:
    if(device_ptr) {
        D3DDEVICE_CREATION_PARAMETERS creation_parameters;
        IDirect3DDevice8_GetCreationParameters(device_ptr, &creation_parameters);
        IDirect3DDevice8_Release(device_ptr);
        DestroyWindow(creation_parameters.hFocusWindow);
    }
}
