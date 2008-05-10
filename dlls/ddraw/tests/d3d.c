/*
 * Some unit tests for d3d functions
 *
 * Copyright (C) 2005 Antoine Chavasse
 * Copyright (C) 2006 Stefan D�singer for CodeWeavers
 * Copyright (C) 2008 Alexander Dorofeyev
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

#include <assert.h>
#include "wine/test.h"
#include "ddraw.h"
#include "d3d.h"

static LPDIRECTDRAW7           lpDD = NULL;
static LPDIRECT3D7             lpD3D = NULL;
static LPDIRECTDRAWSURFACE7    lpDDS = NULL;
static LPDIRECTDRAWSURFACE7    lpDDSdepth = NULL;
static LPDIRECT3DDEVICE7       lpD3DDevice = NULL;
static LPDIRECT3DVERTEXBUFFER7 lpVBufSrc = NULL;
static LPDIRECT3DVERTEXBUFFER7 lpVBufDest1 = NULL;
static LPDIRECT3DVERTEXBUFFER7 lpVBufDest2 = NULL;

static IDirectDraw *DirectDraw1 = NULL;
static IDirectDrawSurface *Surface1 = NULL;
static IDirect3D *Direct3D1 = NULL;
static IDirect3DDevice *Direct3DDevice1 = NULL;
static IDirect3DExecuteBuffer *ExecuteBuffer = NULL;
static IDirect3DViewport *Viewport = NULL;

typedef struct {
    int total;
    int rgb;
    int hal;
    int tnlhal;
    int unk;
} D3D7ETest;

/* To compare bad floating point numbers. Not the ideal way to do it,
 * but it should be enough for here */
#define comparefloat(a, b) ( (((a) - (b)) < 0.0001) && (((a) - (b)) > -0.0001) )

static HRESULT (WINAPI *pDirectDrawCreateEx)(LPGUID,LPVOID*,REFIID,LPUNKNOWN);

typedef struct _VERTEX
{
    float x, y, z;  /* position */
} VERTEX, *LPVERTEX;

typedef struct _TVERTEX
{
    float x, y, z;  /* position */
    float rhw;
} TVERTEX, *LPTVERTEX;


static void init_function_pointers(void)
{
    HMODULE hmod = GetModuleHandleA("ddraw.dll");
    pDirectDrawCreateEx = (void*)GetProcAddress(hmod, "DirectDrawCreateEx");
}


static BOOL CreateDirect3D(void)
{
    HRESULT rc;
    DDSURFACEDESC2 ddsd;

    rc = pDirectDrawCreateEx(NULL, (void**)&lpDD,
        &IID_IDirectDraw7, NULL);
    ok(rc==DD_OK || rc==DDERR_NODIRECTDRAWSUPPORT, "DirectDrawCreateEx returned: %x\n", rc);
    if (!lpDD) {
        trace("DirectDrawCreateEx() failed with an error %x\n", rc);
        return FALSE;
    }

    rc = IDirectDraw_SetCooperativeLevel(lpDD, NULL, DDSCL_NORMAL);
    ok(rc==DD_OK, "SetCooperativeLevel returned: %x\n", rc);

    rc = IDirectDraw7_QueryInterface(lpDD, &IID_IDirect3D7, (void**) &lpD3D);
    if (rc == E_NOINTERFACE) return FALSE;
    ok(rc==DD_OK, "QueryInterface returned: %x\n", rc);

    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_3DDEVICE;
    ddsd.dwWidth = 256;
    ddsd.dwHeight = 256;
    rc = IDirectDraw7_CreateSurface(lpDD, &ddsd, &lpDDS, NULL);
    if (!SUCCEEDED(rc))
        return FALSE;

    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_ZBUFFER;
    U4(ddsd).ddpfPixelFormat.dwSize = sizeof(U4(ddsd).ddpfPixelFormat);
    U4(ddsd).ddpfPixelFormat.dwFlags = DDPF_ZBUFFER;
    U1(U4(ddsd).ddpfPixelFormat).dwZBufferBitDepth = 16;
    U3(U4(ddsd).ddpfPixelFormat).dwZBitMask = 0x0000FFFF;
    ddsd.dwWidth = 256;
    ddsd.dwHeight = 256;
    rc = IDirectDraw7_CreateSurface(lpDD, &ddsd, &lpDDSdepth, NULL);
    ok(rc==DD_OK, "CreateSurface returned: %x\n", rc);
    if (!SUCCEEDED(rc)) {
        lpDDSdepth = NULL;
    } else {
        rc = IDirectDrawSurface_AddAttachedSurface(lpDDS, lpDDSdepth);
        ok(rc == DD_OK, "IDirectDrawSurface_AddAttachedSurface returned %x\n", rc);
        if (!SUCCEEDED(rc))
            return FALSE;
    }

    rc = IDirect3D7_CreateDevice(lpD3D, &IID_IDirect3DTnLHalDevice, lpDDS,
        &lpD3DDevice);
    ok(rc==D3D_OK || rc==DDERR_NOPALETTEATTACHED || rc==E_OUTOFMEMORY, "CreateDevice returned: %x\n", rc);
    if (!lpD3DDevice) {
        trace("IDirect3D7::CreateDevice() for a TnL Hal device failed with an error %x, trying HAL\n", rc);
        rc = IDirect3D7_CreateDevice(lpD3D, &IID_IDirect3DHALDevice, lpDDS,
            &lpD3DDevice);
        if (!lpD3DDevice) {
            trace("IDirect3D7::CreateDevice() for a HAL device failed with an error %x, trying RGB\n", rc);
            rc = IDirect3D7_CreateDevice(lpD3D, &IID_IDirect3DRGBDevice, lpDDS,
                &lpD3DDevice);
            if (!lpD3DDevice) {
                trace("IDirect3D7::CreateDevice() for a RGB device failed with an error %x, giving up\n", rc);
                return FALSE;
            }
        }
    }

    return TRUE;
}

static void ReleaseDirect3D(void)
{
    if (lpD3DDevice != NULL)
    {
        IDirect3DDevice7_Release(lpD3DDevice);
        lpD3DDevice = NULL;
    }

    if (lpDDSdepth != NULL)
    {
        IDirectDrawSurface_Release(lpDDSdepth);
        lpDDSdepth = NULL;
    }

    if (lpDDS != NULL)
    {
        IDirectDrawSurface_Release(lpDDS);
        lpDDS = NULL;
    }

    if (lpD3D != NULL)
    {
        IDirect3D7_Release(lpD3D);
        lpD3D = NULL;
    }

    if (lpDD != NULL)
    {
        IDirectDraw_Release(lpDD);
        lpDD = NULL;
    }
}

static void LightTest(void)
{
    HRESULT rc;
    D3DLIGHT7 light;
    D3DLIGHT7 defaultlight;
    BOOL bEnabled = FALSE;
    float one = 1.0f;
    float zero= 0.0f;
    D3DMATERIAL7 mat;
    BOOL enabled;
    unsigned int i;
    D3DDEVICEDESC7 caps;

    /* Set a few lights with funky indices. */
    memset(&light, 0, sizeof(light));
    light.dltType = D3DLIGHT_DIRECTIONAL;
    U1(light.dcvDiffuse).r = 0.5f;
    U2(light.dcvDiffuse).g = 0.6f;
    U3(light.dcvDiffuse).b = 0.7f;
    U2(light.dvDirection).y = 1.f;

    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 5, &light);
    ok(rc==D3D_OK, "SetLight returned: %x\n", rc);
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 10, &light);
    ok(rc==D3D_OK, "SetLight returned: %x\n", rc);
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 45, &light);
    ok(rc==D3D_OK, "SetLight returned: %x\n", rc);


    /* Try to retrieve a light beyond the indices of the lights that have
       been set. */
    rc = IDirect3DDevice7_GetLight(lpD3DDevice, 50, &light);
    ok(rc==DDERR_INVALIDPARAMS, "GetLight returned: %x\n", rc);
    rc = IDirect3DDevice7_GetLight(lpD3DDevice, 2, &light);
    ok(rc==DDERR_INVALIDPARAMS, "GetLight returned: %x\n", rc);


    /* Try to retrieve one of the lights that have been set */
    rc = IDirect3DDevice7_GetLight(lpD3DDevice, 10, &light);
    ok(rc==D3D_OK, "GetLight returned: %x\n", rc);


    /* Enable a light that have been previously set. */
    rc = IDirect3DDevice7_LightEnable(lpD3DDevice, 10, TRUE);
    ok(rc==D3D_OK, "LightEnable returned: %x\n", rc);


    /* Enable some lights that have not been previously set, and verify that
       they have been initialized with proper default values. */
    memset(&defaultlight, 0, sizeof(D3DLIGHT7));
    defaultlight.dltType = D3DLIGHT_DIRECTIONAL;
    U1(defaultlight.dcvDiffuse).r = 1.f;
    U2(defaultlight.dcvDiffuse).g = 1.f;
    U3(defaultlight.dcvDiffuse).b = 1.f;
    U3(defaultlight.dvDirection).z = 1.f;

    rc = IDirect3DDevice7_LightEnable(lpD3DDevice, 20, TRUE);
    ok(rc==D3D_OK, "LightEnable returned: %x\n", rc);
    memset(&light, 0, sizeof(D3DLIGHT7));
    rc = IDirect3DDevice7_GetLight(lpD3DDevice, 20, &light);
    ok(rc==D3D_OK, "GetLight returned: %x\n", rc);
    ok(!memcmp(&light, &defaultlight, sizeof(D3DLIGHT7)),
        "light data doesn't match expected default values\n" );

    rc = IDirect3DDevice7_LightEnable(lpD3DDevice, 50, TRUE);
    ok(rc==D3D_OK, "LightEnable returned: %x\n", rc);
    memset(&light, 0, sizeof(D3DLIGHT7));
    rc = IDirect3DDevice7_GetLight(lpD3DDevice, 50, &light);
    ok(rc==D3D_OK, "GetLight returned: %x\n", rc);
    ok(!memcmp(&light, &defaultlight, sizeof(D3DLIGHT7)),
        "light data doesn't match expected default values\n" );


    /* Disable one of the light that have been previously enabled. */
    rc = IDirect3DDevice7_LightEnable(lpD3DDevice, 20, FALSE);
    ok(rc==D3D_OK, "LightEnable returned: %x\n", rc);

    /* Try to retrieve the enable status of some lights */
    /* Light 20 is supposed to be disabled */
    rc = IDirect3DDevice7_GetLightEnable(lpD3DDevice, 20, &bEnabled );
    ok(rc==D3D_OK, "GetLightEnable returned: %x\n", rc);
    ok(!bEnabled, "GetLightEnable says the light is enabled\n");

    /* Light 10 is supposed to be enabled */
    bEnabled = FALSE;
    rc = IDirect3DDevice7_GetLightEnable(lpD3DDevice, 10, &bEnabled );
    ok(rc==D3D_OK, "GetLightEnable returned: %x\n", rc);
    ok(bEnabled, "GetLightEnable says the light is disabled\n");

    /* Light 80 has not been set */
    rc = IDirect3DDevice7_GetLightEnable(lpD3DDevice, 80, &bEnabled );
    ok(rc==DDERR_INVALIDPARAMS, "GetLightEnable returned: %x\n", rc);

    /* Light 23 has not been set */
    rc = IDirect3DDevice7_GetLightEnable(lpD3DDevice, 23, &bEnabled );
    ok(rc==DDERR_INVALIDPARAMS, "GetLightEnable returned: %x\n", rc);

    /* Set some lights with invalid parameters */
    memset(&light, 0, sizeof(D3DLIGHT7));
    light.dltType = 0;
    U1(light.dcvDiffuse).r = 1.f;
    U2(light.dcvDiffuse).g = 1.f;
    U3(light.dcvDiffuse).b = 1.f;
    U3(light.dvDirection).z = 1.f;
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 100, &light);
    ok(rc==DDERR_INVALIDPARAMS, "SetLight returned: %x\n", rc);

    memset(&light, 0, sizeof(D3DLIGHT7));
    light.dltType = 12345;
    U1(light.dcvDiffuse).r = 1.f;
    U2(light.dcvDiffuse).g = 1.f;
    U3(light.dcvDiffuse).b = 1.f;
    U3(light.dvDirection).z = 1.f;
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 101, &light);
    ok(rc==DDERR_INVALIDPARAMS, "SetLight returned: %x\n", rc);

    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 102, NULL);
    ok(rc==DDERR_INVALIDPARAMS, "SetLight returned: %x\n", rc);

    memset(&light, 0, sizeof(D3DLIGHT7));
    light.dltType = D3DLIGHT_SPOT;
    U1(light.dcvDiffuse).r = 1.f;
    U2(light.dcvDiffuse).g = 1.f;
    U3(light.dcvDiffuse).b = 1.f;
    U3(light.dvDirection).z = 1.f;

    light.dvAttenuation0 = -one / zero; /* -INFINITY */
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 103, &light);
    ok(rc==DDERR_INVALIDPARAMS, "SetLight returned: %x\n", rc);

    light.dvAttenuation0 = -1.0;
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 103, &light);
    ok(rc==DDERR_INVALIDPARAMS, "SetLight returned: %x\n", rc);

    light.dvAttenuation0 = 0.0;
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 103, &light);
    ok(rc==D3D_OK, "SetLight returned: %x\n", rc);

    light.dvAttenuation0 = 1.0;
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 103, &light);
    ok(rc==D3D_OK, "SetLight returned: %x\n", rc);

    light.dvAttenuation0 = one / zero; /* +INFINITY */
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 103, &light);
    ok(rc==D3D_OK, "SetLight returned: %x\n", rc);

    light.dvAttenuation0 = zero / zero; /* NaN */
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 103, &light);
    ok(rc==D3D_OK, "SetLight returned: %x\n", rc);

    /* Directional light ignores attenuation */
    light.dltType = D3DLIGHT_DIRECTIONAL;
    light.dvAttenuation0 = -1.0;
    rc = IDirect3DDevice7_SetLight(lpD3DDevice, 103, &light);
    ok(rc==D3D_OK, "SetLight returned: %x\n", rc);

    memset(&mat, 0, sizeof(mat));
    rc = IDirect3DDevice7_SetMaterial(lpD3DDevice, &mat);
    ok(rc == D3D_OK, "IDirect3DDevice7_SetMaterial returned: %x\n", rc);

    U4(mat).power = 129.0;
    rc = IDirect3DDevice7_SetMaterial(lpD3DDevice, &mat);
    ok(rc == D3D_OK, "IDirect3DDevice7_SetMaterial(power = 129.0) returned: %x\n", rc);
    memset(&mat, 0, sizeof(mat));
    rc = IDirect3DDevice7_GetMaterial(lpD3DDevice, &mat);
    ok(rc == D3D_OK, "IDirect3DDevice7_GetMaterial returned: %x\n", rc);
    ok(U4(mat).power == 129, "Returned power is %f\n", U4(mat).power);

    U4(mat).power = -1.0;
    rc = IDirect3DDevice7_SetMaterial(lpD3DDevice, &mat);
    ok(rc == D3D_OK, "IDirect3DDevice7_SetMaterial(power = -1.0) returned: %x\n", rc);
    memset(&mat, 0, sizeof(mat));
    rc = IDirect3DDevice7_GetMaterial(lpD3DDevice, &mat);
    ok(rc == D3D_OK, "IDirect3DDevice7_GetMaterial returned: %x\n", rc);
    ok(U4(mat).power == -1, "Returned power is %f\n", U4(mat).power);

    memset(&caps, 0, sizeof(caps));
    rc = IDirect3DDevice7_GetCaps(lpD3DDevice, &caps);
    ok(rc == D3D_OK, "IDirect3DDevice7_GetCaps failed with %x\n", rc);

    if ( caps.dwMaxActiveLights == (DWORD) -1) {
        /* Some cards without T&L Support return -1 (Examples: Voodoo Banshee, RivaTNT / NV4) */
        skip("T&L not supported\n");
        return;
    }

    for(i = 1; i <= caps.dwMaxActiveLights; i++) {
        rc = IDirect3DDevice7_LightEnable(lpD3DDevice, i, TRUE);
        ok(rc == D3D_OK, "Enabling light %u failed with %x\n", i, rc);
        rc = IDirect3DDevice7_GetLightEnable(lpD3DDevice, i, &enabled);
        ok(rc == D3D_OK, "GetLightEnable on light %u failed with %x\n", i, rc);
        ok(enabled, "Light %d is %s\n", i, enabled ? "enabled" : "disabled");
    }

    /* TODO: Test the rendering results in this situation */
    rc = IDirect3DDevice7_LightEnable(lpD3DDevice, i + 1, TRUE);
    ok(rc == D3D_OK, "Enabling one light more than supported returned %x\n", rc);
    rc = IDirect3DDevice7_GetLightEnable(lpD3DDevice, i + 1, &enabled);
    ok(rc == D3D_OK, "GetLightEnable on light %u failed with %x\n", i + 1,  rc);
    ok(enabled, "Light %d is %s\n", i + 1, enabled ? "enabled" : "disabled");
    rc = IDirect3DDevice7_LightEnable(lpD3DDevice, i + 1, FALSE);
    ok(rc == D3D_OK, "Disabling the additional returned %x\n", rc);

    for(i = 1; i <= caps.dwMaxActiveLights; i++) {
        rc = IDirect3DDevice7_LightEnable(lpD3DDevice, i, FALSE);
        ok(rc == D3D_OK, "Disabling light %u failed with %x\n", i, rc);
    }
}

static void ProcessVerticesTest(void)
{
    D3DVERTEXBUFFERDESC desc;
    HRESULT rc;
    VERTEX *in;
    TVERTEX *out;
    VERTEX *out2;
    D3DVIEWPORT7 vp;
    D3DMATRIX view = {  2.0, 0.0, 0.0, 0.0,
                        0.0, -1.0, 0.0, 0.0,
                        0.0, 0.0, 1.0, 0.0,
                        0.0, 0.0, 0.0, 3.0 };

    D3DMATRIX world = { 0.0, 1.0, 0.0, 0.0,
                        1.0, 0.0, 0.0, 0.0,
                        0.0, 0.0, 0.0, 1.0,
                        0.0, 1.0, 1.0, 1.0 };

    D3DMATRIX proj = {  1.0, 0.0, 0.0, 1.0,
                        0.0, 1.0, 1.0, 0.0,
                        0.0, 1.0, 1.0, 0.0,
                        1.0, 0.0, 0.0, 1.0 };
    /* Create some vertex buffers */

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    desc.dwCaps = 0;
    desc.dwFVF = D3DFVF_XYZ;
    desc.dwNumVertices = 16;
    rc = IDirect3D7_CreateVertexBuffer(lpD3D, &desc, &lpVBufSrc, 0);
    ok(rc==D3D_OK || rc==E_OUTOFMEMORY, "CreateVertexBuffer returned: %x\n", rc);
    if (!lpVBufSrc)
    {
        trace("IDirect3D7::CreateVertexBuffer() failed with an error %x\n", rc);
        goto out;
    }

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    desc.dwCaps = 0;
    desc.dwFVF = D3DFVF_XYZRHW;
    desc.dwNumVertices = 16;
    /* Msdn says that the last parameter must be 0 - check that */
    rc = IDirect3D7_CreateVertexBuffer(lpD3D, &desc, &lpVBufDest1, 4);
    ok(rc==D3D_OK || rc==E_OUTOFMEMORY, "CreateVertexBuffer returned: %x\n", rc);
    if (!lpVBufDest1)
    {
        trace("IDirect3D7::CreateVertexBuffer() failed with an error %x\n", rc);
        goto out;
    }

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    desc.dwCaps = 0;
    desc.dwFVF = D3DFVF_XYZ;
    desc.dwNumVertices = 16;
    /* Msdn says that the last parameter must be 0 - check that */
    rc = IDirect3D7_CreateVertexBuffer(lpD3D, &desc, &lpVBufDest2, 12345678);
    ok(rc==D3D_OK || rc==E_OUTOFMEMORY, "CreateVertexBuffer returned: %x\n", rc);
    if (!lpVBufDest2)
    {
        trace("IDirect3D7::CreateVertexBuffer() failed with an error %x\n", rc);
        goto out;
    }

    rc = IDirect3DVertexBuffer7_Lock(lpVBufSrc, 0, (void **) &in, NULL);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Lock returned: %x\n", rc);
    if(!in) goto out;

    /* Check basic transformation */

    in[0].x = 0.0;
    in[0].y = 0.0;
    in[0].z = 0.0;

    in[1].x = 1.0;
    in[1].y = 1.0;
    in[1].z = 1.0;

    in[2].x = -1.0;
    in[2].y = -1.0;
    in[2].z = 0.5;

    in[3].x = 0.5;
    in[3].y = -0.5;
    in[3].z = 0.25;
    rc = IDirect3DVertexBuffer7_Unlock(lpVBufSrc);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Unlock returned: %x\n", rc);

    rc = IDirect3DVertexBuffer7_ProcessVertices(lpVBufDest1, D3DVOP_TRANSFORM, 0, 4, lpVBufSrc, 0, lpD3DDevice, 0);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::ProcessVertices returned: %x\n", rc);

    rc = IDirect3DVertexBuffer7_ProcessVertices(lpVBufDest2, D3DVOP_TRANSFORM, 0, 4, lpVBufSrc, 0, lpD3DDevice, 0);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::ProcessVertices returned: %x\n", rc);

    rc = IDirect3DVertexBuffer7_Lock(lpVBufDest1, 0, (void **) &out, NULL);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Lock returned: %x\n", rc);
    if(!out) goto out;

    /* Check the results */
    ok( comparefloat(out[0].x, 128.0 ) &&
        comparefloat(out[0].y, 128.0 ) &&
        comparefloat(out[0].z, 0.0 ) &&
        comparefloat(out[0].rhw, 1.0 ),
        "Output 0 vertex is (%f , %f , %f , %f)\n", out[0].x, out[0].y, out[0].z, out[0].rhw);

    ok( comparefloat(out[1].x, 256.0 ) &&
        comparefloat(out[1].y, 0.0 ) &&
        comparefloat(out[1].z, 1.0 ) &&
        comparefloat(out[1].rhw, 1.0 ),
        "Output 1 vertex is (%f , %f , %f , %f)\n", out[1].x, out[1].y, out[1].z, out[1].rhw);

    ok( comparefloat(out[2].x, 0.0 ) &&
        comparefloat(out[2].y, 256.0 ) &&
        comparefloat(out[2].z, 0.5 ) &&
        comparefloat(out[2].rhw, 1.0 ),
        "Output 2 vertex is (%f , %f , %f , %f)\n", out[2].x, out[2].y, out[2].z, out[2].rhw);

    ok( comparefloat(out[3].x, 192.0 ) &&
        comparefloat(out[3].y, 192.0 ) &&
        comparefloat(out[3].z, 0.25 ) &&
        comparefloat(out[3].rhw, 1.0 ),
        "Output 3 vertex is (%f , %f , %f , %f)\n", out[3].x, out[3].y, out[3].z, out[3].rhw);

    rc = IDirect3DVertexBuffer7_Unlock(lpVBufDest1);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Unlock returned: %x\n", rc);
    out = NULL;

    rc = IDirect3DVertexBuffer7_Lock(lpVBufDest2, 0, (void **) &out2, NULL);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Lock returned: %x\n", rc);
    if(!out2) goto out;
    /* Small thing without much practical meaning, but I stumbled upon it,
     * so let's check for it: If the output vertex buffer has to RHW value,
     * The RHW value of the last vertex is written into the next vertex
     */
    ok( comparefloat(out2[4].x, 1.0 ) &&
        comparefloat(out2[4].y, 0.0 ) &&
        comparefloat(out2[4].z, 0.0 ),
        "Output 4 vertex is (%f , %f , %f)\n", out2[4].x, out2[4].y, out2[4].z);

    rc = IDirect3DVertexBuffer7_Unlock(lpVBufDest2);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Unlock returned: %x\n", rc);
    out = NULL;

    /* Try a more complicated viewport, same vertices */
    memset(&vp, 0, sizeof(vp));
    vp.dwX = 10;
    vp.dwY = 5;
    vp.dwWidth = 246;
    vp.dwHeight = 130;
    vp.dvMinZ = -2.0;
    vp.dvMaxZ = 4.0;
    rc = IDirect3DDevice7_SetViewport(lpD3DDevice, &vp);
    ok(rc==D3D_OK, "IDirect3DDevice7_SetViewport failed with rc=%x\n", rc);

    /* Process again */
    rc = IDirect3DVertexBuffer7_ProcessVertices(lpVBufDest1, D3DVOP_TRANSFORM, 0, 4, lpVBufSrc, 0, lpD3DDevice, 0);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::ProcessVertices returned: %x\n", rc);

    rc = IDirect3DVertexBuffer7_Lock(lpVBufDest1, 0, (void **) &out, NULL);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Lock returned: %x\n", rc);
    if(!out) goto out;

    /* Check the results */
    ok( comparefloat(out[0].x, 133.0 ) &&
        comparefloat(out[0].y, 70.0 ) &&
        comparefloat(out[0].z, -2.0 ) &&
        comparefloat(out[0].rhw, 1.0 ),
        "Output 0 vertex is (%f , %f , %f , %f)\n", out[0].x, out[0].y, out[0].z, out[0].rhw);

    ok( comparefloat(out[1].x, 256.0 ) &&
        comparefloat(out[1].y, 5.0 ) &&
        comparefloat(out[1].z, 4.0 ) &&
        comparefloat(out[1].rhw, 1.0 ),
        "Output 1 vertex is (%f , %f , %f , %f)\n", out[1].x, out[1].y, out[1].z, out[1].rhw);

    ok( comparefloat(out[2].x, 10.0 ) &&
        comparefloat(out[2].y, 135.0 ) &&
        comparefloat(out[2].z, 1.0 ) &&
        comparefloat(out[2].rhw, 1.0 ),
        "Output 2 vertex is (%f , %f , %f , %f)\n", out[1].x, out[1].y, out[1].z, out[1].rhw);

    ok( comparefloat(out[3].x, 194.5 ) &&
        comparefloat(out[3].y, 102.5 ) &&
        comparefloat(out[3].z, -0.5 ) &&
        comparefloat(out[3].rhw, 1.0 ),
        "Output 3 vertex is (%f , %f , %f , %f)\n", out[3].x, out[3].y, out[3].z, out[3].rhw);

    rc = IDirect3DVertexBuffer7_Unlock(lpVBufDest1);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Unlock returned: %x\n", rc);
    out = NULL;

    /* Play with some matrices. */

    rc = IDirect3DDevice7_SetTransform(lpD3DDevice, D3DTRANSFORMSTATE_VIEW, &view);
    ok(rc==D3D_OK, "IDirect3DDevice7_SetTransform failed\n");

    rc = IDirect3DDevice7_SetTransform(lpD3DDevice, D3DTRANSFORMSTATE_PROJECTION, &proj);
    ok(rc==D3D_OK, "IDirect3DDevice7_SetTransform failed\n");

    rc = IDirect3DDevice7_SetTransform(lpD3DDevice, D3DTRANSFORMSTATE_WORLD, &world);
    ok(rc==D3D_OK, "IDirect3DDevice7_SetTransform failed\n");

    rc = IDirect3DVertexBuffer7_ProcessVertices(lpVBufDest1, D3DVOP_TRANSFORM, 0, 4, lpVBufSrc, 0, lpD3DDevice, 0);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::ProcessVertices returned: %x\n", rc);

    rc = IDirect3DVertexBuffer7_Lock(lpVBufDest1, 0, (void **) &out, NULL);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Lock returned: %x\n", rc);
    if(!out) goto out;

    /* Keep the viewport simpler, otherwise we get bad numbers to compare */
    vp.dwX = 0;
    vp.dwY = 0;
    vp.dwWidth = 100;
    vp.dwHeight = 100;
    vp.dvMinZ = 1.0;
    vp.dvMaxZ = 0.0;
    rc = IDirect3DDevice7_SetViewport(lpD3DDevice, &vp);
    ok(rc==D3D_OK, "IDirect3DDevice7_SetViewport failed\n");

    /* Check the results */
    ok( comparefloat(out[0].x, 256.0 ) &&    /* X coordinate is cut at the surface edges */
        comparefloat(out[0].y, 70.0 ) &&
        comparefloat(out[0].z, -2.0 ) &&
        comparefloat(out[0].rhw, (1.0 / 3.0)),
        "Output 0 vertex is (%f , %f , %f , %f)\n", out[0].x, out[0].y, out[0].z, out[0].rhw);

    ok( comparefloat(out[1].x, 256.0 ) &&
        comparefloat(out[1].y, 78.125000 ) &&
        comparefloat(out[1].z, -2.750000 ) &&
        comparefloat(out[1].rhw, 0.125000 ),
        "Output 1 vertex is (%f , %f , %f , %f)\n", out[1].x, out[1].y, out[1].z, out[1].rhw);

    ok( comparefloat(out[2].x, 256.0 ) &&
        comparefloat(out[2].y, 44.000000 ) &&
        comparefloat(out[2].z, 0.400000 ) &&
        comparefloat(out[2].rhw, 0.400000 ),
        "Output 2 vertex is (%f , %f , %f , %f)\n", out[2].x, out[2].y, out[2].z, out[2].rhw);

    ok( comparefloat(out[3].x, 256.0 ) &&
        comparefloat(out[3].y, 81.818184 ) &&
        comparefloat(out[3].z, -3.090909 ) &&
        comparefloat(out[3].rhw, 0.363636 ),
        "Output 3 vertex is (%f , %f , %f , %f)\n", out[3].x, out[3].y, out[3].z, out[3].rhw);

    rc = IDirect3DVertexBuffer7_Unlock(lpVBufDest1);
    ok(rc==D3D_OK , "IDirect3DVertexBuffer::Unlock returned: %x\n", rc);
    out = NULL;

out:
    IDirect3DVertexBuffer7_Release(lpVBufSrc);
    IDirect3DVertexBuffer7_Release(lpVBufDest1);
    IDirect3DVertexBuffer7_Release(lpVBufDest2);
}

static void StateTest( void )
{
    HRESULT rc;

    /* The msdn says its undocumented, does it return an error too? */
    rc = IDirect3DDevice7_SetRenderState(lpD3DDevice, D3DRENDERSTATE_ZVISIBLE, TRUE);
    ok(rc == D3D_OK, "IDirect3DDevice7_SetRenderState(D3DRENDERSTATE_ZVISIBLE, TRUE) returned %08x\n", rc);
    rc = IDirect3DDevice7_SetRenderState(lpD3DDevice, D3DRENDERSTATE_ZVISIBLE, FALSE);
    ok(rc == D3D_OK, "IDirect3DDevice7_SetRenderState(D3DRENDERSTATE_ZVISIBLE, FALSE) returned %08x\n", rc);
}


static void SceneTest(void)
{
    HRESULT                      hr;

    /* Test an EndScene without beginscene. Should return an error */
    hr = IDirect3DDevice7_EndScene(lpD3DDevice);
    ok(hr == D3DERR_SCENE_NOT_IN_SCENE, "IDirect3DDevice7_EndScene returned %08x\n", hr);

    /* Test a normal BeginScene / EndScene pair, this should work */
    hr = IDirect3DDevice7_BeginScene(lpD3DDevice);
    ok(hr == D3D_OK, "IDirect3DDevice7_BeginScene failed with %08x\n", hr);
    if(SUCCEEDED(hr))
    {
        DDBLTFX fx;
        memset(&fx, 0, sizeof(fx));
        fx.dwSize = sizeof(fx);

        if(lpDDSdepth) {
            hr = IDirectDrawSurface7_Blt(lpDDSdepth, NULL, NULL, NULL, DDBLT_DEPTHFILL, &fx);
            ok(hr == D3D_OK, "Depthfill failed in a BeginScene / EndScene pair\n");
        } else {
            skip("Depth stencil creation failed at startup, skipping\n");
        }
        hr = IDirect3DDevice7_EndScene(lpD3DDevice);
        ok(hr == D3D_OK, "IDirect3DDevice7_EndScene failed with %08x\n", hr);
    }

    /* Test another EndScene without having begun a new scene. Should return an error */
    hr = IDirect3DDevice7_EndScene(lpD3DDevice);
    ok(hr == D3DERR_SCENE_NOT_IN_SCENE, "IDirect3DDevice7_EndScene returned %08x\n", hr);

    /* Two nested BeginScene and EndScene calls */
    hr = IDirect3DDevice7_BeginScene(lpD3DDevice);
    ok(hr == D3D_OK, "IDirect3DDevice7_BeginScene failed with %08x\n", hr);
    hr = IDirect3DDevice7_BeginScene(lpD3DDevice);
    ok(hr == D3DERR_SCENE_IN_SCENE, "IDirect3DDevice7_BeginScene returned %08x\n", hr);
    hr = IDirect3DDevice7_EndScene(lpD3DDevice);
    ok(hr == D3D_OK, "IDirect3DDevice7_EndScene failed with %08x\n", hr);
    hr = IDirect3DDevice7_EndScene(lpD3DDevice);
    ok(hr == D3DERR_SCENE_NOT_IN_SCENE, "IDirect3DDevice7_EndScene returned %08x\n", hr);

    /* TODO: Verify that blitting works in the same way as in d3d9 */
}

static void LimitTest(void)
{
    IDirectDrawSurface7 *pTexture = NULL;
    HRESULT hr;
    int i;
    DDSURFACEDESC2 ddsd;

    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE;
    ddsd.dwWidth = 16;
    ddsd.dwHeight = 16;
    hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &pTexture, NULL);
    ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
    if(!pTexture) return;

    for(i = 0; i < 8; i++) {
        hr = IDirect3DDevice7_SetTexture(lpD3DDevice, i, pTexture);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetTexture for sampler %d failed with %08x\n", i, hr);
        hr = IDirect3DDevice7_SetTexture(lpD3DDevice, i, NULL);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetTexture for sampler %d failed with %08x\n", i, hr);
        hr = IDirect3DDevice7_SetTextureStageState(lpD3DDevice, i, D3DTSS_COLOROP, D3DTOP_ADD);
        ok(hr == D3D_OK, "IDirect3DDevice8_SetTextureStageState for texture %d failed with %08x\n", i, hr);
    }

    IDirectDrawSurface7_Release(pTexture);
}

static HRESULT WINAPI enumDevicesCallback(GUID *Guid,LPSTR DeviceDescription,LPSTR DeviceName, D3DDEVICEDESC *hal, D3DDEVICEDESC *hel, VOID *ctx)
{
    UINT ver = *((UINT *) ctx);
    if(IsEqualGUID(&IID_IDirect3DRGBDevice, Guid))
    {
        ok((hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) == 0,
           "RGB Device %d hal line caps has D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok((hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) == 0,
           "RGB Device %d hal tri caps has D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2,
           "RGB Device %d hel line caps does not have D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2,
           "RGB Device %d hel tri caps does not have D3DPTEXTURECAPS_POW2 flag set\n", ver);

        ok((hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "RGB Device %d hal line caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok((hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "RGB Device %d hal tri caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "RGB Device %d hel tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "RGB Device %d hel tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
    }
    else if(IsEqualGUID(&IID_IDirect3DHALDevice, Guid))
    {
        /* pow2 is hardware dependent */

        ok(hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "HAL Device %d hal line caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "HAL Device %d hal tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok((hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "HAL Device %d hel line caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok((hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "HAL Device %d hel tri caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
    }
    else if(IsEqualGUID(&IID_IDirect3DRefDevice, Guid))
    {
        ok((hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) == 0,
           "REF Device %d hal line caps has D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok((hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) == 0,
           "REF Device %d hal tri caps has D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2,
           "REF Device %d hel line caps does not have D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2,
           "REF Device %d hel tri caps does not have D3DPTEXTURECAPS_POW2 flag set\n", ver);

        ok((hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "REF Device %d hal line caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok((hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "REF Device %d hal tri caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "REF Device %d hel tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "REF Device %d hel tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
    }
    else if(IsEqualGUID(&IID_IDirect3DRampDevice, Guid))
    {
        ok((hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) == 0,
           "Ramp Device %d hal line caps has D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok((hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) == 0,
           "Ramp Device %d hal tri caps has D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2,
           "Ramp Device %d hel line caps does not have D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2,
           "Ramp Device %d hel tri caps does not have D3DPTEXTURECAPS_POW2 flag set\n", ver);

        ok((hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "Ramp Device %d hal line caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok((hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "Ramp Device %d hal tri caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "Ramp Device %d hel tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "Ramp Device %d hel tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
    }
    else if(IsEqualGUID(&IID_IDirect3DMMXDevice, Guid))
    {
        ok((hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) == 0,
           "MMX Device %d hal line caps has D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok((hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) == 0,
           "MMX Device %d hal tri caps has D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2,
           "MMX Device %d hel line caps does not have D3DPTEXTURECAPS_POW2 flag set\n", ver);
        ok(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2,
           "MMX Device %d hel tri caps does not have D3DPTEXTURECAPS_POW2 flag set\n", ver);

        ok((hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "MMX Device %d hal line caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok((hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE) == 0,
           "MMX Device %d hal tri caps has D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "MMX Device %d hel tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
        ok(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_PERSPECTIVE,
           "MMX Device %d hel tri caps does not have D3DPTEXTURECAPS_PERSPECTIVE set\n", ver);
    }
    else
    {
        ok(FALSE, "Unexpected device enumerated: \"%s\" \"%s\"\n", DeviceDescription, DeviceName);
        if(hal->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) trace("hal line has pow2 set\n");
        else trace("hal line does NOT have pow2 set\n");
        if(hal->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) trace("hal tri has pow2 set\n");
        else trace("hal tri does NOT have pow2 set\n");
        if(hel->dpcLineCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) trace("hel line has pow2 set\n");
        else trace("hel line does NOT have pow2 set\n");
        if(hel->dpcTriCaps.dwTextureCaps & D3DPTEXTURECAPS_POW2) trace("hel tri has pow2 set\n");
        else trace("hel tri does NOT have pow2 set\n");
    }
    return DDENUMRET_OK;
}

static HRESULT WINAPI enumDevicesCallbackTest7(LPSTR DeviceDescription, LPSTR DeviceName, LPD3DDEVICEDESC7 lpdd7, LPVOID Context)
{
    D3D7ETest *d3d7et = (D3D7ETest*)Context;
    if(IsEqualGUID(&lpdd7->deviceGUID, &IID_IDirect3DRGBDevice))
        d3d7et->rgb++;
    else if(IsEqualGUID(&lpdd7->deviceGUID, &IID_IDirect3DHALDevice))
        d3d7et->hal++;
    else if(IsEqualGUID(&lpdd7->deviceGUID, &IID_IDirect3DTnLHalDevice))
        d3d7et->tnlhal++;
    else
        d3d7et->unk++;

    d3d7et->total++;

    return DDENUMRET_OK;
}


/*  Check the deviceGUID of devices enumerated by
    IDirect3D7_EnumDevices. */
static void D3D7EnumTest(void)
{
    D3D7ETest d3d7et;

    if (!lpD3D) {
        skip("No Direct3D7 interface.\n");
        return;
    }

    memset(&d3d7et, 0, sizeof(d3d7et));
    IDirect3D7_EnumDevices(lpD3D, enumDevicesCallbackTest7, (LPVOID) &d3d7et);


    /* A couple of games (Delta Force LW and TFD) rely on this behaviour */
    ok(d3d7et.tnlhal < d3d7et.total, "TnLHal device enumerated as only device.\n");

    /* We make two additional assumptions. */
    ok(d3d7et.rgb, "No RGB Device enumerated.\n");

    if(d3d7et.tnlhal)
        ok(d3d7et.hal, "TnLHal device enumerated, but no Hal device found.\n");

    return;
}

static void CapsTest(void)
{
    IDirect3D3 *d3d3;
    IDirect3D3 *d3d2;
    IDirectDraw *dd1;
    HRESULT hr;
    UINT ver;

    hr = DirectDrawCreate(NULL, &dd1, NULL);
    ok(hr == DD_OK, "Cannot create a DirectDraw 1 interface, hr = %08x\n", hr);
    hr = IDirectDraw_QueryInterface(dd1, &IID_IDirect3D3, (void **) &d3d3);
    ok(hr == D3D_OK, "IDirectDraw_QueryInterface returned %08x\n", hr);
    ver = 3;
    IDirect3D3_EnumDevices(d3d3, enumDevicesCallback, &ver);

    IDirect3D3_Release(d3d3);
    IDirectDraw_Release(dd1);

    hr = DirectDrawCreate(NULL, &dd1, NULL);
    ok(hr == DD_OK, "Cannot create a DirectDraw 1 interface, hr = %08x\n", hr);
    hr = IDirectDraw_QueryInterface(dd1, &IID_IDirect3D2, (void **) &d3d2);
    ok(hr == D3D_OK, "IDirectDraw_QueryInterface returned %08x\n", hr);
    ver = 2;
    IDirect3D2_EnumDevices(d3d2, enumDevicesCallback, &ver);

    IDirect3D2_Release(d3d2);
    IDirectDraw_Release(dd1);
}

struct v_in {
    float x, y, z;
};
struct v_out {
    float x, y, z, rhw;
};

static BOOL D3D1_createObjects(void)
{
    HRESULT hr;
    DDSURFACEDESC ddsd;
    D3DEXECUTEBUFFERDESC desc;
    D3DVIEWPORT vp_data;

    /* An IDirect3DDevice cannot be queryInterfaced from an IDirect3DDevice7 on windows */
    hr = DirectDrawCreate(NULL, &DirectDraw1, NULL);
    ok(hr==DD_OK || hr==DDERR_NODIRECTDRAWSUPPORT, "DirectDrawCreate returned: %x\n", hr);
    if (!DirectDraw1) {
        return FALSE;
    }

    hr = IDirectDraw_SetCooperativeLevel(DirectDraw1, NULL, DDSCL_NORMAL);
    ok(hr==DD_OK, "SetCooperativeLevel returned: %x\n", hr);

    hr = IDirectDraw_QueryInterface(DirectDraw1, &IID_IDirect3D, (void**) &Direct3D1);
    ok(hr==DD_OK, "QueryInterface returned: %x\n", hr);
    if (!Direct3D1) {
        return FALSE;
    }

    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_3DDEVICE;
    ddsd.dwWidth = 256;
    ddsd.dwHeight = 256;
    hr = IDirectDraw_CreateSurface(DirectDraw1, &ddsd, &Surface1, NULL);
    if (!Surface1) {
        skip("DDSCAPS_3DDEVICE surface not available\n");
        return FALSE;
    }

    hr = IDirectDrawSurface_QueryInterface(Surface1, &IID_IDirect3DRGBDevice, (void **) &Direct3DDevice1);
    ok(hr==D3D_OK || hr==DDERR_NOPALETTEATTACHED || hr==E_OUTOFMEMORY, "CreateDevice returned: %x\n", hr);
    if(!Direct3DDevice1) {
        return FALSE;
    }

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    desc.dwFlags = D3DDEB_BUFSIZE | D3DDEB_CAPS;
    desc.dwCaps = D3DDEBCAPS_VIDEOMEMORY;
    desc.dwBufferSize = 128;
    desc.lpData = NULL;
    hr = IDirect3DDevice_CreateExecuteBuffer(Direct3DDevice1, &desc, &ExecuteBuffer, NULL);
    ok(hr == D3D_OK, "IDirect3DDevice_CreateExecuteBuffer failed: %08x\n", hr);
    if(!ExecuteBuffer) {
        return FALSE;
    }

    hr = IDirect3D_CreateViewport(Direct3D1, &Viewport, NULL);
    ok(hr == D3D_OK, "IDirect3D_CreateViewport failed: %08x\n", hr);
    if(!Viewport) {
        return FALSE;
    }

    hr = IDirect3DViewport_Initialize(Viewport, Direct3D1);
    ok(hr == DDERR_ALREADYINITIALIZED, "IDirect3DViewport_Initialize returned %08x\n", hr);

    hr = IDirect3DDevice_AddViewport(Direct3DDevice1, Viewport);
    ok(hr == D3D_OK, "IDirect3DDevice_AddViewport returned %08x\n", hr);
    vp_data.dwSize = sizeof(vp_data);
    vp_data.dwX = 0;
    vp_data.dwY = 0;
    vp_data.dwWidth = 256;
    vp_data.dwHeight = 256;
    vp_data.dvScaleX = 1;
    vp_data.dvScaleY = 1;
    vp_data.dvMaxX = 256;
    vp_data.dvMaxY = 256;
    vp_data.dvMinZ = 0;
    vp_data.dvMaxZ = 1;
    hr = IDirect3DViewport_SetViewport(Viewport, &vp_data);
    ok(hr == D3D_OK, "IDirect3DViewport_SetViewport returned %08x\n", hr);

    return TRUE;
}

static void D3D1_releaseObjects(void)
{
    if (Viewport) IDirect3DViewport_Release(Viewport);
    if (ExecuteBuffer) IDirect3DExecuteBuffer_Release(ExecuteBuffer);
    if (Direct3DDevice1) IDirect3DDevice_Release(Direct3DDevice1);
    if (Surface1) IDirectDrawSurface_Release(Surface1);
    if (Direct3D1) IDirect3D_Release(Direct3D1);
    if (DirectDraw1) IDirectDraw_Release(DirectDraw1);
}

static void Direct3D1Test(void)
{
    HRESULT hr;
    D3DEXECUTEBUFFERDESC desc;
    D3DVIEWPORT vp_data;
    D3DINSTRUCTION *instr;
    D3DBRANCH *branch;
    unsigned int idx = 0;
    static struct v_in testverts[] = {
        {0.0, 0.0, 0.0},  { 1.0,  1.0,  1.0}, {-1.0, -1.0, -1.0},
        {0.5, 0.5, 0.5},  {-0.5, -0.5, -0.5}, {-0.5, -0.5, 0.0},
    };
    static struct v_in cliptest[] = {
        {25.59, 25.59, 1.0},  {-25.59, -25.59,  0.0},
        {25.61, 25.61, 1.01}, {-25.61, -25.61, -0.01},
    };
    static struct v_in offscreentest[] = {
        {128.1, 0.0, 0.0},
    };
    struct v_out out[sizeof(testverts) / sizeof(testverts[0])];
    D3DHVERTEX outH[sizeof(testverts) / sizeof(testverts[0])];
    D3DTRANSFORMDATA transformdata;
    DWORD i = FALSE;

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    hr = IDirect3DExecuteBuffer_Lock(ExecuteBuffer, &desc);
    ok(hr == D3D_OK, "IDirect3DExecuteBuffer_Lock failed: %08x\n", hr);

    memset(desc.lpData, 0, 128);
    instr = desc.lpData;
    instr[idx].bOpcode = D3DOP_BRANCHFORWARD;
    instr[idx].bSize = sizeof(*branch);
    instr[idx].wCount = 1;
    idx++;
    branch = (D3DBRANCH *) &instr[idx];
    branch->dwMask = 0x0;
    branch->dwValue = 1;
    branch->bNegate = TRUE;
    branch->dwOffset = 0;
    idx += (sizeof(*branch) / sizeof(*instr));
    instr[idx].bOpcode = D3DOP_EXIT;
    instr[idx].bSize = 0;
    instr[idx].wCount = 0;
    hr = IDirect3DExecuteBuffer_Unlock(ExecuteBuffer);
    ok(hr == D3D_OK, "IDirect3DExecuteBuffer_Unlock failed: %08x\n", hr);

    hr = IDirect3DDevice_Execute(Direct3DDevice1, ExecuteBuffer, Viewport, D3DEXECUTE_CLIPPED);
    ok(hr == D3D_OK, "IDirect3DDevice_Execute returned %08x\n", hr);

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);

    hr = IDirect3DExecuteBuffer_Lock(ExecuteBuffer, &desc);
    ok(hr == D3D_OK, "IDirect3DExecuteBuffer_Lock failed: %08x\n", hr);

    memset(desc.lpData, 0, 128);
    instr = desc.lpData;
    idx = 0;
    instr[idx].bOpcode = D3DOP_BRANCHFORWARD;
    instr[idx].bSize = sizeof(*branch);
    instr[idx].wCount = 1;
    idx++;
    branch = (D3DBRANCH *) &instr[idx];
    branch->dwMask = 0x0;
    branch->dwValue = 1;
    branch->bNegate = TRUE;
    branch->dwOffset = 64;
    instr = (D3DINSTRUCTION*)((char*)desc.lpData + 64);
    instr[0].bOpcode = D3DOP_EXIT;
    instr[0].bSize = 0;
    instr[0].wCount = 0;
    hr = IDirect3DExecuteBuffer_Unlock(ExecuteBuffer);
    ok(hr == D3D_OK, "IDirect3DExecuteBuffer_Unlock failed: %08x\n", hr);

    hr = IDirect3DDevice_Execute(Direct3DDevice1, ExecuteBuffer, Viewport, D3DEXECUTE_CLIPPED);
    ok(hr == D3D_OK, "IDirect3DDevice_Execute returned %08x\n", hr);

    /* Test rendering 0 triangles */
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);

    hr = IDirect3DExecuteBuffer_Lock(ExecuteBuffer, &desc);
    ok(hr == D3D_OK, "IDirect3DExecuteBuffer_Lock failed: %08x\n", hr);

    memset(desc.lpData, 0, 128);
    instr = desc.lpData;
    idx = 0;

    instr->bOpcode = D3DOP_TRIANGLE;
    instr->bSize = sizeof(D3DOP_TRIANGLE);
    instr->wCount = 0;
    instr = ((D3DINSTRUCTION*)(instr))+1;
    instr->bOpcode = D3DOP_EXIT;
    instr->bSize = 0;
    instr->wCount = 0;
    hr = IDirect3DExecuteBuffer_Unlock(ExecuteBuffer);
    ok(hr == D3D_OK, "IDirect3DExecuteBuffer_Unlock failed: %08x\n", hr);

    hr = IDirect3DDevice_Execute(Direct3DDevice1, ExecuteBuffer, Viewport, D3DEXECUTE_CLIPPED);
    ok(hr == D3D_OK, "IDirect3DDevice_Execute returned %08x\n", hr);

    memset(&transformdata, 0, sizeof(transformdata));
    transformdata.dwSize = sizeof(transformdata);
    transformdata.lpIn = (void *) testverts;
    transformdata.dwInSize = sizeof(testverts[0]);
    transformdata.lpOut = out;
    transformdata.dwOutSize = sizeof(out[0]);

    transformdata.lpHOut = NULL;
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(testverts) / sizeof(testverts[0]),
                                             &transformdata, D3DTRANSFORM_UNCLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);

    transformdata.lpHOut = outH;
    memset(outH, 0xcc, sizeof(outH));
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(testverts) / sizeof(testverts[0]),
                                             &transformdata, D3DTRANSFORM_UNCLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);

    for(i = 0; i < sizeof(testverts) / sizeof(testverts[0]); i++) {
        static const struct v_out cmp[] = {
            {128.0, 128.0, 0.0, 1}, {129.0, 127.0,  1.0, 1}, {127.0, 129.0, -1, 1},
            {128.5, 127.5, 0.5, 1}, {127.5, 128.5, -0.5, 1}, {127.5, 128.5,  0, 1}
        };

        ok(cmp[i].x == out[i].x && cmp[i].y == out[i].y &&
           cmp[i].z == out[i].z && cmp[i].rhw == out[i].rhw,
           "Vertex %d differs. Got %f %f %f %f, expexted %f %f %f %f\n", i + 1,
           out[i].x, out[i].y, out[i].z, out[i].rhw,
           cmp[i].x, cmp[i].y, cmp[i].z, cmp[i].rhw);
    }
    for(i = 0; i < sizeof(outH); i++) {
        if(((unsigned char *) outH)[i] != 0xcc) {
            ok(FALSE, "Homogeneous output was generated despite UNCLIPPED flag\n");
            break;
        }
    }

    vp_data.dwSize = sizeof(vp_data);
    vp_data.dwX = 0;
    vp_data.dwY = 0;
    vp_data.dwWidth = 256;
    vp_data.dwHeight = 256;
    vp_data.dvMaxX = 256;
    vp_data.dvMaxY = 256;
    vp_data.dvScaleX = 5;
    vp_data.dvScaleY = 5;
    vp_data.dvMinZ = -25;
    vp_data.dvMaxZ = 60;
    hr = IDirect3DViewport_SetViewport(Viewport, &vp_data);
    ok(hr == D3D_OK, "IDirect3DViewport_SetViewport returned %08x\n", hr);
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(testverts) / sizeof(testverts[0]),
                                             &transformdata, D3DTRANSFORM_UNCLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);

    for(i = 0; i < sizeof(testverts) / sizeof(testverts[0]); i++) {
        static const struct v_out cmp[] = {
            {128.0, 128.0, 0.0, 1}, {133.0, 123.0,  1.0, 1}, {123.0, 133.0, -1, 1},
            {130.5, 125.5, 0.5, 1}, {125.5, 130.5, -0.5, 1}, {125.5, 130.5,  0, 1}
        };
        ok(cmp[i].x == out[i].x && cmp[i].y == out[i].y &&
           cmp[i].z == out[i].z && cmp[i].rhw == out[i].rhw,
           "Vertex %d differs. Got %f %f %f %f, expexted %f %f %f %f\n", i + 1,
           out[i].x, out[i].y, out[i].z, out[i].rhw,
           cmp[i].x, cmp[i].y, cmp[i].z, cmp[i].rhw);
    }

    vp_data.dwX = 10;
    vp_data.dwY = 20;
    hr = IDirect3DViewport_SetViewport(Viewport, &vp_data);
    ok(hr == D3D_OK, "IDirect3DViewport_SetViewport returned %08x\n", hr);
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(testverts) / sizeof(testverts[0]),
                                             &transformdata, D3DTRANSFORM_UNCLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);
    for(i = 0; i < sizeof(testverts) / sizeof(testverts[0]); i++) {
        static const struct v_out cmp[] = {
            {138.0, 148.0, 0.0, 1}, {143.0, 143.0,  1.0, 1}, {133.0, 153.0, -1, 1},
            {140.5, 145.5, 0.5, 1}, {135.5, 150.5, -0.5, 1}, {135.5, 150.5,  0, 1}
        };
        ok(cmp[i].x == out[i].x && cmp[i].y == out[i].y &&
           cmp[i].z == out[i].z && cmp[i].rhw == out[i].rhw,
           "Vertex %d differs. Got %f %f %f %f, expexted %f %f %f %f\n", i + 1,
           out[i].x, out[i].y, out[i].z, out[i].rhw,
           cmp[i].x, cmp[i].y, cmp[i].z, cmp[i].rhw);
    }

    memset(out, 0xcc, sizeof(out));
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(testverts) / sizeof(testverts[0]),
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);
    for(i = 0; i < sizeof(testverts) / sizeof(testverts[0]); i++) {
        static const D3DHVERTEX cmpH[] = {
            {0,             { 0.0}, { 0.0}, { 0.0}}, {0, { 1.0}, { 1.0}, {1.0}},
            {D3DCLIP_FRONT, {-1.0}, {-1.0}, {-1.0}}, {0, { 0.5}, { 0.5}, {0.5}},
            {D3DCLIP_FRONT, {-0.5}, {-0.5}, {-0.5}}, {0, {-0.5}, {-0.5}, {0.0}}
        };
        ok(U1(cmpH[i]).hx == U1(outH[i]).hx && U2(cmpH[i]).hy == U2(outH[i]).hy &&
           U3(cmpH[i]).hz == U3(outH[i]).hz && cmpH[i].dwFlags == outH[i].dwFlags,
           "HVertex %d differs. Got %08x %f %f %f, expexted %08x %f %f %f\n", i + 1,
           outH[i].dwFlags, U1(outH[i]).hx, U2(outH[i]).hy, U3(outH[i]).hz,
           cmpH[i].dwFlags, U1(cmpH[i]).hx, U2(cmpH[i]).hy, U3(cmpH[i]).hz);

        /* No scheme has been found behind those return values. It seems to be
         * whatever data windows has when throwing the vertex away. Modify the
         * input test vertices to test this more. Depending on the input data
         * it can happen that the z coord gets written into y, or similar things
         */
        if(0)
        {
            static const struct v_out cmp[] = {
                {138.0, 148.0, 0.0, 1}, {143.0, 143.0,  1.0, 1}, { -1.0,  -1.0, 0.5, 1},
                {140.5, 145.5, 0.5, 1}, { -0.5,  -0.5, -0.5, 1}, {135.5, 150.5, 0.0, 1}
            };
            ok(cmp[i].x == out[i].x && cmp[i].y == out[i].y &&
               cmp[i].z == out[i].z && cmp[i].rhw == out[i].rhw,
                "Vertex %d differs. Got %f %f %f %f, expexted %f %f %f %f\n", i + 1,
               out[i].x, out[i].y, out[i].z, out[i].rhw,
               cmp[i].x, cmp[i].y, cmp[i].z, cmp[i].rhw);
        }
    }
    for(i = 0; i < sizeof(out) / sizeof(DWORD); i++) {
        ok(((DWORD *) out)[i] != 0xcccccccc,
                "Regular output DWORD %d remained untouched\n", i);
    }

    transformdata.lpIn = (void *) cliptest;
    transformdata.dwInSize = sizeof(cliptest[0]);
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(cliptest) / sizeof(cliptest[0]),
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);
    for(i = 0; i < sizeof(cliptest) / sizeof(cliptest[0]); i++) {
        DWORD Flags[sizeof(cliptest) / sizeof(cliptest[0])] =
        {
            0,
            0,
            D3DCLIP_RIGHT | D3DCLIP_BACK   | D3DCLIP_TOP,
            D3DCLIP_LEFT  | D3DCLIP_BOTTOM | D3DCLIP_FRONT,
        };
        ok(Flags[i] == outH[i].dwFlags,
           "Cliptest %d differs. Got %08x expexted %08x\n", i + 1,
           outH[i].dwFlags, Flags[i]);
    }

    vp_data.dwWidth = 10;
    vp_data.dwHeight = 1000;
    hr = IDirect3DViewport_SetViewport(Viewport, &vp_data);
    i = 10;
    ok(hr == D3D_OK, "IDirect3DViewport_SetViewport returned %08x\n", hr);
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(cliptest) / sizeof(cliptest[0]),
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);
    for(i = 0; i < sizeof(cliptest) / sizeof(cliptest[0]); i++) {
        DWORD Flags[sizeof(cliptest) / sizeof(cliptest[0])] =
        {
            D3DCLIP_RIGHT,
            D3DCLIP_LEFT,
            D3DCLIP_RIGHT | D3DCLIP_BACK,
            D3DCLIP_LEFT  | D3DCLIP_FRONT,
        };
        ok(Flags[i] == outH[i].dwFlags,
           "Cliptest %d differs. Got %08x expexted %08x\n", i + 1,
           outH[i].dwFlags, Flags[i]);
    }
    vp_data.dwWidth = 256;
    vp_data.dwHeight = 256;
    vp_data.dvScaleX = 1;
    vp_data.dvScaleY = 1;
    hr = IDirect3DViewport_SetViewport(Viewport, &vp_data);
    ok(hr == D3D_OK, "IDirect3DViewport_SetViewport returned %08x\n", hr);
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(cliptest) / sizeof(cliptest[0]),
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %s\n", i ? "TRUE" : "FALSE");
    for(i = 0; i < sizeof(cliptest) / sizeof(cliptest[0]); i++) {
        DWORD Flags[sizeof(cliptest) / sizeof(cliptest[0])] =
        {
            0,
            0,
            D3DCLIP_BACK,
            D3DCLIP_FRONT,
        };
        ok(Flags[i] == outH[i].dwFlags,
           "Cliptest %d differs. Got %08x expexted %08x\n", i + 1,
           outH[i].dwFlags, Flags[i]);
    }

    /* Finally try to figure out how the DWORD dwOffscreen works.
     * Apparently no vertex is offscreen with clipping off,
     * and with clipping on the offscreen flag is set if only one vertex
     * is transformed, and this vertex is offscreen.
     */
    vp_data.dwWidth = 5;
    vp_data.dwHeight = 5;
    vp_data.dvScaleX = 10000;
    vp_data.dvScaleY = 10000;
    hr = IDirect3DViewport_SetViewport(Viewport, &vp_data);
    ok(hr == D3D_OK, "IDirect3DViewport_SetViewport returned %08x\n", hr);
    transformdata.lpIn = cliptest;
    hr = IDirect3DViewport_TransformVertices(Viewport, 1,
                                             &transformdata, D3DTRANSFORM_UNCLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);
    hr = IDirect3DViewport_TransformVertices(Viewport, 1,
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == (D3DCLIP_RIGHT | D3DCLIP_TOP), "Offscreen is %d\n", i);
    hr = IDirect3DViewport_TransformVertices(Viewport, 2,
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);
    transformdata.lpIn = cliptest + 1;
    hr = IDirect3DViewport_TransformVertices(Viewport, 1,
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == (D3DCLIP_BOTTOM | D3DCLIP_LEFT), "Offscreen is %d\n", i);

    transformdata.lpIn = (void *) offscreentest;
    transformdata.dwInSize = sizeof(offscreentest[0]);
    vp_data.dwWidth = 257;
    vp_data.dwHeight = 257;
    vp_data.dvScaleX = 1;
    vp_data.dvScaleY = 1;
    hr = IDirect3DViewport_SetViewport(Viewport, &vp_data);
    i = 12345;
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(offscreentest) / sizeof(offscreentest[0]),
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == 0, "Offscreen is %d\n", i);
    vp_data.dwWidth = 256;
    vp_data.dwHeight = 256;
    hr = IDirect3DViewport_SetViewport(Viewport, &vp_data);
    i = 12345;
    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(offscreentest) / sizeof(offscreentest[0]),
                                             &transformdata, D3DTRANSFORM_CLIPPED,
                                             &i);
    ok(hr == D3D_OK, "IDirect3DViewport_TransformVertices returned %08x\n", hr);
    ok(i == D3DCLIP_RIGHT, "Offscreen is %d\n", i);

    hr = IDirect3DViewport_TransformVertices(Viewport, sizeof(testverts) / sizeof(testverts[0]),
                                             &transformdata, 0,
                                             &i);
    ok(hr == DDERR_INVALIDPARAMS, "IDirect3DViewport_TransformVertices returned %08x\n", hr);

    hr = IDirect3DDevice_DeleteViewport(Direct3DDevice1, Viewport);
    ok(hr == D3D_OK, "IDirect3DDevice_DeleteViewport returned %08x\n", hr);
}

static BOOL colortables_check_equality(PALETTEENTRY table1[256], PALETTEENTRY table2[256])
{
    int i;

    for (i = 0; i < 256; i++) {
       if (table1[i].peRed != table2[i].peRed || table1[i].peGreen != table2[i].peGreen ||
           table1[i].peBlue != table2[i].peBlue) return FALSE;
    }

    return TRUE;
}

/* test palette handling in IDirect3DTexture_Load */
static void TextureLoadTest(void)
{
    IDirectDrawSurface *TexSurface = NULL;
    IDirect3DTexture *Texture = NULL;
    IDirectDrawSurface *TexSurface2 = NULL;
    IDirect3DTexture *Texture2 = NULL;
    IDirectDrawPalette *palette = NULL;
    IDirectDrawPalette *palette2 = NULL;
    IDirectDrawPalette *palette_tmp = NULL;
    PALETTEENTRY table1[256], table2[256], table_tmp[256];
    HRESULT hr;
    DDSURFACEDESC ddsd;
    int i;

    memset (&ddsd, 0, sizeof (ddsd));
    ddsd.dwSize = sizeof (ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PIXELFORMAT;
    ddsd.dwHeight = 128;
    ddsd.dwWidth = 128;
    ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE;
    ddsd.ddpfPixelFormat.dwSize = sizeof(ddsd.ddpfPixelFormat);
    ddsd.ddpfPixelFormat.dwFlags = DDPF_RGB | DDPF_PALETTEINDEXED8;
    U1(ddsd.ddpfPixelFormat).dwRGBBitCount = 8;

    hr = IDirectDraw_CreateSurface(DirectDraw1, &ddsd, &TexSurface, NULL);
    ok(hr==D3D_OK, "CreateSurface returned: %x\n", hr);
    if (FAILED(hr)) {
        skip("IDirectDraw_CreateSurface failed; skipping further tests\n");
        goto cleanup;
    }

    hr = IDirectDrawSurface_QueryInterface(TexSurface, &IID_IDirect3DTexture,
                (void *)&Texture);
    ok(hr==D3D_OK, "IDirectDrawSurface_QueryInterface returned: %x\n", hr);
    if (FAILED(hr)) {
        skip("Can't get IDirect3DTexture interface; skipping further tests\n");
        goto cleanup;
    }

    hr = IDirectDraw_CreateSurface(DirectDraw1, &ddsd, &TexSurface2, NULL);
    ok(hr==D3D_OK, "CreateSurface returned: %x\n", hr);
    if (FAILED(hr)) {
        skip("IDirectDraw_CreateSurface failed; skipping further tests\n");
        goto cleanup;
    }

    hr = IDirectDrawSurface_QueryInterface(TexSurface2, &IID_IDirect3DTexture,
                (void *)&Texture2);
    ok(hr==D3D_OK, "IDirectDrawSurface_QueryInterface returned: %x\n", hr);
    if (FAILED(hr)) {
        skip("Can't get IDirect3DTexture interface; skipping further tests\n");
        goto cleanup;
    }

    /* test Load when both textures have no palette */
    hr = IDirect3DTexture_Load(Texture2, Texture);
    ok(hr == DD_OK, "IDirect3DTexture_Load returned %08x\n", hr);

    for (i = 0; i < 256; i++) {
        table1[i].peRed = i;
        table1[i].peGreen = i;
        table1[i].peBlue = i;
        table1[i].peFlags = 0;
    }

    hr = IDirectDraw_CreatePalette(DirectDraw1, DDPCAPS_ALLOW256 | DDPCAPS_8BIT, table1, &palette, NULL);
    ok(hr == DD_OK, "CreatePalette returned %08x\n", hr);
    if (FAILED(hr)) {
        skip("IDirectDraw_CreatePalette failed; skipping further tests\n");
        goto cleanup;
    }

    /* test Load when source texture has palette and destination has no palette */
    hr = IDirectDrawSurface_SetPalette(TexSurface, palette);
    ok(hr == DD_OK, "IDirectDrawSurface_SetPalette returned %08x\n", hr);
    hr = IDirect3DTexture_Load(Texture2, Texture);
    ok(hr == DDERR_NOPALETTEATTACHED, "IDirect3DTexture_Load returned %08x\n", hr);

    for (i = 0; i < 256; i++) {
        table2[i].peRed = 255 - i;
        table2[i].peGreen = 255 - i;
        table2[i].peBlue = 255 - i;
        table2[i].peFlags = 0;
    }

    hr = IDirectDraw_CreatePalette(DirectDraw1, DDPCAPS_ALLOW256 | DDPCAPS_8BIT, table2, &palette2, NULL);
    ok(hr == DD_OK, "CreatePalette returned %08x\n", hr);
    if (FAILED(hr)) {
        skip("IDirectDraw_CreatePalette failed; skipping further tests\n");
        goto cleanup;
    }

    /* test Load when source has no palette and destination has a palette */
    hr = IDirectDrawSurface_SetPalette(TexSurface, NULL);
    ok(hr == DD_OK, "IDirectDrawSurface_SetPalette returned %08x\n", hr);
    hr = IDirectDrawSurface_SetPalette(TexSurface2, palette2);
    ok(hr == DD_OK, "IDirectDrawSurface_SetPalette returned %08x\n", hr);
    hr = IDirect3DTexture_Load(Texture2, Texture);
    ok(hr == DD_OK, "IDirect3DTexture_Load returned %08x\n", hr);
    hr = IDirectDrawSurface_GetPalette(TexSurface2, &palette_tmp);
    ok(hr == DD_OK, "IDirectDrawSurface_GetPalette returned %08x\n", hr);
    if (!palette_tmp) {
        skip("IDirectDrawSurface_GetPalette failed; skipping color table check\n");
        goto cleanup;
    } else {
        hr = IDirectDrawPalette_GetEntries(palette_tmp, 0, 0, 256, table_tmp);
        ok(hr == DD_OK, "IDirectDrawPalette_GetEntries returned %08x\n", hr);
        ok(colortables_check_equality(table2, table_tmp), "Unexpected palettized texture color table\n");
        IDirectDrawPalette_Release(palette_tmp);
    }

    /* test Load when both textures have palettes */
    hr = IDirectDrawSurface_SetPalette(TexSurface, palette);
    ok(hr == DD_OK, "IDirectDrawSurface_SetPalette returned %08x\n", hr);
    hr = IDirect3DTexture_Load(Texture2, Texture);
    ok(hr == DD_OK, "IDirect3DTexture_Load returned %08x\n", hr);
    hr = IDirect3DTexture_Load(Texture2, Texture);
    ok(hr == DD_OK, "IDirect3DTexture_Load returned %08x\n", hr);
    hr = IDirectDrawSurface_GetPalette(TexSurface2, &palette_tmp);
    ok(hr == DD_OK, "IDirectDrawSurface_GetPalette returned %08x\n", hr);
    if (!palette_tmp) {
        skip("IDirectDrawSurface_GetPalette failed; skipping color table check\n");
        goto cleanup;
    } else {
        hr = IDirectDrawPalette_GetEntries(palette_tmp, 0, 0, 256, table_tmp);
        ok(hr == DD_OK, "IDirectDrawPalette_GetEntries returned %08x\n", hr);
        ok(colortables_check_equality(table1, table_tmp), "Unexpected palettized texture color table\n");
        IDirectDrawPalette_Release(palette_tmp);
    }

    cleanup:

    if (palette) IDirectDrawPalette_Release(palette);
    if (palette2) IDirectDrawPalette_Release(palette2);
    if (TexSurface) IDirectDrawSurface_Release(TexSurface);
    if (Texture) IDirect3DTexture_Release(Texture);
    if (TexSurface2) IDirectDrawSurface_Release(TexSurface2);
    if (Texture2) IDirect3DTexture_Release(Texture2);
}

static void VertexBufferDescTest(void)
{
    HRESULT rc;
    D3DVERTEXBUFFERDESC desc;
    union mem_t
    {
        D3DVERTEXBUFFERDESC desc2;
        unsigned char buffer[512];
    } mem;

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(desc);
    desc.dwCaps = 0;
    desc.dwFVF = D3DFVF_XYZ;
    desc.dwNumVertices = 1;
    rc = IDirect3D7_CreateVertexBuffer(lpD3D, &desc, &lpVBufSrc, 0);
    ok(rc==D3D_OK || rc==E_OUTOFMEMORY, "CreateVertexBuffer returned: %x\n", rc);
    if (!lpVBufSrc)
    {
        trace("IDirect3D7::CreateVertexBuffer() failed with an error %x\n", rc);
        goto out;
    }

    memset(mem.buffer, 0x12, sizeof(mem.buffer));
    mem.desc2.dwSize = sizeof(D3DVERTEXBUFFERDESC)*2;
    rc = IDirect3DVertexBuffer7_GetVertexBufferDesc(lpVBufSrc, &mem.desc2);
    if(rc != D3D_OK)
        skip("GetVertexBuffer Failed!\n");
    ok( mem.desc2.dwSize == sizeof(D3DVERTEXBUFFERDESC)*2, "Size returned from GetVertexBufferDesc does not match the value put in\n" );
    ok( mem.buffer[sizeof(D3DVERTEXBUFFERDESC)] == 0x12, "GetVertexBufferDesc cleared outside of the struct! (dwSize was double the size of the struct)\n");
    ok( mem.desc2.dwCaps == desc.dwCaps, "dwCaps returned differs. Got %x, expected %x\n", mem.desc2.dwCaps, desc.dwCaps);
    ok( mem.desc2.dwFVF == desc.dwFVF, "dwFVF returned differs. Got %x, expected %x\n", mem.desc2.dwFVF, desc.dwFVF);
    ok (mem.desc2.dwNumVertices == desc.dwNumVertices, "dwNumVertices returned differs. Got %x, expected %x\n", mem.desc2.dwNumVertices, desc.dwNumVertices);

    memset(mem.buffer, 0x12, sizeof(mem.buffer));
    mem.desc2.dwSize = 0;
    rc = IDirect3DVertexBuffer7_GetVertexBufferDesc(lpVBufSrc, &mem.desc2);
    if(rc != D3D_OK)
        skip("GetVertexBuffer Failed!\n");
    ok( mem.desc2.dwSize == 0, "Size returned from GetVertexBufferDesc does not match the value put in\n" );
    ok( mem.buffer[sizeof(D3DVERTEXBUFFERDESC)] == 0x12, "GetVertexBufferDesc cleared outside of the struct! (dwSize was 0)\n");
    ok( mem.desc2.dwCaps == desc.dwCaps, "dwCaps returned differs. Got %x, expected %x\n", mem.desc2.dwCaps, desc.dwCaps);
    ok( mem.desc2.dwFVF == desc.dwFVF, "dwFVF returned differs. Got %x, expected %x\n", mem.desc2.dwFVF, desc.dwFVF);
    ok (mem.desc2.dwNumVertices == desc.dwNumVertices, "dwNumVertices returned differs. Got %x, expected %x\n", mem.desc2.dwNumVertices, desc.dwNumVertices);

    memset(mem.buffer, 0x12, sizeof(mem.buffer));
    mem.desc2.dwSize = sizeof(D3DVERTEXBUFFERDESC);
    rc = IDirect3DVertexBuffer7_GetVertexBufferDesc(lpVBufSrc, &mem.desc2);
    if(rc != D3D_OK)
        skip("GetVertexBuffer Failed!\n");
    ok( mem.desc2.dwSize == sizeof(D3DVERTEXBUFFERDESC), "Size returned from GetVertexBufferDesc does not match the value put in\n" );
    ok( mem.buffer[sizeof(D3DVERTEXBUFFERDESC)] == 0x12, "GetVertexBufferDesc cleared outside of the struct! (dwSize was the size of the struct)\n");
    ok( mem.desc2.dwCaps == desc.dwCaps, "dwCaps returned differs. Got %x, expected %x\n", mem.desc2.dwCaps, desc.dwCaps);
    ok( mem.desc2.dwFVF == desc.dwFVF, "dwFVF returned differs. Got %x, expected %x\n", mem.desc2.dwFVF, desc.dwFVF);
    ok (mem.desc2.dwNumVertices == desc.dwNumVertices, "dwNumVertices returned differs. Got %x, expected %x\n", mem.desc2.dwNumVertices, desc.dwNumVertices);

out:
    IDirect3DVertexBuffer7_Release(lpVBufSrc);
}

static void D3D7_OldRenderStateTest(void)
{
    HRESULT rc;
    DWORD val;

    /* Test reaction to some deprecated states in D3D7.

     * IDirect3DDevice7 in Wine currently relays such states to wined3d where they are do-nothing and return 0, instead
     * of INVALIDPARAMS. Unless an app is found which cares this is probably ok. What this test shows is that these states
     * need not to be handled in D3D7.
     */
    todo_wine {
        rc = IDirect3DDevice7_SetRenderState(lpD3DDevice, D3DRENDERSTATE_TEXTUREHANDLE, 0);
        ok(rc == DDERR_INVALIDPARAMS, "IDirect3DDevice7_SetRenderState returned %08x\n", rc);

        rc = IDirect3DDevice7_GetRenderState(lpD3DDevice, D3DRENDERSTATE_TEXTUREHANDLE, &val);
        ok(rc == DDERR_INVALIDPARAMS, "IDirect3DDevice7_GetRenderState returned %08x\n", rc);

        rc = IDirect3DDevice7_SetRenderState(lpD3DDevice, D3DRENDERSTATE_TEXTUREMAPBLEND, D3DTBLEND_MODULATE);
        ok(rc == DDERR_INVALIDPARAMS, "IDirect3DDevice7_SetRenderState returned %08x\n", rc);

        rc = IDirect3DDevice7_GetRenderState(lpD3DDevice, D3DRENDERSTATE_TEXTUREMAPBLEND, &val);
        ok(rc == DDERR_INVALIDPARAMS, "IDirect3DDevice7_GetRenderState returned %08x\n", rc);
    }
}

#define IS_VALUE_NEAR(a, b)    ( ((a) == (b)) || ((a) == (b) - 1) || ((a) == (b) + 1) )
#define MIN(a, b)    ((a) < (b) ? (a) : (b))

static void DeviceLoadTest()
{
    DDSURFACEDESC2 ddsd;
    IDirectDrawSurface7 *texture_levels[2][8];
    IDirectDrawSurface7 *cube_face_levels[2][6][8];
    DWORD flags;
    HRESULT hr;
    DDBLTFX ddbltfx;
    RECT loadrect;
    POINT loadpoint;
    int i, i1, i2;
    unsigned diff_count = 0, diff_count2 = 0;
    unsigned x, y;
    BOOL load_mip_subset_broken = FALSE;
    IDirectDrawPalette *palettes[5];
    PALETTEENTRY table1[256];
    DDCOLORKEY ddckey;

    /* Test loading of texture subrectangle with a mipmap surface. */
    memset(texture_levels, 0, sizeof(texture_levels));
    memset(cube_face_levels, 0, sizeof(cube_face_levels));
    memset(palettes, 0, sizeof(palettes));

    for (i = 0; i < 2; i++)
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
        ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
        ddsd.dwWidth = 128;
        ddsd.dwHeight = 128;
        U4(ddsd).ddpfPixelFormat.dwSize = sizeof(U4(ddsd).ddpfPixelFormat);
        U4(ddsd).ddpfPixelFormat.dwFlags = DDPF_RGB;
        U1(U4(ddsd).ddpfPixelFormat).dwRGBBitCount = 32;
        U2(U4(ddsd).ddpfPixelFormat).dwRBitMask = 0x00FF0000;
        U3(U4(ddsd).ddpfPixelFormat).dwGBitMask = 0x0000FF00;
        U4(U4(ddsd).ddpfPixelFormat).dwBBitMask = 0x000000FF;
        hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &texture_levels[i][0], NULL);
        ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        /* Check the number of created mipmaps */
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        hr = IDirectDrawSurface7_GetSurfaceDesc(texture_levels[i][0], &ddsd);
        ok(hr==DD_OK,"IDirectDrawSurface7_GetSurfaceDesc returned: %x\n",hr);
        ok(U2(ddsd).dwMipMapCount == 8, "unexpected mip count %u\n", U2(ddsd).dwMipMapCount);
        if (U2(ddsd).dwMipMapCount != 8) goto out;

        for (i1 = 1; i1 < 8; i1++)
        {
            hr = IDirectDrawSurface7_GetAttachedSurface(texture_levels[i][i1 - 1], &ddsd.ddsCaps, &texture_levels[i][i1]);
            ok(hr == DD_OK, "GetAttachedSurface returned %08x\n", hr);
            if (FAILED(hr)) goto out;
        }
    }

    for (i1 = 0; i1 < 8; i1++)
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        hr = IDirectDrawSurface7_Lock(texture_levels[0][i1], NULL, &ddsd, DDLOCK_WAIT, NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        for (y = 0 ; y < ddsd.dwHeight; y++)
        {
            DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

            for (x = 0; x < ddsd.dwWidth;  x++)
            {
                /* x stored in green component, y in blue. */
                DWORD color = 0xff0000 | (x << 8)  | y;
                *textureRow++ = color;
            }
        }

        hr = IDirectDrawSurface7_Unlock(texture_levels[0][i1], NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);
    }

    for (i1 = 0; i1 < 8; i1++)
    {
        memset(&ddbltfx, 0, sizeof(ddbltfx));
        ddbltfx.dwSize = sizeof(ddbltfx);
        U5(ddbltfx).dwFillColor = 0;
        hr = IDirectDrawSurface7_Blt(texture_levels[1][i1], NULL, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, &ddbltfx);
        ok(hr == DD_OK, "IDirectDrawSurface7_Blt failed with %08x\n", hr);
    }

    /* First test some broken coordinates. */
    loadpoint.x = loadpoint.y = 0;
    loadrect.left = 0;
    loadrect.top = 0;
    loadrect.right = 0;
    loadrect.bottom = 0;
    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], &loadpoint, texture_levels[0][0], &loadrect, 0);
    ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    loadpoint.x = loadpoint.y = 50;
    loadrect.left = 0;
    loadrect.top = 0;
    loadrect.right = 100;
    loadrect.bottom = 100;
    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], &loadpoint, texture_levels[0][0], &loadrect, 0);
    ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    /* Test actual loading. */
    loadpoint.x = loadpoint.y = 31;
    loadrect.left = 30;
    loadrect.top = 20;
    loadrect.right = 93;
    loadrect.bottom = 52;

    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], &loadpoint, texture_levels[0][0], &loadrect, 0);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    for (i1 = 0; i1 < 8; i1++)
    {
        diff_count = 0;
        diff_count2 = 0;

        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        hr = IDirectDrawSurface7_Lock(texture_levels[1][i1], NULL, &ddsd, DDLOCK_WAIT, NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        for (y = 0 ; y < ddsd.dwHeight; y++)
        {
            DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

            for (x = 0; x < ddsd.dwWidth;  x++)
            {
                DWORD color = *textureRow++;

                if (x < loadpoint.x || x >= loadpoint.x + loadrect.right - loadrect.left ||
                    y < loadpoint.y || y >= loadpoint.y + loadrect.bottom - loadrect.top)
                {
                    if (color & 0xffffff) diff_count++;
                }
                else
                {
                    DWORD r = (color & 0xff0000) >> 16;
                    DWORD g = (color & 0xff00) >> 8;
                    DWORD b = (color & 0xff);

                    if (r != 0xff || g != x + loadrect.left - loadpoint.x || b != y + loadrect.top - loadpoint.y) diff_count++;
                }

                /* This codepath is for software RGB device. It has what looks like some weird off by one errors, but may
                   technically be correct as it's not precisely defined by docs. */
                if (x < loadpoint.x || x >= loadpoint.x + loadrect.right - loadrect.left ||
                    y < loadpoint.y || y >= loadpoint.y + loadrect.bottom - loadrect.top + 1)
                {
                    if (color & 0xffffff) diff_count2++;
                }
                else
                {
                    DWORD r = (color & 0xff0000) >> 16;
                    DWORD g = (color & 0xff00) >> 8;
                    DWORD b = (color & 0xff);

                    if (r != 0xff || !IS_VALUE_NEAR(g, x + loadrect.left - loadpoint.x) ||
                        !IS_VALUE_NEAR(b, y + loadrect.top - loadpoint.y)) diff_count2++;
                }
            }
        }

        hr = IDirectDrawSurface7_Unlock(texture_levels[1][i1], NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);

        ok(diff_count == 0 || diff_count2 == 0, "Unexpected destination texture level pixels; %u differences at %d level\n",
                MIN(diff_count, diff_count2), i1);

        loadpoint.x /= 2;
        loadpoint.y /= 2;
        loadrect.top /= 2;
        loadrect.left /= 2;
        loadrect.right = (loadrect.right + 1) / 2;
        loadrect.bottom = (loadrect.bottom + 1) / 2;
    }

    /* This crashes on native (tested on real windows XP / directx9 / nvidia and
     * qemu Win98 / directx7 / RGB software rasterizer):
     * passing non toplevel surfaces (sublevels) to Load (DX7 docs tell not to do this)
    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][1], NULL, texture_levels[0][1], NULL, 0);
    */

    /* Freed in reverse order as native seems to dislike and crash on freeing top level surface first. */
    for (i = 0; i < 2; i++)
    {
        for (i1 = 7; i1 >= 0; i1--)
        {
            if (texture_levels[i][i1]) IDirectDrawSurface7_Release(texture_levels[i][i1]);
        }
    }
    memset(texture_levels, 0, sizeof(texture_levels));

    /* Test texture size mismatch. */
    for (i = 0; i < 2; i++)
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
        ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE;
        ddsd.dwWidth = i ? 256 : 128;
        ddsd.dwHeight = 128;
        hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &texture_levels[i][0], NULL);
        ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
        if (FAILED(hr)) goto out;
    }

    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], NULL, texture_levels[0][0], NULL, 0);
    ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[0][0], NULL, texture_levels[1][0], NULL, 0);
    ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    IDirectDrawSurface7_Release(texture_levels[0][0]);
    IDirectDrawSurface7_Release(texture_levels[1][0]);
    memset(texture_levels, 0, sizeof(texture_levels));

    /* Test loading mipmapped cubemap texture subrectangle from another similar texture. */
    for (i = 0; i < 2; i++)
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
        ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
        ddsd.ddsCaps.dwCaps2 = DDSCAPS2_CUBEMAP | DDSCAPS2_CUBEMAP_ALLFACES;
        ddsd.dwWidth = 128;
        ddsd.dwHeight = 128;
        U4(ddsd).ddpfPixelFormat.dwSize = sizeof(U4(ddsd).ddpfPixelFormat);
        U4(ddsd).ddpfPixelFormat.dwFlags = DDPF_RGB;
        U1(U4(ddsd).ddpfPixelFormat).dwRGBBitCount = 32;
        U2(U4(ddsd).ddpfPixelFormat).dwRBitMask = 0x00FF0000;
        U3(U4(ddsd).ddpfPixelFormat).dwGBitMask = 0x0000FF00;
        U4(U4(ddsd).ddpfPixelFormat).dwBBitMask = 0x000000FF;
        hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &cube_face_levels[i][0][0], NULL);
        ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        flags = DDSCAPS2_CUBEMAP_NEGATIVEX;
        for (i1 = 1; i1 < 6; i1++, flags <<= 1)
        {
            ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE;
            ddsd.ddsCaps.dwCaps2 = DDSCAPS2_CUBEMAP | flags;
            hr = IDirectDrawSurface7_GetAttachedSurface(cube_face_levels[i][0][0], &ddsd.ddsCaps, &cube_face_levels[i][i1][0]);
            ok(hr == DD_OK, "GetAttachedSurface returned %08x\n", hr);
            if (FAILED(hr)) goto out;
        }

        for (i1 = 0; i1 < 6; i1++)
        {
            /* Check the number of created mipmaps */
            memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
            ddsd.dwSize = sizeof(ddsd);
            hr = IDirectDrawSurface7_GetSurfaceDesc(cube_face_levels[i][i1][0], &ddsd);
            ok(hr==DD_OK,"IDirectDrawSurface7_GetSurfaceDesc returned: %x\n",hr);
            ok(U2(ddsd).dwMipMapCount == 8, "unexpected mip count %u\n", U2(ddsd).dwMipMapCount);
            if (U2(ddsd).dwMipMapCount != 8) goto out;

            for (i2 = 1; i2 < 8; i2++)
            {
                ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_MIPMAP;
                ddsd.ddsCaps.dwCaps2 = DDSCAPS2_MIPMAPSUBLEVEL;
                hr = IDirectDrawSurface7_GetAttachedSurface(cube_face_levels[i][i1][i2 - 1], &ddsd.ddsCaps, &cube_face_levels[i][i1][i2]);
                ok(hr == DD_OK, "GetAttachedSurface returned %08x\n", hr);
                if (FAILED(hr)) goto out;
            }
        }
    }

    for (i = 0; i < 6; i++)
        for (i1 = 0; i1 < 8; i1++)
        {
            memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
            ddsd.dwSize = sizeof(ddsd);
            hr = IDirectDrawSurface7_Lock(cube_face_levels[0][i][i1], NULL, &ddsd, DDLOCK_WAIT, NULL);
            ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
            if (FAILED(hr)) goto out;

            for (y = 0 ; y < ddsd.dwHeight; y++)
            {
                DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

                for (x = 0; x < ddsd.dwWidth;  x++)
                {
                    /* face number in low 4 bits of red, x stored in green component, y in blue. */
                    DWORD color = 0xf00000 | (i << 16) | (x << 8)  | y;
                    *textureRow++ = color;
                }
            }

            hr = IDirectDrawSurface7_Unlock(cube_face_levels[0][i][i1], NULL);
            ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);
        }

    for (i = 0; i < 6; i++)
        for (i1 = 0; i1 < 8; i1++)
        {
            memset(&ddbltfx, 0, sizeof(ddbltfx));
            ddbltfx.dwSize = sizeof(ddbltfx);
            U5(ddbltfx).dwFillColor = 0;
            hr = IDirectDrawSurface7_Blt(cube_face_levels[1][i][i1], NULL, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, &ddbltfx);
            ok(hr == DD_OK, "IDirectDrawSurface7_Blt failed with %08x\n", hr);
        }

    loadpoint.x = loadpoint.y = 10;
    loadrect.left = 30;
    loadrect.top = 20;
    loadrect.right = 93;
    loadrect.bottom = 52;

    hr = IDirect3DDevice7_Load(lpD3DDevice, cube_face_levels[1][0][0], &loadpoint, cube_face_levels[0][0][0], &loadrect,
                                    DDSCAPS2_CUBEMAP_ALLFACES);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    for (i = 0; i < 6; i++)
    {
        loadpoint.x = loadpoint.y = 10;
        loadrect.left = 30;
        loadrect.top = 20;
        loadrect.right = 93;
        loadrect.bottom = 52;

        for (i1 = 0; i1 < 8; i1++)
        {
            diff_count = 0;
            diff_count2 = 0;

            memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
            ddsd.dwSize = sizeof(ddsd);
            hr = IDirectDrawSurface7_Lock(cube_face_levels[1][i][i1], NULL, &ddsd, DDLOCK_WAIT, NULL);
            ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
            if (FAILED(hr)) goto out;

            for (y = 0 ; y < ddsd.dwHeight; y++)
            {
                DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

                for (x = 0; x < ddsd.dwWidth;  x++)
                {
                    DWORD color = *textureRow++;

                    if (x < loadpoint.x || x >= loadpoint.x + loadrect.right - loadrect.left ||
                        y < loadpoint.y || y >= loadpoint.y + loadrect.bottom - loadrect.top)
                    {
                        if (color & 0xffffff) diff_count++;
                    }
                    else
                    {
                        DWORD r = (color & 0xff0000) >> 16;
                        DWORD g = (color & 0xff00) >> 8;
                        DWORD b = (color & 0xff);

                        if (r != (0xf0 | i) || g != x + loadrect.left - loadpoint.x ||
                            b != y + loadrect.top - loadpoint.y) diff_count++;
                    }

                    /* This codepath is for software RGB device. It has what looks like some weird off by one errors, but may
                    technically be correct as it's not precisely defined by docs. */
                    if (x < loadpoint.x || x >= loadpoint.x + loadrect.right - loadrect.left ||
                        y < loadpoint.y || y >= loadpoint.y + loadrect.bottom - loadrect.top + 1)
                    {
                        if (color & 0xffffff) diff_count2++;
                    }
                    else
                    {
                        DWORD r = (color & 0xff0000) >> 16;
                        DWORD g = (color & 0xff00) >> 8;
                        DWORD b = (color & 0xff);

                        if (r != (0xf0 | i) || !IS_VALUE_NEAR(g, x + loadrect.left - loadpoint.x) ||
                            !IS_VALUE_NEAR(b, y + loadrect.top - loadpoint.y)) diff_count2++;
                    }
                }
            }

            hr = IDirectDrawSurface7_Unlock(cube_face_levels[1][i][i1], NULL);
            ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);

            ok(diff_count == 0 || diff_count2 == 0,
                "Unexpected destination texture level pixels; %u differences at face %x level %d\n",
                MIN(diff_count, diff_count2), i, i1);

            loadpoint.x /= 2;
            loadpoint.y /= 2;
            loadrect.top /= 2;
            loadrect.left /= 2;
            loadrect.right = (loadrect.right + 1) / 2;
            loadrect.bottom = (loadrect.bottom + 1) / 2;
        }
    }

    for (i = 0; i < 2; i++)
        for (i1 = 5; i1 >= 0; i1--)
            for (i2 = 7; i2 >= 0; i2--)
            {
                if (cube_face_levels[i][i1][i2]) IDirectDrawSurface7_Release(cube_face_levels[i][i1][i2]);
            }
    memset(cube_face_levels, 0, sizeof(cube_face_levels));

    /* Test cubemap loading from regular texture. */
    memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX;
    ddsd.ddsCaps.dwCaps2 = DDSCAPS2_CUBEMAP | DDSCAPS2_CUBEMAP_ALLFACES;
    ddsd.dwWidth = 128;
    ddsd.dwHeight = 128;
    hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &cube_face_levels[0][0][0], NULL);
    ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
    if (FAILED(hr)) goto out;

    memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE;
    ddsd.dwWidth = 128;
    ddsd.dwHeight = 128;
    hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &texture_levels[0][0], NULL);
    ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
    if (FAILED(hr)) goto out;

    hr = IDirect3DDevice7_Load(lpD3DDevice, cube_face_levels[0][0][0], NULL, texture_levels[0][0], NULL,
                                    DDSCAPS2_CUBEMAP_ALLFACES);
    ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    IDirectDrawSurface7_Release(cube_face_levels[0][0][0]);
    memset(cube_face_levels, 0, sizeof(cube_face_levels));
    IDirectDrawSurface7_Release(texture_levels[0][0]);
    memset(texture_levels, 0, sizeof(texture_levels));

    /* Test cubemap loading from cubemap with different number of faces. */
    memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX;
    ddsd.ddsCaps.dwCaps2 = DDSCAPS2_CUBEMAP | DDSCAPS2_CUBEMAP_POSITIVEX;
    ddsd.dwWidth = 128;
    ddsd.dwHeight = 128;
    hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &cube_face_levels[0][0][0], NULL);
    ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
    if (FAILED(hr)) goto out;

    memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX;
    ddsd.ddsCaps.dwCaps2 = DDSCAPS2_CUBEMAP | DDSCAPS2_CUBEMAP_POSITIVEX | DDSCAPS2_CUBEMAP_POSITIVEY;
    ddsd.dwWidth = 128;
    ddsd.dwHeight = 128;
    hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &cube_face_levels[1][0][0], NULL);
    ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
    if (FAILED(hr)) goto out;

    /* INVALIDPARAMS tests currently would fail because wine doesn't support partial cube faces
        (the above created cubemaps will have all faces. */
    hr = IDirect3DDevice7_Load(lpD3DDevice, cube_face_levels[0][0][0], NULL, cube_face_levels[1][0][0], NULL,
                                    DDSCAPS2_CUBEMAP_ALLFACES);
    todo_wine ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, cube_face_levels[0][0][0], NULL, cube_face_levels[1][0][0], NULL,
                                    DDSCAPS2_CUBEMAP_POSITIVEX | DDSCAPS2_CUBEMAP_POSITIVEY);
    todo_wine ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, cube_face_levels[0][0][0], NULL, cube_face_levels[1][0][0], NULL,
                                    DDSCAPS2_CUBEMAP_POSITIVEX);
    todo_wine ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, cube_face_levels[1][0][0], NULL, cube_face_levels[0][0][0], NULL,
                                    DDSCAPS2_CUBEMAP_ALLFACES);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, cube_face_levels[1][0][0], NULL, cube_face_levels[0][0][0], NULL,
                                    DDSCAPS2_CUBEMAP_POSITIVEX);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, cube_face_levels[1][0][0], NULL, cube_face_levels[0][0][0], NULL,
                                    DDSCAPS2_CUBEMAP_POSITIVEZ);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    IDirectDrawSurface7_Release(cube_face_levels[0][0][0]);
    IDirectDrawSurface7_Release(cube_face_levels[1][0][0]);
    memset(cube_face_levels, 0, sizeof(cube_face_levels));

    /* Test texture loading with different mip level count (larger levels match, smaller levels missing in destination. */
    for (i = 0; i < 2; i++)
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT | DDSD_MIPMAPCOUNT;
        ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
        ddsd.dwWidth = 128;
        ddsd.dwHeight = 128;
        ddsd.dwMipMapCount = i ? 4 : 8;
        U4(ddsd).ddpfPixelFormat.dwSize = sizeof(U4(ddsd).ddpfPixelFormat);
        U4(ddsd).ddpfPixelFormat.dwFlags = DDPF_RGB;
        U1(U4(ddsd).ddpfPixelFormat).dwRGBBitCount = 32;
        U2(U4(ddsd).ddpfPixelFormat).dwRBitMask = 0x00FF0000;
        U3(U4(ddsd).ddpfPixelFormat).dwGBitMask = 0x0000FF00;
        U4(U4(ddsd).ddpfPixelFormat).dwBBitMask = 0x000000FF;
        hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &texture_levels[i][0], NULL);
        ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        /* Check the number of created mipmaps */
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        hr = IDirectDrawSurface7_GetSurfaceDesc(texture_levels[i][0], &ddsd);
        ok(hr==DD_OK,"IDirectDrawSurface7_GetSurfaceDesc returned: %x\n",hr);
        ok(U2(ddsd).dwMipMapCount == (i ? 4 : 8), "unexpected mip count %u\n", U2(ddsd).dwMipMapCount);
        if (U2(ddsd).dwMipMapCount != (i ? 4 : 8)) goto out;

        for (i1 = 1; i1 < (i ? 4 : 8); i1++)
        {
            hr = IDirectDrawSurface7_GetAttachedSurface(texture_levels[i][i1 - 1], &ddsd.ddsCaps, &texture_levels[i][i1]);
            ok(hr == DD_OK, "GetAttachedSurface returned %08x\n", hr);
            if (FAILED(hr)) goto out;
        }
    }

    for (i1 = 0; i1 < 8; i1++)
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        hr = IDirectDrawSurface7_Lock(texture_levels[0][i1], NULL, &ddsd, DDLOCK_WAIT, NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        for (y = 0 ; y < ddsd.dwHeight; y++)
        {
            DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

            for (x = 0; x < ddsd.dwWidth;  x++)
            {
                /* x stored in green component, y in blue. */
                DWORD color = 0xf00000 | (i1 << 16) | (x << 8)  | y;
                *textureRow++ = color;
            }
        }

        hr = IDirectDrawSurface7_Unlock(texture_levels[0][i1], NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);
    }

    for (i1 = 0; i1 < 4; i1++)
    {
        memset(&ddbltfx, 0, sizeof(ddbltfx));
        ddbltfx.dwSize = sizeof(ddbltfx);
        U5(ddbltfx).dwFillColor = 0;
        hr = IDirectDrawSurface7_Blt(texture_levels[1][i1], NULL, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, &ddbltfx);
        ok(hr == DD_OK, "IDirectDrawSurface7_Blt failed with %08x\n", hr);
    }

    loadpoint.x = loadpoint.y = 31;
    loadrect.left = 30;
    loadrect.top = 20;
    loadrect.right = 93;
    loadrect.bottom = 52;

    /* Destination mip levels are a subset of source mip levels. */
    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], &loadpoint, texture_levels[0][0], &loadrect, 0);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    for (i1 = 0; i1 < 4; i1++)
    {
        diff_count = 0;
        diff_count2 = 0;

        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        hr = IDirectDrawSurface7_Lock(texture_levels[1][i1], NULL, &ddsd, DDLOCK_WAIT, NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        for (y = 0 ; y < ddsd.dwHeight; y++)
        {
            DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

            for (x = 0; x < ddsd.dwWidth;  x++)
            {
                DWORD color = *textureRow++;

                if (x < loadpoint.x || x >= loadpoint.x + loadrect.right - loadrect.left ||
                    y < loadpoint.y || y >= loadpoint.y + loadrect.bottom - loadrect.top)
                {
                    if (color & 0xffffff) diff_count++;
                }
                else
                {
                    DWORD r = (color & 0xff0000) >> 16;
                    DWORD g = (color & 0xff00) >> 8;
                    DWORD b = (color & 0xff);

                    if (r != (0xf0 | i1) || g != x + loadrect.left - loadpoint.x ||
                        b != y + loadrect.top - loadpoint.y) diff_count++;
                }

                /* This codepath is for software RGB device. It has what looks like some weird off by one errors, but may
                technically be correct as it's not precisely defined by docs. */
                if (x < loadpoint.x || x >= loadpoint.x + loadrect.right - loadrect.left ||
                    y < loadpoint.y || y >= loadpoint.y + loadrect.bottom - loadrect.top + 1)
                {
                    if (color & 0xffffff) diff_count2++;
                }
                else
                {
                    DWORD r = (color & 0xff0000) >> 16;
                    DWORD g = (color & 0xff00) >> 8;
                    DWORD b = (color & 0xff);

                    if (r != (0xf0 | i1) || !IS_VALUE_NEAR(g, x + loadrect.left - loadpoint.x) ||
                        !IS_VALUE_NEAR(b, y + loadrect.top - loadpoint.y)) diff_count2++;
                }
            }
        }

        hr = IDirectDrawSurface7_Unlock(texture_levels[1][i1], NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);

        ok(diff_count == 0 || diff_count2 == 0, "Unexpected destination texture level pixels; %u differences at %d level\n",
             MIN(diff_count, diff_count2), i1);

        loadpoint.x /= 2;
        loadpoint.y /= 2;
        loadrect.top /= 2;
        loadrect.left /= 2;
        loadrect.right = (loadrect.right + 1) / 2;
        loadrect.bottom = (loadrect.bottom + 1) / 2;
    }

    /* Destination mip levels are a superset of source mip levels (should fail). */
    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[0][0], &loadpoint, texture_levels[1][0], &loadrect, 0);
    ok(hr==DDERR_INVALIDPARAMS, "IDirect3DDevice7_Load returned: %x\n",hr);

    for (i = 0; i < 2; i++)
    {
        for (i1 = 7; i1 >= 0; i1--)
        {
            if (texture_levels[i][i1]) IDirectDrawSurface7_Release(texture_levels[i][i1]);
        }
    }
    memset(texture_levels, 0, sizeof(texture_levels));

    /* Test loading from mipmap texture to a regular texture that matches one sublevel in size. */
    memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
    ddsd.dwWidth = 128;
    ddsd.dwHeight = 128;
    U4(ddsd).ddpfPixelFormat.dwSize = sizeof(U4(ddsd).ddpfPixelFormat);
    U4(ddsd).ddpfPixelFormat.dwFlags = DDPF_RGB;
    U1(U4(ddsd).ddpfPixelFormat).dwRGBBitCount = 32;
    U2(U4(ddsd).ddpfPixelFormat).dwRBitMask = 0x00FF0000;
    U3(U4(ddsd).ddpfPixelFormat).dwGBitMask = 0x0000FF00;
    U4(U4(ddsd).ddpfPixelFormat).dwBBitMask = 0x000000FF;
    hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &texture_levels[0][0], NULL);
    ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
    if (FAILED(hr)) goto out;

    memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE;
    ddsd.dwWidth = 32;
    ddsd.dwHeight = 32;
    U4(ddsd).ddpfPixelFormat.dwSize = sizeof(U4(ddsd).ddpfPixelFormat);
    U4(ddsd).ddpfPixelFormat.dwFlags = DDPF_RGB;
    U1(U4(ddsd).ddpfPixelFormat).dwRGBBitCount = 32;
    U2(U4(ddsd).ddpfPixelFormat).dwRBitMask = 0x00FF0000;
    U3(U4(ddsd).ddpfPixelFormat).dwGBitMask = 0x0000FF00;
    U4(U4(ddsd).ddpfPixelFormat).dwBBitMask = 0x000000FF;
    hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &texture_levels[1][0], NULL);
    ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
    if (FAILED(hr)) goto out;

    for (i1 = 1; i1 < 8; i1++)
    {
        hr = IDirectDrawSurface7_GetAttachedSurface(texture_levels[0][i1 - 1], &ddsd.ddsCaps, &texture_levels[0][i1]);
        ok(hr == DD_OK, "GetAttachedSurface returned %08x\n", hr);
        if (FAILED(hr)) goto out;
    }

    for (i1 = 0; i1 < 8; i1++)
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        hr = IDirectDrawSurface7_Lock(texture_levels[0][i1], NULL, &ddsd, DDLOCK_WAIT, NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        for (y = 0 ; y < ddsd.dwHeight; y++)
        {
            DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

            for (x = 0; x < ddsd.dwWidth;  x++)
            {
                /* x stored in green component, y in blue. */
                DWORD color = 0xf00000 | (i1 << 16) | (x << 8)  | y;
                *textureRow++ = color;
            }
        }

        hr = IDirectDrawSurface7_Unlock(texture_levels[0][i1], NULL);
        ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);
    }

    memset(&ddbltfx, 0, sizeof(ddbltfx));
    ddbltfx.dwSize = sizeof(ddbltfx);
    U5(ddbltfx).dwFillColor = 0;
    hr = IDirectDrawSurface7_Blt(texture_levels[1][0], NULL, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, &ddbltfx);
    ok(hr == DD_OK, "IDirectDrawSurface7_Blt failed with %08x\n", hr);

    loadpoint.x = loadpoint.y = 32;
    loadrect.left = 32;
    loadrect.top = 32;
    loadrect.right = 96;
    loadrect.bottom = 96;

    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], &loadpoint, texture_levels[0][0], &loadrect, 0);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    loadpoint.x /= 4;
    loadpoint.y /= 4;
    loadrect.top /= 4;
    loadrect.left /= 4;
    loadrect.right = (loadrect.right + 3) / 4;
    loadrect.bottom = (loadrect.bottom + 3) / 4;

    /* NOTE: something in either nvidia driver or directx9 on WinXP appears to be broken:
     * this kind of Load calls (to subset with smaller surface(s)) produces wrong results with
     * copied subrectangles divided more than needed, without apparent logic. But it works
     * as expected on qemu / Win98 / directx7 / RGB device. Some things are broken on XP, e.g.
     * some games don't work that worked in Win98, so it is assumed here XP results are wrong.
     * The following code attempts to detect broken results, actual tests will then be skipped
     */
    load_mip_subset_broken = TRUE;
    diff_count = 0;

    memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
    ddsd.dwSize = sizeof(ddsd);
    hr = IDirectDrawSurface7_Lock(texture_levels[1][0], NULL, &ddsd, DDLOCK_WAIT, NULL);
    ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
    if (FAILED(hr)) goto out;

    for (y = 0 ; y < ddsd.dwHeight; y++)
    {
        DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

        for (x = 0; x < ddsd.dwWidth;  x++)
        {
            DWORD color = *textureRow++;

            if (x < 2 || x >= 2 + 4 ||
                y < 2 || y >= 2 + 4)
            {
                if (color & 0xffffff) diff_count++;
            }
            else
            {
                DWORD r = (color & 0xff0000) >> 16;

                if ((r & (0xf0)) != 0xf0) diff_count++;
            }
        }
    }

    if (diff_count) load_mip_subset_broken = FALSE;

    if (load_mip_subset_broken) {
        skip("IDirect3DDevice7_Load is broken (happens on some modern Windows installations like XP). Skipping affected tests.\n");
    } else {
        diff_count = 0;

        for (y = 0 ; y < ddsd.dwHeight; y++)
        {
            DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

            for (x = 0; x < ddsd.dwWidth;  x++)
            {
                DWORD color = *textureRow++;

                if (x < loadpoint.x || x >= loadpoint.x + loadrect.right - loadrect.left ||
                    y < loadpoint.y || y >= loadpoint.y + loadrect.bottom - loadrect.top)
                {
                    if (color & 0xffffff) diff_count++;
                }
                else
                {
                    DWORD r = (color & 0xff0000) >> 16;
                    DWORD g = (color & 0xff00) >> 8;
                    DWORD b = (color & 0xff);

                    if (r != (0xf0 | 2) || g != x + loadrect.left - loadpoint.x ||
                        b != y + loadrect.top - loadpoint.y) diff_count++;
                }
            }
        }
    }

    hr = IDirectDrawSurface7_Unlock(texture_levels[1][0], NULL);
    ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);

    ok(diff_count == 0, "Unexpected destination texture level pixels; %u differences\n", diff_count);

    for (i = 0; i < 2; i++)
    {
        for (i1 = 7; i1 >= 0; i1--)
        {
            if (texture_levels[i][i1]) IDirectDrawSurface7_Release(texture_levels[i][i1]);
        }
    }
    memset(texture_levels, 0, sizeof(texture_levels));

    if (!load_mip_subset_broken)
    {
        /* Test loading when destination mip levels are a subset of source mip levels and start from smaller
        * surface (than first source mip level)
        */
        for (i = 0; i < 2; i++)
        {
            memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
            ddsd.dwSize = sizeof(ddsd);
            ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
            if (i) ddsd.dwFlags |= DDSD_MIPMAPCOUNT;
            ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
            ddsd.dwWidth = i ? 32 : 128;
            ddsd.dwHeight = i ? 32 : 128;
            if (i) ddsd.dwMipMapCount = 4;
            U4(ddsd).ddpfPixelFormat.dwSize = sizeof(U4(ddsd).ddpfPixelFormat);
            U4(ddsd).ddpfPixelFormat.dwFlags = DDPF_RGB;
            U1(U4(ddsd).ddpfPixelFormat).dwRGBBitCount = 32;
            U2(U4(ddsd).ddpfPixelFormat).dwRBitMask = 0x00FF0000;
            U3(U4(ddsd).ddpfPixelFormat).dwGBitMask = 0x0000FF00;
            U4(U4(ddsd).ddpfPixelFormat).dwBBitMask = 0x000000FF;
            hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &texture_levels[i][0], NULL);
            ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
            if (FAILED(hr)) goto out;

            /* Check the number of created mipmaps */
            memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
            ddsd.dwSize = sizeof(ddsd);
            hr = IDirectDrawSurface7_GetSurfaceDesc(texture_levels[i][0], &ddsd);
            ok(hr==DD_OK,"IDirectDrawSurface7_GetSurfaceDesc returned: %x\n",hr);
            ok(U2(ddsd).dwMipMapCount == (i ? 4 : 8), "unexpected mip count %u\n", U2(ddsd).dwMipMapCount);
            if (U2(ddsd).dwMipMapCount != (i ? 4 : 8)) goto out;

            for (i1 = 1; i1 < (i ? 4 : 8); i1++)
            {
                hr = IDirectDrawSurface7_GetAttachedSurface(texture_levels[i][i1 - 1], &ddsd.ddsCaps, &texture_levels[i][i1]);
                ok(hr == DD_OK, "GetAttachedSurface returned %08x\n", hr);
                if (FAILED(hr)) goto out;
            }
        }

        for (i1 = 0; i1 < 8; i1++)
        {
            memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
            ddsd.dwSize = sizeof(ddsd);
            hr = IDirectDrawSurface7_Lock(texture_levels[0][i1], NULL, &ddsd, DDLOCK_WAIT, NULL);
            ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
            if (FAILED(hr)) goto out;

            for (y = 0 ; y < ddsd.dwHeight; y++)
            {
                DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

                for (x = 0; x < ddsd.dwWidth;  x++)
                {
                    /* x stored in green component, y in blue. */
                    DWORD color = 0xf00000 | (i1 << 16) | (x << 8)  | y;
                    *textureRow++ = color;
                }
            }

            hr = IDirectDrawSurface7_Unlock(texture_levels[0][i1], NULL);
            ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);
        }

        for (i1 = 0; i1 < 4; i1++)
        {
            memset(&ddbltfx, 0, sizeof(ddbltfx));
            ddbltfx.dwSize = sizeof(ddbltfx);
            U5(ddbltfx).dwFillColor = 0;
            hr = IDirectDrawSurface7_Blt(texture_levels[1][i1], NULL, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, &ddbltfx);
            ok(hr == DD_OK, "IDirectDrawSurface7_Blt failed with %08x\n", hr);
        }

        loadpoint.x = loadpoint.y = 0;
        loadrect.left = 0;
        loadrect.top = 0;
        loadrect.right = 64;
        loadrect.bottom = 64;

        hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], &loadpoint, texture_levels[0][0], &loadrect, 0);
        ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

        i = 0;
        for (i1 = 0; i1 < 8 && i < 4; i1++)
        {
            DDSURFACEDESC2 ddsd2;

            memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
            ddsd.dwSize = sizeof(ddsd);
            hr = IDirectDrawSurface7_GetSurfaceDesc(texture_levels[0][i1], &ddsd);

            memset(&ddsd2, 0, sizeof(DDSURFACEDESC2));
            ddsd2.dwSize = sizeof(ddsd2);
            hr = IDirectDrawSurface7_GetSurfaceDesc(texture_levels[1][i], &ddsd2);

            if (ddsd.dwWidth == ddsd2.dwWidth && ddsd.dwHeight == ddsd2.dwHeight)
            {
                diff_count = 0;

                memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
                ddsd.dwSize = sizeof(ddsd);
                hr = IDirectDrawSurface7_Lock(texture_levels[1][i], NULL, &ddsd, DDLOCK_WAIT, NULL);
                ok(hr==DD_OK, "IDirectDrawSurface7_Lock returned: %x\n",hr);
                if (FAILED(hr)) goto out;

                for (y = 0 ; y < ddsd.dwHeight; y++)
                {
                    DWORD *textureRow = (DWORD*)((char*)ddsd.lpSurface + y * ddsd.lPitch);

                    for (x = 0; x < ddsd.dwWidth;  x++)
                    {
                        DWORD color = *textureRow++;

                        if (x < loadpoint.x || x >= loadpoint.x + loadrect.right - loadrect.left ||
                            y < loadpoint.y || y >= loadpoint.y + loadrect.bottom - loadrect.top)
                        {
                            if (color & 0xffffff) diff_count++;
                        }
                        else
                        {
                            DWORD r = (color & 0xff0000) >> 16;
                            DWORD g = (color & 0xff00) >> 8;
                            DWORD b = (color & 0xff);

                            if (r != (0xf0 | i1) || g != x + loadrect.left - loadpoint.x ||
                                b != y + loadrect.top - loadpoint.y) diff_count++;
                        }
                    }
                }

                hr = IDirectDrawSurface7_Unlock(texture_levels[1][i], NULL);
                ok(hr==DD_OK, "IDirectDrawSurface7_Unlock returned: %x\n",hr);

                ok(diff_count == 0, "Unexpected destination texture level pixels; %u differences at %d level\n", diff_count, i1);

                i++;
            }

            loadpoint.x /= 2;
            loadpoint.y /= 2;
            loadrect.top /= 2;
            loadrect.left /= 2;
            loadrect.right = (loadrect.right + 1) / 2;
            loadrect.bottom = (loadrect.bottom + 1) / 2;
        }

        for (i = 0; i < 2; i++)
        {
            for (i1 = 7; i1 >= 0; i1--)
            {
                if (texture_levels[i][i1]) IDirectDrawSurface7_Release(texture_levels[i][i1]);
            }
        }
        memset(texture_levels, 0, sizeof(texture_levels));
    }

    /* Test palette copying. */
    for (i = 0; i < 2; i++)
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        ddsd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT | DDSD_PIXELFORMAT;
        ddsd.ddsCaps.dwCaps = DDSCAPS_TEXTURE | DDSCAPS_COMPLEX | DDSCAPS_MIPMAP;
        ddsd.dwWidth = 128;
        ddsd.dwHeight = 128;
        U4(ddsd).ddpfPixelFormat.dwSize = sizeof(U4(ddsd).ddpfPixelFormat);
        U4(ddsd).ddpfPixelFormat.dwFlags = DDPF_RGB | DDPF_PALETTEINDEXED8;
        U1(U4(ddsd).ddpfPixelFormat).dwRGBBitCount = 8;
        hr = IDirectDraw7_CreateSurface(lpDD, &ddsd, &texture_levels[i][0], NULL);
        ok(hr==DD_OK,"CreateSurface returned: %x\n",hr);
        if (FAILED(hr)) goto out;

        /* Check the number of created mipmaps */
        memset(&ddsd, 0, sizeof(DDSURFACEDESC2));
        ddsd.dwSize = sizeof(ddsd);
        hr = IDirectDrawSurface7_GetSurfaceDesc(texture_levels[i][0], &ddsd);
        ok(hr==DD_OK,"IDirectDrawSurface7_GetSurfaceDesc returned: %x\n",hr);
        ok(U2(ddsd).dwMipMapCount == 8, "unexpected mip count %u\n", U2(ddsd).dwMipMapCount);
        if (U2(ddsd).dwMipMapCount != 8) goto out;

        for (i1 = 1; i1 < 8; i1++)
        {
            hr = IDirectDrawSurface7_GetAttachedSurface(texture_levels[i][i1 - 1], &ddsd.ddsCaps, &texture_levels[i][i1]);
            ok(hr == DD_OK, "GetAttachedSurface returned %08x\n", hr);
            if (FAILED(hr)) goto out;
        }
    }

    memset(table1, 0, sizeof(table1));
    for (i = 0; i < 3; i++)
    {
        table1[0].peBlue = i + 1;
        hr = IDirectDraw7_CreatePalette(lpDD, DDPCAPS_ALLOW256 | DDPCAPS_8BIT, table1, &palettes[i], NULL);
        ok(hr == DD_OK, "CreatePalette returned %08x\n", hr);
        if (FAILED(hr))
        {
            skip("IDirectDraw7_CreatePalette failed; skipping further tests\n");
            goto out;
        }
    }

    hr = IDirectDrawSurface7_SetPalette(texture_levels[0][0], palettes[0]);
    ok(hr==DD_OK, "IDirectDrawSurface7_SetPalette returned: %x\n", hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], NULL, texture_levels[0][0], NULL, 0);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    hr = IDirectDrawSurface7_GetPalette(texture_levels[1][0], &palettes[4]);
    ok(hr==DDERR_NOPALETTEATTACHED, "IDirectDrawSurface7_GetPalette returned: %x\n", hr);

    hr = IDirectDrawSurface7_SetPalette(texture_levels[0][1], palettes[1]);
    todo_wine ok(hr==DDERR_NOTONMIPMAPSUBLEVEL, "IDirectDrawSurface7_SetPalette returned: %x\n", hr);
    hr = IDirectDrawSurface7_SetPalette(texture_levels[1][0], palettes[2]);
    ok(hr==DD_OK, "IDirectDrawSurface7_SetPalette returned: %x\n", hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], NULL, texture_levels[0][0], NULL, 0);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    memset(table1, 0, sizeof(table1));
    hr = IDirectDrawSurface7_GetPalette(texture_levels[1][0], &palettes[4]);
    ok(hr==DD_OK, "IDirectDrawSurface7_GetPalette returned: %x\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IDirectDrawPalette_GetEntries(palettes[4], 0, 0, 256, table1);
        ok(hr == DD_OK, "IDirectDrawPalette_GetEntries returned %08x\n", hr);
        ok(table1[0].peBlue == 1, "Unexpected palette color after load: %u\n", (unsigned)table1[0].peBlue);
    }

    /* Test colorkey copying. */
    ddckey.dwColorSpaceLowValue = ddckey.dwColorSpaceHighValue = 64;
    hr = IDirectDrawSurface7_SetColorKey(texture_levels[0][0], DDCKEY_SRCBLT, &ddckey);
    ok(hr==DD_OK, "IDirectDrawSurface7_SetColorKey returned: %x\n", hr);
    hr = IDirectDrawSurface7_SetColorKey(texture_levels[0][1], DDCKEY_SRCBLT, &ddckey);
    todo_wine ok(hr==DDERR_NOTONMIPMAPSUBLEVEL, "IDirectDrawSurface7_SetColorKey returned: %x\n", hr);

    hr = IDirectDrawSurface7_GetColorKey(texture_levels[1][0], DDCKEY_SRCBLT, &ddckey);
    ok(hr==DDERR_NOCOLORKEY, "IDirectDrawSurface7_GetColorKey returned: %x\n", hr);

    hr = IDirect3DDevice7_Load(lpD3DDevice, texture_levels[1][0], NULL, texture_levels[0][0], NULL, 0);
    ok(hr==D3D_OK, "IDirect3DDevice7_Load returned: %x\n",hr);

    hr = IDirectDrawSurface7_GetColorKey(texture_levels[1][0], DDCKEY_SRCBLT, &ddckey);
    ok(hr==DD_OK, "IDirectDrawSurface7_GetColorKey returned: %x\n", hr);
    ok(ddckey.dwColorSpaceLowValue == ddckey.dwColorSpaceHighValue && ddckey.dwColorSpaceLowValue == 64,
        "Unexpected color key values: %u - %u\n", ddckey.dwColorSpaceLowValue, ddckey.dwColorSpaceHighValue);

    out:

    for (i = 0; i < 5; i++)
    {
        if (palettes[i]) IDirectDrawPalette_Release(palettes[i]);
    }

    for (i = 0; i < 2; i++)
    {
        for (i1 = 7; i1 >= 0; i1--)
        {
            if (texture_levels[i][i1]) IDirectDrawSurface7_Release(texture_levels[i][i1]);
        }
    }

    for (i = 0; i < 2; i++)
        for (i1 = 5; i1 >= 0; i1--)
            for (i2 = 7; i2 >= 0; i2--)
            {
                if (cube_face_levels[i][i1][i2]) IDirectDrawSurface7_Release(cube_face_levels[i][i1][i2]);
            }
}

START_TEST(d3d)
{
    init_function_pointers();
    if(!pDirectDrawCreateEx) {
        skip("function DirectDrawCreateEx not available\n");
        return;
    }

    if(!CreateDirect3D()) {
        skip("Skipping d3d7 tests\n");
    } else {
        LightTest();
        ProcessVerticesTest();
        StateTest();
        SceneTest();
        LimitTest();
        D3D7EnumTest();
        CapsTest();
        VertexBufferDescTest();
        D3D7_OldRenderStateTest();
        DeviceLoadTest();
        ReleaseDirect3D();
    }

    if (!D3D1_createObjects()) {
        skip("Skipping d3d1 tests\n");
    } else {
        Direct3D1Test();
        TextureLoadTest();
        D3D1_releaseObjects();
    }
}
