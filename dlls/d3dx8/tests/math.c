/*
 * Copyright 2007 David Adam
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
#include "d3dx8.h"

#include "wine/test.h"

#define admitted_error 0.0001f

#define expect_color(expectedcolor,gotcolor) ok((fabs(expectedcolor.r-gotcolor.r)<admitted_error)&&(fabs(expectedcolor.g-gotcolor.g)<admitted_error)&&(fabs(expectedcolor.b-gotcolor.b)<admitted_error)&&(fabs(expectedcolor.a-gotcolor.a)<admitted_error),"Expected Color= (%f, %f, %f, %f)\n , Got Color= (%f, %f, %f, %f)\n", expectedcolor.r, expectedcolor.g, expectedcolor.b, expectedcolor.a, gotcolor.r, gotcolor.g, gotcolor.b, gotcolor.a);

#define expect_mat(expectedmat,gotmat)\
{ \
    int i,j,equal=1; \
    for (i=0; i<4; i++)\
        {\
         for (j=0; j<4; j++)\
             {\
                 if (fabs(U(expectedmat).m[i][j]-U(gotmat).m[i][j])>admitted_error) \
                 {\
                  equal=0;\
                 }\
             }\
        }\
    ok(equal, "Expected matrix=\n(%f,%f,%f,%f\n %f,%f,%f,%f\n %f,%f,%f,%f\n %f,%f,%f,%f\n)\n\n" \
       "Got matrix=\n(%f,%f,%f,%f\n %f,%f,%f,%f\n %f,%f,%f,%f\n %f,%f,%f,%f)\n", \
       U(expectedmat).m[0][0],U(expectedmat).m[0][1],U(expectedmat).m[0][2],U(expectedmat).m[0][3], \
       U(expectedmat).m[1][0],U(expectedmat).m[1][1],U(expectedmat).m[1][2],U(expectedmat).m[1][3], \
       U(expectedmat).m[2][0],U(expectedmat).m[2][1],U(expectedmat).m[2][2],U(expectedmat).m[2][3], \
       U(expectedmat).m[3][0],U(expectedmat).m[3][1],U(expectedmat).m[3][2],U(expectedmat).m[3][3], \
       U(gotmat).m[0][0],U(gotmat).m[0][1],U(gotmat).m[0][2],U(gotmat).m[0][3], \
       U(gotmat).m[1][0],U(gotmat).m[1][1],U(gotmat).m[1][2],U(gotmat).m[1][3], \
       U(gotmat).m[2][0],U(gotmat).m[2][1],U(gotmat).m[2][2],U(gotmat).m[2][3], \
       U(gotmat).m[3][0],U(gotmat).m[3][1],U(gotmat).m[3][2],U(gotmat).m[3][3]); \
}

#define expect_plane(expectedplane,gotplane) ok((fabs(expectedplane.a-gotplane.a)<admitted_error)&&(fabs(expectedplane.b-gotplane.b)<admitted_error)&&(fabs(expectedplane.c-gotplane.c)<admitted_error)&&(fabs(expectedplane.d-gotplane.d)<admitted_error),"Expected Plane= (%f, %f, %f, %f)\n , Got Plane= (%f, %f, %f, %f)\n", expectedplane.a, expectedplane.b, expectedplane.c, expectedplane.d, gotplane.a, gotplane.b, gotplane.c, gotplane.d);

#define expect_vec(expectedvec,gotvec) ok((fabs(expectedvec.x-gotvec.x)<admitted_error)&&(fabs(expectedvec.y-gotvec.y)<admitted_error),"Expected Vector= (%f, %f)\n , Got Vector= (%f, %f)\n", expectedvec.x, expectedvec.y, gotvec.x, gotvec.y);

#define expect_vec3(expectedvec,gotvec) ok((fabs(expectedvec.x-gotvec.x)<admitted_error)&&(fabs(expectedvec.y-gotvec.y)<admitted_error)&&(fabs(expectedvec.z-gotvec.z)<admitted_error),"Expected Vector= (%f, %f, %f)\n , Got Vector= (%f, %f, %f)\n", expectedvec.x, expectedvec.y, expectedvec.z, gotvec.x, gotvec.y, gotvec.z);

#define expect_vec4(expectedvec,gotvec) ok((fabs(expectedvec.x-gotvec.x)<admitted_error)&&(fabs(expectedvec.y-gotvec.y)<admitted_error)&&(fabs(expectedvec.z-gotvec.z)<admitted_error)&&(fabs(expectedvec.w-gotvec.w)<admitted_error),"Expected Vector= (%f, %f, %f, %f)\n , Got Vector= (%f, %f, %f, %f)\n", expectedvec.x, expectedvec.y, expectedvec.z, expectedvec.w, gotvec.x, gotvec.y, gotvec.z, gotvec.w);

static void D3DXColorTest(void)
{
    D3DXCOLOR color, color1, color2, expected, got;
    LPD3DXCOLOR funcpointer;
    FLOAT scale;

    color.r = 0.2f; color.g = 0.75f; color.b = 0.41f; color.a = 0.93f;
    color1.r = 0.6f; color1.g = 0.55f; color1.b = 0.23f; color1.a = 0.82f;
    color2.r = 0.3f; color2.g = 0.5f; color2.b = 0.76f; color2.a = 0.11f;

    scale = 0.3f;

/*_______________D3DXColorAdd________________*/
    expected.r = 0.9f; expected.g = 1.05f; expected.b = 0.99f, expected.a = 0.93f;
    D3DXColorAdd(&got,&color1,&color2);
    expect_color(expected,got);
    /* Test the NULL case */
    funcpointer = D3DXColorAdd(&got,NULL,&color2);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorAdd(NULL,NULL,&color2);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorAdd(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXColorAdjustContrast______*/
    expected.r = 0.41f; expected.g = 0.575f; expected.b = 0.473f, expected.a = 0.93f;
    D3DXColorAdjustContrast(&got,&color,scale);
    expect_color(expected,got);

/*_______________D3DXColorAdjustSaturation______*/
    expected.r = 0.486028f; expected.g = 0.651028f; expected.b = 0.549028f, expected.a = 0.93f;
    D3DXColorAdjustSaturation(&got,&color,scale);
    expect_color(expected,got);

/*_______________D3DXColorLerp________________*/
    expected.r = 0.32f; expected.g = 0.69f; expected.b = 0.356f; expected.a = 0.897f;
    D3DXColorLerp(&got,&color,&color1,scale);
    expect_color(expected,got);
    /* Test the NULL case */
    funcpointer = D3DXColorLerp(&got,NULL,&color1,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorLerp(NULL,NULL,&color1,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorLerp(NULL,NULL,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXColorModulate________________*/
    expected.r = 0.18f; expected.g = 0.275f; expected.b = 0.1748f; expected.a = 0.0902f;
    D3DXColorModulate(&got,&color1,&color2);
    expect_color(expected,got);
    /* Test the NULL case */
    funcpointer = D3DXColorModulate(&got,NULL,&color2);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorModulate(NULL,NULL,&color2);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorModulate(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXColorNegative________________*/
    expected.r = 0.8f; expected.g = 0.25f; expected.b = 0.59f; expected.a = 0.93f;
    D3DXColorNegative(&got,&color);
    expect_color(got,expected);
    /* Test the greater than 1 case */
    color1.r = 0.2f; color1.g = 1.75f; color1.b = 0.41f; color1.a = 0.93f;
    expected.r = 0.8f; expected.g = -0.75f; expected.b = 0.59f; expected.a = 0.93f;
    D3DXColorNegative(&got,&color1);
    expect_color(got,expected);
    /* Test the negative case */
    color1.r = 0.2f; color1.g = -0.75f; color1.b = 0.41f; color1.a = 0.93f;
    expected.r = 0.8f; expected.g = 1.75f; expected.b = 0.59f; expected.a = 0.93f;
    D3DXColorNegative(&got,&color1);
    expect_color(got,expected);
    /* Test the NULL case */
    funcpointer = D3DXColorNegative(&got,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorNegative(NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXColorScale________________*/
    expected.r = 0.06f; expected.g = 0.225f; expected.b = 0.123f; expected.a = 0.279f;
    D3DXColorScale(&got,&color,scale);
    expect_color(expected,got);
    /* Test the NULL case */
    funcpointer = D3DXColorScale(&got,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorScale(NULL,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXColorSubtract_______________*/
    expected.r = -0.1f; expected.g = 0.25f; expected.b = -0.35f, expected.a = 0.82f;
    D3DXColorSubtract(&got,&color,&color2);
    expect_color(expected,got);
    /* Test the NULL case */
    funcpointer = D3DXColorSubtract(&got,NULL,&color2);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorSubtract(NULL,NULL,&color2);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXColorSubtract(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
}

static void D3DXMatrixTest(void)
{
    D3DXMATRIX expectedmat, gotmat, mat, mat2, mat3;
    LPD3DXMATRIX funcpointer;
    D3DXPLANE plane;
    D3DXQUATERNION q, r;
    D3DXVECTOR3 at, axis, eye, last, scaling;
    D3DXVECTOR4 light;
    BOOL expected, got;
    FLOAT angle, determinant, expectedfloat, gotfloat;

    U(mat).m[0][1] = 5.0f; U(mat).m[0][2] = 7.0f; U(mat).m[0][3] = 8.0f;
    U(mat).m[1][0] = 11.0f; U(mat).m[1][2] = 16.0f; U(mat).m[1][3] = 33.0f;
    U(mat).m[2][0] = 19.0f; U(mat).m[2][1] = -21.0f; U(mat).m[2][3] = 43.0f;
    U(mat).m[3][0] = 2.0f; U(mat).m[3][1] = 3.0f; U(mat).m[3][2] = -4.0f;
    U(mat).m[0][0] = 10.0f; U(mat).m[1][1] = 20.0f; U(mat).m[2][2] = 30.0f;
    U(mat).m[3][3] = -40.0f;

    U(mat2).m[0][0] = 1.0f; U(mat2).m[1][0] = 2.0f; U(mat2).m[2][0] = 3.0f;
    U(mat2).m[3][0] = 4.0f; U(mat2).m[0][1] = 5.0f; U(mat2).m[1][1] = 6.0f;
    U(mat2).m[2][1] = 7.0f; U(mat2).m[3][1] = 8.0f; U(mat2).m[0][2] = -8.0f;
    U(mat2).m[1][2] = -7.0f; U(mat2).m[2][2] = -6.0f; U(mat2).m[3][2] = -5.0f;
    U(mat2).m[0][3] = -4.0f; U(mat2).m[1][3] = -3.0f; U(mat2).m[2][3] = -2.0f;
    U(mat2).m[3][3] = -1.0f;

    plane.a = -3.0f; plane.b = -1.0f; plane.c = 4.0f; plane.d = 7.0f;

    q.x = 1.0f; q.y = -4.0f; q.z =7.0f; q.w = -11.0f;
    r.x = 0.87f; r.y = 0.65f; r.z =0.43f; r.w= 0.21f;

    at.x = -2.0f; at.y = 13.0f; at.z = -9.0f;
    axis.x = 1.0f; axis.y = -3.0f; axis.z = 7.0f;
    eye.x = 8.0f; eye.y = -5.0f; eye.z = 5.75f;
    last.x = 9.7f; last.y = -8.6; last.z = 1.3f;
    scaling.x = 0.03f; scaling.y =0.05f; scaling.z = 0.06f;

    light.x = 9.6f; light.y = 8.5f; light.z = 7.4; light.w = 6.3;

    angle = D3DX_PI/3.0f;

/*____________D3DXMatrixAffineTransformation______*/
    U(expectedmat).m[0][0] = -459.239990f; U(expectedmat).m[0][1] = -576.719971f; U(expectedmat).m[0][2] = -263.440002f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 519.760010f; U(expectedmat).m[1][1] = -352.440002f; U(expectedmat).m[1][2] = -277.679993f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 363.119995f; U(expectedmat).m[2][1] = -121.040001f; U(expectedmat).m[2][2] = -117.479996f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = -1239.0f; U(expectedmat).m[3][1] = 667.0f; U(expectedmat).m[3][2] = 567.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixAffineTransformation(&gotmat,3.56f,&at,&q,&axis);
    expect_mat(expectedmat,gotmat);
/* Test the NULL case */
    U(expectedmat).m[0][0] = -459.239990f; U(expectedmat).m[0][1] = -576.719971f; U(expectedmat).m[0][2] = -263.440002f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 519.760010f; U(expectedmat).m[1][1] = -352.440002f; U(expectedmat).m[1][2] = -277.679993f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 363.119995f; U(expectedmat).m[2][1] = -121.040001f; U(expectedmat).m[2][2] = -117.479996f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 1.0f; U(expectedmat).m[3][1] = -3.0f; U(expectedmat).m[3][2] = 7.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixAffineTransformation(&gotmat,3.56f,NULL,&q,&axis);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixfDeterminant_____________*/
    expectedfloat = -147888.0f;
    gotfloat = D3DXMatrixfDeterminant(&mat);
    ok(fabs( gotfloat - expectedfloat ) < admitted_error, "Expected: %f, Got: %f\n", expectedfloat, gotfloat);

/*____________D3DXMatrixInverse______________*/
    U(expectedmat).m[0][0] = 16067.0f/73944.0f; U(expectedmat).m[0][1] = -10165.0f/147888.0f; U(expectedmat).m[0][2] = -2729.0f/147888.0f; U(expectedmat).m[0][3] = -1631.0f/49296.0f;
    U(expectedmat).m[1][0] = -565.0f/36972.0f; U(expectedmat).m[1][1] = 2723.0f/73944.0f; U(expectedmat).m[1][2] = -1073.0f/73944.0f; U(expectedmat).m[1][3] = 289.0f/24648.0f;
    U(expectedmat).m[2][0] = -389.0f/2054.0f; U(expectedmat).m[2][1] = 337.0f/4108.0f; U(expectedmat).m[2][2] = 181.0f/4108.0f; U(expectedmat).m[2][3] = 317.0f/4108.0f;
    U(expectedmat).m[3][0] = 163.0f/5688.0f; U(expectedmat).m[3][1] = -101.0f/11376.0f; U(expectedmat).m[3][2] = -73.0f/11376.0f; U(expectedmat).m[3][3] = -127.0f/3792.0f;
    expectedfloat = -147888.0f;
    D3DXMatrixInverse(&gotmat,&determinant,&mat);
    expect_mat(expectedmat,gotmat);
    ok(fabs( determinant - expectedfloat ) < admitted_error, "Expected: %f, Got: %f\n", expectedfloat, determinant);
    funcpointer = D3DXMatrixInverse(&gotmat,NULL,&mat2);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*____________D3DXMatrixIsIdentity______________*/
    expected = FALSE;
    got = D3DXMatrixIsIdentity(&mat3);
    ok(expected == got, "Expected : %d, Got : %d\n", expected, got);
    D3DXMatrixIdentity(&mat3);
    expected = TRUE;
    got = D3DXMatrixIsIdentity(&mat3);
    ok(expected == got, "Expected : %d, Got : %d\n", expected, got);
    U(mat3).m[0][0] = 0.000009f;
    expected = FALSE;
    got = D3DXMatrixIsIdentity(&mat3);
    ok(expected == got, "Expected : %d, Got : %d\n", expected, got);
    /* Test the NULL case */
    expected = FALSE;
    got = D3DXMatrixIsIdentity(NULL);
    ok(expected == got, "Expected : %d, Got : %d\n", expected, got);

/*____________D3DXMatrixLookatLH_______________*/
    U(expectedmat).m[0][0] = -0.822465f; U(expectedmat).m[0][1] = -0.409489f; U(expectedmat).m[0][2] = -0.394803f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = -0.555856f; U(expectedmat).m[1][1] = 0.431286f; U(expectedmat).m[1][2] = 0.710645f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = -0.120729f; U(expectedmat).m[2][1] = 0.803935f; U(expectedmat).m[2][2] = -0.582335f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 4.494634f; U(expectedmat).m[3][1] = 0.809719f; U(expectedmat).m[3][2] = 10.060076f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixLookAtLH(&gotmat,&eye,&at,&axis);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixLookatRH_______________*/
    U(expectedmat).m[0][0] = 0.822465f; U(expectedmat).m[0][1] = -0.409489f; U(expectedmat).m[0][2] = 0.394803f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.555856f; U(expectedmat).m[1][1] = 0.431286f; U(expectedmat).m[1][2] = -0.710645f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.120729f; U(expectedmat).m[2][1] = 0.803935f; U(expectedmat).m[2][2] = 0.582335f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = -4.494634f; U(expectedmat).m[3][1] = 0.809719f; U(expectedmat).m[3][2] = -10.060076f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixLookAtRH(&gotmat,&eye,&at,&axis);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixMultiply______________*/
    U(expectedmat).m[0][0] = 73.0f; U(expectedmat).m[0][1] = 193.0f; U(expectedmat).m[0][2] = -197.0f; U(expectedmat).m[0][3] = -77.0f;
    U(expectedmat).m[1][0] = 231.0f; U(expectedmat).m[1][1] = 551.0f; U(expectedmat).m[1][2] = -489.0f; U(expectedmat).m[1][3] = -169.0;
    U(expectedmat).m[2][0] = 239.0f; U(expectedmat).m[2][1] = 523.0f; U(expectedmat).m[2][2] = -400.0f; U(expectedmat).m[2][3] = -116.0f;
    U(expectedmat).m[3][0] = -164.0f; U(expectedmat).m[3][1] = -320.0f; U(expectedmat).m[3][2] = 187.0f; U(expectedmat).m[3][3] = 31.0f;
    D3DXMatrixMultiply(&gotmat,&mat,&mat2);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixMultiplyTranspose____*/
    U(expectedmat).m[0][0] = 73.0f; U(expectedmat).m[0][1] = 231.0f; U(expectedmat).m[0][2] = 239.0f; U(expectedmat).m[0][3] = -164.0f;
    U(expectedmat).m[1][0] = 193.0f; U(expectedmat).m[1][1] = 551.0f; U(expectedmat).m[1][2] = 523.0f; U(expectedmat).m[1][3] = -320.0;
    U(expectedmat).m[2][0] = -197.0f; U(expectedmat).m[2][1] = -489.0f; U(expectedmat).m[2][2] = -400.0f; U(expectedmat).m[2][3] = 187.0f;
    U(expectedmat).m[3][0] = -77.0f; U(expectedmat).m[3][1] = -169.0f; U(expectedmat).m[3][2] = -116.0f; U(expectedmat).m[3][3] = 31.0f;
    D3DXMatrixMultiplyTranspose(&gotmat,&mat,&mat2);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixOrthoLH_______________*/
    U(expectedmat).m[0][0] = 0.8f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = 0.270270f; U(expectedmat).m[1][2] = 0.0f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = -0.151515f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = -0.484848f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixOrthoLH(&gotmat, 2.5f, 7.4f, -3.2f, -9.8f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixOrthoOffCenterLH_______________*/
    U(expectedmat).m[0][0] = 3.636364f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = 0.180180f; U(expectedmat).m[1][2] = 0.0; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = -0.045662f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = -1.727272f; U(expectedmat).m[3][1] = -0.567568f; U(expectedmat).m[3][2] = 0.424658f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixOrthoOffCenterLH(&gotmat, 0.2f, 0.75f, -2.4f, 8.7f, 9.3, -12.6);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixOrthoOffCenterRH_______________*/
    U(expectedmat).m[0][0] = 3.636364f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = 0.180180f; U(expectedmat).m[1][2] = 0.0; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = 0.045662f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = -1.727272f; U(expectedmat).m[3][1] = -0.567568f; U(expectedmat).m[3][2] = 0.424658f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixOrthoOffCenterRH(&gotmat, 0.2f, 0.75f, -2.4f, 8.7f, 9.3, -12.6);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixOrthoRH_______________*/
    U(expectedmat).m[0][0] = 0.8f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = 0.270270f; U(expectedmat).m[1][2] = 0.0f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = 0.151515f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = -0.484848f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixOrthoRH(&gotmat, 2.5f, 7.4f, -3.2f, -9.8f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixPerspectiveFovLH_______________*/
    U(expectedmat).m[0][0] = 13.288858f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = 9.966644f; U(expectedmat).m[1][2] = 0.0; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = 0.783784f; U(expectedmat).m[2][3] = 1.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 1.881081f; U(expectedmat).m[3][3] = 0.0f;
    D3DXMatrixPerspectiveFovLH(&gotmat, 0.2f, 0.75f, -2.4f, 8.7f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixPerspectiveFovRH_______________*/
    U(expectedmat).m[0][0] = 13.288858f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = 9.966644f; U(expectedmat).m[1][2] = 0.0; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = -0.783784f; U(expectedmat).m[2][3] = -1.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 1.881081f; U(expectedmat).m[3][3] = 0.0f;
    D3DXMatrixPerspectiveFovRH(&gotmat, 0.2f, 0.75f, -2.4f, 8.7f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixPerspectiveLH_______________*/
    U(expectedmat).m[0][0] = -24.0f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = -6.4f; U(expectedmat).m[1][2] = 0.0; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = 0.783784f; U(expectedmat).m[2][3] = 1.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 1.881081f; U(expectedmat).m[3][3] = 0.0f;
    D3DXMatrixPerspectiveLH(&gotmat, 0.2f, 0.75f, -2.4f, 8.7f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixPerspectiveOffCenterLH_______________*/
    U(expectedmat).m[0][0] = 11.636364f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = 0.576577f; U(expectedmat).m[1][2] = 0.0; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = -1.727273f; U(expectedmat).m[2][1] = -0.567568f; U(expectedmat).m[2][2] = 0.840796f; U(expectedmat).m[2][3] = 1.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = -2.690547f; U(expectedmat).m[3][3] = 0.0f;
    D3DXMatrixPerspectiveOffCenterLH(&gotmat, 0.2f, 0.75f, -2.4f, 8.7f, 3.2f, -16.9f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixPerspectiveOffCenterRH_______________*/
    U(expectedmat).m[0][0] = 11.636364f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = 0.576577f; U(expectedmat).m[1][2] = 0.0; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 1.727273f; U(expectedmat).m[2][1] = 0.567568f; U(expectedmat).m[2][2] = -0.840796f; U(expectedmat).m[2][3] = -1.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = -2.690547f; U(expectedmat).m[3][3] = 0.0f;
    D3DXMatrixPerspectiveOffCenterRH(&gotmat, 0.2f, 0.75f, -2.4f, 8.7f, 3.2f, -16.9f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixPerspectiveRH_______________*/
    U(expectedmat).m[0][0] = -24.0f; U(expectedmat).m[0][1] = -0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0f; U(expectedmat).m[1][1] = -6.4f; U(expectedmat).m[1][2] = 0.0; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = -0.783784f; U(expectedmat).m[2][3] = -1.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 1.881081f; U(expectedmat).m[3][3] = 0.0f;
    D3DXMatrixPerspectiveRH(&gotmat, 0.2f, 0.75f, -2.4f, 8.7f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixReflect______________*/
    U(expectedmat).m[0][0] = 0.307692f; U(expectedmat).m[0][1] = -0.230769f; U(expectedmat).m[0][2] = 0.923077f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = -0.230769; U(expectedmat).m[1][1] = 0.923077f; U(expectedmat).m[1][2] = 0.307693f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.923077f; U(expectedmat).m[2][1] = 0.307693f; U(expectedmat).m[2][2] = -0.230769f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 1.615385f; U(expectedmat).m[3][1] = 0.538462f; U(expectedmat).m[3][2] = -2.153846f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixReflect(&gotmat,&plane);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixRotationAxis_____*/
    U(expectedmat).m[0][0] = 0.508475f; U(expectedmat).m[0][1] = 0.763805f; U(expectedmat).m[0][2] = 0.397563f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = -0.814652f; U(expectedmat).m[1][1] = 0.576271f; U(expectedmat).m[1][2] = -0.065219f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = -0.278919f; U(expectedmat).m[2][1] = -0.290713f; U(expectedmat).m[2][2] = 0.915254f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 0.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixRotationAxis(&gotmat,&axis,angle);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixRotationQuaternion______________*/
    U(expectedmat).m[0][0] = -129.0f; U(expectedmat).m[0][1] = -162.0f; U(expectedmat).m[0][2] = -74.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 146.0f; U(expectedmat).m[1][1] = -99.0f; U(expectedmat).m[1][2] = -78.0f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 102.0f; U(expectedmat).m[2][1] = -34.0f; U(expectedmat).m[2][2] = -33.0f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 0.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixRotationQuaternion(&gotmat,&q);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixRotationX______________*/
    U(expectedmat).m[0][0] = 1.0f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0; U(expectedmat).m[1][1] = 0.5f; U(expectedmat).m[1][2] = sqrt(3.0f)/2.0f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = -sqrt(3.0f)/2.0f; U(expectedmat).m[2][2] = 0.5f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 0.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixRotationX(&gotmat,angle);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixRotationY______________*/
    U(expectedmat).m[0][0] = 0.5f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = -sqrt(3.0f)/2.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0; U(expectedmat).m[1][1] = 1.0f; U(expectedmat).m[1][2] = 0.0f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = sqrt(3.0f)/2.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = 0.5f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 0.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixRotationY(&gotmat,angle);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixRotationYawPitchRoll____*/
    U(expectedmat).m[0][0] = 0.888777f; U(expectedmat).m[0][1] = 0.091875f; U(expectedmat).m[0][2] = -0.449037f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.351713f; U(expectedmat).m[1][1] = 0.491487f; U(expectedmat).m[1][2] = 0.796705f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.293893f; U(expectedmat).m[2][1] = -0.866025f; U(expectedmat).m[2][2] = 0.404509f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 0.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixRotationYawPitchRoll(&gotmat, 3.0f*angle/5.0f, angle, 3.0f*angle/17.0f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixRotationZ______________*/
    U(expectedmat).m[0][0] = 0.5f; U(expectedmat).m[0][1] = sqrt(3.0f)/2.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = -sqrt(3.0f)/2.0f; U(expectedmat).m[1][1] = 0.5f; U(expectedmat).m[1][2] = 0.0f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = 1.0f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 0.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixRotationZ(&gotmat,angle);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixScaling______________*/
    U(expectedmat).m[0][0] = 0.69f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0; U(expectedmat).m[1][1] = 0.53f; U(expectedmat).m[1][2] = 0.0f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = 4.11f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.0f; U(expectedmat).m[3][1] = 0.0f; U(expectedmat).m[3][2] = 0.0f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixScaling(&gotmat,0.69f,0.53f,4.11f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixShadow______________*/
    U(expectedmat).m[0][0] = 12.786773f; U(expectedmat).m[0][1] = 5.000961f; U(expectedmat).m[0][2] = 4.353778f; U(expectedmat).m[0][3] = 3.706595f;
    U(expectedmat).m[1][0] = 1.882715; U(expectedmat).m[1][1] = 8.805615f; U(expectedmat).m[1][2] = 1.451259f; U(expectedmat).m[1][3] = 1.235532f;
    U(expectedmat).m[2][0] = -7.530860f; U(expectedmat).m[2][1] = -6.667949f; U(expectedmat).m[2][2] = 1.333590f; U(expectedmat).m[2][3] = -4.942127f;
    U(expectedmat).m[3][0] = -13.179006f; U(expectedmat).m[3][1] = -11.668910f; U(expectedmat).m[3][2] = -10.158816f; U(expectedmat).m[3][3] = -1.510094f;
    D3DXMatrixShadow(&gotmat,&light,&plane);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixTransformation______________*/
    U(expectedmat).m[0][0] = -0.2148f; U(expectedmat).m[0][1] = 1.3116f; U(expectedmat).m[0][2] = 0.4752f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.9504f; U(expectedmat).m[1][1] = -0.8836f; U(expectedmat).m[1][2] = 0.9244f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 1.0212f; U(expectedmat).m[2][1] = 0.1936f; U(expectedmat).m[2][2] = -1.3588f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 18.2985f; U(expectedmat).m[3][1] = -29.624001f; U(expectedmat).m[3][2] = 15.683499f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixTransformation(&gotmat,&at,&q,NULL,&eye,&r,&last);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixTranslation______________*/
    U(expectedmat).m[0][0] = 1.0f; U(expectedmat).m[0][1] = 0.0f; U(expectedmat).m[0][2] = 0.0f; U(expectedmat).m[0][3] = 0.0f;
    U(expectedmat).m[1][0] = 0.0; U(expectedmat).m[1][1] = 1.0f; U(expectedmat).m[1][2] = 0.0f; U(expectedmat).m[1][3] = 0.0f;
    U(expectedmat).m[2][0] = 0.0f; U(expectedmat).m[2][1] = 0.0f; U(expectedmat).m[2][2] = 1.0f; U(expectedmat).m[2][3] = 0.0f;
    U(expectedmat).m[3][0] = 0.69f; U(expectedmat).m[3][1] = 0.53f; U(expectedmat).m[3][2] = 4.11f; U(expectedmat).m[3][3] = 1.0f;
    D3DXMatrixTranslation(&gotmat,0.69f,0.53f,4.11f);
    expect_mat(expectedmat,gotmat);

/*____________D3DXMatrixTranspose______________*/
    U(expectedmat).m[0][0] = 10.0f; U(expectedmat).m[0][1] = 11.0f; U(expectedmat).m[0][2] = 19.0f; U(expectedmat).m[0][3] = 2.0f;
    U(expectedmat).m[1][0] = 5.0; U(expectedmat).m[1][1] = 20.0f; U(expectedmat).m[1][2] = -21.0f; U(expectedmat).m[1][3] = 3.0f;
    U(expectedmat).m[2][0] = 7.0f; U(expectedmat).m[2][1] = 16.0f; U(expectedmat).m[2][2] = 30.f; U(expectedmat).m[2][3] = -4.0f;
    U(expectedmat).m[3][0] = 8.0f; U(expectedmat).m[3][1] = 33.0f; U(expectedmat).m[3][2] = 43.0f; U(expectedmat).m[3][3] = -40.0f;
    D3DXMatrixTranspose(&gotmat,&mat);
    expect_mat(expectedmat,gotmat);
}

static void D3DXPlaneTest(void)
{
    D3DXMATRIX mat;
    D3DXPLANE expectedplane, gotplane, nulplane, plane;
    D3DXVECTOR3 expectedvec, gotvec, vec1, vec2, vec3;
    LPD3DXVECTOR3 funcpointer;
    D3DXVECTOR4 vec;
    FLOAT expected, got;

    U(mat).m[0][1] = 5.0f; U(mat).m[0][2] = 7.0f; U(mat).m[0][3] = 8.0f;
    U(mat).m[1][0] = 11.0f; U(mat).m[1][2] = 16.0f; U(mat).m[1][3] = 33.0f;
    U(mat).m[2][0] = 19.0f; U(mat).m[2][1] = -21.0f; U(mat).m[2][3] = 43.0f;
    U(mat).m[3][0] = 2.0f; U(mat).m[3][1] = 3.0f; U(mat).m[3][2] = -4.0f;
    U(mat).m[0][0] = 10.0f; U(mat).m[1][1] = 20.0f; U(mat).m[2][2] = 30.0f;
    U(mat).m[3][3] = -40.0f;

    plane.a = -3.0f; plane.b = -1.0f; plane.c = 4.0f; plane.d = 7.0f;

    vec.x = 2.0f; vec.y = 5.0f; vec.z = -6.0f; vec.w = 11.0f;

/*_______________D3DXPlaneDot________________*/
    expected = 42.0f;
    got = D3DXPlaneDot(&plane,&vec),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);
    expected = 0.0f;
    got = D3DXPlaneDot(NULL,&vec),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);
    expected = 0.0f;
    got = D3DXPlaneDot(NULL,NULL),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);

/*_______________D3DXPlaneDotCoord________________*/
    expected = -28.0f;
    got = D3DXPlaneDotCoord(&plane,&vec),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);
    expected = 0.0f;
    got = D3DXPlaneDotCoord(NULL,&vec),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);
    expected = 0.0f;
    got = D3DXPlaneDotCoord(NULL,NULL),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);

/*_______________D3DXPlaneDotNormal______________*/
    expected = -35.0f;
    got = D3DXPlaneDotNormal(&plane,&vec),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);
    expected = 0.0f;
    got = D3DXPlaneDotNormal(NULL,&vec),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);
    expected = 0.0f;
    got = D3DXPlaneDotNormal(NULL,NULL),
    ok( expected == got, "Expected : %f, Got : %f\n",expected, got);

/*_______________D3DXPlaneFromPointNormal_______*/
    vec1.x = 11.0f; vec1.y = 13.0f; vec1.z = 15.0f;
    vec2.x = 17.0f; vec2.y = 31.0f; vec2.z = 24.0f;
    expectedplane.a = 17.0f; expectedplane.b = 31.0f; expectedplane.c = 24.0f; expectedplane.d = -950.0f;
    D3DXPlaneFromPointNormal(&gotplane,&vec1,&vec2);
    expect_plane(expectedplane, gotplane);

/*_______________D3DXPlaneFromPoints_______*/
    vec1.x = 1.0f; vec1.y = 2.0f; vec1.z = 3.0f;
    vec2.x = 1.0f; vec2.y = -6.0f; vec2.z = -5.0f;
    vec3.x = 83.0f; vec3.y = 74.0f; vec3.z = 65.0f;
    expectedplane.a = 0.085914f; expectedplane.b = -0.704492f; expectedplane.c = 0.704492f; expectedplane.d = -0.790406f;
    D3DXPlaneFromPoints(&gotplane,&vec1,&vec2,&vec3);
    expect_plane(expectedplane, gotplane);
    /* Test if 2 vectors are parallels */
    vec3.x = 1.0f; vec3.y = 1.0f; vec3.z = 2.0f;
    expectedplane.a = 0.0f; expectedplane.b = 0.0f; expectedplane.c = 0.0f; expectedplane.d = 0.0f;
    D3DXPlaneFromPoints(&gotplane,&vec1,&vec2,&vec3);
    expect_plane(expectedplane, gotplane);

/*_______________D3DXPlaneIntersectLine___________*/
    vec1.x = 9.0f; vec1.y = 6.0f; vec1.z = 3.0f;
    vec2.x = 2.0f; vec2.y = 5.0f; vec2.z = 8.0f;
    expectedvec.x = 20.0f/3.0f; expectedvec.y = 17.0f/3.0f; expectedvec.z = 14.0f/3.0f;
    D3DXPlaneIntersectLine(&gotvec,&plane,&vec1,&vec2);
    expect_vec3(expectedvec, gotvec);
    /* Test a parallel line */
    vec1.x = 11.0f; vec1.y = 13.0f; vec1.z = 15.0f;
    vec2.x = 17.0f; vec2.y = 31.0f; vec2.z = 24.0f;
    expectedvec.x = 20.0f/3.0f; expectedvec.y = 17.0f/3.0f; expectedvec.z = 14.0f/3.0f;
    funcpointer = D3DXPlaneIntersectLine(&gotvec,&plane,&vec1,&vec2);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXPlaneNormalize______________*/
    expectedplane.a = -3.0f/sqrt(26.0f); expectedplane.b = -1.0f/sqrt(26.0f); expectedplane.c = 4.0f/sqrt(26.0f); expectedplane.d = 7.0/sqrt(26.0f);
    D3DXPlaneNormalize(&gotplane, &plane);
    expect_plane(expectedplane, gotplane);
    nulplane.a = 0.0; nulplane.b = 0.0f, nulplane.c = 0.0f; nulplane.d = 0.0f;
    expectedplane.a = 0.0f; expectedplane.b = 0.0f; expectedplane.c = 0.0f; expectedplane.d = 0.0f;
    D3DXPlaneNormalize(&gotplane, &nulplane);
    expect_plane(expectedplane, gotplane);
    nulplane.a = 0.0; nulplane.b = 0.0f, nulplane.c = 0.0f; nulplane.d = 4.3f;
    expectedplane.a = 0.0f; expectedplane.b = 0.0f; expectedplane.c = 0.0f; expectedplane.d = 0.0f;
    D3DXPlaneNormalize(&gotplane, &nulplane);
    expect_plane(expectedplane, gotplane);

/*_______________D3DXPlaneTransform____________*/
    expectedplane.a = 49.0f; expectedplane.b = -98.0f; expectedplane.c = 55.0f; expectedplane.d = -165.0f;
    D3DXPlaneTransform(&gotplane,&plane,&mat);
    expect_plane(expectedplane, gotplane);
}

static void D3X8QuaternionTest(void)
{
    D3DXMATRIX mat;
    D3DXQUATERNION expectedquat, gotquat, Nq, Nq1, nul, q, r, s, t, u;
    LPD3DXQUATERNION funcpointer;
    D3DXVECTOR3 axis, expectedvec;
    FLOAT angle, expected, got, scale, scale2;
    BOOL expectedbool, gotbool;

    nul.x = 0.0f; nul.y = 0.0f; nul.z = 0.0f; nul.w = 0.0f;
    q.x = 1.0f, q.y = 2.0f; q.z = 4.0f; q.w = 10.0f;
    r.x = -3.0f; r.y = 4.0f; r.z = -5.0f; r.w = 7.0;
    t.x = -1111.0f, t.y= 111.0f; t.z = -11.0f; t.w = 1.0f;
    u.x = 91.0f; u.y = - 82.0f; u.z = 7.3f; u.w = -6.4f;

    scale = 0.3f;
    scale2 = 0.78f;

/*_______________D3DXQuaternionBaryCentric________________________*/
    expectedquat.x = -867.444458; expectedquat.y = 87.851111f; expectedquat.z = -9.937778f; expectedquat.w = 3.235555f;
    D3DXQuaternionBaryCentric(&gotquat,&q,&r,&t,scale,scale2);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionConjugate________________*/
    expectedquat.x = -1.0f; expectedquat.y = -2.0f; expectedquat.z = -4.0f; expectedquat.w = 10.0f;
    D3DXQuaternionConjugate(&gotquat,&q);
    expect_vec4(expectedquat,gotquat);
    /* Test the NULL case */
    funcpointer = D3DXQuaternionConjugate(&gotquat,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXQuaternionConjugate(NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXQuaternionDot______________________*/
    expected = 55.0f;
    got = D3DXQuaternionDot(&q,&r);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    /* Tests the case NULL */
    expected=0.0f;
    got = D3DXQuaternionDot(NULL,&r);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    expected=0.0f;
    got = D3DXQuaternionDot(NULL,NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXQuaternionExp______________________________*/
    expectedquat.x = -0.216382f; expectedquat.y = -0.432764f; expectedquat.z = -0.8655270f; expectedquat.w = -0.129449f;
    D3DXQuaternionExp(&gotquat,&q);
    expect_vec4(expectedquat,gotquat);
    /* Test the null quaternion */
    expectedquat.x = 0.0f; expectedquat.y = 0.0f; expectedquat.z = 0.0f; expectedquat.w = 1.0f;
    D3DXQuaternionExp(&gotquat,&nul);
    expect_vec4(expectedquat,gotquat);
    /* Test the case where the norm of the quaternion is <1 */
    Nq1.x = 0.2f; Nq1.y = 0.1f; Nq1.z = 0.3; Nq1.w= 0.9f;
    expectedquat.x = 0.195366; expectedquat.y = 0.097683f; expectedquat.z = 0.293049f; expectedquat.w = 0.930813f;
    D3DXQuaternionExp(&gotquat,&Nq1);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionIdentity________________*/
    expectedquat.x = 0.0f; expectedquat.y = 0.0f; expectedquat.z = 0.0f; expectedquat.w = 1.0f;
    D3DXQuaternionIdentity(&gotquat);
    expect_vec4(expectedquat,gotquat);
    /* Test the NULL case */
    funcpointer = D3DXQuaternionIdentity(NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXQuaternionInverse________________________*/
    expectedquat.x = -1.0f/121.0f; expectedquat.y = -2.0f/121.0f; expectedquat.z = -4.0f/121.0f; expectedquat.w = 10.0f/121.0f;
    D3DXQuaternionInverse(&gotquat,&q);
    expect_vec4(expectedquat,gotquat);
    /* test the null quaternion */
    expectedquat.x = 0.0f; expectedquat.y = 0.0f; expectedquat.z = 0.0f; expectedquat.w = 0.0f;
    D3DXQuaternionInverse(&gotquat,&nul);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionIsIdentity________________*/
    s.x = 0.0f; s.y = 0.0f; s.z = 0.0f; s.w = 1.0f;
    expectedbool = TRUE;
    gotbool = D3DXQuaternionIsIdentity(&s);
    ok( expectedbool == gotbool, "Expected boolean : %d, Got bool : %d\n", expectedbool, gotbool);
    s.x = 2.3f; s.y = -4.2f; s.z = 1.2f; s.w=0.2f;
    expectedbool = FALSE;
    gotbool = D3DXQuaternionIsIdentity(&q);
    ok( expectedbool == gotbool, "Expected boolean : %d, Got bool : %d\n", expectedbool, gotbool);
    /* Test the NULL case */
    gotbool = D3DXQuaternionIsIdentity(NULL);
    ok(gotbool == FALSE, "Expected boolean: %d, Got boolean: %d\n", FALSE, gotbool);

/*_______________D3DXQuaternionLength__________________________*/
   expected = 11.0f;
   got = D3DXQuaternionLength(&q);
   ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
   /* Tests the case NULL */
    expected=0.0f;
    got = D3DXQuaternionLength(NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXQuaternionLengthSq________________________*/
    expected = 121.0f;
    got = D3DXQuaternionLengthSq(&q);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    /* Tests the case NULL */
    expected=0.0f;
    got = D3DXQuaternionLengthSq(NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXQuaternionLn______________________________*/
    expectedquat.x = 1.0f; expectedquat.y = 2.0f; expectedquat.z = 4.0f; expectedquat.w = 0.0f;
    D3DXQuaternionLn(&gotquat,&q);
    expect_vec4(expectedquat,gotquat);
    expectedquat.x = -3.0f; expectedquat.y = 4.0f; expectedquat.z = -5.0f; expectedquat.w = 0.0f;
    D3DXQuaternionLn(&gotquat,&r);
    expect_vec4(expectedquat,gotquat);
    Nq.x = 1.0f/11.0f; Nq.y = 2.0f/11.0f; Nq.z = 4.0f/11.0f; Nq.w=10.0f/11.0f;
    expectedquat.x = 0.093768f; expectedquat.y = 0.187536f; expectedquat.z = 0.375073f; expectedquat.w = 0.0f;
    D3DXQuaternionLn(&gotquat,&Nq);
    expect_vec4(expectedquat,gotquat);
    /* Test the cas where the norm of the quaternion is <1 */
    Nq1.x = 0.2f; Nq1.y = 0.1f; Nq1.z = 0.3; Nq1.w= 0.9f;
    expectedquat.x = 0.206945f; expectedquat.y = 0.103473f; expectedquat.z = 0.310418f; expectedquat.w = 0.0f;
    D3DXQuaternionLn(&gotquat,&Nq1);
    todo_wine{ expect_vec4(expectedquat,gotquat) };

/*_______________D3DXQuaternionMultiply________________________*/
    expectedquat.x = 3.0f; expectedquat.y = 61.0f; expectedquat.z = -32.0f; expectedquat.w = 85.0f;
    D3DXQuaternionMultiply(&gotquat,&q,&r);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionNormalize________________________*/
    expectedquat.x = 1.0f/11.0f; expectedquat.y = 2.0f/11.0f; expectedquat.z = 4.0f/11.0f; expectedquat.w = 10.0f/11.0f;
    D3DXQuaternionNormalize(&gotquat,&q);
    expect_vec4(expectedquat,gotquat);
    /* Test the nul quaternion */
    expectedquat.x = 0.0f; expectedquat.y = 0.0f; expectedquat.z = 0.0f; expectedquat.w = 0.0f;
    D3DXQuaternionNormalize(&gotquat,&nul);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionRotationAxis___________________*/
    axis.x = 2.0f; axis.y = 7.0; axis.z = 13.0f;
    angle = D3DX_PI/3.0f;
    expectedquat.x = 0.067116; expectedquat.y = 0.234905f; expectedquat.z = 0.436251f; expectedquat.w = 0.866025f;
    D3DXQuaternionRotationAxis(&gotquat,&axis,angle);
    expect_vec4(expectedquat,gotquat);
 /* Test the nul quaternion */
    axis.x = 0.0f; axis.y = 0.0; axis.z = 0.0f;
    expectedquat.x = 0.0f; expectedquat.y = 0.0f; expectedquat.z = 0.0f; expectedquat.w = 0.866025f;
    D3DXQuaternionRotationAxis(&gotquat,&axis,angle);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionRotationMatrix___________________*/
    /* test when the trace is >0 */
    U(mat).m[0][1] = 5.0f; U(mat).m[0][2] = 7.0f; U(mat).m[0][3] = 8.0f;
    U(mat).m[1][0] = 11.0f; U(mat).m[1][2] = 16.0f; U(mat).m[1][3] = 33.0f;
    U(mat).m[2][0] = 19.0f; U(mat).m[2][1] = -21.0f; U(mat).m[2][3] = 43.0f;
    U(mat).m[3][0] = 2.0f; U(mat).m[3][1] = 3.0f; U(mat).m[3][2] = -4.0f;
    U(mat).m[0][0] = 10.0f; U(mat).m[1][1] = 20.0f; U(mat).m[2][2] = 30.0f;
    U(mat).m[3][3] = 48.0f;
    expectedquat.x = 2.368682f; expectedquat.y = 0.768221f; expectedquat.z = -0.384111f; expectedquat.w = 3.905125f;
    D3DXQuaternionRotationMatrix(&gotquat,&mat);
    expect_vec4(expectedquat,gotquat);
    /* test the case when the greater element is (2,2) */
    U(mat).m[0][1] = 5.0f; U(mat).m[0][2] = 7.0f; U(mat).m[0][3] = 8.0f;
    U(mat).m[1][0] = 11.0f; U(mat).m[1][2] = 16.0f; U(mat).m[1][3] = 33.0f;
    U(mat).m[2][0] = 19.0f; U(mat).m[2][1] = -21.0f; U(mat).m[2][3] = 43.0f;
    U(mat).m[3][0] = 2.0f; U(mat).m[3][1] = 3.0f; U(mat).m[3][2] = -4.0f;
    U(mat).m[0][0] = -10.0f; U(mat).m[1][1] = -60.0f; U(mat).m[2][2] = 40.0f;
    U(mat).m[3][3] = 48.0f;
    expectedquat.x = 1.233905f; expectedquat.y = -0.237290f; expectedquat.z = 5.267827f; expectedquat.w = -0.284747f;
    D3DXQuaternionRotationMatrix(&gotquat,&mat);
    expect_vec4(expectedquat,gotquat);
    /* test the case when the greater element is (1,1) */
    U(mat).m[0][1] = 5.0f; U(mat).m[0][2] = 7.0f; U(mat).m[0][3] = 8.0f;
    U(mat).m[1][0] = 11.0f; U(mat).m[1][2] = 16.0f; U(mat).m[1][3] = 33.0f;
    U(mat).m[2][0] = 19.0f; U(mat).m[2][1] = -21.0f; U(mat).m[2][3] = 43.0f;
    U(mat).m[3][0] = 2.0f; U(mat).m[3][1] = 3.0f; U(mat).m[3][2] = -4.0f;
    U(mat).m[0][0] = -10.0f; U(mat).m[1][1] = 60.0f; U(mat).m[2][2] = -80.0f;
    U(mat).m[3][3] = 48.0f;
    expectedquat.x = 0.651031f; expectedquat.y = 6.144103f; expectedquat.z = -0.203447f; expectedquat.w = 0.488273f;
    D3DXQuaternionRotationMatrix(&gotquat,&mat);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionRotationYawPitchRoll__________*/
    expectedquat.x = 0.303261f; expectedquat.y = 0.262299f; expectedquat.z = 0.410073f; expectedquat.w = 0.819190f;
    D3DXQuaternionRotationYawPitchRoll(&gotquat,D3DX_PI/4.0f,D3DX_PI/11.0f,D3DX_PI/3.0f);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionSlerp________________________*/
    expectedquat.x = -0.2f; expectedquat.y = 2.6f; expectedquat.z = 1.3f; expectedquat.w = 9.1f;
    D3DXQuaternionSlerp(&gotquat,&q,&r,scale);
    expect_vec4(expectedquat,gotquat);
    expectedquat.x = 334.0f; expectedquat.y = -31.9f; expectedquat.z = 6.1f; expectedquat.w = 6.7f;
    D3DXQuaternionSlerp(&gotquat,&q,&t,scale);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionSquad________________________*/
    expectedquat.x = -156.296f; expectedquat.y = 30.242f; expectedquat.z = -2.5022f; expectedquat.w = 7.3576f;
    D3DXQuaternionSquad(&gotquat,&q,&r,&t,&u,scale);
    expect_vec4(expectedquat,gotquat);

/*_______________D3DXQuaternionToAxisAngle__________________*/
    Nq.x = 1.0f/22.0f; Nq.y = 2.0f/22.0f; Nq.z = 4.0f/22.0f; Nq.w = 10.0f/22.0f;
    expectedvec.x = 1.0f/11.0f; expectedvec.y = 2.0f/11.0f; expectedvec.z = 4.0f/11.0f;
    expected = 2.197869f;
    D3DXQuaternionToAxisAngle(&Nq,&axis,&angle);
    expect_vec3(expectedvec,axis);
    ok(fabs( angle - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, angle);
    /* Test if |w|>1.0f */
    expectedvec.x = 1.0f/11.0f; expectedvec.y = 2.0f/11.0f; expectedvec.z = 4.0f/11.0f;
    expected = 0.0f;
    D3DXQuaternionToAxisAngle(&q,&axis,&angle);
    expect_vec3(expectedvec,axis);
    ok(fabs( angle - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, angle);
    /* Test the null quaternion */
    expectedvec.x = 1.0f; expectedvec.y = 0.0f; expectedvec.z = 0.0f;
    expected = 0.0f;
    D3DXQuaternionToAxisAngle(&nul,&axis,&angle);
    expect_vec3(expectedvec,axis);
    ok(fabs( angle - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, angle);
}

static void D3X8Vector2Test(void)
{
    D3DXVECTOR2 expectedvec, gotvec, nul, nulproj, u, v, w, x;
    LPD3DXVECTOR2 funcpointer;
    D3DXVECTOR4 expectedtrans, gottrans;
    D3DXMATRIX mat;
    FLOAT coeff1, coeff2, expected, got, scale;

    nul.x = 0.0f; nul.y = 0.0f;
    u.x = 3.0f; u.y = 4.0f;
    v.x = -7.0f; v.y = 9.0f;
    w.x = 4.0f; w.y = -3.0f;
    x.x = 2.0f; x.y = -11.0f;

    U(mat).m[0][0] = 1.0f; U(mat).m[0][1] = 2.0f; U(mat).m[0][2] = 3.0f; U(mat).m[0][3] = 4.0f;
    U(mat).m[1][0] = 5.0f; U(mat).m[1][1] = 6.0f; U(mat).m[1][2] = 7.0f; U(mat).m[1][3] = 8.0f;
    U(mat).m[2][0] = 9.0f; U(mat).m[2][1] = 10.0f; U(mat).m[2][2] = 11.0f; U(mat).m[2][3] = 12.0f;
    U(mat).m[3][0] = 13.0f; U(mat).m[3][1] = 14.0f; U(mat).m[3][2] = 15.0f; U(mat).m[3][3] = 16.0f;

    coeff1 = 2.0f; coeff2 = 5.0f;
    scale = -6.5f;

/*_______________D3DXVec2Add__________________________*/
    expectedvec.x = -4.0f; expectedvec.y = 13.0f;
    D3DXVec2Add(&gotvec,&u,&v);
    expect_vec(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec2Add(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec2Add(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec2BaryCentric___________________*/
    expectedvec.x = -12.0f; expectedvec.y = -21.0f;
    D3DXVec2BaryCentric(&gotvec,&u,&v,&w,coeff1,coeff2);
    expect_vec(expectedvec,gotvec);

/*_______________D3DXVec2CatmullRom____________________*/
    expectedvec.x = 5820.25f; expectedvec.y = -3654.5625f;
    D3DXVec2CatmullRom(&gotvec,&u,&v,&w,&x,scale);
    expect_vec(expectedvec,gotvec);

/*_______________D3DXVec2CCW__________________________*/
   expected = 55.0f;
   got = D3DXVec2CCW(&u,&v);
   ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
   /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec2CCW(NULL,&v);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    expected=0.0f;
    got = D3DXVec2CCW(NULL,NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec2Dot__________________________*/
    expected = 15.0f;
    got = D3DXVec2Dot(&u,&v);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec2Dot(NULL,&v);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    expected=0.0f;
    got = D3DXVec2Dot(NULL,NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec2Hermite__________________________*/
    expectedvec.x = 2604.625f; expectedvec.y = -4533.0f;
    D3DXVec2Hermite(&gotvec,&u,&v,&w,&x,scale);
    expect_vec(expectedvec,gotvec);

/*_______________D3DXVec2Length__________________________*/
   expected = 5.0f;
   got = D3DXVec2Length(&u);
   ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
   /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec2Length(NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec2LengthSq________________________*/
   expected = 25.0f;
   got = D3DXVec2LengthSq(&u);
   ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
   /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec2LengthSq(NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec2Lerp__________________________*/
   expectedvec.x = 68.0f; expectedvec.y = -28.5f;
   D3DXVec2Lerp(&gotvec,&u,&v,scale);
   expect_vec(expectedvec,gotvec);
   /* Tests the case NULL */
    funcpointer = D3DXVec2Lerp(&gotvec,NULL,&v,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec2Lerp(NULL,NULL,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec2Maximize__________________________*/
   expectedvec.x = 3.0f; expectedvec.y = 9.0f;
   D3DXVec2Maximize(&gotvec,&u,&v);
   expect_vec(expectedvec,gotvec);
   /* Tests the case NULL */
    funcpointer = D3DXVec2Maximize(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec2Maximize(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec2Minimize__________________________*/
    expectedvec.x = -7.0f; expectedvec.y = 4.0f;
    D3DXVec2Minimize(&gotvec,&u,&v);
    expect_vec(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec2Minimize(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec2Minimize(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec2Normalize_________________________*/
    expectedvec.x = 0.6f; expectedvec.y = 0.8f;
    D3DXVec2Normalize(&gotvec,&u);
    expect_vec(expectedvec,gotvec);
    /* Test the nul vector */
    expectedvec.x = 0.0f; expectedvec.y = 0.0f;
    D3DXVec2Normalize(&gotvec,&nul);
    expect_vec(expectedvec,gotvec);

/*_______________D3DXVec2Scale____________________________*/
    expectedvec.x = -19.5f; expectedvec.y = -26.0f;
    D3DXVec2Scale(&gotvec,&u,scale);
    expect_vec(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec2Scale(&gotvec,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec2Scale(NULL,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec2Subtract__________________________*/
   expectedvec.x = 10.0f; expectedvec.y = -5.0f;
   D3DXVec2Subtract(&gotvec,&u,&v);
   expect_vec(expectedvec,gotvec);
   /* Tests the case NULL */
    funcpointer = D3DXVec2Subtract(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec2Subtract(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec2Transform_______________________*/
    expectedtrans.x = 36.0f; expectedtrans.y = 44.0f; expectedtrans.z = 52.0f; expectedtrans.w = 60.0f;
    D3DXVec2Transform(&gottrans,&u,&mat);
    expect_vec4(expectedtrans,gottrans);

/*_______________D3DXVec2TransformCoord_______________________*/
    expectedvec.x = 0.6f; expectedvec.y = 11.0f/15.0f;
    D3DXVec2TransformCoord(&gotvec,&u,&mat);
    expect_vec(expectedvec,gotvec);
    /* Test the nul projected vector */
    nulproj.x = -2.0f; nulproj.y = -1.0f;
    expectedvec.x = 0.0f; expectedvec.y = 0.0f;
    D3DXVec2TransformCoord(&gotvec,&nulproj,&mat);
    expect_vec(expectedvec,gotvec);

 /*_______________D3DXVec2TransformNormal______________________*/
    expectedvec.x = 23.0f; expectedvec.y = 30.0f;
    D3DXVec2TransformNormal(&gotvec,&u,&mat);
    expect_vec(expectedvec,gotvec);
}

static void D3X8Vector3Test(void)
{
    D3DVIEWPORT8 viewport;
    D3DXVECTOR3 expectedvec, gotvec, nul, nulproj, u, v, w, x;
    LPD3DXVECTOR3 funcpointer;
    D3DXVECTOR4 expectedtrans, gottrans;
    D3DXMATRIX mat, projection, view, world;
    FLOAT coeff1, coeff2, expected, got, scale;

    nul.x = 0.0f; nul.y = 0.0f; nul.z = 0.0f;
    u.x = 9.0f; u.y = 6.0f; u.z = 2.0f;
    v.x = 2.0f; v.y = -3.0f; v.z = -4.0;
    w.x = 3.0f; w.y = -5.0f; w.z = 7.0f;
    x.x = 4.0f; x.y = 1.0f; x.z = 11.0f;

    viewport.Width = 800; viewport.MinZ = 0.2f; viewport.X = 10;
    viewport.Height = 680; viewport.MaxZ = 0.9f; viewport.Y = 5;

    U(mat).m[0][0] = 1.0f; U(mat).m[0][1] = 2.0f; U(mat).m[0][2] = 3.0f; U(mat).m[0][3] = 4.0f;
    U(mat).m[1][0] = 5.0f; U(mat).m[1][1] = 6.0f; U(mat).m[1][2] = 7.0f; U(mat).m[1][3] = 8.0f;
    U(mat).m[2][0] = 9.0f; U(mat).m[2][1] = 10.0f; U(mat).m[2][2] = 11.0f; U(mat).m[2][3] = 12.0f;
    U(mat).m[3][0] = 13.0f; U(mat).m[3][1] = 14.0f; U(mat).m[3][2] = 15.0f; U(mat).m[3][3] = 16.0f;

    U(view).m[0][1] = 5.0f; U(view).m[0][2] = 7.0f; U(view).m[0][3] = 8.0f;
    U(view).m[1][0] = 11.0f; U(view).m[1][2] = 16.0f; U(view).m[1][3] = 33.0f;
    U(view).m[2][0] = 19.0f; U(view).m[2][1] = -21.0f; U(view).m[2][3] = 43.0f;
    U(view).m[3][0] = 2.0f; U(view).m[3][1] = 3.0f; U(view).m[3][2] = -4.0f;
    U(view).m[0][0] = 10.0f; U(view).m[1][1] = 20.0f; U(view).m[2][2] = 30.0f;
    U(view).m[3][3] = -40.0f;

    U(world).m[0][0] = 21.0f; U(world).m[0][1] = 2.0f; U(world).m[0][2] = 3.0f; U(world).m[0][3] = 4.0;
    U(world).m[1][0] = 5.0f; U(world).m[1][1] = 23.0f; U(world).m[1][2] = 7.0f; U(world).m[1][3] = 8.0f;
    U(world).m[2][0] = -8.0f; U(world).m[2][1] = -7.0f; U(world).m[2][2] = 25.0f; U(world).m[2][3] = -5.0f;
    U(world).m[3][0] = -4.0f; U(world).m[3][1] = -3.0f; U(world).m[3][2] = -2.0f; U(world).m[3][3] = 27.0f;

    coeff1 = 2.0f; coeff2 = 5.0f;
    scale = -6.5f;

/*_______________D3DXVec3Add__________________________*/
    expectedvec.x = 11.0f; expectedvec.y = 3.0f; expectedvec.z = -2.0f;
    D3DXVec3Add(&gotvec,&u,&v);
    expect_vec3(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec3Add(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec3Add(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec3BaryCentric___________________*/
    expectedvec.x = -35.0f; expectedvec.y = -67.0; expectedvec.z = 15.0f;
    D3DXVec3BaryCentric(&gotvec,&u,&v,&w,coeff1,coeff2);

    expect_vec3(expectedvec,gotvec);

/*_______________D3DXVec3CatmullRom____________________*/
    expectedvec.x = 1458.0f; expectedvec.y = 22.1875f; expectedvec.z = 4141.375f;
    D3DXVec3CatmullRom(&gotvec,&u,&v,&w,&x,scale);
    expect_vec3(expectedvec,gotvec);

/*_______________D3DXVec3Cross________________________*/
    expectedvec.x = -18.0f; expectedvec.y = 40.0f; expectedvec.z = -39.0f;
    D3DXVec3Cross(&gotvec,&u,&v);
    expect_vec3(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec3Cross(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec3Cross(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec3Dot__________________________*/
    expected = -8.0f;
    got = D3DXVec3Dot(&u,&v);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec3Dot(NULL,&v);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    expected=0.0f;
    got = D3DXVec3Dot(NULL,NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec3Hermite__________________________*/
    expectedvec.x = -6045.75f; expectedvec.y = -6650.0f; expectedvec.z = 1358.875f;
    D3DXVec3Hermite(&gotvec,&u,&v,&w,&x,scale);
    expect_vec3(expectedvec,gotvec);

/*_______________D3DXVec3Length__________________________*/
   expected = 11.0f;
   got = D3DXVec3Length(&u);
   ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
   /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec3Length(NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec3LengthSq________________________*/
    expected = 121.0f;
    got = D3DXVec3LengthSq(&u);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
   /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec3LengthSq(NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec3Lerp__________________________*/
    expectedvec.x = 54.5f; expectedvec.y = 64.5f, expectedvec.z = 41.0f ;
    D3DXVec3Lerp(&gotvec,&u,&v,scale);
    expect_vec3(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec3Lerp(&gotvec,NULL,&v,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec3Lerp(NULL,NULL,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec3Maximize__________________________*/
    expectedvec.x = 9.0f; expectedvec.y = 6.0f; expectedvec.z = 2.0f;
    D3DXVec3Maximize(&gotvec,&u,&v);
    expect_vec3(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec3Maximize(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec3Maximize(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec3Minimize__________________________*/
    expectedvec.x = 2.0f; expectedvec.y = -3.0f; expectedvec.z = -4.0f;
    D3DXVec3Minimize(&gotvec,&u,&v);
    expect_vec3(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec3Minimize(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec3Minimize(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec3Normalize_________________________*/
    expectedvec.x = 9.0f/11.0f; expectedvec.y = 6.0f/11.0f; expectedvec.z = 2.0f/11.0f;
    D3DXVec3Normalize(&gotvec,&u);
    expect_vec3(expectedvec,gotvec);
    /* Test the nul vector */
    expectedvec.x = 0.0f; expectedvec.y = 0.0f; expectedvec.z = 0.0f;
    D3DXVec3Normalize(&gotvec,&nul);
    expect_vec3(expectedvec,gotvec);

/*_______________D3DXVec3Project_________________________*/
    expectedvec.x = 1135.721924f; expectedvec.y = 147.086914f; expectedvec.z = 0.153412f;
    D3DXMatrixPerspectiveFovLH(&projection,D3DX_PI/4.0f,20.0f/17.0f,1.0f,1000.0f);
    D3DXVec3Project(&gotvec,&u,&viewport,&projection,&view,&world);
    expect_vec3(expectedvec,gotvec);

/*_______________D3DXVec3Scale____________________________*/
    expectedvec.x = -58.5f; expectedvec.y = -39.0f; expectedvec.z = -13.0f;
    D3DXVec3Scale(&gotvec,&u,scale);
    expect_vec3(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec3Scale(&gotvec,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec3Scale(NULL,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec3Subtract_______________________*/
    expectedvec.x = 7.0f; expectedvec.y = 9.0f; expectedvec.z = 6.0f;
    D3DXVec3Subtract(&gotvec,&u,&v);
    expect_vec3(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec3Subtract(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec3Subtract(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec3Transform_______________________*/
    expectedtrans.x = 70.0f; expectedtrans.y = 88.0f; expectedtrans.z = 106.0f; expectedtrans.w = 124.0f;
    D3DXVec3Transform(&gottrans,&u,&mat);
    expect_vec4(expectedtrans,gottrans);

/*_______________D3DXVec3TransformCoord_______________________*/
    expectedvec.x = 70.0f/124.0f; expectedvec.y = 88.0f/124.0f; expectedvec.z = 106.0f/124.0f;
    D3DXVec3TransformCoord(&gotvec,&u,&mat);
    expect_vec3(expectedvec,gotvec);
    /* Test the nul projected vector */
    nulproj.x = 1.0f; nulproj.y = -1.0f, nulproj.z = -1.0f;
    expectedvec.x = 0.0f; expectedvec.y = 0.0f; expectedvec.z = 0.0f;
    D3DXVec3TransformCoord(&gotvec,&nulproj,&mat);
    expect_vec3(expectedvec,gotvec);

/*_______________D3DXVec3TransformNormal______________________*/
    expectedvec.x = 57.0f; expectedvec.y = 74.0f; expectedvec.z = 91.0f;
    D3DXVec3TransformNormal(&gotvec,&u,&mat);
    expect_vec3(expectedvec,gotvec);

/*_______________D3DXVec3Unproject_________________________*/
    expectedvec.x = -2.913411f; expectedvec.y = 1.593215f; expectedvec.z = 0.380724f;
    D3DXMatrixPerspectiveFovLH(&projection,D3DX_PI/4.0f,20.0f/17.0f,1.0f,1000.0f);
    D3DXVec3Unproject(&gotvec,&u,&viewport,&projection,&view,&world);
    expect_vec3(expectedvec,gotvec);
}

static void D3X8Vector4Test(void)
{
    D3DXVECTOR4 expectedvec, gotvec, nul, u, v, w, x;
    LPD3DXVECTOR4 funcpointer;
    D3DXVECTOR4 expectedtrans, gottrans;
    D3DXMATRIX mat;
    FLOAT coeff1, coeff2, expected, got, scale;

    nul.x = 0.0f; nul.y = 0.0f; nul.z = 0.0f; nul.w = 0.0f;
    u.x = 1.0f; u.y = 2.0f; u.z = 4.0f; u.w = 10.0;
    v.x = -3.0f; v.y = 4.0f; v.z = -5.0f; v.w = 7.0;
    w.x = 4.0f; w.y =6.0f; w.z = -2.0f; w.w = 1.0f;
    x.x = 6.0f; x.y = -7.0f; x.z =8.0f; x.w = -9.0f;

    U(mat).m[0][0] = 1.0f; U(mat).m[0][1] = 2.0f; U(mat).m[0][2] = 3.0f; U(mat).m[0][3] = 4.0f;
    U(mat).m[1][0] = 5.0f; U(mat).m[1][1] = 6.0f; U(mat).m[1][2] = 7.0f; U(mat).m[1][3] = 8.0f;
    U(mat).m[2][0] = 9.0f; U(mat).m[2][1] = 10.0f; U(mat).m[2][2] = 11.0f; U(mat).m[2][3] = 12.0f;
    U(mat).m[3][0] = 13.0f; U(mat).m[3][1] = 14.0f; U(mat).m[3][2] = 15.0f; U(mat).m[3][3] = 16.0f;

    coeff1 = 2.0f; coeff2 = 5.0;
    scale = -6.5f;

/*_______________D3DXVec4Add__________________________*/
    expectedvec.x = -2.0f; expectedvec.y = 6.0f; expectedvec.z = -1.0f; expectedvec.w = 17.0f;
    D3DXVec4Add(&gotvec,&u,&v);
    expect_vec4(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec4Add(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec4Add(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec4BaryCentric____________________*/
    expectedvec.x = 8.0f; expectedvec.y = 26.0; expectedvec.z =  -44.0f; expectedvec.w = -41.0f;
    D3DXVec4BaryCentric(&gotvec,&u,&v,&w,coeff1,coeff2);
    expect_vec4(expectedvec,gotvec);

/*_______________D3DXVec4CatmullRom____________________*/
    expectedvec.x = 2754.625f; expectedvec.y = 2367.5625f; expectedvec.z = 1060.1875f; expectedvec.w = 131.3125f;
    D3DXVec4CatmullRom(&gotvec,&u,&v,&w,&x,scale);
    expect_vec4(expectedvec,gotvec);

/*_______________D3DXVec4Cross_________________________*/
    expectedvec.x = 390.0f; expectedvec.y = -393.0f; expectedvec.z = -316.0f; expectedvec.w = 166.0f;
    D3DXVec4Cross(&gotvec,&u,&v,&w);
    expect_vec4(expectedvec,gotvec);

/*_______________D3DXVec4Dot__________________________*/
    expected = 55.0f;
    got = D3DXVec4Dot(&u,&v);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec4Dot(NULL,&v);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    expected=0.0f;
    got = D3DXVec4Dot(NULL,NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec4Hermite_________________________*/
    expectedvec.x = 1224.625f; expectedvec.y = 3461.625f; expectedvec.z = -4758.875f; expectedvec.w = -5781.5f;
    D3DXVec4Hermite(&gotvec,&u,&v,&w,&x,scale);
    expect_vec4(expectedvec,gotvec);

/*_______________D3DXVec4Length__________________________*/
   expected = 11.0f;
   got = D3DXVec4Length(&u);
   ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
   /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec4Length(NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec4LengthSq________________________*/
    expected = 121.0f;
    got = D3DXVec4LengthSq(&u);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);
    /* Tests the case NULL */
    expected=0.0f;
    got = D3DXVec4LengthSq(NULL);
    ok(fabs( got - expected ) < admitted_error, "Expected: %f, Got: %f\n", expected, got);

/*_______________D3DXVec4Lerp__________________________*/
    expectedvec.x = 27.0f; expectedvec.y = -11.0f; expectedvec.z = 62.5;  expectedvec.w = 29.5;
    D3DXVec4Lerp(&gotvec,&u,&v,scale);
    expect_vec4(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec4Lerp(&gotvec,NULL,&v,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec4Lerp(NULL,NULL,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec4Maximize__________________________*/
    expectedvec.x = 1.0f; expectedvec.y = 4.0f; expectedvec.z = 4.0f; expectedvec.w = 10.0;
    D3DXVec4Maximize(&gotvec,&u,&v);
    expect_vec4(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec4Maximize(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec4Maximize(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec4Minimize__________________________*/
    expectedvec.x = -3.0f; expectedvec.y = 2.0f; expectedvec.z = -5.0f; expectedvec.w = 7.0;
    D3DXVec4Minimize(&gotvec,&u,&v);
    expect_vec4(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec4Minimize(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec4Minimize(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec4Normalize_________________________*/
    expectedvec.x = 1.0f/11.0f; expectedvec.y = 2.0f/11.0f; expectedvec.z = 4.0f/11.0f; expectedvec.w = 10.0f/11.0f;
    D3DXVec4Normalize(&gotvec,&u);
    expect_vec4(expectedvec,gotvec);
    /* Test the nul vector */
    expectedvec.x = 0.0f; expectedvec.y = 0.0f; expectedvec.z = 0.0f; expectedvec.w = 0.0f;
    D3DXVec4Normalize(&gotvec,&nul);
    expect_vec4(expectedvec,gotvec);

/*_______________D3DXVec4Scale____________________________*/
    expectedvec.x = -6.5f; expectedvec.y = -13.0f; expectedvec.z = -26.0f; expectedvec.w = -65.0f;
    D3DXVec4Scale(&gotvec,&u,scale);
    expect_vec4(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec4Scale(&gotvec,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec4Scale(NULL,NULL,scale);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec4Subtract__________________________*/
    expectedvec.x = 4.0f; expectedvec.y = -2.0f; expectedvec.z = 9.0f; expectedvec.w = 3.0f;
    D3DXVec4Subtract(&gotvec,&u,&v);
    expect_vec4(expectedvec,gotvec);
    /* Tests the case NULL */
    funcpointer = D3DXVec4Subtract(&gotvec,NULL,&v);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);
    funcpointer = D3DXVec4Subtract(NULL,NULL,NULL);
    ok(funcpointer == NULL, "Expected: %p, Got: %p\n", NULL, funcpointer);

/*_______________D3DXVec4Transform_______________________*/
    expectedtrans.x = 177.0f; expectedtrans.y = 194.0f; expectedtrans.z = 211.0f; expectedtrans.w = 228.0f;
    D3DXVec4Transform(&gottrans,&u,&mat);
    expect_vec4(expectedtrans,gottrans);
}

START_TEST(math)
{
    D3DXColorTest();
    D3DXMatrixTest();
    D3DXPlaneTest();
    D3X8QuaternionTest();
    D3X8Vector2Test();
    D3X8Vector3Test();
    D3X8Vector4Test();
}
