@ stdcall D3DXVec2Normalize(ptr ptr)
@ stdcall D3DXVec2Hermite(ptr ptr ptr ptr ptr long)
@ stdcall D3DXVec2CatmullRom(ptr ptr ptr ptr ptr long)
@ stdcall D3DXVec2BaryCentric(ptr ptr ptr ptr long long)
@ stdcall D3DXVec2Transform(ptr ptr ptr)
@ stdcall D3DXVec2TransformCoord(ptr ptr ptr)
@ stdcall D3DXVec2TransformNormal(ptr ptr ptr)
@ stdcall D3DXVec3Normalize(ptr ptr)
@ stdcall D3DXVec3Hermite(ptr ptr ptr ptr ptr long)
@ stdcall D3DXVec3CatmullRom(ptr ptr ptr ptr ptr long)
@ stdcall D3DXVec3BaryCentric(ptr ptr ptr ptr long long)
@ stdcall D3DXVec3Transform(ptr ptr ptr)
@ stdcall D3DXVec3TransformCoord(ptr ptr ptr)
@ stdcall D3DXVec3TransformNormal(ptr ptr ptr)
@ stdcall D3DXVec3Project(ptr ptr ptr ptr ptr ptr)
@ stdcall D3DXVec3Unproject(ptr ptr ptr ptr ptr ptr)
@ stdcall D3DXVec4Cross(ptr ptr ptr ptr)
@ stdcall D3DXVec4Normalize(ptr ptr)
@ stdcall D3DXVec4Hermite(ptr ptr ptr ptr ptr long)
@ stdcall D3DXVec4CatmullRom(ptr ptr ptr ptr ptr long)
@ stdcall D3DXVec4BaryCentric(ptr ptr ptr ptr long long)
@ stdcall D3DXVec4Transform(ptr ptr ptr)
@ stdcall D3DXMatrixfDeterminant(ptr)
@ stdcall D3DXMatrixMultiply(ptr ptr ptr)
@ stdcall D3DXMatrixMultiplyTranspose(ptr ptr ptr)
@ stdcall D3DXMatrixTranspose(ptr ptr)
@ stdcall D3DXMatrixInverse(ptr ptr ptr)
@ stdcall D3DXMatrixScaling(ptr long long long)
@ stdcall D3DXMatrixTranslation(ptr long long long)
@ stdcall D3DXMatrixRotationX(ptr long)
@ stdcall D3DXMatrixRotationY(ptr long)
@ stdcall D3DXMatrixRotationZ(ptr long)
@ stdcall D3DXMatrixRotationAxis(ptr ptr long)
@ stdcall D3DXMatrixRotationQuaternion(ptr ptr)
@ stdcall D3DXMatrixRotationYawPitchRoll(ptr long long long)
@ stdcall D3DXMatrixTransformation(ptr ptr ptr ptr ptr ptr ptr)
@ stdcall D3DXMatrixAffineTransformation(ptr long ptr ptr ptr)
@ stdcall D3DXMatrixLookAtRH(ptr ptr ptr ptr)
@ stdcall D3DXMatrixLookAtLH(ptr ptr ptr ptr)
@ stdcall D3DXMatrixPerspectiveRH(ptr long long long long)
@ stdcall D3DXMatrixPerspectiveLH(ptr long long long long)
@ stdcall D3DXMatrixPerspectiveFovRH(ptr long long long long)
@ stdcall D3DXMatrixPerspectiveFovLH(ptr long long long long)
@ stdcall D3DXMatrixPerspectiveOffCenterRH(ptr long long long long long long)
@ stdcall D3DXMatrixPerspectiveOffCenterLH(ptr long long long long long long)
@ stdcall D3DXMatrixOrthoRH(ptr long long long long)
@ stdcall D3DXMatrixOrthoLH(ptr long long long long)
@ stdcall D3DXMatrixOrthoOffCenterRH(ptr long long long long long long)
@ stdcall D3DXMatrixOrthoOffCenterLH(ptr long long long long long long)
@ stdcall D3DXMatrixShadow(ptr ptr ptr)
@ stdcall D3DXMatrixReflect(ptr ptr)
@ stdcall D3DXQuaternionToAxisAngle(ptr ptr ptr)
@ stdcall D3DXQuaternionRotationMatrix(ptr ptr)
@ stdcall D3DXQuaternionRotationAxis(ptr ptr long)
@ stdcall D3DXQuaternionRotationYawPitchRoll(ptr long long long)
@ stdcall D3DXQuaternionMultiply(ptr ptr ptr)
@ stdcall D3DXQuaternionNormalize(ptr ptr)
@ stdcall D3DXQuaternionInverse(ptr ptr)
@ stdcall D3DXQuaternionLn(ptr ptr)
@ stdcall D3DXQuaternionExp(ptr ptr)
@ stdcall D3DXQuaternionSlerp(ptr ptr ptr long)
@ stdcall D3DXQuaternionSquad(ptr ptr ptr ptr ptr long)
@ stdcall D3DXQuaternionBaryCentric(ptr ptr ptr ptr long long)
@ stdcall D3DXPlaneNormalize(ptr ptr)
@ stdcall D3DXPlaneIntersectLine(ptr ptr ptr ptr)
@ stdcall D3DXPlaneFromPointNormal(ptr ptr ptr)
@ stdcall D3DXPlaneFromPoints(ptr ptr ptr ptr)
@ stdcall D3DXPlaneTransform(ptr ptr ptr)
@ stdcall D3DXColorAdjustSaturation(ptr ptr long)
@ stdcall D3DXColorAdjustContrast(ptr ptr long)
@ stdcall D3DXCreateMatrixStack(long ptr)
@ stdcall D3DXCreateFont(ptr ptr ptr)
@ stub D3DXCreateFontIndirect
@ stub D3DXCreateSprite
@ stub D3DXCreateRenderToSurface
@ stub D3DXCreateRenderToEnvMap
@ stdcall D3DXAssembleShaderFromFileA(ptr long ptr ptr ptr)
@ stdcall D3DXAssembleShaderFromFileW(ptr long ptr ptr ptr)
@ stdcall D3DXGetFVFVertexSize(long)
@ stub D3DXGetErrorStringA
@ stub D3DXGetErrorStringW
@ stdcall D3DXAssembleShader(ptr long long ptr ptr ptr)
@ stub D3DXCompileEffectFromFileA
@ stub D3DXCompileEffectFromFileW
@ stub D3DXCompileEffect
@ stub D3DXCreateEffect
@ stub D3DXCreateMesh
@ stub D3DXCreateMeshFVF
@ stub D3DXCreateSPMesh
@ stub D3DXCleanMesh
@ stub D3DXValidMesh
@ stub D3DXGeneratePMesh
@ stub D3DXSimplifyMesh
@ stub D3DXComputeBoundingSphere
@ stub D3DXComputeBoundingBox
@ stub D3DXComputeNormals
@ stdcall D3DXCreateBuffer(long ptr)
@ stub D3DXLoadMeshFromX
@ stub D3DXSaveMeshToX
@ stub D3DXCreatePMeshFromStream
@ stub D3DXCreateSkinMesh
@ stub D3DXCreateSkinMeshFVF
@ stub D3DXCreateSkinMeshFromMesh
@ stub D3DXLoadMeshFromXof
@ stub D3DXLoadSkinMeshFromXof
@ stub D3DXTesselateMesh
@ stub D3DXDeclaratorFromFVF
@ stub D3DXFVFFromDeclarator
@ stub D3DXWeldVertices
@ stub D3DXIntersect
@ stub D3DXSphereBoundProbe
@ stub D3DXBoxBoundProbe
@ stub D3DXCreatePolygon
@ stub D3DXCreateBox
@ stub D3DXCreateCylinder
@ stub D3DXCreateSphere
@ stub D3DXCreateTorus
@ stub D3DXCreateTeapot
@ stub D3DXCreateTextA
@ stub D3DXCreateTextW
@ stub D3DXLoadSurfaceFromFileA
@ stub D3DXLoadSurfaceFromFileW
@ stub D3DXLoadSurfaceFromResourceA
@ stub D3DXLoadSurfaceFromResourceW
@ stub D3DXLoadSurfaceFromFileInMemory
@ stub D3DXLoadSurfaceFromSurface
@ stub D3DXLoadSurfaceFromMemory
@ stub D3DXLoadVolumeFromVolume
@ stub D3DXLoadVolumeFromMemory
@ stub D3DXCheckTextureRequirements
@ stub D3DXCreateTexture
@ stub D3DXCreateTextureFromFileA
@ stub D3DXCreateTextureFromFileW
@ stub D3DXCreateTextureFromResourceA
@ stub D3DXCreateTextureFromResourceW
@ stub D3DXCreateTextureFromFileExA
@ stub D3DXCreateTextureFromFileExW
@ stub D3DXCreateTextureFromResourceExA
@ stub D3DXCreateTextureFromResourceExW
@ stub D3DXCreateTextureFromFileInMemory
@ stub D3DXCreateTextureFromFileInMemoryEx
@ stub D3DXFilterTexture
@ stub D3DXCheckCubeTextureRequirements
@ stub D3DXCreateCubeTexture
@ stub D3DXCreateCubeTextureFromFileA
@ stub D3DXCreateCubeTextureFromFileW
@ stub D3DXCreateCubeTextureFromFileExA
@ stub D3DXCreateCubeTextureFromFileExW
@ stub D3DXCreateCubeTextureFromFileInMemory
@ stub D3DXCreateCubeTextureFromFileInMemoryEx
@ stub D3DXFilterCubeTexture
@ stub D3DXCheckVolumeTextureRequirements
@ stub D3DXCreateVolumeTexture
@ stub D3DXFilterVolumeTexture
