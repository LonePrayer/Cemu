#pragma once

#if HAS_OPENGL
#include "Common/GLInclude/GLInclude.h"
#else
using GLuint = unsigned int;
#endif

typedef struct
{
	GLuint glProgamId;
	struct
	{
		GLuint uniformLoc_textureSrc;
		GLuint uniformLoc_vertexOffsets;
	}copyShaderUniforms;
}LatteDefaultShader_t;

LatteDefaultShader_t* LatteDefaultShader_getPixelCopyShader_depthToColor();
LatteDefaultShader_t* LatteDefaultShader_getPixelCopyShader_colorToDepth();
