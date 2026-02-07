#include "Cafe/HW/Latte/Renderer/Metal/MetalVoidVertexPipeline.h"
#include "Cemu/Logging/CemuLogging.h"

MetalVoidVertexPipeline::MetalVoidVertexPipeline(class MetalRenderer* mtlRenderer, MTL::Library* library, const std::string& vertexFunctionName)
{
    m_renderPipelineState = nullptr;
    if (!library)
    {
        cemuLog_log(LogType::Force, "utility library missing for pipeline {}", vertexFunctionName);
        return;
    }

    // Render pipeline state
    NS_STACK_SCOPED MTL::Function* vertexFunction = library->newFunction(ToNSString(vertexFunctionName));
    if (!vertexFunction)
    {
        cemuLog_log(LogType::Force, "missing Metal function {}", vertexFunctionName);
        return;
    }

    NS_STACK_SCOPED MTL::RenderPipelineDescriptor* renderPipelineDescriptor = MTL::RenderPipelineDescriptor::alloc()->init();
    renderPipelineDescriptor->setVertexFunction(vertexFunction);
    renderPipelineDescriptor->setRasterizationEnabled(false);

    NS::Error* error = nullptr;
    m_renderPipelineState = mtlRenderer->GetDevice()->newRenderPipelineState(renderPipelineDescriptor, &error);
    if (error || !m_renderPipelineState)
    {
        if (error)
            cemuLog_log(LogType::Force, "error creating hybrid render pipeline state: {}", error->localizedDescription()->utf8String());
        if (m_renderPipelineState)
            m_renderPipelineState->release();
        m_renderPipelineState = nullptr;
    }
}

MetalVoidVertexPipeline::~MetalVoidVertexPipeline()
{
    if (m_renderPipelineState)
        m_renderPipelineState->release();
}
