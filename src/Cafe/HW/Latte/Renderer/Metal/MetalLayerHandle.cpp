#include "Cafe/HW/Latte/Renderer/Metal/MetalLayerHandle.h"
#include "Cafe/HW/Latte/Renderer/Metal/MetalLayer.h"

#include "gui/interface/WindowSystem.h"

#if defined(CEMU_IOS)
#include <dispatch/dispatch.h>
#include <pthread.h>
#endif

MetalLayerHandle::MetalLayerHandle(MTL::Device* device, const Vector2i& size, bool mainWindow)
{
    const auto& windowInfo = (mainWindow ? WindowSystem::GetWindowInfo().window_main : WindowSystem::GetWindowInfo().window_pad);

    m_layer = (CA::MetalLayer*)CreateMetalLayer(windowInfo.surface, m_layerScaleX, m_layerScaleY);
    m_layer->setDevice(device);
    m_layer->setDrawableSize(CGSize{(float)size.x * m_layerScaleX, (float)size.y * m_layerScaleY});
    m_layer->setFramebufferOnly(true);

    cemuLog_log(LogType::Force, "MetalLayerHandle: size={}x{} scale={}x{} drawableSize={}x{} mainWin={}",
        size.x, size.y, m_layerScaleX, m_layerScaleY,
        (int)(size.x * m_layerScaleX), (int)(size.y * m_layerScaleY), mainWindow);
}

MetalLayerHandle::~MetalLayerHandle()
{
#if !defined(CEMU_IOS)
    if (m_layer)
        m_layer->release();
#endif
}

void MetalLayerHandle::Resize(const Vector2i& size)
{
    m_layer->setDrawableSize(CGSize{(float)size.x * m_layerScaleX, (float)size.y * m_layerScaleY});
}

bool MetalLayerHandle::AcquireDrawable()
{
    if (m_drawable)
        return true;

#if defined(CEMU_IOS)
    // On iOS, CAMetalLayer must be accessed from the main thread to avoid
    // corrupting the CoreAnimation layer tree.
    __block CA::MetalDrawable* drawable = nullptr;
    auto acquireBlock = ^{
        drawable = m_layer->nextDrawable();
        if (drawable)
            drawable->retain();
    };
    if (pthread_main_np())
        acquireBlock();
    else
        dispatch_sync(dispatch_get_main_queue(), acquireBlock);
    m_drawable = drawable;
#else
    m_drawable = m_layer->nextDrawable();
#endif
    if (!m_drawable)
    {
        cemuLog_log(LogType::Force, "layer {} failed to acquire next drawable", (void*)this);
        return false;
    }

    return true;
}

void MetalLayerHandle::PresentDrawable(MTL::CommandBuffer* commandBuffer)
{
    commandBuffer->presentDrawable(m_drawable);
#if defined(CEMU_IOS)
    m_drawable->release();
#endif
    m_drawable = nullptr;
}
