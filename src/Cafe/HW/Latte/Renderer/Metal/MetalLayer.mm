#include "Cafe/HW/Latte/Renderer/Metal/MetalLayer.h"

#include "Cafe/HW/Latte/Renderer/MetalView.h"

void* CreateMetalLayer(void* handle, float& scaleX, float& scaleY)
{
#if defined(CEMU_IOS)
	UIView* view = (UIView*)handle;

	__block MetalView* childView = nil;
	__block CGFloat scale = 1.0;

	void (^createBlock)(void) = ^{
		childView = [[MetalView alloc] initWithFrame:view.bounds];
		childView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
		// Ensure native screen scale is used (contentScaleFactor may default to 1.0
		// if the view is created before being fully attached to the window)
		CGFloat nativeScale = UIScreen.mainScreen.scale;
		childView.contentScaleFactor = nativeScale;
		CAMetalLayer* metalLayer = (CAMetalLayer*)childView.layer;
		metalLayer.contentsScale = nativeScale;
		[view addSubview:childView];
		scale = nativeScale;
	};

	if ([NSThread isMainThread])
		createBlock();
	else
		dispatch_sync(dispatch_get_main_queue(), createBlock);

	scaleX = (float)scale;
	scaleY = (float)scale;

	return childView.layer;
#else
	NSView* view = (NSView*)handle;

	MetalView* childView = [[MetalView alloc] initWithFrame:view.bounds];
	childView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
	childView.wantsLayer = YES;

	[view addSubview:childView];

	const NSRect points = [childView frame];
    const NSRect pixels = [childView convertRectToBacking:points];

	scaleX = (float)(pixels.size.width / points.size.width);
    scaleY = (float)(pixels.size.height / points.size.height);

	return childView.layer;
#endif
}
