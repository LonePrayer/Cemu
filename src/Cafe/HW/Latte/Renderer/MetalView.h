#pragma once

#if defined(CEMU_IOS)
#import <UIKit/UIKit.h>
#import <QuartzCore/CAMetalLayer.h>

@interface MetalView : UIView
@end
#else
#import <Cocoa/Cocoa.h>
#import <QuartzCore/CAMetalLayer.h>

@interface MetalView : NSView
@end
#endif
