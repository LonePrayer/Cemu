#if defined(CEMU_IOS)
#include "iOSController.h"
#import <GameController/GameController.h>
#include "Cemu/Logging/CemuLogging.h"

// VPAD button flags (from ControllerVPADMapping2 in VPADController.cpp)
#define VPAD_A       0x8000
#define VPAD_B       0x4000
#define VPAD_X       0x2000
#define VPAD_Y       0x1000
#define VPAD_L       0x0020
#define VPAD_R       0x0010
#define VPAD_ZL      0x0080
#define VPAD_ZR      0x0040
#define VPAD_PLUS    0x0008
#define VPAD_MINUS   0x0004
#define VPAD_UP      0x0200
#define VPAD_DOWN    0x0100
#define VPAD_LEFT    0x0800
#define VPAD_RIGHT   0x0400
#define VPAD_STICK_L 0x00040000
#define VPAD_STICK_R 0x00020000

IOSControllerState g_iosControllerState;

void IOSController_init()
{
	cemuLog_log(LogType::Force, "IOSController: init");

	// Monitor controller connections
	[[NSNotificationCenter defaultCenter] addObserverForName:GCControllerDidConnectNotification
		object:nil queue:[NSOperationQueue mainQueue]
		usingBlock:^(NSNotification* note) {
			GCController* controller = note.object;
			cemuLog_log(LogType::Force, "IOSController: connected - {}", [controller.vendorName UTF8String] ?: "Unknown");
			g_iosControllerState.connected.store(true, std::memory_order_relaxed);

			// Set up value changed handler for extended gamepad
			if (controller.extendedGamepad)
			{
				controller.extendedGamepad.valueChangedHandler = ^(GCExtendedGamepad* gamepad, GCControllerElement* element) {
					uint32_t buttons = 0;
					if (gamepad.buttonA.pressed) buttons |= VPAD_A;
					if (gamepad.buttonB.pressed) buttons |= VPAD_B;
					if (gamepad.buttonX.pressed) buttons |= VPAD_X;
					if (gamepad.buttonY.pressed) buttons |= VPAD_Y;
					if (gamepad.leftShoulder.pressed) buttons |= VPAD_L;
					if (gamepad.rightShoulder.pressed) buttons |= VPAD_R;
					if (gamepad.leftTrigger.pressed) buttons |= VPAD_ZL;
					if (gamepad.rightTrigger.pressed) buttons |= VPAD_ZR;
					if (gamepad.buttonMenu.pressed) buttons |= VPAD_PLUS;
					if (gamepad.buttonOptions.pressed) buttons |= VPAD_MINUS;
					if (gamepad.dpad.up.pressed) buttons |= VPAD_UP;
					if (gamepad.dpad.down.pressed) buttons |= VPAD_DOWN;
					if (gamepad.dpad.left.pressed) buttons |= VPAD_LEFT;
					if (gamepad.dpad.right.pressed) buttons |= VPAD_RIGHT;
					if (gamepad.leftThumbstickButton.pressed) buttons |= VPAD_STICK_L;
					if (gamepad.rightThumbstickButton.pressed) buttons |= VPAD_STICK_R;

					g_iosControllerState.hold.store(buttons, std::memory_order_relaxed);
					g_iosControllerState.leftStickX.store(gamepad.leftThumbstick.xAxis.value, std::memory_order_relaxed);
					g_iosControllerState.leftStickY.store(gamepad.leftThumbstick.yAxis.value, std::memory_order_relaxed);
					g_iosControllerState.rightStickX.store(gamepad.rightThumbstick.xAxis.value, std::memory_order_relaxed);
					g_iosControllerState.rightStickY.store(gamepad.rightThumbstick.yAxis.value, std::memory_order_relaxed);
				};
			}
		}];

	[[NSNotificationCenter defaultCenter] addObserverForName:GCControllerDidDisconnectNotification
		object:nil queue:[NSOperationQueue mainQueue]
		usingBlock:^(NSNotification* note) {
			cemuLog_log(LogType::Force, "IOSController: disconnected");
			g_iosControllerState.connected.store(false, std::memory_order_relaxed);
			g_iosControllerState.hold.store(0, std::memory_order_relaxed);
			g_iosControllerState.leftStickX.store(0, std::memory_order_relaxed);
			g_iosControllerState.leftStickY.store(0, std::memory_order_relaxed);
			g_iosControllerState.rightStickX.store(0, std::memory_order_relaxed);
			g_iosControllerState.rightStickY.store(0, std::memory_order_relaxed);
		}];

	// Check for already connected controllers
	for (GCController* controller in [GCController controllers])
	{
		if (controller.extendedGamepad)
		{
			cemuLog_log(LogType::Force, "IOSController: already connected - {}", [controller.vendorName UTF8String] ?: "Unknown");
			g_iosControllerState.connected.store(true, std::memory_order_relaxed);
			// Post a fake connect notification to trigger handler setup
			[[NSNotificationCenter defaultCenter] postNotificationName:GCControllerDidConnectNotification object:controller];
			break;
		}
	}
}

#endif
