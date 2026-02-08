#if defined(CEMU_IOS)
#include "iOSController.h"
#import <GameController/GameController.h>
#include "Cemu/Logging/CemuLogging.h"

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
					if (gamepad.buttonA.pressed) buttons |= ios_vpad::A;
					if (gamepad.buttonB.pressed) buttons |= ios_vpad::B;
					if (gamepad.buttonX.pressed) buttons |= ios_vpad::X;
					if (gamepad.buttonY.pressed) buttons |= ios_vpad::Y;
					if (gamepad.leftShoulder.pressed) buttons |= ios_vpad::L;
					if (gamepad.rightShoulder.pressed) buttons |= ios_vpad::R;
					if (gamepad.leftTrigger.pressed) buttons |= ios_vpad::ZL;
					if (gamepad.rightTrigger.pressed) buttons |= ios_vpad::ZR;
					if (gamepad.buttonMenu.pressed) buttons |= ios_vpad::PLUS;
					if (gamepad.buttonOptions.pressed) buttons |= ios_vpad::MINUS;
					if (gamepad.dpad.up.pressed) buttons |= ios_vpad::UP;
					if (gamepad.dpad.down.pressed) buttons |= ios_vpad::DOWN;
					if (gamepad.dpad.left.pressed) buttons |= ios_vpad::LEFT;
					if (gamepad.dpad.right.pressed) buttons |= ios_vpad::RIGHT;
					if (gamepad.leftThumbstickButton.pressed) buttons |= ios_vpad::STICK_L;
					if (gamepad.rightThumbstickButton.pressed) buttons |= ios_vpad::STICK_R;

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
