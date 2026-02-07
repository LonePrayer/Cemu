#pragma once
#if defined(CEMU_IOS)

#include <cstdint>
#include <atomic>

// Global iOS controller state — written by GCController polling, read by VPAD
struct IOSControllerState
{
	std::atomic<uint32_t> hold{0};     // VPAD button flags
	std::atomic<float> leftStickX{0};
	std::atomic<float> leftStickY{0};
	std::atomic<float> rightStickX{0};
	std::atomic<float> rightStickY{0};
	std::atomic<bool> connected{false};
};

extern IOSControllerState g_iosControllerState;

void IOSController_init();

#endif
