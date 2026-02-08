#pragma once
#if defined(CEMU_IOS)

#include <cstdint>
#include <atomic>

namespace ios_vpad
{
	static constexpr uint32_t A = 0x8000;
	static constexpr uint32_t B = 0x4000;
	static constexpr uint32_t X = 0x2000;
	static constexpr uint32_t Y = 0x1000;
	static constexpr uint32_t L = 0x0020;
	static constexpr uint32_t R = 0x0010;
	static constexpr uint32_t ZL = 0x0080;
	static constexpr uint32_t ZR = 0x0040;
	static constexpr uint32_t PLUS = 0x0008;
	static constexpr uint32_t MINUS = 0x0004;
	static constexpr uint32_t UP = 0x0200;
	static constexpr uint32_t DOWN = 0x0100;
	static constexpr uint32_t LEFT = 0x0800;
	static constexpr uint32_t RIGHT = 0x0400;
	static constexpr uint32_t STICK_L = 0x00040000;
	static constexpr uint32_t STICK_R = 0x00020000;
}

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
