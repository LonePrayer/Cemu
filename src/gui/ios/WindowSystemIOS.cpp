#include "interface/WindowSystem.h"

#include <string>

namespace WindowSystem
{
	static WindowInfo g_window_info{};

	extern "C" void CemuIOS_ShowErrorDialog(const char* message, const char* title);

	void ShowErrorDialog(std::string_view message, std::string_view title, std::optional<ErrorCategory> /*errorCategory*/)
	{
		if (message.empty())
			return;

		std::string messageCopy(message);
		std::string titleCopy(title);
		CemuIOS_ShowErrorDialog(messageCopy.c_str(), titleCopy.c_str());
	}

	void Create()
	{
		g_window_info.app_active.store(true);
		g_window_info.dpi_scale.store(1.0);
		g_window_info.pad_dpi_scale.store(1.0);
		g_window_info.window_main.backend = WindowHandleInfo::Backend::Cocoa;
		g_window_info.window_pad.backend = WindowHandleInfo::Backend::Cocoa;
		g_window_info.canvas_main.backend = WindowHandleInfo::Backend::Cocoa;
		g_window_info.canvas_pad.backend = WindowHandleInfo::Backend::Cocoa;
	}

	WindowInfo& GetWindowInfo()
	{
		return g_window_info;
	}

	void UpdateWindowTitles(bool /*isIdle*/, bool /*isLoading*/, double /*fps*/)
	{
	}

	void GetWindowSize(int& w, int& h)
	{
		w = g_window_info.width.load();
		h = g_window_info.height.load();
	}

	void GetPadWindowSize(int& w, int& h)
	{
		w = g_window_info.pad_width.load();
		h = g_window_info.pad_height.load();
	}

	void GetWindowPhysSize(int& w, int& h)
	{
		w = g_window_info.phys_width.load();
		h = g_window_info.phys_height.load();
	}

	void GetPadWindowPhysSize(int& w, int& h)
	{
		w = g_window_info.phys_pad_width.load();
		h = g_window_info.phys_pad_height.load();
	}

	double GetWindowDPIScale()
	{
		return g_window_info.dpi_scale.load();
	}

	double GetPadDPIScale()
	{
		return g_window_info.pad_dpi_scale.load();
	}

	bool IsPadWindowOpen()
	{
		return g_window_info.pad_open.load();
	}

	bool IsKeyDown(uint32 key)
	{
		return g_window_info.get_keystate(key);
	}

	bool IsKeyDown(PlatformKeyCodes /*key*/)
	{
		return false;
	}

	std::string GetKeyCodeName(uint32 /*key*/)
	{
		return {};
	}

	bool InputConfigWindowHasFocus()
	{
		return false;
	}

	void NotifyGameLoaded()
	{
	}

	void NotifyGameExited()
	{
	}

	void RefreshGameList()
	{
	}

	bool IsFullScreen()
	{
		return g_window_info.is_fullscreen.load();
	}

	void CaptureInput(const ControllerState& /*currentState*/, const ControllerState& /*lastState*/)
	{
	}
} // namespace WindowSystem
