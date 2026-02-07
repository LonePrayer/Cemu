#import <UIKit/UIKit.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <cstring>
#include <fstream>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>

// Write logs to both stderr and a file in Documents for retrieval
static FILE* g_logFile = nullptr;
static void openLogFile() {
    if (g_logFile) return;
    NSArray* paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    if (paths.count > 0) {
        NSString* logPath = [paths.firstObject stringByAppendingPathComponent:@"cemu_launch.log"];
        g_logFile = fopen(logPath.UTF8String, "w");
    }
}
#define IOSLOG(fmt, ...) do { \
    fprintf(stderr, "[CemuIOS] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
    if (g_logFile) { fprintf(g_logFile, "[CemuIOS] " fmt "\n", ##__VA_ARGS__); fflush(g_logFile); } \
} while(0)

#include <fmt/format.h>

#include "Cemu/Logging/CemuLogging.h"
#include "Cafe/GraphicPack/GraphicPack2.h"
#include "Cafe/CafeSystem.h"
#include "Cafe/HW/Latte/Core/LatteOverlay.h"
#include "Cafe/HW/Latte/Renderer/Metal/MetalRenderer.h"
#include "Cafe/HW/Latte/Renderer/Renderer.h"
#include "Cafe/HW/Espresso/PPCState.h"
#include "Cafe/TitleList/SaveList.h"
#include "Cafe/TitleList/TitleInfo.h"
#include "Cafe/TitleList/TitleList.h"
#include "Cemu/ncrypto/ncrypto.h"
#include "Common/ExceptionHandler/ExceptionHandler.h"
#include "config/ActiveSettings.h"
#include "input/api/iOSController.h"
#include "audio/IAudioAPI.h"
#include "audio/IAudioInputAPI.h"
#include "config/ActiveSettings.h"
#include "config/CemuConfig.h"
#include "config/NetworkSettings.h"
#include "Cafe/OS/libs/swkbd/swkbd.h"
#include "gui/interface/WindowSystem.h"
#include "input/InputManager.h"
#include "util/crypto/aes128.h"
#include "util/helpers/helpers.h"

#include <curl/curl.h>
#include <zip.h>
#include <rapidjson/document.h>
#include "Common/FileStream.h"

std::atomic_bool g_isGPUInitFinished = false;
std::atomic<uint32_t> g_cemuFrameCounter{0}; // incremented each frame swap, read by FPS label
std::atomic_bool g_renderPadView{false}; // user setting: render GamePad (DRC) view
void LatteDraw_cleanupAfterFrame() {}
void LatteDraw_handleSpecialState8_clearAsDepth() {}

#include <sys/types.h>
#include <sys/sysctl.h>

// PT_TRACE_ME sets CS_DEBUGGED flag which enables JIT on iOS
#define PT_TRACE_ME 0
extern "C" int ptrace(int request, pid_t pid, caddr_t addr, int data);

static void EnableJIT()
{
	// Method 1: ptrace(PT_TRACE_ME) - sets CS_DEBUGGED flag
	int ret = ptrace(PT_TRACE_ME, 0, nullptr, 0);
	IOSLOG("ptrace(PT_TRACE_ME) returned %d, errno=%d (%s)", ret, errno, strerror(errno));

	// Method 2: Try via syscall if ptrace symbol fails
	// syscall(26 /* SYS_ptrace */, 0 /* PT_TRACE_ME */, 0, 0, 0);
}

namespace
{
UIViewController* g_rootController = nil;
UIView* g_renderView = nil;
UIView* g_padView = nil;
bool g_cemu_initialized = false;

// --- Security-scoped bookmark helpers for Game Paths ---
static NSString* const kGamePathBookmarksKey = @"gamePathBookmarks";

static NSArray<NSData*>* LoadGamePathBookmarks()
{
	NSArray* arr = [[NSUserDefaults standardUserDefaults] arrayForKey:kGamePathBookmarksKey];
	if (!arr) return @[];
	return arr;
}

static void SaveGamePathBookmarks(NSArray<NSData*>* bookmarks)
{
	[[NSUserDefaults standardUserDefaults] setObject:bookmarks forKey:kGamePathBookmarksKey];
}

// Resolve all saved bookmarks, start accessing, and add as scan paths
static void ResolveAndActivateGamePathBookmarks()
{
	NSArray<NSData*>* bookmarks = LoadGamePathBookmarks();
	NSMutableArray<NSData*>* validBookmarks = [NSMutableArray array];
	for (NSData* data in bookmarks)
	{
		BOOL stale = NO;
		NSError* err = nil;
		NSURL* url = [NSURL URLByResolvingBookmarkData:data options:0 relativeToURL:nil bookmarkDataIsStale:&stale error:&err];
		if (url && !err)
		{
			[url startAccessingSecurityScopedResource];
			[validBookmarks addObject:data];
			CafeTitleList::AddScanPath(fs::path(url.fileSystemRepresentation));
			cemuLog_log(LogType::Force, "Game path bookmark resolved: {}", url.fileSystemRepresentation);
		}
	}
	if (validBookmarks.count != bookmarks.count)
		SaveGamePathBookmarks(validBookmarks);
}

// --- Graphic Packs Download ---
static size_t curlWriteCallback(void* ptr, size_t size, size_t nmemb, std::vector<uint8>* data)
{
	size_t total = size * nmemb;
	size_t oldSize = data->size();
	data->resize(oldSize + total);
	memcpy(data->data() + oldSize, ptr, total);
	return total;
}

static bool curlDownload(const char* url, std::vector<uint8>& outData)
{
	CURL* curl = curl_easy_init();
	if (!curl) return false;
	outData.clear();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &outData);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "CemuIOS/1.0");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
	CURLcode res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	return res == CURLE_OK;
}

// Returns error string or empty on success
static std::string DownloadAndExtractGraphicPacks()
{
	cemuLog_log(LogType::Force, "DownloadGraphicPacks: starting");
	// 1. Get latest release info from GitHub API
	std::vector<uint8> apiData;
	const char* apiUrl = "https://api.github.com/repos/cemu-project/cemu_graphic_packs/releases/latest";
	if (!curlDownload(apiUrl, apiData))
		return "Failed to connect to GitHub API";

	rapidjson::Document doc;
	doc.Parse((const char*)apiData.data(), apiData.size());
	if (doc.HasParseError() || !doc.IsObject())
		return "Failed to parse GitHub API response";

	if (!doc.HasMember("name") || !doc["name"].IsString())
		return "Invalid API response (no name)";
	std::string releaseName = doc["name"].GetString();

	// Check if already up to date
	auto versionPath = ActiveSettings::GetUserDataPath("graphicPacks/downloadedGraphicPacks/version.txt");
	{
		std::unique_ptr<FileStream> vf(FileStream::openFile2(versionPath));
		std::string existingVersion;
		if (vf && vf->readLine(existingVersion) && existingVersion == releaseName)
			return ""; // already up to date
	}

	if (!doc.HasMember("assets") || !doc["assets"].IsArray() || doc["assets"].GetArray().Size() == 0)
		return "No assets in release";
	auto& asset = doc["assets"].GetArray()[0];
	if (!asset.HasMember("browser_download_url") || !asset["browser_download_url"].IsString())
		return "No download URL in asset";
	const char* downloadUrl = asset["browser_download_url"].GetString();

	cemuLog_log(LogType::Force, "DownloadGraphicPacks: downloading from {}", downloadUrl);

	// 2. Download ZIP
	std::vector<uint8> zipData;
	if (!curlDownload(downloadUrl, zipData))
		return "Failed to download graphic packs ZIP";

	cemuLog_log(LogType::Force, "DownloadGraphicPacks: downloaded {} bytes, extracting", zipData.size());

	// 3. Extract ZIP
	zip_error_t zipErr;
	zip_error_init(&zipErr);
	zip_source_t* src = zip_source_buffer_create(zipData.data(), zipData.size(), 0, &zipErr);
	if (!src) { zip_error_fini(&zipErr); return "Failed to create zip source"; }

	zip_t* za = zip_open_from_source(src, 0, &zipErr);
	if (!za) { zip_source_free(src); zip_error_fini(&zipErr); return "Failed to open zip"; }

	auto basePath = ActiveSettings::GetUserDataPath("graphicPacks/downloadedGraphicPacks");
	std::error_code ec;
	// Clean existing
	if (fs::exists(basePath, ec))
	{
		for (auto& p : fs::directory_iterator(basePath, ec))
			fs::remove_all(p.path(), ec);
	}
	fs::create_directories(basePath, ec);

	sint32 numEntries = zip_get_num_entries(za, 0);
	for (sint32 i = 0; i < numEntries; i++)
	{
		zip_stat_t sb{};
		if (zip_stat_index(za, i, 0, &sb) != 0) continue;
		if (!sb.name || strlen(sb.name) == 0) continue;
		if (strstr(sb.name, "../") || strstr(sb.name, "..\\")) continue;

		auto entryPath = ActiveSettings::GetUserDataPath("graphicPacks/downloadedGraphicPacks/{}", sb.name);
		if (sb.name[strlen(sb.name) - 1] == '/')
		{
			fs::create_directories(entryPath, ec);
			continue;
		}
		if (sb.size == 0 || sb.size > 128 * 1024 * 1024) continue;

		zip_file_t* zf = zip_fopen_index(za, i, 0);
		if (!zf) continue;

		std::vector<uint8> buf(sb.size);
		if (zip_fread(zf, buf.data(), sb.size) == (zip_int64_t)sb.size)
		{
			fs::create_directories(entryPath.parent_path(), ec);
			FileStream* fout = FileStream::createFile2(entryPath);
			if (fout) { fout->writeData(buf.data(), buf.size()); delete fout; }
		}
		zip_fclose(zf);
	}
	zip_close(za);

	// Write version file
	{
		FileStream* vf = FileStream::createFile2(versionPath);
		if (vf) { vf->writeString(releaseName.c_str()); delete vf; }
	}

	cemuLog_log(LogType::Force, "DownloadGraphicPacks: extracted {} entries", numEntries);
	return "";
}

// csops to check code-signing flags (CS_DEBUGGED)
#include <sys/types.h>
extern "C" int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define CS_OPS_STATUS    0
#define CS_DEBUGGED      0x10000000

bool CheckJitEnabled(std::string& detail)
{
	// Approach 1: MAP_JIT — works with proper entitlement (e.g. SideStore JIT)
	{
		void* mem = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
						 MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
		if (mem != MAP_FAILED)
		{
			munmap(mem, 4096);
			IOSLOG("JIT check: MAP_JIT+RWX mmap succeeded");
			detail = "MAP_JIT";
			return true;
		}
		IOSLOG("JIT check: MAP_JIT mmap failed: %s", strerror(errno));
	}

	// Approach 2: Check CS_DEBUGGED flag (set when debugger is attached)
	// If CS_DEBUGGED is set, anon+RWX pages are truly executable.
	{
		uint32_t flags = 0;
		if (csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags)) == 0)
		{
			IOSLOG("JIT check: csops flags=0x%08x CS_DEBUGGED=%s", flags,
				   (flags & CS_DEBUGGED) ? "YES" : "NO");
			if (flags & CS_DEBUGGED)
			{
				// Verify anon+RWX mmap works too
				void* mem = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
								 MAP_PRIVATE | MAP_ANON, -1, 0);
				if (mem != MAP_FAILED)
				{
					munmap(mem, 4096);
					detail = "CS_DEBUGGED (debugger)";
					return true;
				}
				IOSLOG("JIT check: CS_DEBUGGED set but anon+RWX failed: %s", strerror(errno));
			}
		}
		else
		{
			IOSLOG("JIT check: csops failed: %s", strerror(errno));
		}
	}

	detail = "No executable memory available";
	return false;
}

void UpdateWindowInfo(UIView* view)
{
	if (!view)
		return;

	auto& info = WindowSystem::GetWindowInfo();
	const CGRect bounds = view.bounds;
	// Use native screen scale — contentScaleFactor may report 1.0 before view is in window
	const CGFloat scale = UIScreen.mainScreen.scale;

	info.app_active.store(true);
	info.width.store(static_cast<int>(bounds.size.width));
	info.height.store(static_cast<int>(bounds.size.height));
	info.phys_width.store(static_cast<int>(bounds.size.width * scale));
	info.phys_height.store(static_cast<int>(bounds.size.height * scale));
	info.dpi_scale.store(scale);

	info.window_main.backend = WindowSystem::WindowHandleInfo::Backend::Cocoa;
	info.canvas_main.backend = WindowSystem::WindowHandleInfo::Backend::Cocoa;
	info.window_main.surface = (__bridge void*)view;
	info.canvas_main.surface = (__bridge void*)view;

	// Pad/DRC view
	if (g_padView && !g_padView.hidden && g_padView.bounds.size.width > 0 && g_padView.bounds.size.height > 0)
	{
		const CGRect padBounds = g_padView.bounds;
		info.pad_width.store(static_cast<int>(padBounds.size.width));
		info.pad_height.store(static_cast<int>(padBounds.size.height));
		info.phys_pad_width.store(static_cast<int>(padBounds.size.width * scale));
		info.phys_pad_height.store(static_cast<int>(padBounds.size.height * scale));
		info.pad_dpi_scale.store(scale);
		info.window_pad.backend = WindowSystem::WindowHandleInfo::Backend::Cocoa;
		info.canvas_pad.backend = WindowSystem::WindowHandleInfo::Backend::Cocoa;
		info.window_pad.surface = (__bridge void*)g_padView;
		info.canvas_pad.surface = (__bridge void*)g_padView;
		info.pad_open.store(true);
	}
	else
	{
		info.pad_open.store(false);
	}
}

fs::path GetSearchPath(NSSearchPathDirectory directory)
{
	NSArray<NSString*>* paths = NSSearchPathForDirectoriesInDomains(directory, NSUserDomainMask, YES);
	if (paths.count == 0)
		return {};
	return _utf8ToPath(paths.firstObject.UTF8String);
}

bool HasTitleFolders(const fs::path& path);
std::optional<fs::path> FindTitleTmd(const fs::path& path, std::string& error);

struct GameCandidateList
{
	std::vector<fs::path> paths;
	std::vector<std::string> names;
	std::string message;
};

GameCandidateList CollectGameCandidates()
{
	GameCandidateList list;
	const fs::path documentsPath = GetSearchPath(NSDocumentDirectory);
	IOSLOG("CollectGameCandidates: documentsPath=%s", documentsPath.c_str());
	if (!documentsPath.empty())
	{
		std::error_code ec;
		for (const auto& entry : fs::directory_iterator(documentsPath, ec))
		{
			IOSLOG("CollectGameCandidates: checking %s (is_dir=%d)", entry.path().c_str(), entry.is_directory(ec) ? 1 : 0);
			if (ec || !entry.is_directory(ec))
				continue;
			std::string error;
			if (HasTitleFolders(entry.path()))
			{
				IOSLOG("CollectGameCandidates: found title folders at %s", entry.path().c_str());
				list.paths.push_back(entry.path());
				list.names.push_back(_pathToUtf8(entry.path().filename()));
				continue;
			}
			auto tmdPath = FindTitleTmd(entry.path(), error);
			if (tmdPath.has_value())
			{
				IOSLOG("CollectGameCandidates: found TMD at %s", tmdPath.value().c_str());
				list.paths.push_back(tmdPath.value());
				list.names.push_back(_pathToUtf8(entry.path().filename()));
				continue;
			}
			if (!error.empty())
			{
				IOSLOG("CollectGameCandidates: error for %s: %s", entry.path().c_str(), error.c_str());
				list.message = error;
			}
		}
		if (ec)
			IOSLOG("CollectGameCandidates: directory_iterator error: %s", ec.message().c_str());
	}
	IOSLOG("CollectGameCandidates: found %zu candidates", list.paths.size());
	return list;
}

void DeterminePathsIOS(std::set<fs::path>& failedWriteAccess)
{
	const fs::path executablePath = _utf8ToPath([NSBundle mainBundle].executablePath.UTF8String);
	const fs::path userDataPath = GetSearchPath(NSDocumentDirectory) / "Cemu";
	const fs::path configPath = GetSearchPath(NSApplicationSupportDirectory) / "Cemu";
	const fs::path cachePath = GetSearchPath(NSCachesDirectory) / "Cemu";
	const fs::path dataPath = _utf8ToPath([NSBundle mainBundle].resourcePath.UTF8String) / "data";

	ActiveSettings::SetPaths(false, executablePath, userDataPath, configPath, cachePath, dataPath, failedWriteAccess);
}

bool CreateDefaultMLCFiles(const fs::path& mlc)
{
	auto createDirectoriesIfNotExist = [](const fs::path& path)
	{
		std::error_code ec;
		if (!fs::exists(path, ec))
			return fs::create_directories(path, ec);
		return true;
	};

	const fs::path directories[] = {
		mlc,
		mlc / "sys",
		mlc / "usr",
		mlc / "usr/title/00050000",
		mlc / "usr/title/0005000c",
		mlc / "usr/title/0005000e",
		mlc / "usr/save/00050010/1004a000/user/common/db",
		mlc / "usr/save/00050010/1004a100/user/common/db",
		mlc / "usr/save/00050010/1004a200/user/common/db",
		mlc / "sys/title/0005001b/1005c000/content"
	};

	for (auto& path : directories)
	{
		if (!createDirectoriesIfNotExist(path))
			return false;
	}

	try
	{
		const auto langDir = fs::path(mlc).append("sys/title/0005001b/1005c000/content");
		auto langFile = fs::path(langDir).append("language.txt");
		if (!fs::exists(langFile))
		{
			std::ofstream file(langFile);
			if (file.is_open())
			{
				const char* langStrings[] = { "ja","en","fr","de","it","es","zh","ko","nl","pt","ru","zh" };
				for (const char* lang : langStrings)
					file << fmt::format(R"("{}",)", lang) << std::endl;
				file.flush();
				file.close();
			}
		}

		auto countryFile = fs::path(langDir).append("country.txt");
		if (!fs::exists(countryFile))
		{
			std::ofstream file(countryFile);
			for (sint32 i = 0; i < NCrypto::GetCountryCount(); i++)
			{
				const char* countryCode = NCrypto::GetCountryAsString(i);
				if (std::strcmp(countryCode, "NN") == 0)
					file << "NULL," << std::endl;
				else
					file << fmt::format(R"("{}",)", countryCode) << std::endl;
			}
			file.flush();
			file.close();
		}

		const auto dummyFile = fs::path(mlc).append("writetestdummy");
		std::ofstream file(dummyFile);
		if (!file.is_open())
			return false;
		file.close();
		fs::remove(dummyFile);
	}
	catch (const std::exception&)
	{
		return false;
	}
	return true;
}

void CreateDefaultCemuFiles()
{
	try
	{
		const auto controllerProfileFolder = ActiveSettings::GetConfigPath("controllerProfiles");
		if (!fs::exists(controllerProfileFolder))
			fs::create_directories(controllerProfileFolder);

		const auto memorySearcherFolder = ActiveSettings::GetUserDataPath("memorySearcher");
		if (!fs::exists(memorySearcherFolder))
			fs::create_directories(memorySearcherFolder);
	}
	catch (const std::exception& ex)
	{
		WindowSystem::ShowErrorDialog(
			fmt::format("Couldn't create a required Cemu directory or file!\n\nError: {}", ex.what()),
			"Error");
		exit(0);
	}
}

void InitializeMLCOrFail()
{
	if (CreateDefaultMLCFiles(ActiveSettings::GetMlcPath()))
		return;

	WindowSystem::ShowErrorDialog(
		fmt::format("Cemu failed to write to the mlc directory.\nThe path is:\n{}",
			_pathToUtf8(ActiveSettings::GetMlcPath())),
		"Error");
	exit(0);
}

struct LaunchResult
{
	bool success = false;
	std::string titleName;
	std::string error;
};

bool HasTitleFolders(const fs::path& path)
{
	std::error_code ec;
	return fs::exists(path / "code", ec) && fs::exists(path / "content", ec) && fs::exists(path / "meta", ec);
}

std::optional<fs::path> FindTitleTmd(const fs::path& path, std::string& error)
{
	std::error_code ec;
	const fs::path tmdPath = path / "title.tmd";
	if (fs::exists(tmdPath, ec))
		return tmdPath;

	std::vector<fs::path> candidates;
	for (const auto& entry : fs::directory_iterator(path, ec))
	{
		if (ec || !entry.is_directory(ec))
			continue;
		const fs::path nestedTmd = entry.path() / "title.tmd";
		if (fs::exists(nestedTmd, ec))
			candidates.push_back(nestedTmd);
	}

	if (candidates.size() == 1)
		return candidates.front();
	if (candidates.size() > 1)
		error = "This folder contains multiple titles. Please select the folder that directly contains code/content/meta or title.tmd.";
	return std::nullopt;
}

fs::path ResolveLaunchPath(const fs::path& launchPath, std::string& error)
{
	std::error_code ec;
	if (!fs::is_directory(launchPath, ec))
		return launchPath;

	const std::string leafName = _pathToUtf8(launchPath.filename());
	if (leafName == "code" || leafName == "content" || leafName == "meta")
	{
		const fs::path parent = launchPath.parent_path();
		if (!parent.empty() && HasTitleFolders(parent))
			return parent;
	}

	if (HasTitleFolders(launchPath))
		return launchPath;
	auto tmdPath = FindTitleTmd(launchPath, error);
	if (tmdPath.has_value())
		return tmdPath.value();

	std::vector<fs::path> candidates;
	for (const auto& entry : fs::directory_iterator(launchPath, ec))
	{
		if (ec || !entry.is_directory(ec))
			continue;
		if (HasTitleFolders(entry.path()))
			candidates.push_back(entry.path());
	}

	if (candidates.size() == 1)
		return candidates.front();
	if (candidates.size() > 1)
		error = "This folder contains multiple titles. Please select the folder that directly contains code/content/meta.";

	return launchPath;
}

LaunchResult PrepareGameFromPath(const fs::path& launchPath)
{
	LaunchResult result;
	if (CafeSystem::IsTitleRunning())
	{
		result.error = "A title is already running.";
		return result;
	}

	std::string resolveError;
	const fs::path resolvedPath = ResolveLaunchPath(launchPath, resolveError);
	if (!resolveError.empty())
	{
		result.error = resolveError;
		cemuLog_log(LogType::Force, "Launch failed: {}", resolveError);
		return result;
	}

	cemuLog_log(LogType::Force, "Preparing title from path: {}", _pathToUtf8(resolvedPath));

	// Auto-scan sibling directories for updates/DLC
	{
		const fs::path parentDir = resolvedPath.parent_path();
		if (!parentDir.empty())
		{
			cemuLog_log(LogType::Force, "Auto-scanning parent directory: {}", _pathToUtf8(parentDir));
			CafeTitleList::AddScanPath(parentDir);
			// Also scan sibling directories (e.g., rom-update next to rom)
			const fs::path grandParent = parentDir.parent_path();
			if (!grandParent.empty())
			{
				std::error_code ec;
				for (const auto& entry : fs::directory_iterator(grandParent, ec))
				{
					if (entry.is_directory(ec))
					{
						cemuLog_log(LogType::Force, "Auto-scanning sibling: {}", _pathToUtf8(entry.path()));
						CafeTitleList::AddScanPath(entry.path());
					}
				}
			}
			CafeTitleList::Refresh();
			// Wait for scan to complete
			for (int i = 0; i < 40 && CafeTitleList::IsScanning(); i++)
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}

	TitleInfo launchTitle{resolvedPath};
	if (launchTitle.IsValid())
	{
		cemuLog_log(LogType::Force, "Title is valid, adding to title list");
		CafeTitleList::AddTitleFromPath(resolvedPath);
		TitleId baseTitleId;
		if (!CafeTitleList::FindBaseTitleId(launchTitle.GetAppTitleId(), baseTitleId))
		{
			result.error = "Unable to launch game because the base files were not found.";
			cemuLog_log(LogType::Force, "Launch failed: {}", result.error);
			return result;
		}
		cemuLog_log(LogType::Force, "Preparing foreground title");
		const auto r = CafeSystem::PrepareForegroundTitle(baseTitleId);
		if (r == CafeSystem::PREPARE_STATUS_CODE::UNABLE_TO_MOUNT)
		{
			result.error = fmt::format("Unable to mount title.\nPath:\n{}", _pathToUtf8(resolvedPath));
			cemuLog_log(LogType::Force, "Launch failed: {}", result.error);
			return result;
		}
		if (r != CafeSystem::PREPARE_STATUS_CODE::SUCCESS)
		{
			result.error = fmt::format("Failed to launch game.\nPath:\n{}", _pathToUtf8(resolvedPath));
			cemuLog_log(LogType::Force, "Launch failed: {}", result.error);
			return result;
		}
	}
	else
	{
		const CafeTitleFileType fileType = DetermineCafeSystemFileType(resolvedPath);
		if (fileType == CafeTitleFileType::RPX || fileType == CafeTitleFileType::ELF)
		{
			cemuLog_log(LogType::Force, "Preparing standalone executable");
			const auto r = CafeSystem::PrepareForegroundTitleFromStandaloneRPX(resolvedPath);
			if (r != CafeSystem::PREPARE_STATUS_CODE::SUCCESS)
			{
				result.error = fmt::format("Failed to launch executable.\nPath:\n{}", _pathToUtf8(resolvedPath));
				cemuLog_log(LogType::Force, "Launch failed: {}", result.error);
				return result;
			}
		}
		else
		{
			result.error = fmt::format("Unable to launch game.\nPath:\n{}", _pathToUtf8(resolvedPath));
			if (launchTitle.GetInvalidReason() == TitleInfo::InvalidReason::NO_DISC_KEY)
				result.error.append("\n\nCould not decrypt title. Make sure keys.txt contains the correct disc key.");
			if (launchTitle.GetInvalidReason() == TitleInfo::InvalidReason::NO_TITLE_TIK)
				result.error.append("\n\nCould not decrypt title because title.tik is missing.");
			std::error_code ec;
			if (fs::is_directory(resolvedPath, ec) && launchTitle.GetInvalidReason() == TitleInfo::InvalidReason::UNKNOWN_FORMAT)
				result.error.append("\n\nPlease select the folder that directly contains code/content/meta, or the title.tmd file for WUP/NUS dumps (.app/.h3). ");
			cemuLog_log(LogType::Force, "Launch failed: {}", result.error);
			return result;
		}
	}

	result.success = true;
	result.titleName = CafeSystem::GetForegroundTitleName();
	if (result.titleName.empty())
		result.titleName = _pathToUtf8(resolvedPath.filename());
	return result;
}

bool EnsureRenderer(UIView* view, std::string& error)
{
	UIView* tvView = g_renderView ? g_renderView : view;
	if (!tvView)
	{
		error = "Render view is not available.";
		return false;
	}

	UpdateWindowInfo(tvView);
	const CGRect bounds = tvView.bounds;
	if (bounds.size.width <= 0 || bounds.size.height <= 0)
	{
		error = "Render view has an invalid size.";
		return false;
	}

	try
	{
		@try
		{
			if (!g_renderer)
			{
				g_renderer = std::make_unique<MetalRenderer>();
				auto metalRenderer = MetalRenderer::GetInstance();
				metalRenderer->InitializeLayer({static_cast<int>(bounds.size.width), static_cast<int>(bounds.size.height)}, true);
				// Pad layer is initialized in viewDidLayoutSubviews when portrait mode is active
			}
			else
			{
				auto metalRenderer = MetalRenderer::GetInstance();
				metalRenderer->ResizeLayer({static_cast<int>(bounds.size.width), static_cast<int>(bounds.size.height)}, true);
			}
		}
		@catch (NSException* nsex)
		{
			error = fmt::format("ObjC exception in renderer: {} - {}", nsex.name.UTF8String, nsex.reason.UTF8String);
			return false;
		}
	}
	catch (const std::exception& ex)
	{
		error = fmt::format("Error when initializing Metal renderer: {}", ex.what());
		return false;
	}

	return true;
}

class IOSSystemImplementation final : public CafeSystem::SystemImplementation
{
public:
	void CafeRecreateCanvas() override
	{
		if (!g_renderView)
			return;
		dispatch_async(dispatch_get_main_queue(), ^{
			UpdateWindowInfo(g_renderView);
			if (auto* metalRenderer = MetalRenderer::GetInstance())
			{
				const CGRect bounds = g_renderView.bounds;
				metalRenderer->ResizeLayer({static_cast<int>(bounds.size.width), static_cast<int>(bounds.size.height)}, true);
			}
		});
	}
};

IOSSystemImplementation g_system_impl;

void InitializeCemuCore()
{
	if (g_cemu_initialized)
		return;

	IOSLOG("InitializeCemuCore: DeterminePathsIOS");
	std::set<fs::path> failedWriteAccess;
	DeterminePathsIOS(failedWriteAccess);
	IOSLOG("InitializeCemuCore: CreateDefaultCemuFiles");
	CreateDefaultCemuFiles();

	IOSLOG("InitializeCemuCore: config path");
	GetConfigHandle().SetFilename(ActiveSettings::GetConfigPath("settings.xml").generic_wstring());
	std::error_code ec;
	const bool isFirstStart = !fs::exists(ActiveSettings::GetConfigPath("settings.xml"), ec);

	IOSLOG("InitializeCemuCore: NetworkConfig");
	NetworkConfig::LoadOnce();
	if (isFirstStart)
		GetConfigHandle().Save();

	IOSLOG("InitializeCemuCore: InitializeMLCOrFail");
	InitializeMLCOrFail();
	IOSLOG("InitializeCemuCore: ActiveSettings::Init");
	ActiveSettings::Init();
	IOSLOG("InitializeCemuCore: LatteOverlay_init");
	LatteOverlay_init();

	IOSLOG("InitializeCemuCore: AES128_init");
	AES128_init();
	IOSLOG("InitializeCemuCore: PPCTimer_init");
	PPCTimer_init();
	IOSLOG("InitializeCemuCore: ExceptionHandler_Init");
	ExceptionHandler_Init();

	IOSLOG("InitializeCemuCore: config Load");
	GetConfigHandle().Load();
	if (NetworkConfig::XMLExists())
		n_config.Load();

	IOSLOG("InitializeCemuCore: Audio init");
	IAudioAPI::InitializeStatic();
	IAudioInputAPI::InitializeStatic();
	IOSLOG("InitializeCemuCore: GraphicPack2::LoadAll");
	GraphicPack2::LoadAll();
	IOSLOG("InitializeCemuCore: InputManager load");
	InputManager::instance().load();

	IOSLOG("InitializeCemuCore: CafeSystem::Initialize");
	CafeSystem::Initialize();

	IOSLOG("InitializeCemuCore: TitleList init");
	CafeTitleList::Initialize(ActiveSettings::GetUserDataPath("title_list_cache.xml"));
	for (auto& it : GetConfig().game_paths)
		CafeTitleList::AddScanPath(_utf8ToPath(it));

	// Auto-add common iOS game directories as scan paths
	{
		const fs::path documentsPath = GetSearchPath(NSDocumentDirectory);
		if (!documentsPath.empty())
		{
			std::error_code ec;
			CafeTitleList::AddScanPath(documentsPath);
			for (const auto& entry : fs::directory_iterator(documentsPath, ec))
			{
				if (!entry.is_directory(ec))
					continue;
				CafeTitleList::AddScanPath(entry.path());
				std::error_code ec2;
				for (const auto& sub : fs::directory_iterator(entry.path(), ec2))
				{
					if (sub.is_directory(ec2))
						CafeTitleList::AddScanPath(sub.path());
				}
			}
		}
	}

	// Resolve saved game path bookmarks (user-added via Settings > Game Paths)
	ResolveAndActivateGamePathBookmarks();

	const fs::path mlcPath = ActiveSettings::GetMlcPath();
	if (!mlcPath.empty())
		CafeTitleList::SetMLCPath(mlcPath);
	CafeTitleList::Refresh();

	IOSLOG("InitializeCemuCore: SaveList init");
	CafeSaveList::Initialize();
	if (!mlcPath.empty())
	{
		CafeSaveList::SetMLCPath(mlcPath);
		CafeSaveList::Refresh();
	}

	GetConfig().graphic_api = GraphicAPI::kMetal;
	// Configure audio for iOS (CoreAudio via Cubeb slot)
	GetConfig().audio_api = IAudioAPI::Cubeb;
	GetConfig().tv_device = L"ios_default";
	GetConfig().pad_device = L"ios_default";
	GetConfig().tv_volume = 100;
	GetConfig().pad_volume = 100;
	GetConfigHandle().Save();

	CafeSystem::SetImplementation(&g_system_impl);
	g_cemu_initialized = true;

	// Initialize iOS game controller support
	IOSController_init();

	IOSLOG("InitializeCemuCore: COMPLETE");

	for (auto&& path : failedWriteAccess)
	{
		WindowSystem::ShowErrorDialog(
			fmt::format("Cemu can't write to {}!", _pathToUtf8(path)),
			"Warning");
	}
}
} // namespace

extern "C" void CemuIOS_ShowErrorDialog(const char* message, const char* title)
{
	if (!g_rootController || !message)
		return;

	NSString* messageString = [NSString stringWithUTF8String:message];
	NSString* titleString = (title && *title) ? [NSString stringWithUTF8String:title] : @"Error";
	dispatch_async(dispatch_get_main_queue(), ^{
		UIAlertController* alert = [UIAlertController alertControllerWithTitle:titleString
			message:messageString
			preferredStyle:UIAlertControllerStyleAlert];
		[alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
		[g_rootController presentViewController:alert animated:YES completion:nil];
	});
}

// Forward declare CemuViewController for settings
@class CemuViewController;

@interface CemuSettingsViewController : UITableViewController <UIDocumentPickerDelegate>
@property (unsafe_unretained, nonatomic) CemuViewController* cemuVC;
@property (strong, nonatomic) NSMutableArray<NSURL*>* gamePaths;
@end

@implementation CemuSettingsViewController

- (void)viewDidLoad
{
	[super viewDidLoad];
	self.title = @"Settings";
	self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(dismiss)];
	[self reloadGamePaths];
}

- (void)reloadGamePaths
{
	self.gamePaths = [NSMutableArray array];
	NSArray<NSData*>* bookmarks = LoadGamePathBookmarks();
	for (NSData* data in bookmarks)
	{
		BOOL stale = NO;
		NSError* err = nil;
		NSURL* url = [NSURL URLByResolvingBookmarkData:data options:0 relativeToURL:nil bookmarkDataIsStale:&stale error:&err];
		if (url && !err)
			[self.gamePaths addObject:url];
	}
}

- (void)dismiss
{
	[self dismissViewControllerAnimated:YES completion:nil];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView { return 3; }

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
	if (section == 0) return @"Display";
	if (section == 1) return @"Graphic Packs";
	if (section == 2) return @"Game Paths";
	return nil;
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
	if (section == 1)
	{
		auto vPath = ActiveSettings::GetUserDataPath("graphicPacks/downloadedGraphicPacks/version.txt");
		std::unique_ptr<FileStream> vf(FileStream::openFile2(vPath));
		std::string ver;
		if (vf && vf->readLine(ver))
			return [NSString stringWithFormat:@"Installed: %s", ver.c_str()];
		return @"Not installed. Tap to download from GitHub.";
	}
	if (section == 2) return @"Add folders containing game updates or DLC.";
	return nil;
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
	if (section == 0) return 1;
	if (section == 1) return 1;
	if (section == 2) return (NSInteger)self.gamePaths.count + 1;
	return 0;
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
	if (indexPath.section == 0 && indexPath.row == 0)
	{
		UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
		cell.selectionStyle = UITableViewCellSelectionStyleNone;
		extern std::atomic_bool g_renderPadView;
		cell.textLabel.text = @"Render Pad View";
		UISwitch* sw = [[UISwitch alloc] init];
		sw.on = g_renderPadView.load(std::memory_order_relaxed);
		[sw addTarget:self action:@selector(padViewToggled:) forControlEvents:UIControlEventValueChanged];
		cell.accessoryView = sw;
		return cell;
	}
	if (indexPath.section == 1 && indexPath.row == 0)
	{
		UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
		cell.textLabel.text = @"Download / Update Graphic Packs";
		cell.textLabel.textColor = self.view.tintColor;
		return cell;
	}
	if (indexPath.section == 2)
	{
		if (indexPath.row < (NSInteger)self.gamePaths.count)
		{
			UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
			NSURL* url = self.gamePaths[indexPath.row];
			cell.textLabel.text = url.lastPathComponent;
			cell.textLabel.numberOfLines = 1;
			cell.detailTextLabel.text = url.path;
			cell.detailTextLabel.numberOfLines = 1;
			cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
			cell.selectionStyle = UITableViewCellSelectionStyleNone;
			return cell;
		}
		else
		{
			UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
			cell.textLabel.text = @"Add Game Path…";
			cell.textLabel.textColor = self.view.tintColor;
			cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
			return cell;
		}
	}
	return [[UITableViewCell alloc] init];
}

- (BOOL)tableView:(UITableView*)tableView canEditRowAtIndexPath:(NSIndexPath*)indexPath
{
	return indexPath.section == 2 && indexPath.row < (NSInteger)self.gamePaths.count;
}

- (void)tableView:(UITableView*)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle forRowAtIndexPath:(NSIndexPath*)indexPath
{
	if (editingStyle == UITableViewCellEditingStyleDelete && indexPath.section == 2)
	{
		NSMutableArray<NSData*>* bookmarks = [LoadGamePathBookmarks() mutableCopy];
		if (indexPath.row < (NSInteger)bookmarks.count)
		{
			[bookmarks removeObjectAtIndex:indexPath.row];
			SaveGamePathBookmarks(bookmarks);
		}
		[self.gamePaths removeObjectAtIndex:indexPath.row];
		[tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationAutomatic];
	}
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
	[tableView deselectRowAtIndexPath:indexPath animated:YES];
	if (indexPath.section == 1 && indexPath.row == 0)
	{
		[self downloadGraphicPacks];
	}
	else if (indexPath.section == 2 && indexPath.row == (NSInteger)self.gamePaths.count)
	{
		UIDocumentPickerViewController* picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeFolder]];
		picker.delegate = self;
		picker.allowsMultipleSelection = NO;
		[self presentViewController:picker animated:YES completion:nil];
	}
}

- (void)downloadGraphicPacks
{
	UIAlertController* progress = [UIAlertController alertControllerWithTitle:@"Downloading…"
		message:@"Downloading graphic packs from GitHub…"
		preferredStyle:UIAlertControllerStyleAlert];
	[self presentViewController:progress animated:YES completion:nil];

	dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
		std::string err = DownloadAndExtractGraphicPacks();
		dispatch_async(dispatch_get_main_queue(), ^{
			[progress dismissViewControllerAnimated:YES completion:^{
				if (err.empty())
				{
					// Reload graphic packs
					GraphicPack2::LoadAll();
					[self.tableView reloadData];
					UIAlertController* done = [UIAlertController alertControllerWithTitle:@"Done"
						message:@"Graphic packs downloaded and installed successfully."
						preferredStyle:UIAlertControllerStyleAlert];
					[done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
					[self presentViewController:done animated:YES completion:nil];
				}
				else
				{
					UIAlertController* errAlert = [UIAlertController alertControllerWithTitle:@"Error"
						message:[NSString stringWithUTF8String:err.c_str()]
						preferredStyle:UIAlertControllerStyleAlert];
					[errAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
					[self presentViewController:errAlert animated:YES completion:nil];
				}
			}];
		});
	});
}

- (void)documentPicker:(UIDocumentPickerViewController*)controller didPickDocumentsAtURLs:(NSArray<NSURL*>*)urls
{
	NSURL* url = urls.firstObject;
	if (!url) return;
	[url startAccessingSecurityScopedResource];
	NSError* err = nil;
	NSData* bookmark = [url bookmarkDataWithOptions:0 includingResourceValuesForKeys:nil relativeToURL:nil error:&err];
	if (bookmark && !err)
	{
		NSMutableArray<NSData*>* bookmarks = [LoadGamePathBookmarks() mutableCopy];
		[bookmarks addObject:bookmark];
		SaveGamePathBookmarks(bookmarks);
		[self.gamePaths addObject:url];
		[self.tableView reloadData];
		// Add to scan paths immediately
		CafeTitleList::AddScanPath(fs::path(url.fileSystemRepresentation));
		CafeTitleList::Refresh();
		cemuLog_log(LogType::Force, "Added game path: {}", url.fileSystemRepresentation);
	}
}

- (void)padViewToggled:(UISwitch*)sender
{
	[self.cemuVC applyPadViewSetting:sender.on];
}

@end

// --- Graphic Pack Configuration for a specific title ---
@interface GraphicPackConfigViewController : UITableViewController
@property (nonatomic) uint64_t titleId;
@property (strong, nonatomic) NSString* titleName;
@end

@implementation GraphicPackConfigViewController
{
	std::vector<std::shared_ptr<GraphicPack2>> _matchingPacks;
	// For each pack, the list of unique preset categories
	std::vector<std::vector<std::string>> _packCategories;
}

- (void)viewDidLoad
{
	[super viewDidLoad];
	self.title = self.titleName ?: @"Graphic Packs";
	self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone target:self action:@selector(dismiss)];
	// Find all graphic packs matching this title
	_matchingPacks.clear();
	_packCategories.clear();
	for (auto& gp : GraphicPack2::GetGraphicPacks())
	{
		for (uint64_t tid : gp->GetTitleIds())
		{
			if (tid == self.titleId)
			{
				_matchingPacks.push_back(gp);
				// Collect unique categories
				std::vector<std::string> cats;
				std::set<std::string> seen;
				for (auto& p : gp->GetPresets())
				{
					if (seen.insert(p->category).second)
						cats.push_back(p->category);
				}
				_packCategories.push_back(cats);
				break;
			}
		}
	}
}

- (void)saveGraphicPackConfig
{
	auto& config = GetConfig();
	config.graphic_pack_entries.clear();
	for (auto& gp : GraphicPack2::GetGraphicPacks())
	{
		if (gp->IsEnabled())
		{
			std::unordered_map<std::string, std::string> presetMap;
			auto presets = gp->GetActivePresets();
			for (auto& p : presets)
				presetMap[p->category] = p->name;
			config.graphic_pack_entries[gp->GetVirtualPath()] = presetMap;
		}
	}
	GetConfigHandle().Save();
}

- (void)dismiss
{
	[self saveGraphicPackConfig];
	[self dismissViewControllerAnimated:YES completion:nil];
}

- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{
	if (_matchingPacks.empty()) return 1;
	return (NSInteger)_matchingPacks.size();
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
	if (_matchingPacks.empty())
		return @"No graphic packs found. Download them in Settings first.";
	return [NSString stringWithUTF8String:_matchingPacks[section]->GetName().c_str()];
}

- (NSString*)tableView:(UITableView*)tableView titleForFooterInSection:(NSInteger)section
{
	if (section < (NSInteger)_matchingPacks.size())
	{
		auto& desc = _matchingPacks[section]->GetDescription();
		if (!desc.empty())
			return [NSString stringWithUTF8String:desc.c_str()];
	}
	return nil;
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
	if (_matchingPacks.empty()) return 0;
	// Row 0: enable/disable, Row 1..N: preset categories
	return 1 + (NSInteger)_packCategories[section].size();
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
	auto& gp = _matchingPacks[indexPath.section];
	if (indexPath.row == 0)
	{
		// Enable/disable toggle
		UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
		cell.textLabel.text = @"Enabled";
		cell.selectionStyle = UITableViewCellSelectionStyleNone;
		UISwitch* sw = [[UISwitch alloc] init];
		sw.on = gp->IsEnabled();
		sw.tag = indexPath.section;
		[sw addTarget:self action:@selector(packToggled:) forControlEvents:UIControlEventValueChanged];
		cell.accessoryView = sw;
		return cell;
	}
	else
	{
		// Preset category row
		NSInteger catIdx = indexPath.row - 1;
		auto& category = _packCategories[indexPath.section][catIdx];
		std::string activePreset = gp->GetActivePreset(category);

		UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil];
		cell.textLabel.text = category.empty()
			? @"Preset"
			: [NSString stringWithUTF8String:category.c_str()];
		cell.detailTextLabel.text = activePreset.empty()
			? @"Default"
			: [NSString stringWithUTF8String:activePreset.c_str()];
		cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
		return cell;
	}
}

- (void)packToggled:(UISwitch*)sender
{
	NSInteger idx = sender.tag;
	if (idx >= 0 && idx < (NSInteger)_matchingPacks.size())
	{
		_matchingPacks[idx]->SetEnabled(sender.on);
		[self saveGraphicPackConfig];
	}
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
	[tableView deselectRowAtIndexPath:indexPath animated:YES];
	if (indexPath.row == 0) return; // toggle row, handled by switch

	auto& gp = _matchingPacks[indexPath.section];
	NSInteger catIdx = indexPath.row - 1;
	auto& category = _packCategories[indexPath.section][catIdx];

	// Collect presets for this category
	std::vector<std::shared_ptr<GraphicPack2::Preset>> catPresets;
	for (auto& p : gp->GetPresets())
	{
		if (p->category == category)
			catPresets.push_back(p);
	}
	if (catPresets.empty()) return;

	std::string activePreset = gp->GetActivePreset(category);

	UIAlertController* alert = [UIAlertController alertControllerWithTitle:
		category.empty() ? @"Select Preset" : [NSString stringWithUTF8String:category.c_str()]
		message:nil
		preferredStyle:UIAlertControllerStyleActionSheet];

	for (auto& preset : catPresets)
	{
		NSString* name = [NSString stringWithUTF8String:preset->name.c_str()];
		UIAlertActionStyle style = UIAlertActionStyleDefault;
		if (preset->name == activePreset)
			name = [name stringByAppendingString:@" ✓"];

		auto gpCopy = gp;
		std::string catCopy = category;
		std::string presetName = preset->name;
		[alert addAction:[UIAlertAction actionWithTitle:name style:style handler:^(UIAlertAction* action) {
			gpCopy->SetActivePreset(catCopy, presetName);
			[self saveGraphicPackConfig];
			[self.tableView reloadData];
		}]];
	}
	[alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
	if (alert.popoverPresentationController)
	{
		UITableViewCell* cell = [tableView cellForRowAtIndexPath:indexPath];
		alert.popoverPresentationController.sourceView = cell;
		alert.popoverPresentationController.sourceRect = cell.bounds;
	}
	[self presentViewController:alert animated:YES completion:nil];
}

@end

@interface CemuViewController : UIViewController <UIDocumentPickerDelegate, UITextFieldDelegate, UITableViewDataSource, UITableViewDelegate>
@property (strong, nonatomic) UIView* overlayView;
@property (strong, nonatomic) UIView* tvView;
@property (strong, nonatomic) UIView* padView;
@property (strong, nonatomic) UILabel* jitLabel;
@property (strong, nonatomic) UILabel* statusLabel;
@property (strong, nonatomic) UITableView* gameListTable;
@property (strong, nonatomic) UIButton* settingsButton;
@property (strong, nonatomic) UILabel* fpsLabel;
@property (strong, nonatomic) NSTimer* fpsTimer;
@property (nonatomic) uint32_t lastFrameCount;
@property (strong, nonatomic) NSURL* securityScopedURL;
@property (nonatomic) BOOL didAutoLaunch;
@property (strong, nonatomic) UITextField* hiddenTextField;
@property (strong, nonatomic) NSTimer* swkbdTimer;
@property (nonatomic) BOOL swkbdActive;
@property (strong, nonatomic) NSMutableArray<NSDictionary*>* gameEntries; // {name, version, titleId, path, type}
- (void)applyPadViewSetting:(BOOL)enabled;
- (void)refreshGameList;
@end

@implementation CemuViewController
- (void)viewDidLoad
{
	[super viewDidLoad];
	IOSLOG("CemuViewController viewDidLoad");

	// Load saved settings
	{
		extern std::atomic_bool g_renderPadView;
		NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
		if ([defaults objectForKey:@"renderPadView"] != nil)
			g_renderPadView.store([defaults boolForKey:@"renderPadView"], std::memory_order_relaxed);
	}

	self.view.backgroundColor = [UIColor colorWithWhite:0.15 alpha:1.0];

	// TV view (main screen) — top half in portrait
	self.tvView = [[UIView alloc] initWithFrame:CGRectZero];
	self.tvView.backgroundColor = [UIColor blackColor];
	[self.view addSubview:self.tvView];
	g_renderView = self.tvView;

	// Pad/DRC view (GamePad screen) — bottom half in portrait
	self.padView = [[UIView alloc] initWithFrame:CGRectZero];
	self.padView.backgroundColor = [UIColor blackColor];
	[self.view addSubview:self.padView];
	g_padView = self.padView;

	self.overlayView = [[UIView alloc] initWithFrame:self.view.bounds];
	self.overlayView.backgroundColor = [UIColor clearColor];
	[self.view addSubview:self.overlayView];

	self.jitLabel = [[UILabel alloc] initWithFrame:CGRectZero];
	self.jitLabel.textColor = [UIColor whiteColor];
	self.jitLabel.font = [UIFont systemFontOfSize:14.0 weight:UIFontWeightSemibold];
	self.jitLabel.numberOfLines = 2;
	[self.overlayView addSubview:self.jitLabel];

	self.statusLabel = [[UILabel alloc] initWithFrame:CGRectZero];
	self.statusLabel.textColor = [UIColor whiteColor];
	self.statusLabel.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightRegular];
	self.statusLabel.numberOfLines = 0;
	self.statusLabel.textAlignment = NSTextAlignmentCenter;
	self.statusLabel.text = @"Initializing...";
	[self.overlayView addSubview:self.statusLabel];

	// Game list table view
	self.gameEntries = [NSMutableArray array];
	self.gameListTable = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStyleInsetGrouped];
	self.gameListTable.dataSource = self;
	self.gameListTable.delegate = self;
	self.gameListTable.backgroundColor = [UIColor clearColor];
	self.gameListTable.hidden = YES;
	[self.gameListTable registerClass:[UITableViewCell class] forCellReuseIdentifier:@"gameCell"];
	[self.overlayView addSubview:self.gameListTable];

	// Long-press on game list item to configure graphic packs
	UILongPressGestureRecognizer* longPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleGameLongPress:)];
	[self.gameListTable addGestureRecognizer:longPress];

	// Settings gear button (top-right of overlay)
	self.settingsButton = [UIButton buttonWithType:UIButtonTypeSystem];
	UIImage* gearImage = [UIImage systemImageNamed:@"gearshape.fill" withConfiguration:[UIImageSymbolConfiguration configurationWithPointSize:22 weight:UIImageSymbolWeightMedium]];
	[self.settingsButton setImage:gearImage forState:UIControlStateNormal];
	[self.settingsButton addTarget:self action:@selector(openSettings) forControlEvents:UIControlEventTouchUpInside];
	[self.overlayView addSubview:self.settingsButton];

	UIPanGestureRecognizer* pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
	pan.maximumNumberOfTouches = 1;
	pan.minimumNumberOfTouches = 1;
	[self.view addGestureRecognizer:pan];

	// FPS counter label — top-left, always on top
	self.fpsLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 8, 100, 22)];
	self.fpsLabel.textColor = [UIColor greenColor];
	self.fpsLabel.backgroundColor = [UIColor clearColor];
	self.fpsLabel.font = [UIFont monospacedDigitSystemFontOfSize:14.0 weight:UIFontWeightBold];
	self.fpsLabel.text = @"";
	self.fpsLabel.hidden = YES;
	self.fpsLabel.layer.shadowColor = [UIColor blackColor].CGColor;
	self.fpsLabel.layer.shadowOffset = CGSizeMake(1, 1);
	self.fpsLabel.layer.shadowRadius = 2;
	self.fpsLabel.layer.shadowOpacity = 1.0;
	[self.view addSubview:self.fpsLabel];

	// Hidden text field for swkbd keyboard input
	self.hiddenTextField = [[UITextField alloc] initWithFrame:CGRectMake(-100, -100, 1, 1)];
	self.hiddenTextField.autocorrectionType = UITextAutocorrectionTypeNo;
	self.hiddenTextField.autocapitalizationType = UITextAutocapitalizationTypeNone;
	self.hiddenTextField.spellCheckingType = UITextSpellCheckingTypeNo;
	self.hiddenTextField.delegate = self;
	self.hiddenTextField.returnKeyType = UIReturnKeyDone;
	[self.view addSubview:self.hiddenTextField];

	// Poll for swkbd state changes
	self.swkbdActive = NO;
	self.swkbdTimer = [NSTimer scheduledTimerWithTimeInterval:0.25 target:self selector:@selector(checkSwkbd) userInfo:nil repeats:YES];
}

- (void)viewDidLayoutSubviews
{
	[super viewDidLayoutSubviews];

	const CGRect viewBounds = self.view.bounds;
	const BOOL isPortrait = viewBounds.size.height > viewBounds.size.width;

	if (isPortrait)
	{
		extern std::atomic_bool g_renderPadView;
		BOOL showPad = g_renderPadView.load(std::memory_order_relaxed);
		if (showPad)
		{
			// Portrait: TV on top half, DRC on bottom half
			CGFloat halfH = viewBounds.size.height / 2.0;
			self.tvView.frame = CGRectMake(0, 0, viewBounds.size.width, halfH);
			self.padView.frame = CGRectMake(0, halfH, viewBounds.size.width, halfH);
			self.padView.hidden = NO;
			for (UIView* child in self.padView.subviews)
				child.frame = self.padView.bounds;
		}
		else
		{
			// Portrait but pad disabled: TV fullscreen
			self.tvView.frame = viewBounds;
			self.padView.frame = CGRectZero;
			self.padView.hidden = YES;
		}
	}
	else
	{
		// Landscape: TV fullscreen, DRC hidden
		self.tvView.frame = viewBounds;
		self.padView.frame = CGRectZero;
		self.padView.hidden = YES;
	}
	// Also sync MetalView child of TV
	for (UIView* child in self.tvView.subviews)
		child.frame = self.tvView.bounds;

	UpdateWindowInfo(self.tvView);
	if (auto* metalRenderer = MetalRenderer::GetInstance())
	{
		const CGRect tvBounds = self.tvView.bounds;
		metalRenderer->ResizeLayer({static_cast<int>(tvBounds.size.width), static_cast<int>(tvBounds.size.height)}, true);

		if (isPortrait && !self.padView.hidden)
		{
			const CGRect padBounds = self.padView.bounds;
			if (!metalRenderer->IsPadWindowActive())
				metalRenderer->InitializeLayer({static_cast<int>(padBounds.size.width), static_cast<int>(padBounds.size.height)}, false);
			else
				metalRenderer->ResizeLayer({static_cast<int>(padBounds.size.width), static_cast<int>(padBounds.size.height)}, false);
		}
		else if (!isPortrait && metalRenderer->IsPadWindowActive())
		{
			metalRenderer->ShutdownLayer(false);
		}
	}

	self.overlayView.frame = viewBounds;

	const UIEdgeInsets insets = self.view.safeAreaInsets;
	const CGFloat padding = 16.0;
	const CGFloat width = viewBounds.size.width - padding * 2.0;
	CGFloat y = insets.top + padding;

	const CGSize jitSize = [self.jitLabel sizeThatFits:CGSizeMake(width, CGFLOAT_MAX)];
	self.jitLabel.frame = CGRectMake(padding, y, width, jitSize.height);
	y += jitSize.height + 12.0;

	const CGSize statusSize = [self.statusLabel sizeThatFits:CGSizeMake(width, CGFLOAT_MAX)];
	self.statusLabel.frame = CGRectMake(padding, y, width, statusSize.height);
	y += statusSize.height + 12.0;

	// Game list table takes remaining space
	CGFloat tableBottom = viewBounds.size.height - insets.bottom;
	self.gameListTable.frame = CGRectMake(0, y, viewBounds.size.width, tableBottom - y);

	// Settings button in top-right
	self.settingsButton.frame = CGRectMake(viewBounds.size.width - padding - 44, insets.top + 8, 44, 44);

	// Keep FPS label on top
	if (!self.fpsLabel.hidden)
		[self.view bringSubviewToFront:self.fpsLabel];
}

- (void)updateJitStatus:(NSString*)status
{
	self.jitLabel.text = status;
	[self.view setNeedsLayout];
}

- (void)setReady
{
	self.statusLabel.text = @"Select a game to launch";
	self.gameListTable.hidden = NO;
	[self refreshGameList];
	[self.view setNeedsLayout];
}

- (void)handlePan:(UIPanGestureRecognizer*)gesture
{
	const CGPoint location = [gesture locationInView:self.view];
	const CGFloat scale = self.view.contentScaleFactor;
	auto& instance = InputManager::instance();
	std::scoped_lock lock(instance.m_main_touch.m_mutex);
	instance.m_main_touch.position = {static_cast<int>(location.x * scale), static_cast<int>(location.y * scale)};
	const bool active = gesture.state == UIGestureRecognizerStateBegan || gesture.state == UIGestureRecognizerStateChanged;
	instance.m_main_touch.left_down = active;
	if (active)
		instance.m_main_touch.left_down_toggle = true;
}

- (void)updateFPS
{
	extern std::atomic<uint32_t> g_cemuFrameCounter;
	uint32_t current = g_cemuFrameCounter.load(std::memory_order_relaxed);
	uint32_t fps = current - self.lastFrameCount;
	self.lastFrameCount = current;
	self.fpsLabel.text = [NSString stringWithFormat:@" FPS: %u ", fps];
}

- (void)checkSwkbd
{
	BOOL active = swkbd_hasKeyboardInputHook();
	if (active && !self.swkbdActive)
	{
		self.swkbdActive = YES;
		self.hiddenTextField.text = @"";
		[self.hiddenTextField becomeFirstResponder];
	}
	else if (!active && self.swkbdActive)
	{
		self.swkbdActive = NO;
		[self.hiddenTextField resignFirstResponder];
	}
}

- (BOOL)textField:(UITextField*)textField shouldChangeCharactersInRange:(NSRange)range replacementString:(NSString*)string
{
	if (string.length == 0)
	{
		// Backspace
		swkbd_keyInput(8);
	}
	else
	{
		for (NSUInteger i = 0; i < string.length; i++)
		{
			unichar c = [string characterAtIndex:i];
			swkbd_keyInput((uint32)c);
		}
	}
	return YES;
}

- (BOOL)textFieldShouldReturn:(UITextField*)textField
{
	swkbd_keyInput(13); // Enter = confirm
	return NO;
}

- (void)handleGameLongPress:(UILongPressGestureRecognizer*)gesture
{
	if (gesture.state != UIGestureRecognizerStateBegan) return;
	CGPoint point = [gesture locationInView:self.gameListTable];
	NSIndexPath* indexPath = [self.gameListTable indexPathForRowAtPoint:point];
	if (!indexPath || indexPath.section != 0 || indexPath.row >= (NSInteger)self.gameEntries.count) return;

	NSDictionary* entry = self.gameEntries[indexPath.row];
	NSString* tidStr = entry[@"titleId"];
	if (!tidStr || tidStr.length == 0) return;

	// Parse title ID (format: "XXXXXXXX-XXXXXXXX")
	uint64_t titleId = 0;
	std::string tidCpp(tidStr.UTF8String);
	tidCpp.erase(std::remove(tidCpp.begin(), tidCpp.end(), '-'), tidCpp.end());
	TitleIdParser::ParseFromStr(tidCpp, titleId);
	if (titleId == 0) return;

	GraphicPackConfigViewController* gpVC = [[GraphicPackConfigViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
	gpVC.titleId = titleId;
	gpVC.titleName = entry[@"name"];
	UINavigationController* nav = [[UINavigationController alloc] initWithRootViewController:gpVC];
	nav.modalPresentationStyle = UIModalPresentationPageSheet;
	[self presentViewController:nav animated:YES completion:nil];
}

- (void)openSettings
{
	CemuSettingsViewController* settingsVC = [[CemuSettingsViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
	settingsVC.cemuVC = self;
	UINavigationController* nav = [[UINavigationController alloc] initWithRootViewController:settingsVC];
	nav.modalPresentationStyle = UIModalPresentationPageSheet;
	[self presentViewController:nav animated:YES completion:nil];
}

- (void)refreshGameList
{
	[self.gameEntries removeAllObjects];

	// Collect from CafeTitleList (discovered titles via scan paths)
	auto titleIds = CafeTitleList::GetAllTitleIds();
	for (TitleId tid : titleIds)
	{
		TitleInfo info;
		if (!CafeTitleList::GetFirstByTitleId(tid, info))
			continue;
		if (!info.IsValid())
			continue;

		TitleIdParser parser(tid);
		auto titleType = parser.GetType();
		// Only show base titles
		if (titleType != TitleIdParser::TITLE_TYPE::BASE_TITLE &&
			titleType != TitleIdParser::TITLE_TYPE::BASE_TITLE_DEMO)
			continue;

		NSString* name = nil;
		std::string metaName = info.GetMetaTitleName();
		if (!metaName.empty())
			name = [NSString stringWithUTF8String:metaName.c_str()];
		else
			name = [NSString stringWithUTF8String:_pathToUtf8(info.GetPath().filename()).c_str()];

		uint16 version = info.GetAppTitleVersion();
		NSString* versionStr = [NSString stringWithFormat:@"v%u", (unsigned)version];

		// Check if update exists
		TitleId updateTid = parser.GetSeparateUpdateTitleId();
		uint16 updateVersion = 0;
		bool hasUpdate = CafeTitleList::HasTitle(updateTid, updateVersion);
		if (hasUpdate)
			versionStr = [NSString stringWithFormat:@"v%u (Update: v%u)", (unsigned)version, (unsigned)updateVersion];

		// Check for DLC
		TitleId aocTid = (tid & ~(0xFFULL << 32)) | ((uint64)0x0C << 32);
		uint16 aocVersion = 0;
		bool hasDLC = CafeTitleList::HasTitle(aocTid, aocVersion);
		if (hasDLC)
			versionStr = [versionStr stringByAppendingString:@" + DLC"];

		NSString* tidStr = [NSString stringWithFormat:@"%08X-%08X", (uint32)(tid >> 32), (uint32)(tid & 0xFFFFFFFF)];
		std::string pathStr = _pathToUtf8(info.GetPath());
		NSDictionary* entry = @{
			@"name": name,
			@"version": versionStr,
			@"titleId": tidStr,
			@"path": [NSString stringWithUTF8String:pathStr.c_str()],
		};
		[self.gameEntries addObject:entry];
	}

	// Also collect from filesystem (games not yet in title list)
	auto candidates = CollectGameCandidates();
	for (size_t i = 0; i < candidates.paths.size(); i++)
	{
		std::string pathStr = _pathToUtf8(candidates.paths[i]);
		NSString* pathNS = [NSString stringWithUTF8String:pathStr.c_str()];
		// Skip if already in gameEntries
		BOOL found = NO;
		for (NSDictionary* existing in self.gameEntries)
		{
			if ([existing[@"path"] isEqualToString:pathNS]) { found = YES; break; }
		}
		if (found) continue;

		NSString* name = candidates.names[i].empty()
			? [NSString stringWithUTF8String:_pathToUtf8(candidates.paths[i].filename()).c_str()]
			: [NSString stringWithUTF8String:candidates.names[i].c_str()];
		NSDictionary* entry = @{
			@"name": name,
			@"version": @"",
			@"titleId": @"",
			@"path": pathNS,
		};
		[self.gameEntries addObject:entry];
	}

	[self.gameListTable reloadData];
}

// UITableView data source for game list
- (NSInteger)numberOfSectionsInTableView:(UITableView*)tableView
{
	return 2; // games + browse
}

- (NSString*)tableView:(UITableView*)tableView titleForHeaderInSection:(NSInteger)section
{
	if (section == 0) return self.gameEntries.count > 0 ? @"Games" : nil;
	return nil;
}

- (NSInteger)tableView:(UITableView*)tableView numberOfRowsInSection:(NSInteger)section
{
	if (section == 0) return (NSInteger)self.gameEntries.count;
	return 1; // "Browse..." row
}

- (UITableViewCell*)tableView:(UITableView*)tableView cellForRowAtIndexPath:(NSIndexPath*)indexPath
{
	if (indexPath.section == 0)
	{
		UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:nil];
		NSDictionary* entry = self.gameEntries[indexPath.row];
		cell.textLabel.text = entry[@"name"];
		cell.textLabel.textColor = [UIColor whiteColor];
		NSMutableString* detail = [NSMutableString string];
		if ([entry[@"titleId"] length] > 0)
			[detail appendString:entry[@"titleId"]];
		if ([entry[@"version"] length] > 0)
		{
			if (detail.length > 0) [detail appendString:@"  "];
			[detail appendString:entry[@"version"]];
		}
		cell.detailTextLabel.text = detail;
		cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
		cell.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1.0];
		cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
		return cell;
	}
	else
	{
		UITableViewCell* cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleDefault reuseIdentifier:nil];
		cell.textLabel.text = @"Browse…";
		cell.textLabel.textColor = self.view.tintColor;
		cell.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1.0];
		cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
		return cell;
	}
}

- (void)tableView:(UITableView*)tableView didSelectRowAtIndexPath:(NSIndexPath*)indexPath
{
	[tableView deselectRowAtIndexPath:indexPath animated:YES];
	if (indexPath.section == 0)
	{
		NSDictionary* entry = self.gameEntries[indexPath.row];
		[self launchGameWithPathString:entry[@"path"]];
	}
	else
	{
		[self presentDocumentPicker];
	}
}

- (void)applyPadViewSetting:(BOOL)enabled
{
	extern std::atomic_bool g_renderPadView;
	g_renderPadView.store(enabled, std::memory_order_relaxed);
	[[NSUserDefaults standardUserDefaults] setBool:enabled forKey:@"renderPadView"];
	dispatch_async(dispatch_get_main_queue(), ^{
		if (!enabled)
		{
			self.padView.hidden = YES;
			auto* metalRenderer = dynamic_cast<MetalRenderer*>(g_renderer.get());
			if (metalRenderer && metalRenderer->IsPadWindowActive())
				metalRenderer->ShutdownLayer(false);
		}
		[self.view setNeedsLayout];
		[self.view layoutIfNeeded];
	});
}

- (void)presentDocumentPicker
{
	UIDocumentPickerViewController* picker = nil;
	if (@available(iOS 14.0, *))
		picker = [[UIDocumentPickerViewController alloc] initForOpeningContentTypes:@[UTTypeFolder, UTTypeItem] asCopy:NO];
	else
		picker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.folder", @"public.item"] inMode:UIDocumentPickerModeOpen];

	picker.delegate = self;
	picker.allowsMultipleSelection = NO;
	[self presentViewController:picker animated:YES completion:nil];
}

- (void)launchGameWithPathString:(NSString*)pathString
{
	if (!pathString)
		return;
	cemuLog_createLogFile(false);
	self.statusLabel.text = @"Preparing...";
	[self.view setNeedsLayout];

	const std::string path = pathString.UTF8String;
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
		const auto result = PrepareGameFromPath(_utf8ToPath(path));
		dispatch_async(dispatch_get_main_queue(), ^{
			if (!result.success)
			{
				WindowSystem::ShowErrorDialog(result.error, "Error");
				self.statusLabel.text = @"Launch failed";
				[self.view setNeedsLayout];
				return;
			}

			std::string renderError;
			cemuLog_log(LogType::Force, "Initializing renderer");
			if (!EnsureRenderer(self.view, renderError))
			{
				cemuLog_log(LogType::Force, "Renderer init failed: {}", renderError);
				WindowSystem::ShowErrorDialog(renderError, "Error");
				self.statusLabel.text = @"Renderer error";
				[self.view setNeedsLayout];
				return;
			}

			self.gameListTable.hidden = YES;
			self.statusLabel.text = @"Starting...";
			[self.view setNeedsLayout];
			// Start FPS counter and hide overlay before launching (LaunchForegroundTitle blocks until game exits)
			dispatch_async(dispatch_get_main_queue(), ^{
				self.overlayView.hidden = YES;
				self.fpsLabel.hidden = NO;
				[self.view bringSubviewToFront:self.fpsLabel];
				self.lastFrameCount = g_cemuFrameCounter.load(std::memory_order_relaxed);
				self.fpsTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(updateFPS) userInfo:nil repeats:YES];
				[self.view setNeedsLayout];
			});
			dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
				cemuLog_log(LogType::Force, "Launching title thread (timerShift={})", ActiveSettings::GetTimerShiftFactor());
				CafeSystem::LaunchForegroundTitle();
			});
		});
	});
}

- (void)documentPicker:(UIDocumentPickerViewController*)controller didPickDocumentsAtURLs:(NSArray<NSURL*>*)urls
{
	(void)controller;
	NSURL* url = urls.firstObject;
	if (!url)
		return;

	if (self.securityScopedURL)
		[self.securityScopedURL stopAccessingSecurityScopedResource];
	self.securityScopedURL = url;
	[self.securityScopedURL startAccessingSecurityScopedResource];
	[self launchGameWithPathString:url.path];
}
@end

@interface CemuAppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow* window;
@end

@implementation CemuAppDelegate
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)launchOptions
{
	(void)application;
	(void)launchOptions;

	openLogFile();
	IOSLOG("didFinishLaunchingWithOptions START");

	WindowSystem::Create();
	IOSLOG("WindowSystem created");

	const CGRect bounds = [UIScreen mainScreen].bounds;
	IOSLOG("Screen bounds: %s", NSStringFromCGRect(bounds).UTF8String);
	self.window = [[UIWindow alloc] initWithFrame:bounds];
	CemuViewController* rootController = [[CemuViewController alloc] init];
	UpdateWindowInfo(rootController.view);

	self.window.rootViewController = rootController;
	[self.window makeKeyAndVisible];
	IOSLOG("Window made key and visible");

	g_rootController = rootController;

	std::string jitDetail;
	IOSLOG("Enabling JIT via ptrace...");
	EnableJIT();
	IOSLOG("Checking JIT...");
	const bool jitEnabled = CheckJitEnabled(jitDetail);
	NSString* jitStatus = jitEnabled
		? @"JIT: Enabled"
		: [NSString stringWithFormat:@"JIT: Disabled (%s)", jitDetail.c_str()];
	[rootController updateJitStatus:jitStatus];

	IOSLOG("%s", jitStatus.UTF8String);
	if (!jitEnabled)
	{
		IOSLOG("JIT disabled, showing alert");
		dispatch_async(dispatch_get_main_queue(), ^{
			UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"JIT Not Enabled"
				message:jitStatus
				preferredStyle:UIAlertControllerStyleAlert];
			[alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
			[rootController presentViewController:alert animated:YES completion:nil];
		});
	}

	if (jitEnabled)
	{
		IOSLOG("JIT enabled, starting InitializeCemuCore on background thread");
		dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
			IOSLOG("InitializeCemuCore BEGIN");
			InitializeCemuCore();
			IOSLOG("InitializeCemuCore DONE");
			dispatch_async(dispatch_get_main_queue(), ^{
				IOSLOG("Calling setReady on main thread");
				[rootController setReady];
			});
		});
	}

	IOSLOG("didFinishLaunchingWithOptions returning YES");
	return YES;
}

- (void)applicationDidBecomeActive:(UIApplication*)application
{
	(void)application;
	WindowSystem::GetWindowInfo().app_active.store(true);
}

- (void)applicationWillResignActive:(UIApplication*)application
{
	(void)application;
	WindowSystem::GetWindowInfo().app_active.store(false);
}

- (void)applicationWillTerminate:(UIApplication*)application
{
	(void)application;
	if (g_cemu_initialized)
		CafeSystem::Shutdown();
}

- (void)applicationDidReceiveMemoryWarning:(UIApplication*)application
{
	(void)application;
	// Log memory pressure
	struct task_vm_info info;
	mach_msg_type_number_t count = TASK_VM_INFO_COUNT;
	if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
		IOSLOG("MEMORY WARNING: phys_footprint=%.1fMB, limit=%.1fMB",
			info.phys_footprint / (1024.0 * 1024.0),
			info.limit_bytes_remaining > 0 ? (info.phys_footprint + info.limit_bytes_remaining) / (1024.0 * 1024.0) : -1.0);
	} else {
		IOSLOG("MEMORY WARNING received");
	}

	// Purge Metal caches via notification
	@autoreleasepool {
		[[NSNotificationCenter defaultCenter] postNotificationName:@"CemuMemoryWarning" object:nil];
	}
}
@end

int main(int argc, char* argv[])
{
	@autoreleasepool
	{
		// Redirect stderr to a file so low-level fprintf logging can be pulled from device
		NSArray* docPaths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
		if (docPaths.count > 0) {
			NSString* stderrPath = [docPaths.firstObject stringByAppendingPathComponent:@"stderr.log"];
			freopen(stderrPath.UTF8String, "w", stderr);
		}
		return UIApplicationMain(argc, argv, nil, NSStringFromClass([CemuAppDelegate class]));
	}
}
