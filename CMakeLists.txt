cmake_minimum_required(VERSION 3.21.1)

option(ENABLE_VCPKG "Enable the vcpkg package manager" ON)
option(MACOS_BUNDLE "The executable when built on macOS will be created as an application bundle" OFF)
option(ALLOW_PORTABLE "Allow Cemu to be run in portable mode" ON)

# used by CI script to set version:
set(EMULATOR_VERSION_MAJOR "0" CACHE STRING "")
set(EMULATOR_VERSION_MINOR "0" CACHE STRING "")
set(EMULATOR_VERSION_PATCH "0" CACHE STRING "")

execute_process(
		COMMAND git log --format=%h -1
		WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
		OUTPUT_VARIABLE GIT_HASH
		OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_definitions(-DEMULATOR_HASH=${GIT_HASH})

if(NOT DEFINED CEMU_IOS)
	set(CEMU_IOS OFF CACHE BOOL "" FORCE)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR IOS)
	set(CEMU_IOS ON CACHE BOOL "" FORCE)
endif()
if(DEFINED CMAKE_OSX_SYSROOT AND CMAKE_OSX_SYSROOT MATCHES "iphoneos|iphonesimulator")
	set(CEMU_IOS ON CACHE BOOL "" FORCE)
endif()

if (ENABLE_VCPKG)
	if (DEFINED CMAKE_TOOLCHAIN_FILE AND NOT CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg.cmake")
		set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_TOOLCHAIN_FILE}" CACHE STRING "Vcpkg chainload toolchain file")
	endif()
	# check if vcpkg is shallow and unshallow it if necessary
	execute_process(
	COMMAND git rev-parse --is-shallow-repository
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/dependencies/vcpkg
	OUTPUT_VARIABLE is_vcpkg_shallow
	OUTPUT_STRIP_TRAILING_WHITESPACE
    )

	if(is_vcpkg_shallow STREQUAL "true")
		message(STATUS "vcpkg is shallow. Unshallowing it now...")
		execute_process(
			COMMAND git fetch --unshallow
			WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/dependencies/vcpkg"
			RESULT_VARIABLE result
			OUTPUT_VARIABLE output
		)
	endif()

	if(CEMU_IOS)
		set(VCPKG_OVERLAY_PORTS "${CMAKE_CURRENT_LIST_DIR}/dependencies/vcpkg_overlay_ports")
	elseif(UNIX AND NOT APPLE)
		set(VCPKG_OVERLAY_PORTS "${CMAKE_CURRENT_LIST_DIR}/dependencies/vcpkg_overlay_ports_linux;${CMAKE_CURRENT_LIST_DIR}/dependencies/vcpkg_overlay_ports")
	elseif(APPLE)
		set(VCPKG_OVERLAY_PORTS "${CMAKE_CURRENT_LIST_DIR}/dependencies/vcpkg_overlay_ports_mac;${CMAKE_CURRENT_LIST_DIR}/dependencies/vcpkg_overlay_ports")
	else()
		set(VCPKG_OVERLAY_PORTS "${CMAKE_CURRENT_LIST_DIR}/dependencies/vcpkg_overlay_ports_win;${CMAKE_CURRENT_LIST_DIR}/dependencies/vcpkg_overlay_ports")
	endif()
	set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/vcpkg/scripts/buildsystems/vcpkg.cmake"
		CACHE STRING "Vcpkg toolchain file")
	if(DEFINED VCPKG_CHAINLOAD_TOOLCHAIN_FILE)
		get_filename_component(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${VCPKG_CHAINLOAD_TOOLCHAIN_FILE}" ABSOLUTE)
		set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${VCPKG_CHAINLOAD_TOOLCHAIN_FILE}" CACHE STRING "Vcpkg chainload toolchain file" FORCE)
	endif()
	# Set this so that all the various find_package() calls don't need an explicit
	# CONFIG option
	set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
	if (CEMU_IOS AND NOT VCPKG_TARGET_TRIPLET)
		set(VCPKG_TARGET_TRIPLET "arm64-ios" CACHE STRING "")
	endif()
	if (WIN32)
		set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "")
	endif()
endif()

project(Cemu VERSION 2.0.0)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_definitions($<$<CONFIG:Debug>:CEMU_DEBUG_ASSERT>) # if build type is debug, set CEMU_DEBUG_ASSERT

add_definitions(-DEMULATOR_VERSION_MAJOR=${EMULATOR_VERSION_MAJOR})
add_definitions(-DEMULATOR_VERSION_MINOR=${EMULATOR_VERSION_MINOR})
add_definitions(-DEMULATOR_VERSION_PATCH=${EMULATOR_VERSION_PATCH})

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# enable link time optimization for release builds
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)

if (MSVC)
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT CemuBin)
	# floating point model: precise, fiber safe optimizations
	add_compile_options(/EHsc /fp:precise)
	if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
		# Speeds up static linking (especially helpful in incremental compilation)
		if((CMAKE_LINKER MATCHES ".*lld-link.*") AND (CMAKE_AR MATCHES ".*llvm-lib.*"))
			set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY STATIC_LIBRARY_OPTIONS /llvmlibthin)
		endif()
  	else()
	  add_compile_options(/GT)
	endif()
	# enable additional optimization flags for release builds
	add_compile_options($<$<CONFIG:Release,RelWithDebInfo>:/Oi>) # enable intrinsic functions
	add_compile_options($<$<CONFIG:Release,RelWithDebInfo>:/Ot>) # favor speed
endif()

if (APPLE OR CEMU_IOS)
    enable_language(OBJC OBJCXX)
    if(CEMU_IOS)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "18.0")
        add_compile_definitions(CEMU_IOS=1)
    else()
        set(CMAKE_OSX_DEPLOYMENT_TARGET "13.4")
    endif()
endif()

if (UNIX AND NOT APPLE)
	option(ENABLE_WAYLAND "Build with Wayland support" ON)
	option(ENABLE_FERAL_GAMEMODE "Enables Feral Interactive GameMode Support" ON)
	option(ENABLE_BLUEZ "Build with Bluez support" ON)
endif()

if (APPLE)
    set(ENABLE_METAL_DEFAULT ON)
else()
    set(ENABLE_METAL_DEFAULT OFF)
endif()

set(ENABLE_OPENGL_DEFAULT ON)
set(ENABLE_VULKAN_DEFAULT ON)
set(ENABLE_SDL_DEFAULT ON)
set(ENABLE_HIDAPI_DEFAULT ON)
set(ENABLE_DISCORD_RPC_DEFAULT ON)
set(ENABLE_CUBEB_DEFAULT ON)
set(ENABLE_WXWIDGETS_DEFAULT ON)
if(CEMU_IOS)
    set(ENABLE_OPENGL_DEFAULT OFF)
    set(ENABLE_VULKAN_DEFAULT OFF)
    set(ENABLE_SDL_DEFAULT OFF)
    set(ENABLE_HIDAPI_DEFAULT OFF)
    set(ENABLE_DISCORD_RPC_DEFAULT OFF)
    set(ENABLE_CUBEB_DEFAULT OFF)
    set(ENABLE_WXWIDGETS_DEFAULT OFF)
endif()

option(ENABLE_OPENGL "Enables the OpenGL backend" ${ENABLE_OPENGL_DEFAULT})
if (ENABLE_OPENGL)
	add_compile_definitions(HAS_OPENGL=1)
endif()
option(ENABLE_VULKAN "Enables the Vulkan backend" ${ENABLE_VULKAN_DEFAULT})
if (ENABLE_VULKAN)
	add_compile_definitions(HAS_VULKAN=1)
endif()
option(ENABLE_METAL "Enables the Metal backend" ${ENABLE_METAL_DEFAULT})
option(ENABLE_DISCORD_RPC "Enables the Discord Rich Presence feature" ${ENABLE_DISCORD_RPC_DEFAULT})

if (ENABLE_METAL AND NOT APPLE)
    message(FATAL_ERROR "Metal backend is only supported on Apple platforms")
endif()

# input backends
if (WIN32)
	option(ENABLE_XINPUT "Enables the usage of XInput" ON)
	option(ENABLE_DIRECTINPUT "Enables the usage of DirectInput" ON)
	add_compile_definitions(HAS_DIRECTINPUT)
endif()

option(ENABLE_HIDAPI "Build with HIDAPI" ${ENABLE_HIDAPI_DEFAULT})
option(ENABLE_SDL "Enables the SDLController backend" ${ENABLE_SDL_DEFAULT})
if (ENABLE_SDL)
	add_compile_definitions(HAS_SDL=1)
endif()

# audio backends
if (WIN32)
	option(ENABLE_DIRECTAUDIO "Enables the directaudio backend" ON)
	option(ENABLE_XAUDIO "Enables the xaudio backend" ON)
endif()
option(ENABLE_CUBEB "Enabled cubeb backend" ${ENABLE_CUBEB_DEFAULT})

option(ENABLE_WXWIDGETS "Build with wxWidgets UI (Currently required)" ${ENABLE_WXWIDGETS_DEFAULT})
option(CEMU_IOS_UNIVERSAL "Build with both iOS device and simulator deps in one Xcode project" OFF)

if(CEMU_IOS)
	set(ENABLE_OPENGL OFF)
	set(ENABLE_VULKAN OFF)
	set(ENABLE_SDL OFF)
	set(ENABLE_HIDAPI OFF)
	set(ENABLE_DISCORD_RPC OFF)
	set(ENABLE_CUBEB OFF)
	set(ENABLE_WXWIDGETS OFF)
	set(ENABLE_OPENGL OFF CACHE BOOL "" FORCE)
	set(ENABLE_VULKAN OFF CACHE BOOL "" FORCE)
	set(ENABLE_SDL OFF CACHE BOOL "" FORCE)
	set(ENABLE_HIDAPI OFF CACHE BOOL "" FORCE)
	set(ENABLE_DISCORD_RPC OFF CACHE BOOL "" FORCE)
	set(ENABLE_CUBEB OFF CACHE BOOL "" FORCE)
	set(ENABLE_WXWIDGETS OFF CACHE BOOL "" FORCE)
endif()


set(THREADS_PREFER_PTHREAD_FLAG true)
find_package(Threads REQUIRED)
if (ENABLE_SDL AND NOT CEMU_IOS)
	find_package(SDL2 REQUIRED)
endif()
if (CEMU_IOS AND CEMU_IOS_UNIVERSAL)
	set(CEMU_IOS_DEVICE_TRIPLET "arm64-ios")
	set(CEMU_IOS_SIMULATOR_TRIPLET "arm64-ios-simulator")
	set(CEMU_IOS_VCPKG_DEVICE_ROOT "${CMAKE_BINARY_DIR}/vcpkg_installed")
	set(CEMU_IOS_VCPKG_SIM_ROOT "${CMAKE_BINARY_DIR}/vcpkg_installed-sim")
	set(CEMU_IOS_VCPKG_DEVICE_LIB "${CEMU_IOS_VCPKG_DEVICE_ROOT}/${CEMU_IOS_DEVICE_TRIPLET}/lib")
	set(CEMU_IOS_VCPKG_DEVICE_DEBUG_LIB "${CEMU_IOS_VCPKG_DEVICE_ROOT}/${CEMU_IOS_DEVICE_TRIPLET}/debug/lib")
	set(CEMU_IOS_VCPKG_SIM_LIB "${CEMU_IOS_VCPKG_SIM_ROOT}/${CEMU_IOS_SIMULATOR_TRIPLET}/lib")
	set(CEMU_IOS_VCPKG_SIM_DEBUG_LIB "${CEMU_IOS_VCPKG_SIM_ROOT}/${CEMU_IOS_SIMULATOR_TRIPLET}/debug/lib")
	set(CEMU_IOS_VCPKG_INCLUDE_DIR "${CEMU_IOS_VCPKG_DEVICE_ROOT}/${CEMU_IOS_DEVICE_TRIPLET}/include")

	set(CMAKE_XCODE_ATTRIBUTE_LIBRARY_SEARCH_PATHS[sdk=iphoneos*]
		"$(inherited) ${CEMU_IOS_VCPKG_DEVICE_LIB} ${CEMU_IOS_VCPKG_DEVICE_DEBUG_LIB}"
	)
	set(CMAKE_XCODE_ATTRIBUTE_LIBRARY_SEARCH_PATHS[sdk=iphonesimulator*]
		"$(inherited) ${CEMU_IOS_VCPKG_SIM_LIB} ${CEMU_IOS_VCPKG_SIM_DEBUG_LIB}"
	)
	set(CMAKE_XCODE_ATTRIBUTE_HEADER_SEARCH_PATHS
		"$(inherited)"
		"${CEMU_IOS_VCPKG_INCLUDE_DIR}"
	)

	function(cemu_ios_universal_import target_name)
		add_library(${target_name} INTERFACE IMPORTED GLOBAL)
		set_target_properties(${target_name} PROPERTIES
			INTERFACE_INCLUDE_DIRECTORIES "${CEMU_IOS_VCPKG_INCLUDE_DIR}"
		)
		if (ARGN)
			set_target_properties(${target_name} PROPERTIES
				INTERFACE_LINK_LIBRARIES "${ARGN}"
			)
		endif()
	endfunction()

	cemu_ios_universal_import(CURL::libcurl "-lcurl")
	cemu_ios_universal_import(pugixml::pugixml "-lpugixml")
	cemu_ios_universal_import(ZLIB::ZLIB "-lz")
	cemu_ios_universal_import(zstd::zstd "-lzstd")
	cemu_ios_universal_import(zstd::libzstd "-lzstd")
	cemu_ios_universal_import(OpenSSL::SSL "-lssl" "-lcrypto")
	cemu_ios_universal_import(OpenSSL::Crypto "-lcrypto")
	cemu_ios_universal_import(glm::glm)
	cemu_ios_universal_import(fmt::fmt "-lfmt")
	cemu_ios_universal_import(libzip::zip "-lzip")
	cemu_ios_universal_import(Boost::filesystem "-lboost_filesystem" "-lboost_system" "-lboost_atomic")
	cemu_ios_universal_import(Boost::nowide "-lboost_nowide")
	cemu_ios_universal_import(Boost::program_options "-lboost_program_options" "-lboost_system")
	cemu_ios_universal_import(Boost::system "-lboost_system")
	cemu_ios_universal_import(Boost::atomic "-lboost_atomic")
	cemu_ios_universal_import(Boost::container "-lboost_container")
	add_library(Boost::headers INTERFACE IMPORTED GLOBAL)
	set_target_properties(Boost::headers PROPERTIES
		INTERFACE_INCLUDE_DIRECTORIES "${CEMU_IOS_VCPKG_INCLUDE_DIR}"
	)
else()
	find_package(CURL REQUIRED)
	find_package(pugixml REQUIRED)
	find_package(RapidJSON REQUIRED)
	find_package(Boost COMPONENTS program_options filesystem nowide REQUIRED)
	find_package(libzip REQUIRED)
	if (ENABLE_VULKAN)
		find_package(glslang REQUIRED)
	endif()
	find_package(ZLIB REQUIRED)
	find_package(zstd MODULE REQUIRED) # MODULE so that zstd::zstd is available
	find_package(OpenSSL COMPONENTS Crypto SSL REQUIRED)
	find_package(glm REQUIRED)
	find_package(fmt 9 REQUIRED)
	find_package(PNG REQUIRED)
endif()

# glslang versions older than 11.11.0 define targets without a namespace
if (NOT TARGET glslang::SPIRV AND TARGET SPIRV)
	add_library(glslang::SPIRV ALIAS SPIRV)
endif()

if (UNIX AND NOT APPLE)
	find_package(X11 REQUIRED)
	if (ENABLE_WAYLAND)
		find_package(Wayland REQUIRED Client)
		find_package(WaylandScanner REQUIRED)
		find_package(WaylandProtocols 1.15 REQUIRED)

		ecm_add_wayland_client_protocol(WAYLAND_PROTOCOL_SRCS
			PROTOCOL "${WaylandProtocols_DATADIR}/stable/viewporter/viewporter.xml"
			BASENAME viewporter)
		add_library(CemuWaylandProtocols STATIC ${WAYLAND_PROTOCOL_SRCS})
		target_include_directories(CemuWaylandProtocols PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")
		target_include_directories(CemuWaylandProtocols PRIVATE ${Wayland_INCLUDE_DIRS})
		add_compile_definitions(HAS_WAYLAND)
	endif()
	find_package(GTK3 REQUIRED)

	if(ENABLE_BLUEZ)
		find_package(bluez REQUIRED)
		set(SUPPORTS_WIIMOTE ON)
		add_compile_definitions(HAS_BLUEZ)
	endif()

endif()

if (ENABLE_VULKAN)
	include_directories("dependencies/Vulkan-Headers/include")
endif()

if (ENABLE_OPENGL)
	find_package(OpenGL REQUIRED)
endif()

if (ENABLE_METAL)
    include_directories(${CMAKE_SOURCE_DIR}/dependencies/metal-cpp)

    add_definitions(-DENABLE_METAL=1)
endif()

if (ENABLE_DISCORD_RPC)
	add_compile_definitions(ENABLE_DISCORD_RPC)
endif()

if (ENABLE_HIDAPI)
	find_package(hidapi REQUIRED)
	set(SUPPORTS_WIIMOTE ON)
	add_compile_definitions(HAS_HIDAPI)
endif ()

if(UNIX AND NOT APPLE)
	if(ENABLE_FERAL_GAMEMODE)
		add_compile_definitions(ENABLE_FERAL_GAMEMODE)
		add_subdirectory(dependencies/gamemode EXCLUDE_FROM_ALL)
		target_include_directories(gamemode INTERFACE ./dependencies/gamemode/lib)
	endif()
endif()

if (ENABLE_WXWIDGETS)
	find_package(wxWidgets 3.3 REQUIRED COMPONENTS base core gl propgrid xrc)
endif()

if (ENABLE_CUBEB)
	if (NOT ENABLE_VCPKG)
	    find_package(cubeb)
	endif()
	if (NOT cubeb_FOUND)
		option(BUILD_TESTS "" OFF)
		option(BUILD_TOOLS "" OFF)
		option(BUNDLE_SPEEX "" OFF)
		set(USE_WINMM OFF CACHE BOOL "")
		add_subdirectory("dependencies/cubeb" EXCLUDE_FROM_ALL SYSTEM)
		set_property(TARGET cubeb PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
		add_library(cubeb::cubeb ALIAS cubeb)
	endif()
	add_compile_definitions("HAS_CUBEB=1")
endif()

add_subdirectory("dependencies/ih264d" EXCLUDE_FROM_ALL)

if (CMAKE_OSX_ARCHITECTURES)
	set(CEMU_ARCHITECTURE ${CMAKE_OSX_ARCHITECTURES})
else()
	set(CEMU_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
endif()
if(CEMU_ARCHITECTURE MATCHES "(aarch64)|(AARCH64)|(arm64)|(ARM64)")
	add_subdirectory("dependencies/xbyak_aarch64" EXCLUDE_FROM_ALL)
endif()

find_package(ZArchive)
if (NOT ZArchive_FOUND)
	add_subdirectory("dependencies/ZArchive" EXCLUDE_FROM_ALL)
endif()

add_subdirectory(src)
