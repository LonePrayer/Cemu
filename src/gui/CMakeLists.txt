add_library(CemuGui INTERFACE)
target_include_directories(CemuGui INTERFACE "interface")

if(ENABLE_WXWIDGETS)
    add_subdirectory(wxgui)
    target_link_libraries(CemuGui INTERFACE CemuWxGui)
endif()

if(CEMU_IOS)
    add_library(CemuIosGui STATIC
        ios/WindowSystemIOS.cpp
    )
    target_include_directories(CemuIosGui PRIVATE "interface" "..")
    target_link_libraries(CemuIosGui PRIVATE Boost::headers)
    target_link_libraries(CemuGui INTERFACE CemuIosGui)
endif()
