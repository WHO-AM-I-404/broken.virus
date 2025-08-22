cmake_minimum_required(VERSION 3.15)
project(broken4)

add_executable(broken4 BROKEN/broken4.cpp)

target_link_libraries(broken4
    gdi32
    winmm
    dwmapi
    ntdll
    shell32
    advapi32
    iphlpapi
    ws2_32
    winhttp
    wininet
    crypt32
    cryptui
    urlmon
    gdiplus
    setupapi
    virtdisk
)

set_target_properties(broken4 PROPERTIES
    WIN32_EXECUTABLE TRUE
    LINK_FLAGS "-mwindows"
)
