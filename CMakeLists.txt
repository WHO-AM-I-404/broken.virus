cmake_minimum_required(VERSION 3.15)
project(DestructiveGlitchSimulator)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Link libraries
find_package(WindowsSDK REQUIRED)

add_executable(DestructiveGlitchSimulator Main.cpp)

target_compile_options(DestructiveGlitchSimulator PRIVATE /W4 /WX)
target_link_libraries(DestructiveGlitchSimulator
    winmm
    user32
    dwmapi
    gdi32
    ntdll
    shell32
    advapi32
    iphlpapi
    winhttp
    wtsapi32
    userenv
    netapi32
    rasapi32
    sensapi
    wininet
    urlmon
    wintrust
    winscard
    ntsecapi
    secur32
    crypt32
    virtdisk
    setupapi
)
