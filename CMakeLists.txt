cmake_minimum_required(VERSION 3.15)
project(Broken)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Target executable -> broken.exe
add_executable(broken
    BROKEN/broken4.cpp
)

# Compile options
target_compile_options(broken PRIVATE /W4 /WX)

# Link libraries bawaan Windows
target_link_libraries(broken
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
