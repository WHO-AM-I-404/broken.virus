cmake_minimum_required(VERSION 3.15)
project(BROKEN4)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options("/std:c++latest")
else()
    add_compile_options("-std=c++17")
endif()

if(MINGW)
    add_compile_options("-static")
    add_compile_options("-static-libgcc")
    add_compile_options("-static-libstdc++")
    add_compile_options("-mwindows")
endif()

# Hapus find_package(Gdiplus REQUIRED) karena tidak tersedia di Windows SDK
# find_package(Gdiplus REQUIRED)

# Sesuaikan path file sumber, misalnya ada di BROKEN/broken4.cpp
add_executable(BROKEN4 BROKEN/broken4.cpp)

target_link_libraries(BROKEN4
    winmm
    user32
    dwmapi
    gdi32
    ntdll
    shell32
    advapi32
    iphlpapi
    ws2_32
    winhttp
    wininet
    cryptui
    gdiplus
    urlmon
    setupapi
    virtdisk
    crypt32
)

if(MINGW)
    target_link_options(BROKEN4 PRIVATE -static)
endif()
