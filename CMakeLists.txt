cmake_minimum_required(VERSION 3.27)
project(kCaveHook)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
include("${CMAKE_CURRENT_LIST_DIR}/cmake/global-flags.cmake")

add_compile_options("/W0 /GL- /Ox /Ob1 /Os /EHa") # No warnings, no whole program optimization, optimization favor speed, only __inline, intrinsic functions, favor small code, SEH exceptions support
add_link_options("/ENTRY:DriverEntry") # Custom driver entry to allow manual map

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(WDK REQUIRED)
find_package(Zydis REQUIRED)

file(GLOB_RECURSE SOURCES "src/*.cpp")

wdk_add_library(kCaveHook STATIC ${SOURCES})

target_include_directories(kCaveHook PRIVATE headers)
