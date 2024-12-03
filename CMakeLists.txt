cmake_minimum_required(VERSION 3.27)
project(kCaveHook LANGUAGES C)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

add_compile_options("/W0")
add_compile_options("/GL-")
add_compile_options("/EHa")

add_link_options("/ENTRY:DriverEntry") # Custom driver entry to allow manual map

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
if (NOT WDK_FOUND)
    find_package(WDK REQUIRED)
endif()

add_subdirectory(thirdparty/Zydis)

file(GLOB_RECURSE SOURCES "src/*.c")

wdk_add_library(kCaveHook STATIC ${SOURCES})

target_include_directories(kCaveHook PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/headers)
target_link_libraries(kCaveHook PRIVATE Zydis)
