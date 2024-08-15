if (NOT DEFINED(Zycore_Include))
    set(Zycore_Include "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/Zycore/include")
endif()
if (NOT DEFINED(Zycore_Lib))
    set(Zycore_Lib "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/Zycore/lib/Zycore.lib")
endif()
if (NOT DEFINED(Zydis_Include))
    set(Zydis_Include "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/Zydis/include")
endif()
if (NOT DEFINED(Zydis_Lib))
    set(Zydis_Lib "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/Zydis/lib/Zydis.lib")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Zydis REQUIRED_VARS Zycore_Include Zycore_Lib Zydis_Include Zydis_Lib)

include_directories(${Zycore_Include})
link_libraries(${Zycore_Lib})
include_directories(${Zydis_Include})
link_libraries(${Zydis_Lib})