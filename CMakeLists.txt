cmake_minimum_required(VERSION 4.0)

project(FontSlicer
    VERSION 1.0.1
    DESCRIPTION "Tool to do bad things to font tags"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(font-slicer
    src/main.c
)

if(MSVC)
    target_include_directories(font-slicer PRIVATE src/dirent)
    target_compile_options(font-slicer PRIVATE /W4)
    target_compile_definitions(font-slicer PRIVATE _CRT_NONSTDC_NO_DEPRECATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(font-slicer PRIVATE -Wall -Wextra)
endif()

if(WIN32)
    target_sources(font-slicer PRIVATE src/windows.rc)
endif()
