cmake_minimum_required(VERSION 4.0)

project(FontSlicer
    VERSION 1.0.0
    DESCRIPTION "Tool to do bad things to font tags"
    LANGUAGES C
)

add_executable(font-slicer
    src/main.c
)

if(WIN32)
    target_sources(font-slicer PRIVATE src/windows.rc)
endif()
