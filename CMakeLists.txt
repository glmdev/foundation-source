cmake_minimum_required(VERSION 2.8)

project("foundation sources")

option(CONFIG_MATROSKA2 "Build libmatroska2" ON)

set(COREC_CONFIG_DIR ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory("corec")
add_subdirectory("spectool")
add_subdirectory("libebml2")
if(CONFIG_MATROSKA2)
    add_subdirectory("libmatroska2")
    add_subdirectory("mkvalidator")
    add_subdirectory("mkclean")
    add_subdirectory("mkparts")
endif(CONFIG_MATROSKA2)

configure_file(config.h.in config.h)
