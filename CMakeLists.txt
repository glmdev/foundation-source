cmake_minimum_required(VERSION 2.8)

project("foundation sources")


set(COREC_CONFIG_DIR ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory("corec")
add_subdirectory("spectool")
add_subdirectory("mkvalidator")
add_subdirectory("mkclean")
add_subdirectory("mkparts")
add_subdirectory("libebml2")
add_subdirectory("libmatroska2")

configure_file(config.h.in config.h)
