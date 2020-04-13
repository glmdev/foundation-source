cmake_minimum_required(VERSION 2.8)

project("foundation sources" C)

configure_file(config.h.in config.h)

add_subdirectory("corec")
target_include_directories("corec" PRIVATE ".")
