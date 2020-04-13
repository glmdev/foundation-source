cmake_minimum_required(VERSION 2.8)

project("foundation sources" C)

configure_file(config.h.in config.h)

add_subdirectory("corec")
target_include_directories("corec" PRIVATE ".")
target_include_directories("corec_parser" PRIVATE ".")

add_subdirectory("spectool")
# Dirty way for now
target_include_directories("tabler" PRIVATE "corec/corec" "corec/corec/helpers" "corec" ".")

