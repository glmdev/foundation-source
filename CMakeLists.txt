cmake_minimum_required(VERSION 2.8)

project("foundation sources" C)

configure_file(config.h.in config.h)

add_subdirectory("corec")
target_include_directories("corec" PRIVATE ".")
target_include_directories("corec" PUBLIC "corec")
target_include_directories("corec_parser" PRIVATE ".")
target_include_directories("md5" PRIVATE ".")
target_include_directories("ccsystem" PRIVATE ".")

add_subdirectory("spectool")
# Dirty way for now
target_include_directories("tabler" PRIVATE "corec/corec" "corec/corec/helpers" "corec" ".")

add_subdirectory("mkvalidator")
# Dirty way to add the global config.h for now
target_include_directories("mkvalidator" PRIVATE ".")

add_subdirectory("mkclean")
# Dirty way to add the global config.h for now
target_include_directories("mkclean" PRIVATE ".")
target_include_directories("mkcleanreg" PRIVATE ".")

add_subdirectory("mkparts")
# Dirty way to add the global config.h for now
target_include_directories("mkparts" PRIVATE ".")

add_subdirectory("libmatroska2")
target_include_directories("matroska2" PRIVATE ".")
#target_include_directories("matroska2" PUBLIC "libmatroska2")
add_subdirectory("libebml2")
target_include_directories("ebml2" PRIVATE ".")
