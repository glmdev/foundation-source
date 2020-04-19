cmake_minimum_required(VERSION 2.8)

project("foundation sources")

configure_file(config.h.in config.h)

add_subdirectory("corec")
target_include_directories("corec_node" PRIVATE ".")
target_include_directories("corec_array" PRIVATE ".")
target_include_directories("corec_parser" PRIVATE ".")
target_include_directories("corec_md5" PRIVATE ".")
target_include_directories("corec_system" PRIVATE ".")
target_include_directories("corec_charconvert" PRIVATE ".")
target_include_directories("corec_str" PRIVATE ".")
target_include_directories("corec_file" PRIVATE ".")
target_include_directories("corec_date" PRIVATE ".")
target_include_directories("corec_multithread" PRIVATE ".")

add_subdirectory("spectool")
# Dirty way for now
target_include_directories("tabler" PRIVATE "corec/corec" ".")
target_include_directories("data2lib" PRIVATE ".")
target_include_directories("data2spec" PRIVATE ".")
target_include_directories("spec2data" PRIVATE ".")

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

add_subdirectory("libebml2")
target_include_directories("ebml2" PRIVATE ".")
# target_include_directories("ebml2_legacy" PRIVATE ".")

add_subdirectory("libmatroska2")
target_include_directories("matroska2" PRIVATE ".")
# target_include_directories("matroska2_haali" PRIVATE ".")
