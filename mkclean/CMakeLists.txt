option(CONFIG_CODEC_HELPER "Enable Vorbis frame durations in libmatroska2" ON)

project("mkclean" VERSION 0.8.1)

add_executable("mkclean" mkclean.c)
add_executable("mkWDclean" mkclean.c)

configure_file(mkclean_project.h.in mkclean_project.h)
configure_file(config.h.in config.h)
target_include_directories("mkclean" PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories("mkWDclean" PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries("mkclean" PRIVATE "matroska2" "corec_parser")
target_link_libraries("mkWDclean" PRIVATE "matroska2" "corec_parser")

if (CONFIG_CODEC_HELPER)
    add_subdirectory("tremor")
    target_link_libraries("mkclean" PRIVATE "tremor")
    target_link_libraries("mkWDclean" PRIVATE "tremor")
endif(CONFIG_CODEC_HELPER)

add_subdirectory("regression")
