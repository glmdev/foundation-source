option(CONFIG_CODEC_HELPER "Enable Vorbis frame durations in libmatroska2" ON)

if(CONFIG_EBML_WRITING)
    project("mkclean" VERSION 0.8.1)

    add_executable("mkclean" mkclean.c)
    add_executable("mkWDclean" mkclean.c)

    set(CPACK_PACKAGE_NAME "mkclean")
    set(CPACK_PACKAGE_VERSION_MAJOR 0)
    set(CPACK_PACKAGE_VERSION_MINOR 8)
    set(CPACK_PACKAGE_VERSION_PATCH 1)

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/mkclean_project.h.in
        ${CMAKE_CURRENT_SOURCE_DIR}/mkclean_project.h
    )

    target_link_libraries("mkclean" PRIVATE "matroska2" "corec_parser")
    target_link_libraries("mkWDclean" PRIVATE "matroska2" "corec_parser")

    if (CONFIG_CODEC_HELPER)
        add_subdirectory("tremor")
        target_link_libraries("mkclean" PRIVATE "tremor")
        target_link_libraries("mkWDclean" PRIVATE "tremor")
    endif(CONFIG_CODEC_HELPER)
    add_subdirectory("regression")
endif(CONFIG_EBML_WRITING)
