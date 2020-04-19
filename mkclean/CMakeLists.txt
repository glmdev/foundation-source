if(CONFIG_EBML_WRITING)
    add_executable("mkclean" mkclean.c)

    set(CPACK_PACKAGE_NAME "mkclean")
    set(CPACK_PACKAGE_VERSION_MAJOR 0)
    set(CPACK_PACKAGE_VERSION_MINOR 8)
    set(CPACK_PACKAGE_VERSION_PATCH 1)

    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/mkclean_project.h.in
        ${CMAKE_CURRENT_SOURCE_DIR}/mkclean_project.h
    )

    target_link_libraries("mkclean" PRIVATE "matroska2" "corec_parser")

    add_subdirectory("regression")
endif(CONFIG_EBML_WRITING)
