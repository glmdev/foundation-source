project("mkparts" VERSION 0.1.0)

add_executable("mkparts" mkparts.c)

set(CPACK_PACKAGE_NAME "mkparts")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 1)
set(CPACK_PACKAGE_VERSION_PATCH 0)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/mkparts_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/mkparts_project.h
)
target_link_libraries("mkparts" PRIVATE "corec_parser")
target_link_libraries("mkparts" PRIVATE "matroska2")
