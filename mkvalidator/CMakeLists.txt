project("mkvalidator" VERSION 0.5.2)

add_executable("mkvalidator" mkvalidator.c)

set(CPACK_PACKAGE_NAME "mkvalidator")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 5)
set(CPACK_PACKAGE_VERSION_PATCH 2)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/mkvalidator_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/mkvalidator_project.h
)
target_link_libraries("mkvalidator" PRIVATE "corec_parser")
target_link_libraries("mkvalidator" PRIVATE "matroska2")
