add_executable("mkcleanreg" mkcleanreg.c)

set(CPACK_PACKAGE_NAME "mkcleanreg")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 1)
set(CPACK_PACKAGE_VERSION_PATCH 0)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/mkcleanreg_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/mkcleanreg_project.h
)

target_link_libraries("mkcleanreg" PRIVATE "corec_parser")
target_link_libraries("mkcleanreg" PRIVATE "corec_md5")
target_link_libraries("mkcleanreg" PRIVATE "corec_system")
target_link_libraries("mkcleanreg" PRIVATE "matroska2")
