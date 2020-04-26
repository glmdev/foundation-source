project("mkcleanreg" VERSION 0.1.0)

add_executable("mkcleanreg" mkcleanreg.c)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/mkcleanreg_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/mkcleanreg_project.h
)

target_link_libraries("mkcleanreg" PRIVATE "corec_parser")
target_link_libraries("mkcleanreg" PRIVATE "corec_md5")
target_link_libraries("mkcleanreg" PRIVATE "corec_system")
