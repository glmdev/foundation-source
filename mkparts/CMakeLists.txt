project("mkparts" VERSION 0.1.0)

add_executable("mkparts" mkparts.c)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/mkparts_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/mkparts_project.h
)
target_link_libraries("mkparts" PRIVATE "corec_parser")
target_link_libraries("mkparts" PRIVATE "matroska2")
