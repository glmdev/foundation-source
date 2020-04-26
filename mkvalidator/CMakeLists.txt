project("mkvalidator" VERSION 0.5.2)

add_executable("mkvalidator" mkvalidator.c)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/mkvalidator_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/mkvalidator_project.h
)
target_link_libraries("mkvalidator" PRIVATE "corec_parser")
target_link_libraries("mkvalidator" PRIVATE "matroska2")
