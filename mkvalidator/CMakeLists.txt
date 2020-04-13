add_executable("mkvalidator" mkvalidator.c)
# set_target_properties("mkvalidator" VERSION 0.5.2)
target_link_libraries("mkvalidator" PRIVATE "corec_parser")
target_link_libraries("mkvalidator" PRIVATE "matroska2")

# TODO generate mkvalidator_project.h with PROJECT_VERSION