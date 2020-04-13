add_executable("mkclean" mkclean.c)
# set_target_properties("mkclean" VERSION 0.8.1)
target_link_libraries("mkclean" PRIVATE "corec_parser")
target_link_libraries("mkclean" PRIVATE "matroska2")

# TODO generate mkclean_project.h with PROJECT_NAME, PROJECT_VERSION