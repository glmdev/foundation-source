project("mkcleanreg" VERSION 0.1.0)

add_executable("mkcleanreg" mkcleanreg.c)

configure_file(mkcleanreg_project.h.in mkcleanreg_project.h)
configure_file(config.h.in config.h)
target_include_directories("mkcleanreg" PRIVATE ${COREC_CONFIG_DIR})
target_link_libraries("mkcleanreg" PRIVATE "corec_parser" "corec_md5" "corec_system")
