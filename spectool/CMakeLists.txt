add_executable("tabler" tabler.c)
target_link_libraries("tabler" PRIVATE "corec_parser")