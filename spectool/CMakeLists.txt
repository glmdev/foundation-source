add_executable("tabler" tabler.c)
target_link_libraries("tabler" PRIVATE "corec_parser")

add_executable("data2lib" data2lib.c spec_element.c)
target_link_libraries("data2lib" PRIVATE "corec_parser")

add_executable("data2spec" data2spec.c spec_element.c)
target_link_libraries("data2spec" PRIVATE "corec_parser")

add_executable("spec2data" spec2data.c spec_element.c)
target_link_libraries("spec2data" PRIVATE "corec_parser")
