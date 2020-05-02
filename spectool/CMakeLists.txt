add_executable("tabler" tabler.c)
target_link_libraries("tabler" PUBLIC "corec")

add_executable("data2lib" data2lib.c spec_element.c spec_element.h)
target_link_libraries("data2lib" PUBLIC "corec")

add_executable("data2spec" data2spec.c spec_element.c spec_element.h)
target_link_libraries("data2spec" PUBLIC "corec")

add_executable("spec2data" spec2data.c spec_element.c spec_element.h)
target_link_libraries("spec2data" PUBLIC "corec")
