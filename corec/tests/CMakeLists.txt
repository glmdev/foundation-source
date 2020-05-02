add_executable("string_test" string_test.c)
target_link_libraries("string_test" PRIVATE "corec")
# target_link_libraries("string_test" PRIVATE "corec_charconvert")

add_executable("file_test" file_test.c)
target_link_libraries("file_test" PRIVATE "corec")

add_executable("node_test" node_test.c)
target_link_libraries("node_test" PRIVATE "corec")

# add_executable("parser_test" parser_test.c)
# target_link_libraries("parser_test" PUBLIC "corec")
