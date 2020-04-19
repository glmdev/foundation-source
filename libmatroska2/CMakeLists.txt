set(CPACK_PACKAGE_NAME "matroska2")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 22)
set(CPACK_PACKAGE_VERSION_PATCH 3)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/matroska2_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/matroska2_project.h
)

add_library("matroska2"
  matroskamain.c
  matroskablock.c
  matroska_sem.c
)
target_include_directories("matroska2" PUBLIC ".")
target_compile_definitions("matroska2" PUBLIC MATROSKA_LIBRARY)
target_link_libraries("matroska2" PRIVATE "ebml2")

# add_library("matroska2_haali" MatroskaParser/MatroskaParser.c)
# target_include_directories("matroska2_haali" PUBLIC "." "MatroskaParser")
# set_target_properties("matroska2_haali" PROPERTIES PUBLIC_HEADER "MatroskaParser/MatroskaParser.h")
# target_link_libraries("matroska2_haali" PRIVATE "matroska2")
