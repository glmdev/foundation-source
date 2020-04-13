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
target_link_libraries("matroska2" PRIVATE "ebml2")