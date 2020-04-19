set(CPACK_PACKAGE_NAME "ebml2")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 21)
set(CPACK_PACKAGE_VERSION_PATCH 3)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ebml2_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/ebml2_project.h
)

add_library("ebml2"
  ebmlmain.c
  ebmlbinary.c
  ebmlcrc.c
  ebmldate.c
  ebmlelement.c
  ebmlmaster.c
  ebmlnumber.c
  ebmlstring.c
  ebmlvoid.c
)
target_include_directories("ebml2" PUBLIC ".")
target_link_libraries("ebml2" PRIVATE "corec_node")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/legacy/ebml2_legacy_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/legacy/ebml2_legacy_project.h
)

# TODO finish this
# add_library("ebml2_legacy" legacy/legacy.cpp)
# target_compile_definitions("ebml2_legacy" PUBLIC EBML_STRICT_API)
# target_link_libraries("ebml2_legacy" PUBLIC "ebml2")
# target_include_directories("ebml2_legacy" PUBLIC "legacy")
