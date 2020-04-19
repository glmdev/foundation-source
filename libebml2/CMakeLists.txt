set(CPACK_PACKAGE_NAME "ebml2")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 21)
set(CPACK_PACKAGE_VERSION_PATCH 3)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ebml2_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/ebml2_project.h
)

set(EBML2_GROUP_SOURCES
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
add_library("ebml2" ${EBML2_GROUP_SOURCES})
target_include_directories("ebml2" PUBLIC ".")
target_link_libraries("ebml2" PRIVATE "corec_node")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/legacy/ebml2_legacy_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/legacy/ebml2_legacy_project.h
)

# TODO finish this
set(LEGACY_LIBEBML_HEADERS
  legacy/ebml/EbmlBinary.h
  legacy/ebml/EbmlConfig.h
  legacy/ebml/EbmlContexts.h
  legacy/ebml/EbmlCrc32.h
  legacy/ebml/EbmlDate.h
  legacy/ebml/EbmlDummy.h
  legacy/ebml/EbmlElement.h
  legacy/ebml/EbmlFloat.h
  legacy/ebml/EbmlHead.h
  legacy/ebml/EbmlId.h
  legacy/ebml/EbmlMaster.h
  legacy/ebml/EbmlSInteger.h
  legacy/ebml/EbmlStream.h
  legacy/ebml/EbmlString.h
  legacy/ebml/EbmlSubHead.h
  legacy/ebml/EbmlTypes.h
  legacy/ebml/EbmlUInteger.h
  legacy/ebml/EbmlUnicodeString.h
  legacy/ebml/EbmlVersion.h
  legacy/ebml/EbmlVoid.h
  legacy/ebml/IOCallback.h
  legacy/ebml/c/libebml_t.h
)
#add_library("ebml2_legacy" 
#  legacy/legacy.cpp
#  ${EBML2_GROUP_SOURCES}
#  ${LEGACY_LIBEBML_HEADERS}
#)
# target_compile_definitions("ebml2_legacy" PUBLIC EBML_STRICT_API)
# target_compile_definitions("ebml2_legacy" PRIVATE EBML_LEGACY_API)
# target_link_libraries("ebml2_legacy" PUBLIC "ebml2")
# target_include_directories("ebml2_legacy" PUBLIC "legacy")
# set_target_properties("corec_node" PROPERTIES PUBLIC_HEADER 
#  "${LEGACY_LIBEBML_HEADERS}"
#)

