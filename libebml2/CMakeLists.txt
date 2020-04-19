set(CPACK_PACKAGE_NAME "ebml2")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 21)
set(CPACK_PACKAGE_VERSION_PATCH 3)

option(CONFIG_EBML_UNICODE "Build libebml2 with Unicode conversion support" ON)
option(CONFIG_EBML_WRITING "Build libebml2 with write support" ON)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/ebml2_project.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/ebml2_project.h
)

set(EBML2_GROUP_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlmain.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlbinary.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlcrc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmldate.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlelement.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlmaster.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlnumber.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlstring.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlvoid.c
  ${CMAKE_CURRENT_BINARY_DIR}/ebml2_project.h
)
set(EBML2_GROUP_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/ebml/ebml.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ebml/ebml_internal.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ebmlcrc.h
)
add_library("ebml2_group" INTERFACE)
target_sources("ebml2_group" INTERFACE ${EBML2_GROUP_SOURCES} ${EBML2_GROUP_HEADERS})
target_link_libraries("ebml2_group" INTERFACE "corec_node")
target_include_directories("ebml2_group" INTERFACE "." "${CMAKE_CURRENT_BINARY_DIR}")
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("ebml2_group" PROPERTIES 
    PUBLIC_HEADER "${EBML2_GROUP_HEADERS}"
  )
endif()

# the actual library that can be installed/linked
add_library("ebml2")
target_link_libraries("ebml2" PUBLIC "ebml2_group")

# TODO finish this
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/legacy/ebml2_legacy_project.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/legacy/ebml2_legacy_project.h
)
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

