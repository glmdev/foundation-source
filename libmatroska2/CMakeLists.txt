set(CPACK_PACKAGE_NAME "matroska2")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 22)
set(CPACK_PACKAGE_VERSION_PATCH 3)

option(CONFIG_CODEC_HELPER "Enable Vorbis frame durations" ON)
option(CONFIG_LZO1X "Enable lzo (de)compression" ON)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/matroska2_project.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/matroska2_project.h
)
set(MATROSKA2_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/matroska/matroska.h
  ${CMAKE_CURRENT_SOURCE_DIR}/matroska/matroska_sem.h
  ${CMAKE_CURRENT_SOURCE_DIR}/matroska/matroska_internal.h
)

add_library("matroska2"
  matroskamain.c
  matroskablock.c
  matroska_sem.c
)
target_include_directories("matroska2" PUBLIC ".")
target_compile_definitions("matroska2" PUBLIC HAS_MATROSKA2
                                       PRIVATE MATROSKA_LIBRARY)
target_link_libraries("matroska2" PRIVATE "ebml2")
if (CONFIG_ZLIB)
  target_link_libraries("matroska2" PRIVATE "zlib")
endif(CONFIG_ZLIB)
if (CONFIG_LZO1X)
  target_link_libraries("matroska2" PRIVATE "minilzo")
endif(CONFIG_LZO1X)
if (CONFIG_CODEC_HELPER)
  target_link_libraries("matroska2" PRIVATE "tremor")
endif(CONFIG_CODEC_HELPER)
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("matroska2" PROPERTIES 
    PUBLIC_HEADER "${MATROSKA2_HEADERS}"
  )
endif()

# add_library("matroska2_haali" MatroskaParser/MatroskaParser.c)
# option(CONFIG_MATROSKA2_NOGLOBAL "" OFF)
# if (CONFIG_MATROSKA2_NOGLOBAL)
#   target_compile_definitions("matroska2_haali" PRIVATE NO_MATROSKA2_GLOBAL)
# endif(CONFIG_MATROSKA2_NOGLOBAL)
# target_include_directories("matroska2_haali" PUBLIC "." "MatroskaParser")
# set_target_properties("matroska2_haali" PROPERTIES PUBLIC_HEADER "MatroskaParser/MatroskaParser.h")
# target_link_libraries("matroska2_haali" PRIVATE "matroska2")
