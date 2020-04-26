project("matroska2" VERSION 0.22.3)

option(CONFIG_BZLIB "Enable bzlib (de)compression in libmatroska2" ON)
option(CONFIG_LZO1X "Enable lzo (de)compression in libmatroska2" ON)

set(matroska2_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/matroskamain.c
  ${CMAKE_CURRENT_SOURCE_DIR}/matroskablock.c
  ${CMAKE_CURRENT_SOURCE_DIR}/matroska_sem.c
)
set(matroska2_PUBLIC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/matroska/matroska.h
  ${CMAKE_CURRENT_SOURCE_DIR}/matroska/matroska_sem.h
  ${CMAKE_CURRENT_SOURCE_DIR}/matroska/matroska_internal.h
)

add_library("matroska2" ${matroska2_SOURCES} ${matroska2_PUBLIC_HEADERS})
target_include_directories("matroska2" PUBLIC ".")
target_compile_definitions("matroska2" PUBLIC HAS_MATROSKA2)
# defined when building the library, rather than using as an interface
target_compile_definitions("matroska2" PRIVATE MATROSKA_LIBRARY)
target_link_libraries("matroska2" PUBLIC "ebml2")
configure_file(matroska2_project.h.in matroska2_project.h)
target_include_directories("matroska2" PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (CONFIG_ZLIB)
  target_link_libraries("matroska2" PRIVATE "zlib")
endif(CONFIG_ZLIB)
if (CONFIG_LZO1X)
  add_subdirectory("minilzo")
  target_link_libraries("matroska2" PRIVATE "minilzo")
endif(CONFIG_LZO1X)
if (CONFIG_BZLIB)
  add_subdirectory("bzip2")
  target_link_libraries("matroska2" PRIVATE "bzlib")
endif(CONFIG_BZLIB)
if (CONFIG_CODEC_HELPER)
  target_link_libraries("matroska2" PUBLIC "tremor")
endif(CONFIG_CODEC_HELPER)
set_target_properties("matroska2" PROPERTIES 
  PUBLIC_HEADER "${matroska2_PUBLIC_HEADERS}"
)

add_executable("mkvtree" test/mkvtree.c)
target_link_libraries("mkvtree" PRIVATE "matroska2" "corec_parser")

# add_library("matroska2_haali" MatroskaParser/MatroskaParser.c)
# option(CONFIG_MATROSKA2_NOGLOBAL "" OFF)
# if (CONFIG_MATROSKA2_NOGLOBAL)
#   target_compile_definitions("matroska2_haali" PRIVATE NO_MATROSKA2_GLOBAL)
# endif(CONFIG_MATROSKA2_NOGLOBAL)
# target_include_directories("matroska2_haali" PUBLIC "." "MatroskaParser")
# set_target_properties("matroska2_haali" PROPERTIES PUBLIC_HEADER "MatroskaParser/MatroskaParser.h")
# target_link_libraries("matroska2_haali" PRIVATE "matroska2")
