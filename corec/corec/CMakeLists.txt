# Base core API
add_library("corec" INTERFACE)
set(COREC_BASE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/corec.h
  ${CMAKE_CURRENT_SOURCE_DIR}/err.h
  ${CMAKE_CURRENT_SOURCE_DIR}/helper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/memalloc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/portab.h
)
target_sources("corec" INTERFACE ${COREC_BASE_HEADERS})
#if (CONFIG_SAFE_C)
#  target_sources("corec" INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/banned.h)
#endif (WIN32)
#if(COREMAKE_CONFIG_HELPER)
#  target_sources("corec" INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/confhelper.h)
#endif (COREMAKE_CONFIG_HELPER)
target_include_directories("corec" INTERFACE "..")
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("corec" PROPERTIES 
    PUBLIC_HEADER "${COREC_BASE_HEADERS}"
  )
endif()

# Node API
set(COREC_NODE_HEADERS
  node/node.h
  node/nodebase.h
  node/nodetree.h
  node/nodetools.h
)
add_library("corec_node"
  node/node.c
  node/nodetree.c
  ${COREC_NODE_HEADERS}
  # documentation installed with the sources
  node/corec.html
)
set_target_properties("corec_node" PROPERTIES 
  PUBLIC_HEADER "${COREC_NODE_HEADERS}"
)
target_include_directories("corec_node" PUBLIC ".")
target_link_libraries("corec_node" PRIVATE "corec_array" "corec_multithread" "corec_str" "corec_file")

# Array API
add_library("corec_array" array/array.c)
set_target_properties("corec_array" PROPERTIES 
  PUBLIC_HEADER "array/array.h"
)
target_link_libraries("corec_array" PUBLIC "corec")

# File API
set(COREC_FILE_HEADERS
  helpers/file/file.h
  helpers/file/streams.h
)
add_library("corec_file" 
  helpers/file/bufstream.c
  helpers/file/memstream.c
  helpers/file/streams.c
  helpers/file/tools.c
  ${COREC_FILE_HEADERS}
  # TODO only if CONFIG_STDIO is set
  helpers/file/stream_stdio.c
)
if (WIN32)
  target_sources("corec_file" PRIVATE helpers/file/file_win32.c)

  # for SHFileOperation to move files in the recycle bin
  target_link_libraries("corec_file" PRIVATE shell32)
elseif(UNIX)
  target_sources("corec_file" PRIVATE helpers/file/file_libc.c)
endif(WIN32)
set_target_properties("corec_file" PROPERTIES 
  PUBLIC_HEADER "${COREC_FILE_HEADERS}"
)
target_link_libraries("corec_file" PRIVATE "corec_node" "corec_date")

# Parser API
set(COREC_PARSER_HEADERS
  helpers/parser/buffer.h
  helpers/parser/dataheap.h
  helpers/parser/hotkey.h
  helpers/parser/nodelookup.h
  helpers/parser/parser.h
  helpers/parser/strtab.h
  helpers/parser/strtypes.h
  helpers/parser/urlpart.h
)
add_library("corec_parser"
  helpers/parser/buffer.c
  helpers/parser/dataheap.c
  helpers/parser/hotkey.c
  helpers/parser/nodelookup.c
  helpers/parser/parser2.c
  helpers/parser/strtab.c
  helpers/parser/strtypes.c
  helpers/parser/urlpart.c
  ${COREC_PARSER_HEADERS}
)
target_compile_definitions("corec_parser" PUBLIC COREC_PARSER)
target_link_libraries("corec_parser" PRIVATE "corec_str" "corec_charconvert" "corec_file")
target_include_directories("corec_parser" PUBLIC "helpers")
set_target_properties("corec_parser" PROPERTIES
  PUBLIC_HEADER "${COREC_PARSER_HEADERS}"
)

# System call API
add_library("corec_system")
if (WIN32)
  target_sources("corec_system" PRIVATE helpers/system/ccsystem_win32.c)
elseif(UNIX)
  target_sources("corec_system" PRIVATE helpers/system/ccsystem_posix.c)
endif(WIN32)
set_target_properties("corec_system" PROPERTIES PUBLIC_HEADER "helpers/system/ccsystem.h")
target_link_libraries("corec_system" PUBLIC "corec" "corec_node")

# MD5 API
add_library("corec_md5" helpers/md5/md5.c)
set_target_properties("corec_md5" PROPERTIES PUBLIC_HEADER "helpers/md5/md5.h")
target_link_libraries("corec_md5" PUBLIC "corec")

# Date API
add_library("corec_date")
if (WIN32)
  target_sources("corec_date" PRIVATE helpers/date/date_win32.c)
elseif(UNIX)
    target_sources("corec_date" PRIVATE helpers/date/date_libc.c)
endif(WIN32)
set_target_properties("corec_date" PROPERTIES 
  PUBLIC_HEADER "helpers/date/date.h"
)
target_link_libraries("corec_date" PUBLIC "corec")

# String API
add_library("corec_str" INTERFACE)
set(COREC_STR_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str.h
)
target_sources("corec_str" INTERFACE 
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str.c
  ${COREC_STR_HEADERS}
)
if (WIN32)
  target_sources("corec_str" INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/str/str_win32.c)
elseif(APPLE)
    target_sources("corec_str" INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/str/str_osx.c)
elseif(UNIX)
    target_sources("corec_str" INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/str/str_linux.c)
endif(WIN32)
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("corec_str" PROPERTIES 
    PUBLIC_HEADER "${COREC_STR_HEADERS}"
  )
endif()

# Character Conversion API
add_library("corec_charconvert")
if (WIN32)
  target_sources("corec_charconvert" PRIVATE helpers/charconvert/charconvert_win32.c)
elseif(APPLE)
  target_link_libraries("corec_charconvert" PUBLIC "-framework CoreFoundation")
  target_sources("corec_charconvert" PRIVATE helpers/charconvert/charconvert_osx.c)
elseif(UNIX)
  target_sources("corec_charconvert" PRIVATE helpers/charconvert/charconvert_linux.c)
else(UNIX)
  target_sources("corec_charconvert" PRIVATE helpers/charconvert/charconvert_utf8.c)
endif(WIN32)
set_target_properties("corec_charconvert" PROPERTIES 
  PUBLIC_HEADER "helpers/charconvert/charconvert.h"
)
target_link_libraries("corec_charconvert" PUBLIC "corec")

# TODO only if CONFIG_MULTITHREAD is set
add_library("corec_multithread")
if (WIN32)
  target_sources("corec_multithread" PRIVATE multithread/multithread_win32.c)
elseif(UNIX)
  target_sources("corec_multithread" PRIVATE multithread/multithread_pthread.c)
endif(WIN32)
set_target_properties("corec_multithread" PROPERTIES PUBLIC_HEADER "multithread/multithread.h")
target_link_libraries("corec_multithread" PRIVATE "corec_node")
if(UNIX)
  target_link_libraries("corec_multithread" PRIVATE pthread)
endif(UNIX)
