option(CONFIG_STDIO "Build corec file API with stdio support" ON)
option(CONFIG_MULTITHREAD "Enable multithread API")

# Base core API
add_library("corec" INTERFACE)
set(corec_base_PUBLIC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/corec.h
  ${CMAKE_CURRENT_SOURCE_DIR}/err.h
  ${CMAKE_CURRENT_SOURCE_DIR}/helper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/memalloc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/portab.h
)
target_sources("corec" INTERFACE ${corec_base_PUBLIC_HEADERS})
#if (CONFIG_SAFE_C)
#  target_sources("corec" INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/banned.h)
#endif (WIN32)
#if(COREMAKE_CONFIG_HELPER)
#  target_sources("corec" INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/confhelper.h)
#endif (COREMAKE_CONFIG_HELPER)
target_include_directories("corec" INTERFACE ".." "${COREC_CONFIG_DIR}")
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("corec" PROPERTIES 
    PUBLIC_HEADER "${corec_base_PUBLIC_HEADERS}"
  )
endif()

# Node API
set(corec_node_SOURCES
  node/node.c
  node/nodetree.c
)
set(corec_node_PUBLIC_HEADERS
  node/node.h
  node/nodebase.h
  node/nodetree.h
  node/nodetools.h
)
add_library("corec_node" ${corec_node_SOURCES} ${corec_node_PUBLIC_HEADERS}
  # documentation installed with the sources
  node/corec.html
)
set_target_properties("corec_node" PROPERTIES 
  PUBLIC_HEADER "${corec_node_PUBLIC_HEADERS}"
)
target_include_directories("corec_node" PUBLIC ".")
target_link_libraries("corec_node" PUBLIC "corec_array" "corec_str" "corec_file")
if(CONFIG_MULTITHREAD)
  target_link_libraries("corec_node" PUBLIC "corec_multithread")
endif(CONFIG_MULTITHREAD)


# Array API
set(corec_array_SOURCES
  array/array.c
)
set(corec_array_PUBLIC_HEADERS
  array/array.h
)
add_library("corec_array" ${corec_array_SOURCES})
set_target_properties("corec_array" PROPERTIES 
  PUBLIC_HEADER "${corec_array_PUBLIC_HEADERS}"
)
target_link_libraries("corec_array" PUBLIC "corec")

# String API
add_library("corec_str" INTERFACE)
set(corec_str_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str.c
)
set(corec_str_WIN32_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str_win32.c
)
set(corec_str_OSX_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str_osx.c
)
set(corec_str_LINUX_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str_linux.c
)
set(corec_str_PUBLIC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/str/str.h
)
target_sources("corec_str" INTERFACE  ${corec_str_SOURCES} ${corec_str_PUBLIC_HEADERS})
if (WIN32)
  target_sources("corec_str" INTERFACE ${corec_str_WIN32_SOURCES})
elseif(APPLE)
    target_sources("corec_str" INTERFACE ${corec_str_OSX_SOURCES})
elseif(UNIX)
    target_sources("corec_str" INTERFACE ${corec_str_LINUX_SOURCES})
endif(WIN32)
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("corec_str" PROPERTIES 
    PUBLIC_HEADER "${corec_str_PUBLIC_HEADERS}"
  )
endif()

set(corec_multithread_WIN32_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/multithread/multithread_win32.c
)
set(corec_multithread_UNIX_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/multithread/multithread_pthread.c
)
set(corec_multithread_PUBLIC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/multithread/multithread.h
)
add_library("corec_multithread" INTERFACE)
if (WIN32)
  target_sources("corec_multithread" INTERFACE ${corec_multithread_WIN32_SOURCES})
elseif(UNIX)
  target_sources("corec_multithread" INTERFACE ${corec_multithread_UNIX_SOURCES})
  target_link_libraries("corec_multithread" INTERFACE pthread)
endif(WIN32)
if(${CMAKE_VERSION}` VERSION_GREATER_EQUAL "3.15.0")
  set_target_properties("corec_multithread" PROPERTIES
    PUBLIC_HEADER "${corec_multithread_PUBLIC_HEADERS}"
  )
endif()
target_link_libraries("corec_multithread" INTERFACE "corec_node")

add_subdirectory("helpers")

# File API
set(corec_file_BASE_SOURCES
  helpers/file/bufstream.c
  helpers/file/memstream.c
  helpers/file/streams.c
  helpers/file/tools.c
)
set(corec_file_STDIO_SOURCES
  helpers/file/stream_stdio.c
)
set(corec_file_WIN32_SOURCES
  helpers/file/file_win32.c
)
set(corec_file_UNIX_SOURCES
  helpers/file/file_libc.c
)
set(corec_file_PUBLIC_HEADERS
  helpers/file/file.h
  helpers/file/streams.h
)
add_library("corec_file" ${corec_file_BASE_SOURCES} ${corec_file_PUBLIC_HEADERS})
if (CONFIG_STDIO)
  target_sources("corec_file" PRIVATE ${corec_file_STDIO_SOURCES})
endif(CONFIG_STDIO)
if (WIN32)
  target_sources("corec_file" PRIVATE ${corec_file_WIN32_SOURCES})

  # for SHFileOperation to move files in the recycle bin
  target_link_libraries("corec_file" PRIVATE shell32)
elseif(UNIX)
  target_sources("corec_file" PRIVATE ${corec_file_UNIX_SOURCES})
endif(WIN32)
set_target_properties("corec_file" PROPERTIES 
  PUBLIC_HEADER "${corec_file_PUBLIC_HEADERS}"
)
target_link_libraries("corec_file" PUBLIC "corec_node" "corec_date")

# Parser API
set(corec_parser_SOURCES
  helpers/parser/buffer.c
  helpers/parser/dataheap.c
  helpers/parser/hotkey.c
  helpers/parser/nodelookup.c
  helpers/parser/parser2.c
  helpers/parser/strtab.c
  helpers/parser/strtypes.c
  helpers/parser/urlpart.c
)
set(corec_parser_PUBLIC_HEADERS
  helpers/parser/buffer.h
  helpers/parser/dataheap.h
  helpers/parser/hotkey.h
  helpers/parser/nodelookup.h
  helpers/parser/parser.h
  helpers/parser/strtab.h
  helpers/parser/strtypes.h
  helpers/parser/urlpart.h
)
add_library("corec_parser" ${corec_parser_SOURCES} ${corec_parser_PUBLIC_HEADERS}
)
target_compile_definitions("corec_parser" PUBLIC COREC_PARSER)
target_link_libraries("corec_parser" PUBLIC "corec_str" "corec_charconvert" "corec_file")
target_include_directories("corec_parser" PUBLIC "helpers" "..")
set_target_properties("corec_parser" PROPERTIES
  PUBLIC_HEADER "${corec_parser_PUBLIC_HEADERS}"
)

# System call API
add_library("corec_system")
set(corec_system_WIN32_SOURCES
  helpers/system/ccsystem_win32.c
)
set(corec_system_UNIX_SOURCES
  helpers/system/ccsystem_posix.c
)
set(corec_system_PUBLIC_HEADERS
  helpers/system/ccsystem.h
)
if (WIN32)
  target_sources("corec_system" PRIVATE ${corec_system_WIN32_SOURCES})
elseif(UNIX)
  target_sources("corec_system" PRIVATE ${corec_system_UNIX_SOURCES})
endif(WIN32)
set_target_properties("corec_system" PROPERTIES
  PUBLIC_HEADER "${corec_system_PUBLIC_HEADERS}"
)
target_link_libraries("corec_system" PUBLIC "corec" "corec_node")

# MD5 API
set(corec_md5_SOURCES
  helpers/md5/md5.c
)
set(corec_md5_PUBLIC_HEADERS
  helpers/md5/md5.h
)
add_library("corec_md5" ${corec_md5_SOURCES})
set_target_properties("corec_md5" PROPERTIES
  PUBLIC_HEADER "${corec_md5_PUBLIC_HEADERS}"
)
target_link_libraries("corec_md5" PUBLIC "corec")

# Date API
add_library("corec_date")
set(corec_system_WIN32_SOURCES
  helpers/date/date_win32.c
)
set(corec_system_UNIX_SOURCES
  helpers/date/date_libc.c
)
set(corec_system_PUBLIC_HEADERS
  helpers/date/date.h
)
if (WIN32)
  target_sources("corec_date" PRIVATE ${corec_system_WIN32_SOURCES})
elseif(UNIX)
    target_sources("corec_date" PRIVATE ${corec_system_UNIX_SOURCES})
endif(WIN32)
set_target_properties("corec_date" PROPERTIES 
  PUBLIC_HEADER "${corec_system_PUBLIC_HEADERS}"
)
target_link_libraries("corec_date" PUBLIC "corec")

# Character Conversion API
set(corec_charconvert_WIN32_SOURCES
  helpers/charconvert/charconvert_win32.c
)
set(corec_charconvert_OSX_SOURCES
  helpers/charconvert/charconvert_osx.c
)
set(corec_charconvert_LINUX_SOURCES
  helpers/charconvert/charconvert_linux.c
)
set(corec_charconvert_OTHER_SOURCES
  helpers/charconvert/charconvert_utf8.c
)
set(corec_charconvert_PUBLIC_HEADERS
  helpers/charconvert/charconvert.h
)
add_library("corec_charconvert")
if (WIN32)
  target_sources("corec_charconvert" PRIVATE ${corec_charconvert_WIN32_SOURCES})
elseif(APPLE)
  target_link_libraries("corec_charconvert" PUBLIC "-framework CoreFoundation")
  target_sources("corec_charconvert" PRIVATE ${corec_charconvert_OSX_SOURCES})
elseif(UNIX)
  target_sources("corec_charconvert" PRIVATE ${corec_charconvert_LINUX_SOURCES})
else(UNIX)
  target_sources("corec_charconvert" PRIVATE ${corec_charconvert_OTHER_SOURCES})
endif(WIN32)
set_target_properties("corec_charconvert" PROPERTIES 
  PUBLIC_HEADER "${corec_charconvert_PUBLIC_HEADERS}"
)
target_link_libraries("corec_charconvert" PUBLIC "corec")
