add_subdirectory("zlib")

# File API
set(corec_file_BASE_SOURCES
  file/bufstream.c
  file/memstream.c
  file/streams.c
  file/tools.c
)
set(corec_file_STDIO_SOURCES
  file/stream_stdio.c
)
set(corec_file_WIN32_SOURCES
  file/file_win32.c
)
set(corec_file_UNIX_SOURCES
  file/file_libc.c
)
set(corec_file_PUBLIC_HEADERS
  file/file.h
  file/streams.h
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
  parser/buffer.c
  parser/dataheap.c
  parser/hotkey.c
  parser/nodelookup.c
  parser/parser2.c
  parser/strtab.c
  parser/strtypes.c
  parser/urlpart.c
)
set(corec_parser_PUBLIC_HEADERS
  parser/buffer.h
  parser/dataheap.h
  parser/hotkey.h
  parser/nodelookup.h
  parser/parser.h
  parser/strtab.h
  parser/strtypes.h
  parser/urlpart.h
)
add_library("corec_parser" ${corec_parser_SOURCES} ${corec_parser_PUBLIC_HEADERS}
)
target_compile_definitions("corec_parser" PUBLIC COREC_PARSER)
target_link_libraries("corec_parser" PUBLIC "corec_str" "corec_charconvert" "corec_file")
target_include_directories("corec_parser" PUBLIC ".")
set_target_properties("corec_parser" PROPERTIES
  PUBLIC_HEADER "${corec_parser_PUBLIC_HEADERS}"
)

# System call API
add_library("corec_system")
set(corec_system_WIN32_SOURCES
  system/ccsystem_win32.c
)
set(corec_system_UNIX_SOURCES
  system/ccsystem_posix.c
)
set(corec_system_PUBLIC_HEADERS
  system/ccsystem.h
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
  md5/md5.c
)
set(corec_md5_PUBLIC_HEADERS
  md5/md5.h
)
add_library("corec_md5" ${corec_md5_SOURCES})
set_target_properties("corec_md5" PROPERTIES
  PUBLIC_HEADER "${corec_md5_PUBLIC_HEADERS}"
)
target_link_libraries("corec_md5" PUBLIC "corec")

# Date API
add_library("corec_date")
set(corec_system_WIN32_SOURCES
  date/date_win32.c
)
set(corec_system_UNIX_SOURCES
  date/date_libc.c
)
set(corec_system_PUBLIC_HEADERS
  date/date.h
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
  charconvert/charconvert_win32.c
)
set(corec_charconvert_OSX_SOURCES
  charconvert/charconvert_osx.c
)
set(corec_charconvert_LINUX_SOURCES
  charconvert/charconvert_linux.c
)
set(corec_charconvert_OTHER_SOURCES
  charconvert/charconvert_utf8.c
)
set(corec_charconvert_PUBLIC_HEADERS
  charconvert/charconvert.h
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
