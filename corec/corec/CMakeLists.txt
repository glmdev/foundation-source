# Base core API
add_library("corec"
  node/node.c
  node/nodetree.c
  array/array.c
)
set_target_properties("corec" PROPERTIES PUBLIC_HEADER "array/array.h")
target_include_directories("corec" PUBLIC "." "..")

# File API
add_library("corec_file" 
  helpers/file/bufstream.c
  helpers/file/memstream.c
  helpers/file/streams.c
  helpers/file/tools.c

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
target_include_directories("corec_file" PUBLIC "." "..")
set_target_properties("corec_file" PROPERTIES PUBLIC_HEADER "helpers/file/file.h;helpers/file/streams.h")
target_link_libraries("corec_file" PRIVATE "corec" "corec_str" "corec_date")

# Parser API
add_library("corec_parser"
  helpers/parser/buffer.c
  helpers/parser/dataheap.c
  helpers/parser/hotkey.c
  helpers/parser/nodelookup.c
  helpers/parser/parser2.c
  helpers/parser/strtab.c
  helpers/parser/strtypes.c
  helpers/parser/urlpart.c
)
target_link_libraries("corec_parser" PRIVATE "corec_charconvert" "corec_file")
target_include_directories("corec_parser" PUBLIC "." ".." "helpers")
set_target_properties("corec_parser" PROPERTIES PUBLIC_HEADER
  "helpers/parser/buffer.h;helpers/parser/dataheap.h;helpers/parser/hotkey.h;helpers/parser/nodelookup.h;helpers/parser/parser2.h;helpers/parser/strtab.h;helpers/parser/strtypes.hhelpers/parser/urlpart.h"
)

# System call API
add_library("corec_system")
if (WIN32)
  target_sources("corec_system" PRIVATE helpers/system/ccsystem_win32.c)
elseif(UNIX)
  target_sources("corec_system" PRIVATE helpers/system/ccsystem_posix.c)
endif(WIN32)
target_include_directories("corec_system" PUBLIC "." "..")
set_target_properties("corec_system" PROPERTIES PUBLIC_HEADER "helpers/system/ccsystem.h")

add_library("corec_md5" helpers/md5/md5.c)
target_include_directories("corec_md5" PUBLIC "." "..")
set_target_properties("corec_system" PROPERTIES PUBLIC_HEADER "helpers/md5/md5.h")

# Date API
add_library("corec_date")
if (WIN32)
  target_sources("corec_date" PRIVATE helpers/date/date_win32.c)
elseif(UNIX)
    target_sources("corec_date" PRIVATE helpers/date/date_libc.c)
endif(WIN32)
target_include_directories("corec_date" PUBLIC "." "..")
set_target_properties("corec_date" PROPERTIES PUBLIC_HEADER "helpers/date/date.h")

# String API
add_library("corec_str" str/str.c)
if (WIN32)
  target_sources("corec_str" PRIVATE str/str_win32.c)
elseif(APPLE)
    target_sources("corec_str" PRIVATE str/str_osx.c)
elseif(UNIX)
    target_sources("corec_str" PRIVATE str/str_linux.c)
endif(WIN32)
target_include_directories("corec_str" PUBLIC "." "..")
# TODO only for projects using "core_parser"
target_compile_definitions("corec_str" PUBLIC COREC_PARSER)
set_target_properties("corec_str" PROPERTIES PUBLIC_HEADER "helpers/str/str.h")

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
target_include_directories("corec_charconvert" PUBLIC "." "..")
set_target_properties("corec_charconvert" PROPERTIES PUBLIC_HEADER "helpers/charconvert/charconvert.h")
