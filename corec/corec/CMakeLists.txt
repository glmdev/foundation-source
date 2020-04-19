add_library("corec"
  node/node.c
  node/nodetree.c
  array/array.c

  helpers/file/bufstream.c
  helpers/file/memstream.c
  helpers/file/streams.c
  helpers/file/tools.c

  # only if CONFIG_STDIO is set
  helpers/file/stream_stdio.c
)
set_target_properties("corec" PROPERTIES PUBLIC_HEADER "array/array.h;helpers/date/date.h")
if (WIN32)
  target_sources("corec" PRIVATE
    helpers/date/date_win32.c
    helpers/file/file_win32.c
  )
endif(WIN32)
if (UNIX)
  target_sources("corec" PRIVATE
    helpers/date/date_libc.c
    helpers/file/file_libc.c
  )
endif(UNIX)

target_include_directories("corec" PUBLIC "." "..")

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
target_link_libraries("corec_parser" PRIVATE "corec_charconvert")
target_include_directories("corec_parser" PUBLIC "." ".." "helpers")

add_library("corec_system")
if (WIN32)
  target_sources("corec_system" PRIVATE helpers/system/ccsystem_win32.c)
endif(WIN32)
if (UNIX)
  target_sources("corec_system" PRIVATE helpers/system/ccsystem_posix.c)
endif(UNIX)
target_include_directories("corec_system" PUBLIC "." "..")
set_target_properties("corec_system" PROPERTIES PUBLIC_HEADER "helpers/system/ccsystem.h")

add_library("corec_md5" helpers/md5/md5.c)
target_include_directories("corec_md5" PUBLIC "." "..")
set_target_properties("corec_system" PROPERTIES PUBLIC_HEADER "helpers/md5/md5.h")

add_library("corec_charconvert")
if (WIN32)
  target_sources("corec_charconvert" PRIVATE helpers/charconvert/charconvert_win32.c)
endif(WIN32)
if (UNIX)
  if (APPLE)
    target_sources("corec_charconvert" PRIVATE helpers/charconvert/charconvert_osx.c)
  else()
    target_sources("corec_charconvert" PRIVATE helpers/charconvert/charconvert_linux.c)
  endif()
endif(UNIX)
target_include_directories("corec_charconvert" PUBLIC "." "..")
set_target_properties("corec_charconvert" PROPERTIES PUBLIC_HEADER "helpers/charconvert/charconvert.h")
target_link_libraries("corec_parser" PRIVATE "corec" "corec_str")


add_library("corec_str" str/str.c)
if (WIN32)
  target_sources("corec_str" PRIVATE str/str_win32.c)
endif(WIN32)
if (UNIX)
  if (APPLE)
    target_sources("corec_str" PRIVATE str/str_osx.c)
  else()
    target_sources("corec_str" PRIVATE str/str_linux.c)
  endif()
endif(UNIX)
target_include_directories("corec_str" PUBLIC "." "..")
set_target_properties("corec_str" PROPERTIES PUBLIC_HEADER "helpers/charconvert/charconvert.h")
