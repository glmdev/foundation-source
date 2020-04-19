add_library("corec"
  node/node.c
  node/nodetree.c
  array/array.c
  str/str.c

  helpers/file/bufstream.c
  helpers/file/memstream.c
  helpers/file/streams.c
  helpers/file/tools.c

  # only if CONFIG_STDIO is set
  helpers/file/stream_stdio.c
)
set_target_properties("corec" PROPERTIES PUBLIC_HEADER "array/array.h;helpers/date/date.h;helpers/charconvert/charconvert.h")
if (WIN32)
  target_sources("corec" PRIVATE
    str/str_win32.c
    helpers/date/date_win32.c
    helpers/file/file_win32.c
    helpers/charconvert/charconvert_win32.c
  )
endif(WIN32)
if (UNIX)
  target_sources("corec" PRIVATE
    helpers/date/date_libc.c
    helpers/file/file_libc.c
  )
  if (APPLE)
    target_sources("corec" PRIVATE 
      str/str_osx.c
      helpers/charconvert/charconvert_osx.c
    )
  else()
    target_sources("corec" PRIVATE 
      str/str_linux.c
      helpers/charconvert/charconvert_linux.c
    )
  endif()
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
target_link_libraries("corec_parser" PRIVATE "corec")
target_include_directories("corec_parser" PUBLIC "." ".." "helpers")

add_library("ccsystem")
if (WIN32)
  target_sources("ccsystem" PRIVATE helpers/system/ccsystem_win32.c)
endif(WIN32)
if (UNIX)
  target_sources("ccsystem" PRIVATE helpers/system/ccsystem_posix.c)
endif(UNIX)
target_include_directories("ccsystem" PUBLIC "." "..")
set_target_properties("ccsystem" PROPERTIES PUBLIC_HEADER "helpers/system/ccsystem.h")

add_library("md5" helpers/md5/md5.c)
target_include_directories("md5" PUBLIC "." "..")
set_target_properties("ccsystem" PROPERTIES PUBLIC_HEADER "helpers/md5/md5.h")
