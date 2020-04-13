add_library("ebml2"
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
target_include_directories("ebml2" PUBLIC ".")
target_link_libraries("ebml2" PRIVATE "corec")