FOR EACH WORKSPACE

  REMOVE %(¯PATH)make.bat
  FILE %(¯PATH)GNUmakefile
  IFDEF TARGET_QTOPIA
    IF %(QPEDIR)
      // needed to run some of the Qtopia/Greenphone (stupid) scripts like gph
      PRINTNL PREFIX?=%(QPEDIR)/image
      PRINTNL DPREFIX?=%(QPEDIR)/dimage/opt/Qtopia
      PRINTNL D="-d"
    ENDIF
  ENDIF
  IF defined(NO_MAKE_EXE) || defined(NO_MAKE_EXE_JAVA)
    FOR EACH USE
      IF %(TYPE)==EXE && defined(NO_MAKE_EXE)
        // do nothing
      ELIF %(TYPE)==EXE_ANDROID && defined(NO_MAKE_EXE_JAVA)
        // do nothing
      ELSE
        ../ALL_NAMES += %(NAME)
      ENDIF
    ENDFOR
  ELSE
    ALL_NAMES = %(USE)
  ENDIF
  PRINTNL .PHONY: all clean depend cleandep install %(ALL_NAMES)
  PRINTNL 
  PRINTNL all: %(ALL_NAMES)
  PRINTNL 	
  FOR EACH USE
    PRINTNL %(NAME):
    PRINTNL 	@$(MAKE) -C %(¯!PATH) -f %(NAME).mak
  ENDFOR
  PRINTNL clean depend cleandep install:
  FOR EACH USE
    PRINTNL 	@$(MAKE) -C %(¯!PATH) -f %(NAME).mak $@
  ENDFOR
//  PRINTNL 	@rm -rf %(!BUILDPATH)
//  PRINTNL 	@rm -rf %(!OUTPUTPATH)

  IFDEF TARGET_QTOPIA
    PRINTNL install:
    FOR EACH USE
      IF %(TYPE)==EXE
        PRINTNL 	@$(MAKE) -C %(¯!PATH) -f %(NAME).mak install
      ENDIF
    ENDFOR
  ENDIF

ENDFOR

FOR EACH LIB,DLL,EXE,CON
  IF "%(TRANSLATION_QT4)"!=""
    FILE %(¯PATH)%(NAME).tmp.pro
    #include "qmake.inc"
  ENDIF
ENDFOR

FOR EACH LIB,DLL,EXE,CON,EXE_ANDROID,DLL_ANDROID,GENERATE

  IFDEF TARGET_OSX
    IF (%(TYPE)==EXE || %(TYPE)==DLL)
      PLIST_FILE = %(¯PATH)%(NAME).plist
      FILE %(¯PATH)%(NAME).plist
      #include "osx_plist.inc"
    ENDIF
  ENDIF

  IFDEF TARGET_QTOPIA
    #include "qtopia_desktop.inc"
    #include "qtopia_resource.inc"
  ENDIF

  FILE %(¯PATH)%(NAME).mak
  #include "gcc_mak.inc"

ENDFOR
