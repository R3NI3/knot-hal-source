lib_LIBRARIES = libdbusobjman.a
AM_CFLAGS = $(WARNING_CFLAGS) $(BUILD_CFLAGS)

libdbusobjman_a_SOURCES = nrf-object-manager.c
libdbusobjman_a_CPPFLAGS = $(AM_CFLAGS) @GIO_UNIX_LIBS@ @GIO_UNIX_CFLAGS@ \
				-I/usr/include/gio-unix-2.0/  @GLIB_CFLAGS@ \
				@GLIB_LIBS@ -I$(top_srcdir)/src/

all-local:
	$(MKDIR_P) $(top_srcdir)/libs && cp $(lib_LIBRARIES) $(top_srcdir)/libs

clean-local:
	$(RM) -r libdbusobjman.a

