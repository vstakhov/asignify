bin_PROGRAMS=asignify
 
asignify_SOURCES= asignify.c

asignify_LDFLAGS = $(top_srcdir)/libasignify/libasignify.la \
			@OPENSSL_LDFLAGS@ \
			@OPENSSL_LIBS@ \
			@OS_LIBS@
asignify_CPPFLAGS = -I$(top_srcdir)/include \
	@OPENSSL_INCLUDES@
