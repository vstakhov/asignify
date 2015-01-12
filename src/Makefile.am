noinst_HEADERS= readpassphrase_compat.h \
			cli.h

bin_PROGRAMS=asignify
 
asignify_SOURCES= asignify.c \
				verify.c \
				sign.c \
				generate.c \
				encrypt.c

asignify_LDFLAGS = $(top_srcdir)/libasignify/libasignify.la \
			@OPENSSL_LDFLAGS@ \
			@OPENSSL_LIBS@ \
			@OS_LIBS@
asignify_CPPFLAGS = -I$(top_srcdir)/include \
	@OS_CFLAGS@ \
	@OPENSSL_INCLUDES@
