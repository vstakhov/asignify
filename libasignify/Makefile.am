lib_LTLIBRARIES = libasignify.la

noinst_HEADERS=	khash.h \
	tweetnacl.h \
	blf.h \
	blake2.h \
	blake2-impl.h \
	asignify_internal.h 

# Sources for libasignify
libasignify_la_SOURCES =	tweetnacl.c \
							blake2b-ref.c \
							sha2.c \
							pbkdf2.c \
							b64_pton.c \
							pubkey.c \
							verify.c \
							util.c

libasignify_la_LDFLAGS = -version-info @ASIGNIFY_LIBRARY_VERSION@ \
			@OPENSSL_LDFLAGS@ \
			@OPENSSL_LIBS@ \
			@OS_LIBS@

libasignify_la_CPPFLAGS = -I$(top_srcdir)/include \
			@OPENSSL_INCLUDES@