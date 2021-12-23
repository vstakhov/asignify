cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)

set(LIBASIGNIFY_VERSION_MAJOR 2)
set(LIBASIGNIFY_VERSION_MINOR 0)
set(LIBASIGNIFY_VERSION_PATCH 0)
set(LIBASIGNIFY_VERSION "${LIBASIGNIFY_VERSION_MAJOR}.${LIBASIGNIFY_VERSION_MINOR}.${LIBASIGNIFY_VERSION_PATCH}")
project(asignify LANGUAGES C VERSION "${LIBASIGNIFY_VERSION}")

OPTION(ENABLE_OPENSSL       "Link with openssl [default: ON]"                  ON)

include_directories(include)
include_directories(libasignify)
include_directories(src)
include_directories("${CMAKE_BINARY_DIR}")

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckLibraryExists)

check_include_files(sys/types.h HAVE_SYS_TYPES_H)
check_include_files(sys/random.h HAVE_SYS_RANDOM_H)
check_include_files(sys/time.h  HAVE_SYS_TIME_H)
check_include_files(sys/stat.h HAVE_SYS_STAT_H)
check_include_files(math.h      HAVE_MATH_H)
check_include_files(stdio.h     HAVE_STDIO_H)
check_include_files(stdlib.h    HAVE_STDLIB_H)
check_include_files(stddef.h    HAVE_STDDEF_H)
check_include_files(string.h    HAVE_STRING_H)
check_include_files(strings.h   HAVE_STRINGS_H)
check_include_files(memory.h      HAVE_MEMORY_H)
check_include_files(unistd.h    HAVE_UNISTD_H)
check_include_files(stdint.h  HAVE_STDINT_H)
check_include_files(inttypes.h  HAVE_INTTYPES_H)
check_include_files(stdbool.h  HAVE_STDBOOL_H)
check_include_files(readpassphrase.h HAVE_READPASSPHRASE_H)

check_include_files(bsd/libutil.h  HAVE_BSD_LIBUTIL_H)
check_include_files(bsd/readpassphrase.h  HAVE_BSD_READPASSPHRASE_H)
check_include_files(bsd/err.h  HAVE_BSD_ERR_H)
check_include_files(linux/random.h  HAVE_LINUX_RANDOM_H)

check_include_files(sys/capability.h  HAVE_SYS_CAPABILITY_H)
check_include_files(sys/capsicum.h  HAVE_SYS_CAPSICUM_H)
check_include_files(dlfcn.h HAVE_DLFCN_H)

check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
check_function_exists(memset_s HAVE_MEMSET_S)
check_function_exists(valloc HAVE_VALLOC)
check_function_exists(posix_memalign HAVE_POSIX_MEMALIGN)
check_function_exists(aligned_alloc HAVE_ALIGNED_ALLOC)
check_function_exists(arc4random_buf HAVE_ARC4RANDOM_BUF)
check_function_exists(bcopy HAVE_BCOPY)
check_function_exists(memmove HAVE_MEMMOVE)
check_function_exists(getrandom HAVE_GETRANDOM)

check_symbol_exists(O_NOFOLLOW "sys/types.h;sys/fcntl.h" HAVE_O_NOFOLLOW)

check_library_exists(bsd readpassphrase "" HAVE_LIBBSD)

if(HAVE_SYS_CAPSICUM_H)
    set(HAVE_CAPSICUM 1)
endif()

add_definitions(-DHAVE_CONFIG_H)

add_library(libasignify
        include/asignify.h
        libasignify/asignify_internal.h
        libasignify/b64_pton.c
        libasignify/blake2-impl.h
        libasignify/blake2.h
        libasignify/blake2b-ref.c
        libasignify/chacha.c
        libasignify/chacha.h
        libasignify/databuf.c
        libasignify/encrypt.c
        libasignify/generate.c
        libasignify/khash.h
        libasignify/kvec.h
        libasignify/pbkdf2.c
        libasignify/pubkey.c
        libasignify/sha2.c
        libasignify/sha2.h
        libasignify/sign.c
        libasignify/signature.c
        libasignify/tweetnacl.c
        libasignify/tweetnacl.h
        libasignify/util.c
        libasignify/verify.c)
target_link_options(libasignify
        PUBLIC "LINKER:--version-script=${CMAKE_SOURCE_DIR}/libasignify/libasignify.ver")

add_executable(asignify
        src/asignify.c
        src/cli.h
        src/encrypt.c
        src/generate.c
        src/readpassphrase_compat.h
        src/sign.c
        src/verify.c)
target_link_libraries(asignify libasignify)

if (HAVE_LIBBSD)
    target_link_libraries(libasignify bsd)
endif()

if(ENABLE_OPENSSL MATCHES "ON")
    find_package(OpenSSL REQUIRED)

    if(OpenSSL_FOUND)
        include_directories(${OPENSSL_INCLUDE_DIR})
        link_directories(${OPENSSL_LIBRARIES})
        message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
        set(HAVE_OPENSSL 1)
    else()
        message(FATAL_ERROR "Cannot find openssl")
    endif()

    target_link_libraries(libasignify ${OPENSSL_CRYPTO_LIBRARIES})
endif()
configure_file("${CMAKE_SOURCE_DIR}/cmake/config.h.in" "${CMAKE_BINARY_DIR}/config.h")
