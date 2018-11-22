/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

#ifndef _GCRYPT_CONFIG_H_INCLUDED
#define _GCRYPT_CONFIG_H_INCLUDED

/* Enable gpg-error's strerror macro for W32CE.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS 1

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* GIT commit id revision used to build this package */
#define BUILD_REVISION ""

/* The time this package was configured for a build */
#define BUILD_TIMESTAMP "<none>"

/* configure did not test for endianness */
/* #undef DISABLED_ENDIAN_CHECK */

/* Define if you don't want the default EGD socket name. For details see
   cipher/rndegd.c */
#define EGD_SOCKET_NAME ""

/* Enable support for Intel AES-NI instructions. */
#define ENABLE_AESNI_SUPPORT 1

/* Enable support for ARMv8 Crypto Extension instructions. */
/* #undef ENABLE_ARM_CRYPTO_SUPPORT */

/* Enable support for Intel AVX2 instructions. */
#define ENABLE_AVX2_SUPPORT 1

/* Enable support for Intel AVX instructions. */
#define ENABLE_AVX_SUPPORT 1

/* Enable support for Intel DRNG (RDRAND instruction). */
#define ENABLE_DRNG_SUPPORT 1

/* Define to support an HMAC based integrity check */
/* #undef ENABLE_HMAC_BINARY_CHECK */

/* Enable support for the jitter entropy collector. */
#define ENABLE_JENT_SUPPORT 1

/* Enable support for ARM NEON instructions. */
/* #undef ENABLE_NEON_SUPPORT */

/* Enable support for the PadLock engine. */
#define ENABLE_PADLOCK_SUPPORT 1

/* Enable support for Intel PCLMUL instructions. */
#define ENABLE_PCLMUL_SUPPORT 1

/* Enable support for Intel SSE4.1 instructions. */
#define ENABLE_SSE41_SUPPORT 1

/* Define to use the GNU C visibility attribute. */
#define GCRY_USE_VISIBILITY 1

/* The default error source for libgcrypt. */
#define GPG_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_GCRYPT

/* Defined if ARM architecture is v6 or newer */
/* #undef HAVE_ARM_ARCH_V6 */

/* Define to 1 if you have the `atexit' function. */
#define HAVE_ATEXIT 1

/* Defined if the mlock() call does not work */
/* #undef HAVE_BROKEN_MLOCK */

/* Defined if compiler has '__builtin_bswap32' intrinsic */
#define HAVE_BUILTIN_BSWAP32 1

/* Defined if compiler has '__builtin_bswap64' intrinsic */
#define HAVE_BUILTIN_BSWAP64 1

/* Defined if compiler has '__builtin_ctz' intrinsic */
#define HAVE_BUILTIN_CTZ 1

/* Defined if a `byte' is typedef'd */
/* #undef HAVE_BYTE_TYPEDEF */

/* Define to 1 if you have the `clock' function. */
#define HAVE_CLOCK 1

/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Defined if underlying assembler is compatible with ARMv8/Aarch64 assembly
   implementations */
/* #undef HAVE_COMPATIBLE_GCC_AARCH64_PLATFORM_AS */

/* Defined if underlying assembler is compatible with amd64 assembly
   implementations */
#define HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS 1

/* Defined if underlying assembler is compatible with ARM assembly
   implementations */
/* #undef HAVE_COMPATIBLE_GCC_ARM_PLATFORM_AS */

/* Defined if underlying assembler is compatible with WIN64 assembly
   implementations */
/* #undef HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS */

/* Defined for Alpha platforms */
/* #undef HAVE_CPU_ARCH_ALPHA */

/* Defined for ARM AArch64 platforms */
/* #undef HAVE_CPU_ARCH_ARM */

/* Defined for M68k platforms */
/* #undef HAVE_CPU_ARCH_M68K */

/* Defined for MIPS platforms */
/* #undef HAVE_CPU_ARCH_MIPS */

/* Defined for PPC platforms */
/* #undef HAVE_CPU_ARCH_PPC */

/* Defined for SPARC platforms */
/* #undef HAVE_CPU_ARCH_SPARC */

/* Defined for the x86 platforms */
#define HAVE_CPU_ARCH_X86 1

/* Define to 1 if you have the declaration of `sys_siglist', and to 0 if you
   don't. */
#define HAVE_DECL_SYS_SIGLIST 1

/* defined if the system supports a random device */
#define HAVE_DEV_RANDOM 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* defined if we run on some of the PCDOS like systems (DOS, Windoze. OS/2)
   with special properties like no file modes */
/* #undef HAVE_DOSISH_SYSTEM */

/* defined if we must run on a stupid file system */
/* #undef HAVE_DRIVE_LETTERS */

/* Define to 1 if you have the `fcntl' function. */
#define HAVE_FCNTL 1

/* Define to 1 if you have the `flockfile' function. */
#define HAVE_FLOCKFILE 1

/* Define to 1 if you have the `ftruncate' function. */
#define HAVE_FTRUNCATE 1

/* Define if inline asm memory barrier is supported */
#define HAVE_GCC_ASM_VOLATILE_MEMORY 1

/* Defined if a GCC style "__attribute__ ((aligned (n))" is supported */
#define HAVE_GCC_ATTRIBUTE_ALIGNED 1

/* Defined if a GCC style "__attribute__ ((may_alias))" is supported */
#define HAVE_GCC_ATTRIBUTE_MAY_ALIAS 1

/* Defined if compiler supports "__attribute__ ((ms_abi))" function attribute
   */
#define HAVE_GCC_ATTRIBUTE_MS_ABI 1

/* Defined if a GCC style "__attribute__ ((packed))" is supported */
#define HAVE_GCC_ATTRIBUTE_PACKED 1

/* Defined if compiler supports "__attribute__ ((sysv_abi))" function
   attribute */
#define HAVE_GCC_ATTRIBUTE_SYSV_ABI 1

/* Defined if default calling convention is 'ms_abi' */
/* #undef HAVE_GCC_DEFAULT_ABI_IS_MS_ABI */

/* Defined if default calling convention is 'sysv_abi' */
#define HAVE_GCC_DEFAULT_ABI_IS_SYSV_ABI 1

/* Defined if inline assembler supports AArch32 Crypto Extension instructions
   */
/* #undef HAVE_GCC_INLINE_ASM_AARCH32_CRYPTO */

/* Defined if inline assembler supports AArch64 Crypto Extension instructions
   */
/* #undef HAVE_GCC_INLINE_ASM_AARCH64_CRYPTO */

/* Defined if inline assembler supports AArch64 NEON instructions */
/* #undef HAVE_GCC_INLINE_ASM_AARCH64_NEON */

/* Defined if inline assembler supports AVX instructions */
#define HAVE_GCC_INLINE_ASM_AVX 1

/* Defined if inline assembler supports AVX2 instructions */
#define HAVE_GCC_INLINE_ASM_AVX2 1

/* Defined if inline assembler supports BMI2 instructions */
#define HAVE_GCC_INLINE_ASM_BMI2 1

/* Defined if inline assembler supports NEON instructions */
/* #undef HAVE_GCC_INLINE_ASM_NEON */

/* Defined if inline assembler supports PCLMUL instructions */
#define HAVE_GCC_INLINE_ASM_PCLMUL 1

/* Defined if inline assembler supports SSE4.1 instructions */
#define HAVE_GCC_INLINE_ASM_SSE41 1

/* Defined if inline assembler supports SSSE3 instructions */
#define HAVE_GCC_INLINE_ASM_SSSE3 1

/* Define to 1 if you have the `gethrtime' function. */
/* #undef HAVE_GETHRTIME */

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the `getpid' function. */
#define HAVE_GETPID 1

/* Define to 1 if you have the `getrusage' function. */
#define HAVE_GETRUSAGE 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Defined if underlying assembler is compatible with Intel syntax assembly
   implementations */
#define HAVE_INTEL_SYNTAX_PLATFORM_AS 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `rt' library (-lrt). */
/* #undef HAVE_LIBRT */

/* Define to 1 if you have the `memmove' function. */
#define HAVE_MEMMOVE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Defined if the system supports an mlock() call */
#define HAVE_MLOCK 1

/* Define to 1 if you have the `mmap' function. */
#define HAVE_MMAP 1

/* Defined if the GNU Pth is available */
/* #undef HAVE_PTH */

/* Define if we have pthread. */
#define HAVE_PTHREAD 1

/* Define to 1 if you have the `raise' function. */
#define HAVE_RAISE 1

/* Define to 1 if you have the `rand' function. */
#define HAVE_RAND 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `stpcpy' function. */
#define HAVE_STPCPY 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the `stricmp' function. */
/* #undef HAVE_STRICMP */

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* Define to 1 if you have the `syscall' function. */
#define HAVE_SYSCALL 1

/* Define to 1 if you have the `sysconf' function. */
#define HAVE_SYSCONF 1

/* Define to 1 if you have the `syslog' function. */
#define HAVE_SYSLOG 1

/* Define to 1 if you have the <sys/capability.h> header file. */
/* #undef HAVE_SYS_CAPABILITY_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
/* #undef HAVE_SYS_MMAN_H */

/* Define to 1 if you have the <sys/msg.h> header file. */
#define HAVE_SYS_MSG_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Defined if a `u16' is typedef'd */
/* #undef HAVE_U16_TYPEDEF */

/* Defined if a `u32' is typedef'd */
/* #undef HAVE_U32_TYPEDEF */

/* Define to 1 if the system has the type `uintptr_t'. */
#define HAVE_UINTPTR_T 1

/* Defined if a `ulong' is typedef'd */
#define HAVE_ULONG_TYPEDEF 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Defined if a `ushort' is typedef'd */
#define HAVE_USHORT_TYPEDEF 1

/* Defined if variable length arrays are supported */
#define HAVE_VLA 1

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Defined if we run on WindowsCE */
/* #undef HAVE_W32CE_SYSTEM */

/* Defined if we run on a W32 API based system */
/* #undef HAVE_W32_SYSTEM */

/* Define to 1 if you have the `wait4' function. */
#define HAVE_WAIT4 1

/* Define to 1 if you have the `waitpid' function. */
#define HAVE_WAITPID 1

/* Define to 1 if you have the <winsock2.h> header file. */
/* #undef HAVE_WINSOCK2_H */

/* Define to 1 if you have the <ws2tcpip.h> header file. */
/* #undef HAVE_WS2TCPIP_H */

/* Defined if this is not a regular release */
/* #undef IS_DEVELOPMENT_VERSION */

/* List of available cipher algorithms */
#define LIBGCRYPT_CIPHERS "arcfour:blowfish:cast5:des:aes:twofish:serpent:rfc2268:seed:camellia:idea:salsa20:gost28147:chacha20"

/* List of available digest algorithms */
#define LIBGCRYPT_DIGESTS "crc:gostr3411-94::md4:md5:rmd160:sha1:sha256:sha512:sha3:tiger:whirlpool:stribog:blake2"

/* List of available KDF algorithms */
#define LIBGCRYPT_KDFS "s2k:pkdf2:scrypt"

/* List of available public key cipher algorithms */
#define LIBGCRYPT_PUBKEY_CIPHERS "dsa:elgamal:rsa:ecc"

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Define to use the (obsolete) malloc guarding feature */
/* #undef M_GUARD */

/* defined to the name of the strong random device */
#define NAME_OF_DEV_RANDOM "/dev/random"

/* defined to the name of the weaker random device */
#define NAME_OF_DEV_URANDOM "/dev/urandom"

/* Name of this package */
#define PACKAGE "libgcrypt"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "http://bugs.gnupg.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libgcrypt"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libgcrypt 1.8.4"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libgcrypt"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.8.4"

/* A human readable text with the name of the OS */
#define PRINTABLE_OS_NAME "GNU/Linux"

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* The size of `uint64_t', as computed by sizeof. */
#define SIZEOF_UINT64_T 8

/* The size of `unsigned int', as computed by sizeof. */
#define SIZEOF_UNSIGNED_INT 4

/* The size of `unsigned long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG 8

/* The size of `unsigned long long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG_LONG 8

/* The size of `unsigned short', as computed by sizeof. */
#define SIZEOF_UNSIGNED_SHORT 2

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Defined if this module should be included */
#define USE_AES 1

/* Defined if this module should be included */
#define USE_ARCFOUR 1

/* Defined if this module should be included */
#define USE_BLAKE2 1

/* Defined if this module should be included */
#define USE_BLOWFISH 1

/* Defined if this module should be included */
#define USE_CAMELLIA 1

/* define if capabilities should be used */
/* #undef USE_CAPABILITIES */

/* Defined if this module should be included */
#define USE_CAST5 1

/* Defined if this module should be included */
#define USE_CHACHA20 1

/* Defined if this module should be included */
#define USE_CRC 1

/* Defined if this module should be included */
#define USE_DES 1

/* Defined if this module should be included */
#define USE_DSA 1

/* Defined if this module should be included */
#define USE_ECC 1

/* Defined if this module should be included */
#define USE_ELGAMAL 1

/* Defined if the GNU Portable Thread Library should be used */
/* #undef USE_GNU_PTH */

/* Defined if this module should be included */
#define USE_GOST28147 1

/* Defined if this module should be included */
#define USE_GOST_R_3411_12 1

/* Defined if this module should be included */
#define USE_GOST_R_3411_94 1

/* Defined if this module should be included */
#define USE_IDEA 1

/* Defined if this module should be included */
/* #undef USE_MD2 */

/* Defined if this module should be included */
#define USE_MD4 1

/* Defined if this module should be included */
#define USE_MD5 1

/* set this to limit filenames to the 8.3 format */
/* #undef USE_ONLY_8DOT3 */

/* Define to support the experimental random daemon */
/* #undef USE_RANDOM_DAEMON */

/* Defined if this module should be included */
#define USE_RFC2268 1

/* Defined if this module should be included */
#define USE_RMD160 1

/* Defined if the EGD based RNG should be used. */
/* #undef USE_RNDEGD */

/* Defined if the /dev/random RNG should be used. */
#define USE_RNDLINUX 1

/* Defined if the default Unix RNG should be used. */
/* #undef USE_RNDUNIX */

/* Defined if the Windows specific RNG should be used. */
/* #undef USE_RNDW32 */

/* Defined if the WindowsCE specific RNG should be used. */
/* #undef USE_RNDW32CE */

/* Defined if this module should be included */
#define USE_RSA 1

/* Defined if this module should be included */
#define USE_SALSA20 1

/* Defined if this module should be included */
#define USE_SCRYPT 1

/* Defined if this module should be included */
#define USE_SEED 1

/* Defined if this module should be included */
#define USE_SERPENT 1

/* Defined if this module should be included */
#define USE_SHA1 1

/* Defined if this module should be included */
#define USE_SHA256 1

/* Defined if this module should be included */
#define USE_SHA3 1

/* Defined if this module should be included */
#define USE_SHA512 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
#define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
#define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
#define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
#define __EXTENSIONS__ 1
#endif

/* Defined if this module should be included */
#define USE_TIGER 1

/* Defined if this module should be included */
#define USE_TWOFISH 1

/* Defined if this module should be included */
#define USE_WHIRLPOOL 1

/* Version of this package */
#define VERSION "1.8.4"

/* Defined if compiled symbols have a leading underscore */
/* #undef WITH_SYMBOL_UNDERSCORE */

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
#if defined __BIG_ENDIAN__
#define WORDS_BIGENDIAN 1
#endif
#else
#ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
#endif
#endif

/* Expose all libc features (__DARWIN_C_FULL). */
/* #undef _DARWIN_C_SOURCE */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* To allow the use of Libgcrypt in multithreaded programs we have to use
    special features from the library. */
#ifndef _REENTRANT
#define _REENTRANT 1
#endif

/* Define to supported assembler block keyword, if plain 'asm' was not
   supported */
/* #undef asm */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* type to use in place of socklen_t if not defined */
/* #undef socklen_t */

/* Define to the type of an unsigned integer type wide enough to hold a
   pointer, if such a type exists, and if the system does not define it. */
/* #undef uintptr_t */

#define _GCRYPT_IN_LIBGCRYPT 1

/* If the configure check for endianness has been disabled, get it from
   OS macros.  This is intended for making fat binary builds on OS X.  */
#ifdef DISABLED_ENDIAN_CHECK
#if defined(__BIG_ENDIAN__)
#define WORDS_BIGENDIAN 1
#elif defined(__LITTLE_ENDIAN__)
/* #  undef WORDS_BIGENDIAN */
#else
#error "No endianness found"
#endif
#endif /*DISABLED_ENDIAN_CHECK*/

/* We basically use the original Camellia source.  Make sure the symbols
   properly prefixed.  */
#define CAMELLIA_EXT_SYM_PREFIX _gcry_

#endif /*_GCRYPT_CONFIG_H_INCLUDED*/


/// -------------------
/// copy from libgpgerror/config.h
/// -------------------
/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* GIT commit id revision used to build this package */
//#define BUILD_REVISION "0000000"

/* The time this package was configured for a build */
#define BUILD_TIMESTAMP "<none>"

/* Defined to use log_clock timestamps */
/* #undef ENABLE_LOG_CLOCK */

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* Define to use the GNU C visibility attribute. */
#define GPGRT_USE_VISIBILITY 1

/* Define to 1 if you have the Mac OS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYCURRENT */

/* Define to 1 if you have the Mac OS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#define HAVE_DCGETTEXT 1

/* Define to 1 if you have the declaration of `strerror_r', and to 0 if you
   don't. */
#define HAVE_DECL_STRERROR_R 1

/* Define to 1 if you have the <direct.h> header file. */
/* #undef HAVE_DIRECT_H */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `flockfile' function. */
#define HAVE_FLOCKFILE 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Defined if a GCC style "__attribute__ ((aligned (n))" is supported */
#define HAVE_GCC_ATTRIBUTE_ALIGNED 1

/* Define to 1 if you have the `getrlimit' function. */
#define HAVE_GETRLIMIT 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#define HAVE_GETTEXT 1

/* Define if you have the iconv() function and it works. */
/* #undef HAVE_ICONV */

/* Define to 1 if the system has the type `intmax_t'. */
#define HAVE_INTMAX_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if you have <langinfo.h> and nl_langinfo(THOUSANDS_SEP). */
#define HAVE_LANGINFO_THOUSANDS_SEP 1

/* Define to 1 if you have a fully functional readline library. */
/* #undef HAVE_LIBREADLINE */

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if the system has the type `long double'. */
#define HAVE_LONG_DOUBLE 1

/* Define to 1 if the system has the type 'long long int'. */
#define HAVE_LONG_LONG_INT 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memrchr' function. */
#define HAVE_MEMRCHR 1

/* Define to 1 if you have the `mmap' function. */
#define HAVE_MMAP 1

/* Define if the <pthread.h> defines PTHREAD_MUTEX_RECURSIVE. */
#define HAVE_PTHREAD_MUTEX_RECURSIVE 1

/* Define if the POSIX multithreading library has read/write locks. */
#define HAVE_PTHREAD_RWLOCK 1

/* Define to 1 if the system has the type `ptrdiff_t'. */
#define HAVE_PTRDIFF_T 1

/* Define to 1 if you have the `rand' function. */
#define HAVE_RAND 1

/* Define to 1 if you have the `setenv' function. */
#define HAVE_SETENV 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the `stat' function. */
#define HAVE_STAT 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `stpcpy' function. */
#define HAVE_STPCPY 1

/* Define to 1 if you have the `strerror_r' function. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlwr' function. */
/* #undef HAVE_STRLWR */

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if the system has the type `uintmax_t'. */
#define HAVE_UINTMAX_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if the system has the type 'unsigned long long int'. */
#define HAVE_UNSIGNED_LONG_LONG_INT 1

/* Define to 1 if you have the `vasprintf' function. */
#define HAVE_VASPRINTF 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Defined if we run on WindowsCE */
/* #undef HAVE_W32CE_SYSTEM */

/* Defined if we run on a W32 API based system */
/* #undef HAVE_W32_SYSTEM */

/* Defined if we run on 64 bit W32 API system */
/* #undef HAVE_W64_SYSTEM */

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* The host triplet */
#define HOST_TRIPLET_STRING "x86_64-pc-linux-gnu"

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Defined if mkdir() does not take permission flags */
/* #undef MKDIR_TAKES_ONE_ARG */

/* Name of package */
//#define PACKAGE "libgpg-error"

/* Define to the address where bug reports for this package should be sent. */
//#define PACKAGE_BUGREPORT "https://bugs.gnupg.org"

/* Define to the full name of this package. */
//#define PACKAGE_NAME "libgpg-error"

/* Define to the full name and version of this package. */
//#define PACKAGE_STRING "libgpg-error 1.32-unknown"

/* Define to the one symbol short name of this package. */
//#define PACKAGE_TARNAME "libgpg-error"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
//#define PACKAGE_VERSION "1.32-unknown"

/* Define if the pthread_in_use() detection is hard. */
/* #undef PTHREAD_IN_USE_DETECTION_HARD */

/* Used by mkheader to insert the replacement type. */
#define REPLACEMENT_FOR_OFF_T "long"

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* The size of `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of `pthread_mutex_t', as computed by sizeof. */
#define SIZEOF_PTHREAD_MUTEX_T 40

/* The size of `time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 8

/* The size of `unsigned long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG 8

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if strerror_r returns char *. */
#define STRERROR_R_CHAR_P 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define if the POSIX multithreading library can be used. */
#define USE_POSIX_THREADS 1

/* Define if references to the POSIX multithreading library should be made
   weak. */
#define USE_POSIX_THREADS_WEAK 1

/* Define if the old Solaris multithreading library can be used. */
/* #undef USE_SOLARIS_THREADS */

/* Define if references to the old Solaris multithreading library should be
   made weak. */
/* #undef USE_SOLARIS_THREADS_WEAK */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
#define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
#define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
#define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
#define __EXTENSIONS__ 1
#endif

/* Define if the native Windows multithreading API can be used. */
/* #undef USE_WINDOWS_THREADS */

/* Version number of package */
//#define VERSION "1.32-unknown"

/* Expose all libc features (__DARWIN_C_FULL). */
/* #undef _DARWIN_C_SOURCE */

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
#define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to the widest signed integer type if <stdint.h> and <inttypes.h> do
   not define. */
/* #undef intmax_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to the widest unsigned integer type if <stdint.h> and <inttypes.h>
   do not define. */
/* #undef uintmax_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */

/* Force using of NLS for W32 even if no libintl has been found.  This is
   okay because we have our own gettext implementation for W32.  */
#if defined(HAVE_W32_SYSTEM) && !defined(ENABLE_NLS)
#define ENABLE_NLS 1
#endif

/* Connect the generic estream-printf.c to our framework.  */
#define _ESTREAM_PRINTF_REALLOC _gpgrt_realloc
#define _ESTREAM_PRINTF_EXTRA_INCLUDE "gpgrt-int.h"

/* For building we need to define these macro.  */
#define GPG_ERR_ENABLE_GETTEXT_MACROS 1
#define GPG_ERR_ENABLE_ERRNO_MACROS 1
#define GPGRT_ENABLE_ES_MACROS 1
#define GPGRT_ENABLE_LOG_MACROS 1
#define GPGRT_ENABLE_ARGPARSE_MACROS 1
