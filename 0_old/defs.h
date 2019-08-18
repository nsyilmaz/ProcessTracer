#include "kernel_types.h"
#include "sysent.h"


typedef struct ioctlent {
        const char *symbol;
        unsigned int code;
} struct_ioctlent;


#define long_size	sizeof(long)
#define BUFFER_SIZE	9182 
#define TIME_BUFFER	30


#define ARRAY_SIZE(a_)  (sizeof(a_) / sizeof((a_)[0]) + MUST_BE_ARRAY(a_))

#define ARRSZ_PAIR(a_) a_, ARRAY_SIZE(a_)

#define STRINGIFY(...)          #__VA_ARGS__
#define STRINGIFY_VAL(...)      STRINGIFY(__VA_ARGS__)

#ifndef MAX
# define MAX(a, b)              (((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
# define MIN(a, b)              (((a) < (b)) ? (a) : (b))
#endif
#define CLAMP(val, min, max)    MIN(MAX(min, val), max)

#ifndef offsetofend
# define offsetofend(type_, member_)    \
        (offsetof(type_, member_) + sizeof(((type_ *)0)->member_))
#endif



#if __WORDSIZE == 64
#define REG(reg) reg.orig_rax
#define orig_eax orig_rax
#define ecx rcx
#else
#define REG(reg) reg.orig_eax
#define orig_eax orig_eax
#define ecx ecx
#endif



#define QUOTE_0_TERMINATED                      0x01
#define QUOTE_OMIT_LEADING_TRAILING_QUOTES      0x02
#define QUOTE_OMIT_TRAILING_0                   0x08
#define QUOTE_FORCE_HEX                         0x10
#define QUOTE_EMIT_COMMENT                      0x20


/*
 * Maximum number of args to a syscall.
 *
 * Make sure that all entries in all syscallent.h files have nargs <= MAX_ARGS!
 * linux/<ARCH>/syscallent*.h:
 *      all have nargs <= 6 except mips o32 which has nargs <= 7.
 */
#ifndef MAX_ARGS
# ifdef LINUX_MIPSO32
#  define MAX_ARGS      7
# else
#  define MAX_ARGS      6
# endif
#endif



/* To force NOMMU build, set to 1 */
#define NOMMU_SYSTEM 0

#ifndef ERESTARTSYS
# define ERESTARTSYS    512
#endif
#ifndef ERESTARTNOINTR
# define ERESTARTNOINTR 513
#endif
#ifndef ERESTARTNOHAND
# define ERESTARTNOHAND 514
#endif
#ifndef ERESTART_RESTARTBLOCK
# define ERESTART_RESTARTBLOCK 516
#endif

#define PERSONALITY0_WORDSIZE  SIZEOF_LONG
#define PERSONALITY0_KLONGSIZE SIZEOF_KERNEL_LONG_T
#define PERSONALITY0_INCLUDE_PRINTERS_DECLS "native_printer_decls.h"
#define PERSONALITY0_INCLUDE_PRINTERS_DEFS "native_printer_defs.h"

#if SUPPORTED_PERSONALITIES > 1
# define PERSONALITY1_WORDSIZE  4
# define PERSONALITY1_KLONGSIZE PERSONALITY1_WORDSIZE
#endif

#if SUPPORTED_PERSONALITIES > 2
# define PERSONALITY2_WORDSIZE  4
# define PERSONALITY2_KLONGSIZE PERSONALITY0_KLONGSIZE
#endif

#if SUPPORTED_PERSONALITIES > 1 && defined HAVE_M32_MPERS
# define PERSONALITY1_INCLUDE_PRINTERS_DECLS "m32_printer_decls.h"
# define PERSONALITY1_INCLUDE_PRINTERS_DEFS "m32_printer_defs.h"
# define PERSONALITY1_INCLUDE_FUNCS "m32_funcs.h"
# define MPERS_m32_IOCTL_MACROS "ioctl_redefs1.h"
# define HAVE_PERSONALITY_1_MPERS 1
#else
# define PERSONALITY1_INCLUDE_PRINTERS_DECLS "native_printer_decls.h"
# define PERSONALITY1_INCLUDE_PRINTERS_DEFS "native_printer_defs.h"
# define PERSONALITY1_INCLUDE_FUNCS "empty.h"
# define HAVE_PERSONALITY_1_MPERS 0
#endif

#if SUPPORTED_PERSONALITIES > 2 && defined HAVE_MX32_MPERS
# define PERSONALITY2_INCLUDE_FUNCS "mx32_funcs.h"
# define PERSONALITY2_INCLUDE_PRINTERS_DECLS "mx32_printer_decls.h"
# define PERSONALITY2_INCLUDE_PRINTERS_DEFS "mx32_printer_defs.h"
# define MPERS_mx32_IOCTL_MACROS "ioctl_redefs2.h"
# define HAVE_PERSONALITY_2_MPERS 1
#else
# define PERSONALITY2_INCLUDE_PRINTERS_DECLS "native_printer_decls.h"
# define PERSONALITY2_INCLUDE_PRINTERS_DEFS "native_printer_defs.h"
# define PERSONALITY2_INCLUDE_FUNCS "empty.h"
# define HAVE_PERSONALITY_2_MPERS 0
#endif

#ifdef WORDS_BIGENDIAN
# define is_bigendian true
#else
# define is_bigendian false
#endif

