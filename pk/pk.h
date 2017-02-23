// See LICENSE for license details.

#ifndef _PK_H
#define _PK_H

#define MAX_HARTS 32 // coupled to width of booted_harts_mask

#ifndef __ASSEMBLER__

#define debug_printk(s, ...) //printk(s, __VA_ARGS__)

#include "encoding.h"
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

typedef struct
{
  long gpr[32];
  long status;
  long epc;
  long badvaddr;
  long cause;
  long insn;
} trapframe_t;

struct mainvars {
  uint64_t argc;
  uint64_t argv[127]; // this space is shared with the arg strings themselves
};

#define panic(s,...) do { do_panic(s"\n", ##__VA_ARGS__); } while(0)
#define kassert(cond) do { if(!(cond)) kassert_fail(""#cond); } while(0)
void do_panic(const char* s, ...) __attribute__((noreturn));
void kassert_fail(const char* s) __attribute__((noreturn));
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define CLAMP(a, lo, hi) MIN(MAX(a, lo), hi)

#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

#define EXTRACT_FIELD(val, which) (((val) & (which)) / ((which) & ~((which)-1)))
#define INSERT_FIELD(val, which, fieldval) (((val) & ~(which)) | ((fieldval) * ((which) & ~((which)-1))))

#ifdef __cplusplus
extern "C" {
#endif

extern uintptr_t mem_size;
extern int have_vm;
extern uint32_t num_harts;
extern volatile uint32_t booted_harts_mask;

struct mainvars* parse_args(struct mainvars*);
void printk(const char* s, ...);
void printm(const char* s, ...);
int vsnprintf(char* out, size_t n, const char* s, va_list vl);
int snprintf(char* out, size_t n, const char* s, ...);
void init_tf(trapframe_t*, long pc, long sp, int user64);
void start_user(trapframe_t* tf) __attribute__((noreturn));
void dump_tf(trapframe_t*);
void print_logo();

void unhandled_trap(trapframe_t*);
void handle_misaligned_load(trapframe_t*);
void handle_misaligned_store(trapframe_t*);
void handle_fault_load(trapframe_t*);
void handle_fault_store(trapframe_t*);
void handle_memory_due(trapframe_t*); //MWG: this is non-standard
void boot_loader(struct mainvars*);
void run_loaded_program(struct mainvars*);
void boot_other_hart();

//MWG
typedef struct {
    char bytes[32]; //Support UP TO 256-bit words
    size_t size;
} word_t;

//MWG
typedef struct {
    word_t candidate_messages[64]; //Support UP TO 64 candidate messages
    size_t size;
} due_candidates_t;

//MWG
typedef struct {
    word_t words[32]; //Support UP TO 32 words in a cacheline
    size_t blockpos;
    size_t size;
} due_cacheline_t;
      
typedef void (*trap_handler)(trapframe_t*); //MWG
typedef int (*user_due_trap_handler)(trapframe_t*, due_candidates_t*, due_cacheline_t*, word_t*); //MWG
int default_memory_due_trap_handler(trapframe_t*); //MWG
void sys_register_user_memory_due_trap_handler(user_due_trap_handler fptr); //MWG

int getDUECandidateMessages(due_candidates_t* candidates); //MWG
void parse_sdecc_candidate_output(char* script_stdout, size_t len, due_candidates_t* candidates); //MWG
void parse_sdecc_data_recovery_output(const char* script_stdout, word_t* w); //MWG
int getDUECacheline(due_cacheline_t* cacheline); //MWG
void do_data_recovery(word_t* w); //MWG
void copy_word(word_t* dest, word_t* src); //MWG
void copy_cacheline(due_cacheline_t* dest, due_cacheline_t* src); //MWG
void copy_candidates(due_candidates_t* dest, due_candidates_t* src); //MWG
void copy_trapframe(trapframe_t* dest, trapframe_t* src); //MWG

typedef struct {
  int elf64;
  int phent;
  int phnum;
  int is_supervisor;
  size_t phdr;
  size_t phdr_size;
  size_t first_free_paddr;
  size_t first_user_vaddr;
  size_t first_vaddr_after_user;
  size_t bias;
  size_t entry;
  size_t brk_min;
  size_t brk;
  size_t brk_max;
  size_t mmap_max;
  size_t stack_bottom;
  size_t stack_top;
  size_t t0;
} elf_info;

extern elf_info current;

void load_elf(const char* fn, elf_info* info);

static inline int insn_len(long insn)
{
  return (insn & 0x3) < 0x3 ? 2 : 4;
}

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

#define NUM_COUNTERS (18)
extern int uarch_counters_enabled;
extern long uarch_counters[NUM_COUNTERS];
extern char* uarch_counter_names[NUM_COUNTERS];

static inline void wfi()
{
  asm volatile ("wfi" ::: "memory");
}

#ifdef __cplusplus
}
#endif

#endif // !__ASSEMBLER__

#define ROUNDUP(a, b) ((((a)-1)/(b)+1)*(b))
#define ROUNDDOWN(a, b) ((a)/(b)*(b))

#endif
