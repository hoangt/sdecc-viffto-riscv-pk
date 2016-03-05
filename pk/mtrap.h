#ifndef _PK_MTRAP_H
#define _PK_MTRAP_H

#include "bits.h"
#include "encoding.h"

#ifdef __riscv_atomic
# define MAX_HARTS 8 // arbitrary
#else
# define MAX_HARTS 1
#endif

#ifndef __ASSEMBLER__

#include "sbi.h"
#include <stdint.h>

#define read_const_csr(reg) ({ unsigned long __tmp; \
  asm ("csrr %0, " #reg : "=r"(__tmp)); \
  __tmp; })

static inline int supports_extension(char ext)
{
  return read_const_csr(misa) & (1 << (ext - 'A'));
}

static inline int xlen()
{
  return read_const_csr(misa) < 0 ? 64 : 32;
}

extern uintptr_t mem_size;
extern uint32_t num_harts;

typedef uintptr_t csr_t; // TODO this might become uint128_t for RV128

typedef struct {
  volatile csr_t* csrs;
  volatile int mipi_pending;
  volatile int sipi_pending;
  int console_ibuf;

  uint64_t utime_delta;
  uint64_t ucycle_delta;
  uint64_t uinstret_delta;
  uint64_t stime_delta;
  uint64_t scycle_delta;
  uint64_t sinstret_delta;
} hls_t;

#define IPI_SOFT      0x1
#define IPI_FENCE_I   0x2
#define IPI_SFENCE_VM 0x4

void hls_init(uint32_t hart_id, csr_t* csrs);

#define MACHINE_STACK_TOP() ({ \
  register uintptr_t sp asm ("sp"); \
  (void*)((sp + RISCV_PGSIZE) & -RISCV_PGSIZE); })

// hart-local storage, at top of stack
#define HLS() ((hls_t*)(MACHINE_STACK_TOP() - HLS_SIZE))
#define OTHER_HLS(id) ((hls_t*)((void*)HLS() + RISCV_PGSIZE * ((id) - read_const_csr(mhartid))))

void parse_config_string();
void poweroff(void) __attribute((noreturn));
void printm(const char* s, ...);
#define assert(x) ({ if (!(x)) die("assertion failed: %s", #x); })
#define die(str, ...) ({ printm("%s:%d: " str "\n", __FILE__, __LINE__, ##__VA_ARGS__); poweroff(); })
#define printk(...) die("printk")

#endif // !__ASSEMBLER__

#define MACHINE_STACK_SIZE RISCV_PGSIZE
#define MENTRY_FRAME_SIZE (INTEGER_CONTEXT_SIZE + SOFT_FLOAT_CONTEXT_SIZE \
                           + HLS_SIZE)

#ifdef __riscv_hard_float
# define SOFT_FLOAT_CONTEXT_SIZE 0
#else
# define SOFT_FLOAT_CONTEXT_SIZE (8 * 32)
#endif
#define HLS_SIZE 64
#define INTEGER_CONTEXT_SIZE (32 * REGBYTES)

#endif
