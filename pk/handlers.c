// See LICENSE for license details.

#include "pk.h"
#include "config.h"
#include "syscall.h"
#include "vm.h"

user_due_trap_handler g_user_memory_due_trap_handler = NULL; //MWG
due_candidates_t g_candidates; //MWG
due_cacheline_t g_cacheline; //MWG
char g_candidates_cstring[2048]; //MWG
char g_recovery_cstring[2048]; //MWG

static void handle_illegal_instruction(trapframe_t* tf)
{
  tf->insn = *(uint16_t*)tf->epc;
  int len = insn_len(tf->insn);
  if (len == 4)
    tf->insn |= ((uint32_t)*(uint16_t*)(tf->epc + 2) << 16);
  else
    kassert(len == 2);

  dump_tf(tf);
  panic("An illegal instruction was executed!");
}

static void handle_breakpoint(trapframe_t* tf)
{
  dump_tf(tf);
  printk("Breakpoint!\n");
  tf->epc += 4;
}

static void handle_misaligned_fetch(trapframe_t* tf)
{
  dump_tf(tf);
  panic("Misaligned instruction access!");
}

void handle_misaligned_load(trapframe_t* tf)
{
  // TODO emulate misaligned loads and stores
  dump_tf(tf);
  panic("Misaligned load!");
}

void handle_misaligned_store(trapframe_t* tf)
{
  dump_tf(tf);
  panic("Misaligned store!");
}

static void segfault(trapframe_t* tf, uintptr_t addr, const char* type)
{
  dump_tf(tf);
  const char* who = (tf->status & MSTATUS_PRV1) ? "Kernel" : "User";
  panic("%s %s segfault @ %p", who, type, addr);
}

static void handle_fault_fetch(trapframe_t* tf)
{
  if (handle_page_fault(tf->badvaddr, PROT_EXEC) != 0)
    segfault(tf, tf->badvaddr, "fetch");
}

void handle_fault_load(trapframe_t* tf)
{
  if (handle_page_fault(tf->badvaddr, PROT_READ) != 0)
    segfault(tf, tf->badvaddr, "load");
}

void handle_fault_store(trapframe_t* tf)
{
  if (handle_page_fault(tf->badvaddr, PROT_WRITE) != 0)
    segfault(tf, tf->badvaddr, "store");
}

static void handle_syscall(trapframe_t* tf)
{
  tf->gpr[10] = do_syscall(tf->gpr[10], tf->gpr[11], tf->gpr[12], tf->gpr[13],
                           tf->gpr[14], tf->gpr[15], tf->gpr[17]);
  tf->epc += 4;
}

static void handle_interrupt(trapframe_t* tf)
{
  clear_csr(sip, SIP_SSIP);
}

void handle_trap(trapframe_t* tf)
{
  if ((intptr_t)tf->cause < 0)
    return handle_interrupt(tf);

  //MWG moved the following to pk.h
  //typedef void (*trap_handler)(trapframe_t*);

  const static trap_handler trap_handlers[] = {
    [CAUSE_MISALIGNED_FETCH] = handle_misaligned_fetch,
    [CAUSE_FAULT_FETCH] = handle_fault_fetch,
    [CAUSE_ILLEGAL_INSTRUCTION] = handle_illegal_instruction,
    [CAUSE_USER_ECALL] = handle_syscall,
    [CAUSE_BREAKPOINT] = handle_breakpoint,
    [CAUSE_MISALIGNED_LOAD] = handle_misaligned_load,
    [CAUSE_MISALIGNED_STORE] = handle_misaligned_store,
    [CAUSE_FAULT_LOAD] = handle_fault_load,
    [CAUSE_FAULT_STORE] = handle_fault_store,
    [CAUSE_MEMORY_DUE] = handle_memory_due, //MWG: this is non-standard
  };

  kassert(tf->cause < ARRAY_SIZE(trap_handlers) && trap_handlers[tf->cause]);

  trap_handlers[tf->cause](tf);
}

//MWG
void sys_register_user_memory_due_trap_handler(user_due_trap_handler fptr) {
   g_user_memory_due_trap_handler = fptr;
}

//MWG
int default_memory_due_trap_handler(trapframe_t* tf) {
  if (tf) {
      //Ignore candidates, simply writeback 0 word
      word_t recovered_value;
      for (size_t i = 0; i < 32; i++)
          recovered_value.bytes[i] = 0; //Just make sure
      memcpy((void*)(tf->badvaddr), recovered_value.bytes, 8); //Put the recovered data back in memory. FIXME: this is architecturally incorrect.. we need to recover via CSR to be technically correct
  }
  panic("Default pk memory DUE trap handler: panic()");
}

//MWG
void handle_memory_due(trapframe_t* tf) {
  if (g_user_memory_due_trap_handler && !getDUECandidateMessages(&g_candidates) && !getDUECacheline(&g_cacheline)) {
       word_t recovered_value, user_recovered_value;
       do_data_recovery(&recovered_value); //Pre-select recovery value. FIXME: inst recovery?
       copy_word(&user_recovered_value, &recovered_value);
       int retval = g_user_memory_due_trap_handler(tf, &g_candidates, &g_cacheline, &user_recovered_value); //May clobber recovered_value
       void* ptr = (void*)(tf->badvaddr);
       switch (retval) {
         case 0: //User handler indicated success
             memcpy(ptr, user_recovered_value.bytes, 8); //Put the recovered data back in memory. FIXME: this is architecturally incorrect.. we need to recover via CSR to be technically correct
             return;
         case 1: //User handler wants us to use the pre-selected recovery value
             memcpy(ptr, recovered_value.bytes, 8); //Put the recovered data back in memory. FIXME: this is architecturally incorrect.. we need to recover via CSR to be technically correct
             return;
         default: //User handler wants us to use default safe handler
             default_memory_due_trap_handler(tf);
             return;
       }
  }
  default_memory_due_trap_handler(tf);
}

//MWG
int getDUECandidateMessages(due_candidates_t* candidates) {
    //Magical Spike hook to compute candidates, so we don't have to re-implement in C
    asm volatile("custom2 0,%0,0,0;"
                 : 
                 : "r" (&g_candidates_cstring));

    //Parse returned value
    parse_sdecc_candidate_output(g_candidates_cstring, 2048, candidates);
    
    return 0; 
}

//MWG
int getDUECacheline(due_cacheline_t* cacheline) {
    if (!cacheline)
        return 1;

    //FIXME: how to pass in as runtime options to pk? These MUST match what is used by Spike!
    unsigned wordsize = 8;
    unsigned words_per_block = 8;

    unsigned long cl[words_per_block];
    size_t blockpos;

    //FIXME: cacheline and word sizes scalability
    cl[0] = read_csr(0x5); //CSR_PENALTY_BOX_CACHELINE_BLK0
    cl[1] = read_csr(0x6); //CSR_PENALTY_BOX_CACHELINE_BLK1
    cl[2] = read_csr(0x7); //CSR_PENALTY_BOX_CACHELINE_BLK2
    cl[3] = read_csr(0x8); //CSR_PENALTY_BOX_CACHELINE_BLK3
    cl[4] = read_csr(0x9); //CSR_PENALTY_BOX_CACHELINE_BLK4
    cl[5] = read_csr(0xa); //CSR_PENALTY_BOX_CACHELINE_BLK5
    cl[6] = read_csr(0xb); //CSR_PENALTY_BOX_CACHELINE_BLK6
    cl[7] = read_csr(0xc); //CSR_PENALTY_BOX_CACHELINE_BLK7
    blockpos = read_csr(0xd); //CSR_PENALTY_BOX_CACHELINE_BLKPOS
    
    for (int i = 0; i < words_per_block; i++) {
        memcpy(cacheline->words[i].bytes, cl+i, wordsize);
        cacheline->words[i].size = wordsize;
    }
    cacheline->blockpos = blockpos;
    cacheline->size = words_per_block;

    return 0; 
}

//MWG
void parse_sdecc_candidate_output(char* script_stdout, size_t len, due_candidates_t* candidates) {
      int count = 0;
      int k = 0;
      size_t wordsize = 8; //FIXME: how to make this a run-time option? This MUST match spike!
      word_t w;
      w.size = wordsize;
      // Output is expected to be simply a bunch of rows, each with k=8*wordsize binary messages, e.g. '001010100101001...001010'
      do {
          for (size_t i = 0; i < wordsize; i++) {
              w.bytes[i] = 0;
              for (size_t j = 0; j < 8; j++) {
                  w.bytes[i] |= (script_stdout[k++] == '1' ? (1 << (8-j-1)) : 0);
              }
          }
          script_stdout[k++] = ','; //Change newline to comma in buffer so we can reuse it for data recovery insn
          copy_word(candidates->candidate_messages+count, &w);
          count++;
      } while(script_stdout[k] != '\0' && count < 32 && k < len);
      candidates->size = count;
      script_stdout[k-1] = '\0';
}

//MWG
void parse_sdecc_data_recovery_output(const char* script_stdout, word_t* w) {
      int k = 0;
      size_t wordsize = 8;
      // Output is expected to be simply a bunch of rows, each with k=8*wordsize binary messages, e.g. '001010100101001...001010'
      do {
          for (size_t i = 0; i < wordsize; i++) {
              w->bytes[i] = 0;
              for (size_t j = 0; j < 8; j++) {
                  w->bytes[i] |= (script_stdout[k++] == '1' ? (1 << (8-j-1)) : 0);
              }
          }
          k++; //Skip newline
      } while(script_stdout[k] != '\0' && k < 8*wordsize);
      w->size = wordsize;
}

//MWG
void do_data_recovery(word_t* w) {
    //Magical Spike hook to recover, so we don't have to re-implement in C
    asm volatile("custom3 0,%0,%1,0;"
                 : 
                 : "r" (&g_recovery_cstring), "r" (&g_candidates_cstring));

    parse_sdecc_data_recovery_output(g_recovery_cstring, w);
}

//MWG
void copy_word(word_t* dest, word_t* src) {
   if (dest && src) {
       for (int i = 0; i < 32; i++)
           dest->bytes[i] = src->bytes[i];
       dest->size = src->size;
   }
}

//MWG
void copy_cacheline(due_cacheline_t* dest, due_cacheline_t* src) {
    if (dest && src) {
        for (int i = 0; i < 32; i++)
            copy_word(dest->words+i, src->words+i);
        dest->size = src->size;
        dest->blockpos = src->blockpos;
    }
}

//MWG
void copy_candidates(due_candidates_t* dest, due_candidates_t* src) {
    if (dest && src) {
        for (int i = 0; i < 32; i++)
            copy_word(dest->candidate_messages+i, src->candidate_messages+i);
        dest->size = src->size;
    }
}

//MWG
void copy_trapframe(trapframe_t* dest, trapframe_t* src) {
   if (dest && src) {
       for (int i = 0; i < 32; i++)
           dest->gpr[i] = src->gpr[i];
       dest->status = src->status;
       dest->epc = src->epc;
       dest->badvaddr = src->badvaddr;
       dest->cause = src->cause;
       dest->insn = src->insn;
   }
}
