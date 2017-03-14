// See LICENSE for license details.

#include "pk.h"
#include "config.h"
#include "syscall.h"
#include "vm.h"

user_due_trap_handler g_user_memory_due_trap_handler = NULL; //MWG
due_candidates_t g_candidates; //MWG
due_cacheline_t g_cacheline; //MWG
char g_candidates_cstring[G_CANDIDATES_CSTRING_SIZE]; //MWG
char g_recovery_cstring[G_RECOVERY_CSTRING_SIZE]; //MWG

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
int default_memory_due_trap_handler(trapframe_t* tf, int error_code, const char* expl) {
  dump_tf(tf);
  panic("FAILED DUE RECOVERY, error code %d, reason: %s\n", error_code, expl);
  return 0; //Should never be reached
}

//MWG
void handle_memory_due(trapframe_t* tf) {
  //TODO FIXME: 3/9/2017, Major corner-case issue: I finally found source of the rare hang bug. It occurs when a memory DUE occurs right when pk holds a lock in frontend_syscall(). In this case, the trap handler re-enters and will eventually find itself hung on its own lock!!!! That was the most horrible bug I have ever had to find.. took 4 solid days. Problem is, how do we fix it? Even die() and panic() use frontend_syscall() to talk to our host. We need to somehow escape the nested locking pattern, it's our only hope if we don't want that sort of hang.

  if ((tf->epc < 0x20000 && tf->epc >= 0) || (tf->badvaddr < 0x20000 && tf->badvaddr >= 0)) { //FIXME: hardcoded values
      default_memory_due_trap_handler(tf, -5, "DUE while fetching or loading from kernel address space"); 
      return;
  } 
  
  if (g_user_memory_due_trap_handler == NULL) {
      default_memory_due_trap_handler(tf, -5, "no registered DUE handler"); 
      return;
  }
  
  if (getDUECandidateMessages(&g_candidates) != 0 || getDUECacheline(&g_cacheline) != 0) {
      default_memory_due_trap_handler(tf, -5, "kernel handler failed to get DUE candidates and/or cacheline SI"); 
      return;
  }
   
   int error_code = 0;

   //Init
   word_t user_recovered_value;
   word_t system_recovered_value;
   word_t recovered_load_value;
   word_t cheat_msg;
   word_t cheat_load_value;
   user_recovered_value.size = 0;
   system_recovered_value.size = 0;
   recovered_load_value.size = 0;
   cheat_msg.size = 0;
   cheat_load_value.size = 0;
   copy_word(&system_recovered_value, &(g_candidates.candidate_messages[0]));
   size_t msg_size = system_recovered_value.size;
   long badvaddr = tf->badvaddr;
   long demand_vaddr = 0;
   size_t demand_dest_reg = 0;
   int demand_float_regfile = 0;
   int mem_type = (int)(read_csr(0x9)); //CSR_PENALTY_BOX_MEM_TYPE
   size_t demand_load_size = read_csr(0x4); //CSR_PENALTY_BOX_LOAD_SIZE
   if (mem_type == 0) { //data
       demand_vaddr = decode_load_vaddr(tf->insn, tf);
       demand_dest_reg = decode_rd(tf->insn);
       demand_float_regfile = decode_regfile(tf->insn);
   } else if (mem_type == 1) { //inst
       demand_vaddr = tf->epc;
   } else
      default_memory_due_trap_handler(tf, -5, "pk could not determine whether victim was data or inst memory");

   
   int demand_load_message_offset = (int)(demand_vaddr - badvaddr); //Positive offset: DUE came before demand load

   if (mem_type == 0 && (demand_dest_reg < 0 || demand_dest_reg > NUM_GPR || demand_dest_reg > NUM_FPR))
      default_memory_due_trap_handler(tf, -5, "pk decoded bad dest. reg from the insn");

   if (mem_type == 0 && (demand_float_regfile != 0 && demand_float_regfile != 1))
      default_memory_due_trap_handler(tf, -5, "pk decoded bad int/float type of insn load");

   float_trapframe_t float_tf;
   error_code = set_float_trapframe(&float_tf);
   if (error_code)
      default_memory_due_trap_handler(tf, error_code, "pk failed to set float trapframe");
  
   int system_suggested_to_crash = do_system_recovery(&system_recovered_value); //"System" will figure out inst or data
   copy_word(&user_recovered_value, &system_recovered_value);
   
   //For book-keeping only!!
   if (getDUECheatMessage(&cheat_msg) != 0) {
        default_memory_due_trap_handler(tf, -5, "pk failed to load cheat-recovery message for bookkeeping from HW");
        return;
   }

   error_code = load_value_from_message(&cheat_msg, &cheat_load_value, &g_cacheline, demand_load_size, demand_load_message_offset); //For bookkeeping only
   if (error_code) {
       default_memory_due_trap_handler(tf, error_code, "pk failed to load cheat value from cheat message");
       return;
   }
  

   error_code = g_user_memory_due_trap_handler(tf, &float_tf, demand_vaddr, &g_candidates, &g_cacheline, &user_recovered_value, demand_load_size, demand_dest_reg, demand_float_regfile, demand_load_message_offset, mem_type); //May clobber user_recovered_value
   
   switch (error_code) {
     case 0: //User handler indicated success, use their specified value
         error_code = load_value_from_message(&user_recovered_value, &recovered_load_value, &g_cacheline, demand_load_size, demand_load_message_offset);    
         if (error_code)
             default_memory_due_trap_handler(tf, error_code, "pk failed to load value from user message during user-specified recovery");
         
         error_code = compare_recovery(&user_recovered_value, &cheat_msg, &recovered_load_value, &cheat_load_value, demand_load_message_offset); //For bookkeeping only
         if (error_code)
             default_memory_due_trap_handler(tf, error_code, "pk failed to compare recovered value with cheat value for bookkeeping");

         error_code = writeback_recovered_message(&user_recovered_value, &recovered_load_value, tf, mem_type, demand_dest_reg, demand_float_regfile);
         if (error_code)
             default_memory_due_trap_handler(tf, error_code, "pk failed to write back recovered message during user-specified recovery");
         if (mem_type == 0) //Only advance PC if the error was data mem, otherwise we want to re-fetch.
             tf->epc += 4;
         return;
     case 1: //User handler wants us to use the generic recovery policy. Use our specified value. 
         error_code = load_value_from_message(&system_recovered_value, &recovered_load_value, &g_cacheline, demand_load_size, demand_load_message_offset);

         if (error_code)
             default_memory_due_trap_handler(tf, error_code, "pk failed to load value from system message during system-specified recovery");
         
         error_code = compare_recovery(&system_recovered_value, &cheat_msg, &recovered_load_value, &cheat_load_value, demand_load_message_offset); //For bookkeeping only

         if (error_code)
             default_memory_due_trap_handler(tf, error_code, "pk failed to compare recovered value with cheat value for bookkeeping");

         if (system_suggested_to_crash == -1)
             default_memory_due_trap_handler(tf, -1, "system-defined recovery policy suggested to panic");
         
         error_code = writeback_recovered_message(&system_recovered_value, &recovered_load_value, tf, mem_type, demand_dest_reg, demand_float_regfile);
         if (error_code)
             default_memory_due_trap_handler(tf, error_code, "pk failed to write back recovered message during system-specified recovery");
         if (mem_type == 0) //Only advance PC if the error was data mem, otherwise we want to re-fetch.
             tf->epc += 4;
         return;
     case -1: //User handler wants us to use default safe handler (crash)
         default_memory_due_trap_handler(tf, error_code, "user program opted to crash safely");
         return;
     case -2: //User handler not registered
         default_memory_due_trap_handler(tf, error_code, "user DUE handler not registered");
         return;
     case -3: //DUE was out-of-bounds for user handler
         default_memory_due_trap_handler(tf, error_code, "user DUE handler was out of user-defined bounds");
         return;
     case -4: //User handler problem
         default_memory_due_trap_handler(tf, error_code, "user handler problem");
         return;
     case -5: //Kernel handler problem
         default_memory_due_trap_handler(tf, error_code, "kernel handler problem");
         return;
     default: //Any other problem
         default_memory_due_trap_handler(tf, error_code, "unknown handler problem"); 
         return;
   }
  default_memory_due_trap_handler(tf, -5, "this should not ever have happened"); 
}

//MWG
int getDUECandidateMessages(due_candidates_t* candidates) {
    //Magical Spike hook to compute candidates, so we don't have to re-implement in C
    asm volatile("custom2 0,%0,0,0;"
                 : 
                 : "r" (&g_candidates_cstring));

    //Parse returned value
    parse_sdecc_candidate_output(g_candidates_cstring, G_CANDIDATES_CSTRING_SIZE, candidates);
    
    return 0; 
}

//MWG
int getDUECacheline(due_cacheline_t* cacheline) {
    if (!cacheline)
        return -5;

    size_t wordsize = read_csr(0x5); //CSR_PENALTY_BOX_MSG_SIZE
    size_t cacheline_size = read_csr(0x6); //CSR_PENALTY_BOX_CACHELINE_SIZE
    size_t blockpos = read_csr(0x7); //CSR_PENALTY_BOX_CACHELINE_BLKPOS
    size_t num_reads = (cacheline_size % sizeof(size_t) == 0 ? cacheline_size/sizeof(size_t) : cacheline_size/sizeof(size_t)+1);
    size_t cl[num_reads];

    for (size_t i = 0; i < num_reads; i++)
        cl[i] = read_csr(0x8); //CSR_PENALTY_BOX_CACHELINE_WORD. Hardware will give us a different 64-bit chunk every iteration. If we over-read, then something bad may happen in HW.

    size_t words_per_block = cacheline_size / wordsize;
    char* cl_cast = (char*)(cl);
    for (size_t i = 0; i < words_per_block; i++) {
        memcpy(cacheline->words[i].bytes, cl_cast+(i*wordsize), wordsize);
        cacheline->words[i].size = wordsize;
    }
    cacheline->blockpos = blockpos;
    cacheline->size = words_per_block;

    return 0; 
}

//MWG
int getDUECheatMessage(word_t* cheat_msg) {
    if (!cheat_msg)
        return -5;

    size_t wordsize = read_csr(0x5); //CSR_PENALTY_BOX_MSG_SIZE
    size_t num_reads = (wordsize % sizeof(size_t) == 0 ? wordsize/sizeof(size_t) : wordsize/sizeof(size_t)+1);
    size_t victim_msg[num_reads];

    for (size_t i = 0; i < num_reads; i++)
        victim_msg[i] = read_csr(0xb); //CSR_PENALTY_BOX_CHEAT_MSG. Hardware will give us a different 64-bit chunk every iteration. FIXME: If we over-read, then something bad may happen in HW.

    memcpy(cheat_msg->bytes, victim_msg, wordsize);
    cheat_msg->size = wordsize;

    return 0; 
}

//MWG
void parse_sdecc_candidate_output(char* script_stdout, size_t len, due_candidates_t* candidates) {
      int count = 0;
      int k = 0;
      size_t wordsize = read_csr(0x5); //CSR_PENALTY_BOX_MSG_SIZE
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
      } while(script_stdout[k] != '\0' && count < 64 && k < len);
      candidates->size = count;
      script_stdout[k-1] = '\0';
}

//MWG
int parse_sdecc_recovery_output(const char* script_stdout, word_t* w) {
      int k = 0;
      size_t wordsize = read_csr(0x5); //CSR_PENALTY_BOX_MSG_SIZE, FIXME
      // Output is expected to be simply a bunch of rows, each with k=8*wordsize binary messages, e.g. '001010100101001...001010'
      for (size_t i = 0; i < wordsize; i++) {
          w->bytes[i] = 0;
          for (size_t j = 0; j < 8; j++) {
              w->bytes[i] |= (script_stdout[k++] == '1' ? (1 << (8-j-1)) : 0);
          }
      }
      w->size = wordsize;

      //Check for SUGGEST_TO_CRASH
      if (strcmp(script_stdout+k, " SUGGEST_TO_CRASH\n") == 0)
          return -1;
      else
          return 0;
}

//MWG
int do_system_recovery(word_t* w) {
    //Magical Spike hook to recover, so we don't have to re-implement in C
    asm volatile("custom3 0,%0,%1,0;"
                 : 
                 : "r" (&g_recovery_cstring), "r" (&g_candidates_cstring));

    return parse_sdecc_recovery_output(g_recovery_cstring, w);
}


//MWG
int copy_word(word_t* dest, word_t* src) {
   if (dest && src && src->size <= MAX_WORD_SIZE) {
       for (size_t i = 0; i < src->size; i++)
           dest->bytes[i] = src->bytes[i];
       dest->size = src->size;

       return 0;
   }

   return -5;
}

//MWG
int copy_cacheline(due_cacheline_t* dest, due_cacheline_t* src) {
    if (dest && src && src->size <= MAX_CACHELINE_WORDS) {
        for (size_t i = 0; i < src->size; i++)
            copy_word(dest->words+i, src->words+i);
        dest->size = src->size;
        dest->blockpos = src->blockpos;

        return 0;
    }
    
    return -5;
}

//MWG
int copy_candidates(due_candidates_t* dest, due_candidates_t* src) {
    if (dest && src && src->size <= MAX_CANDIDATE_MSG) {
        for (size_t i = 0; i < src->size; i++)
            copy_word(dest->candidate_messages+i, src->candidate_messages+i);
        dest->size = src->size;
        
        return 0;
    }

    return -5;
}

//MWG
int copy_trapframe(trapframe_t* dest, trapframe_t* src) {
   if (dest && src) {
       for (size_t i = 0; i < NUM_GPR; i++)
           dest->gpr[i] = src->gpr[i];
       dest->status = src->status;
       dest->epc = src->epc;
       dest->badvaddr = src->badvaddr;
       dest->cause = src->cause;
       dest->insn = src->insn;

       return 0;
   }

   return -5;
}

//MWG
int copy_float_trapframe(float_trapframe_t* dest, float_trapframe_t* src) {
   if (dest && src) {
       for (size_t i = 0; i < NUM_FPR; i++)
           dest->fpr[i] = src->fpr[i];
       return 0;
   }

   return -5;
}

//MWG
long decode_load_vaddr(long insn, trapframe_t* tf) {
   //RS1 + i_imm
   //Applies to ld, lw, lb, flw, fld, etc.
   long base = tf->gpr[decode_rs1(insn)];
   return base + decode_i_imm(insn);
}

//MWG
long decode_i_imm(long insn) {
   long tmp = insn << 32; //Left shift so we can get immediate sign bit at long's MSB
   return tmp >> (20+32); //Right shift to sign extend correctly
}

//MWG
size_t decode_rs1(long insn) {
   return (insn >> 15) & ((1 << 5)-1); 
}

//MWG
size_t decode_rd(long insn) {
   return (insn >> 7) & ((1 << 5)-1); 
}

//MWG
int decode_regfile(long insn) {
   //FLW: 0x2007 match, FLD: 0x3007
   return ((insn & MATCH_FLW) == MATCH_FLW || (insn & MATCH_FLD) == MATCH_FLD);
}

//MWG
int load_value_from_message(word_t* recovered_message, word_t* load_value, due_cacheline_t* cl, size_t load_size, int offset) {
    if (!recovered_message || !load_value || !cl)
        return -5;
   
    //Init
    load_value->size = 0;
    int msg_size = (int) recovered_message->size; 
    int load_width = (int) load_size;
    int blockpos = (int) cl->blockpos;
    int clsize = (int) cl->size;
    int offset_in_block = (offset < 0 ? -offset : offset) % msg_size;
    int remain = load_width;
    int transferred = 0;
    int curr_blockpos = blockpos + offset/msg_size + ((offset < 0 && offset_in_block != 0) ? -1 : 0); 

    if (msg_size < 0 || msg_size > MAX_WORD_SIZE || load_width < 0 || load_width > MAX_WORD_SIZE || clsize < 0 || clsize > MAX_CACHELINE_WORDS || blockpos < 0 || blockpos > clsize || curr_blockpos < 0 || curr_blockpos > clsize) //Something went wrong
        return -5;
        
    while (remain > 0) {
        if (curr_blockpos == blockpos)
            memcpy(load_value->bytes+transferred, recovered_message->bytes+offset_in_block, (msg_size-offset_in_block > remain ? remain : msg_size-offset_in_block));
        else
            memcpy(load_value->bytes+transferred, cl->words[curr_blockpos].bytes+offset_in_block, (msg_size-offset_in_block > remain ? remain : msg_size-offset_in_block));
        remain -= (msg_size-offset_in_block > remain ? remain : msg_size-offset_in_block);
        offset_in_block = 0;
        transferred = load_width-remain;
        curr_blockpos++;
    }

    load_value->size = load_size;
    return 0;
}

//MWG
int writeback_recovered_message(word_t* recovered_message, word_t* load_value, trapframe_t* tf, int mem_type, size_t rd, int float_regfile) {
    if (!recovered_message || !load_value || !tf || (mem_type == 0 && (rd < 0 || rd >= NUM_GPR || rd >= NUM_FPR || float_regfile < 0 || float_regfile > 1)))
        return -5;
 
    if (mem_type == 0) { //data-only: write to changes to register file/trapframe. inst should only writeback to memory
        unsigned long val;
        switch (load_value->size) {
            case 1:
                ; //shut up compiler
                unsigned char* tmp = (unsigned char*)(load_value->bytes);
                val = (unsigned long)(*tmp);
                break;
            case 2:
                ; //shut up compiler
                unsigned short* tmp2 = (unsigned short*)(load_value->bytes);
                val = (unsigned long)(*tmp2);
                break;
            case 4:
                ; //shut up compiler
                unsigned* tmp3 = (unsigned*)(load_value->bytes);
                val = (unsigned long)(*tmp3);
                break;
            case 8:
                ; //shut up compiler
                unsigned long* tmp4 = (unsigned long*)(load_value->bytes);
                val = *tmp4;
                break;
            default: 
                return -5;
        }

        if (float_regfile) {
            //Floating-point registers are not part of the trapframe, so I suppose we should just write the register directly.
            if (set_float_register(rd, val)) {
                return -5;
            }
        } else {
            tf->gpr[rd] = val; //Write load value to trapframe
        }
    }

    size_t msg_size = recovered_message->size; 
    void* badvaddr_msg = (void*)((unsigned long)(tf->badvaddr) & (~(msg_size-1)));
    memcpy(badvaddr_msg, recovered_message->bytes, msg_size); //Write message to main memory
    return 0;
}

int set_float_register(size_t frd, unsigned long raw_value) {
    switch (frd) {
        case 0: //f0
            asm volatile("fmv.d.x f0, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 1: //f1
            asm volatile("fmv.d.x f1, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 2: //f2
            asm volatile("fmv.d.x f2, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 3: //f3
            asm volatile("fmv.d.x f3, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 4: //f4
            asm volatile("fmv.d.x f4, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 5: //f5
            asm volatile("fmv.d.x f5, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 6: //f6
            asm volatile("fmv.d.x f6, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 7: //f7
            asm volatile("fmv.d.x f7, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 8: //f8
            asm volatile("fmv.d.x f8, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 9: //f9
            asm volatile("fmv.d.x f9, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 10: //f10
            asm volatile("fmv.d.x f10, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 11: //f11
            asm volatile("fmv.d.x f11, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 12: //f12
            asm volatile("fmv.d.x f12, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 13: //f13
            asm volatile("fmv.d.x f13, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 14: //f14
            asm volatile("fmv.d.x f14, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 15: //f15
            asm volatile("fmv.d.x f15, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 16: //f16
            asm volatile("fmv.d.x f16, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 17: //f17
            asm volatile("fmv.d.x f17, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 18: //f18
            asm volatile("fmv.d.x f18, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 19: //f19
            asm volatile("fmv.d.x f19, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 20: //f20
            asm volatile("fmv.d.x f20, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 21: //f21
            asm volatile("fmv.d.x f21, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 22: //f22
            asm volatile("fmv.d.x f22, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 23: //f23
            asm volatile("fmv.d.x f23, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 24: //f24
            asm volatile("fmv.d.x f24, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 25: //f25
            asm volatile("fmv.d.x f25, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 26: //f26
            asm volatile("fmv.d.x f26, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 27: //f27
            asm volatile("fmv.d.x f27, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 28: //f28
            asm volatile("fmv.d.x f28, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 29: //f29
            asm volatile("fmv.d.x f29, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 30: //f30
            asm volatile("fmv.d.x f30, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        case 31: //f31
            asm volatile("fmv.d.x f31, %0;"
                         :
                         : "r" (raw_value));
            return 0;
        default: //Bad register
            return -5;
    }
}

int get_float_register(size_t frd, unsigned long* raw_value) {
    if (!raw_value)
        return -5;

    unsigned long tmp; 
    switch (frd) {
        case 0: //f0
            asm volatile("fmv.x.d %0, f0;"
                         : "=r" (tmp)
                         :);
            break;
        case 1: //f1
            asm volatile("fmv.x.d %0, f1;"
                         : "=r" (tmp)
                         :);
            break;
        case 2: //f2
            asm volatile("fmv.x.d %0, f2;"
                         : "=r" (tmp)
                         :);
            break;
        case 3: //f3
            asm volatile("fmv.x.d %0, f3;"
                         : "=r" (tmp)
                         :);
            break;
        case 4: //f4
            asm volatile("fmv.x.d %0, f4;"
                         : "=r" (tmp)
                         :);
            break;
        case 5: //f5
            asm volatile("fmv.x.d %0, f5;"
                         : "=r" (tmp)
                         :);
            break;
        case 6: //f6
            asm volatile("fmv.x.d %0, f6;"
                         : "=r" (tmp)
                         :);
            break;
        case 7: //f7
            asm volatile("fmv.x.d %0, f7;"
                         : "=r" (tmp)
                         :);
            break;
        case 8: //f8
            asm volatile("fmv.x.d %0, f8;"
                         : "=r" (tmp)
                         :);
            break;
        case 9: //f9
            asm volatile("fmv.x.d %0, f9;"
                         : "=r" (tmp)
                         :);
            break;
        case 10: //f10
            asm volatile("fmv.x.d %0, f10;"
                         : "=r" (tmp)
                         :);
            break;
        case 11: //f11
            asm volatile("fmv.x.d %0, f11;"
                         : "=r" (tmp)
                         :);
            break;
        case 12: //f12
            asm volatile("fmv.x.d %0, f12;"
                         : "=r" (tmp)
                         :);
            break;
        case 13: //f13
            asm volatile("fmv.x.d %0, f13;"
                         : "=r" (tmp)
                         :);
            break;
        case 14: //f14
            asm volatile("fmv.x.d %0, f14;"
                         : "=r" (tmp)
                         :);
            break;
        case 15: //f15
            asm volatile("fmv.x.d %0, f15;"
                         : "=r" (tmp)
                         :);
            break;
        case 16: //f16
            asm volatile("fmv.x.d %0, f16;"
                         : "=r" (tmp)
                         :);
            break;
        case 17: //f17
            asm volatile("fmv.x.d %0, f17;"
                         : "=r" (tmp)
                         :);
            break;
        case 18: //f18
            asm volatile("fmv.x.d %0, f18;"
                         : "=r" (tmp)
                         :);
            break;
        case 19: //f19
            asm volatile("fmv.x.d %0, f19;"
                         : "=r" (tmp)
                         :);
            break;
        case 20: //f20
            asm volatile("fmv.x.d %0, f20;"
                         : "=r" (tmp)
                         :);
            break;
        case 21: //f21
            asm volatile("fmv.x.d %0, f21;"
                         : "=r" (tmp)
                         :);
            break;
        case 22: //f22
            asm volatile("fmv.x.d %0, f22;"
                         : "=r" (tmp)
                         :);
            break;
        case 23: //f23
            asm volatile("fmv.x.d %0, f23;"
                         : "=r" (tmp)
                         :);
            break;
        case 24: //f24
            asm volatile("fmv.x.d %0, f24;"
                         : "=r" (tmp)
                         :);
            break;
        case 25: //f25
            asm volatile("fmv.x.d %0, f25;"
                         : "=r" (tmp)
                         :);
            break;
        case 26: //f26
            asm volatile("fmv.x.d %0, f26;"
                         : "=r" (tmp)
                         :);
            break;
        case 27: //f27
            asm volatile("fmv.x.d %0, f27;"
                         : "=r" (tmp)
                         :);
            break;
        case 28: //f28
            asm volatile("fmv.x.d %0, f28;"
                         : "=r" (tmp)
                         :);
            break;
        case 29: //f29
            asm volatile("fmv.x.d %0, f29;"
                         : "=r" (tmp)
                         :);
            break;
        case 30: //f30
            asm volatile("fmv.x.d %0, f30;"
                         : "=r" (tmp)
                         :);
            break;
        case 31: //f31
            asm volatile("fmv.x.d %0, f31;"
                         : "=r" (tmp)
                         :);
            break;
        default: //Bad register
            return -5;
    }

    *raw_value = tmp;
    return 0;
}

//MWG
int set_float_trapframe(float_trapframe_t* float_tf) {
    if (!float_tf)
        return -5;

    unsigned long raw_value;
    for (size_t i = 0; i < NUM_FPR; i++) {
        if (get_float_register(i, &raw_value))
            return -5;
        float_tf->fpr[i] = raw_value;
    }

    return 0;
}

//MWG
void dump_word(word_t* w) {
   printk("0x");
   for (size_t i = 0; i < w->size; i++)
       printk("%X", w->bytes[i]);
}

//MWG
int compare_recovery(word_t* recovered_value, word_t* cheat_msg, word_t* recovered_load_value, word_t* cheat_load_value, int demand_load_message_offset) {
    if (!recovered_value || !cheat_msg || !recovered_load_value || !cheat_load_value)
        return -5;

    if (recovered_value->size != cheat_msg->size || recovered_load_value->size != cheat_load_value->size || recovered_value->size > MAX_WORD_SIZE || recovered_load_value->size > MAX_WORD_SIZE)
        return -5;

    int correct = 1;
    int mismatch = 0;
    int overlap = 0;
    int retval = 0;

    int starts_within = (demand_load_message_offset >= 0 && demand_load_message_offset < cheat_msg->size);
    int ends_within = (demand_load_message_offset + cheat_load_value->size > 0 && demand_load_message_offset + cheat_load_value->size <= cheat_msg->size);
    int completely_covers = (demand_load_message_offset < 0 && demand_load_message_offset + cheat_load_value->size > cheat_msg->size);
    if (starts_within || ends_within || completely_covers)
        overlap = 1;

    for (size_t i = 0; i < cheat_msg->size; i++) {
        if (recovered_value->bytes[i] != cheat_msg->bytes[i]) {
            correct = 0;
            break;
        }
    }
    if (correct || !overlap) {
        for (size_t i = 0; i < cheat_load_value->size; i++) {
            if (recovered_load_value->bytes[i] != cheat_load_value->bytes[i]) {
                mismatch = 1;
                break;
            }
        }
    }

    if (correct) {
        if (!mismatch) {
            printk("pk: DUE RECOVERY: CORRECT\n");
            retval = 0;
        } else {
            printk("pk: DUE RECOVERY: MISMATCH BUG\n");
            retval = -5;
        }
    } else {
        if (overlap && mismatch) {
            printk("pk: DUE RECOVERY: MCE\n");
            retval = 0;
        } else if (!overlap && mismatch) {
            printk("pk: DUE RECOVERY: MISMATCH BUG\n");
            retval = -5;
        } else {
            printk("pk: DUE RECOVERY: MCE\n"); //FIXME: partial overlap case, can be either MCE or MISMATCH BUG here.
            retval = 0;
        }
    }

    printk("pk: Correct msg: ");
    dump_word(cheat_msg);
    printk("\n");
    printk("pk: Chosen msg:  ");
    dump_word(recovered_value);
    printk("\n");
    printk("pk: Correct load value: ");
    dump_word(cheat_load_value);
    printk("\n");
    printk("pk: Chosen load value:  ");
    dump_word(recovered_load_value);
    printk("\n");

    return retval;
}
