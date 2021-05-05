/******************************************************************************
 * Copyright (C) 2019 Synopsys, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 ******************************************************************************/

#ifndef ARMCORE_H
#define ARMCORE_H

#define OCX_DLL_EXPORT

#include <ocx/ocx.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

#include <string>
#include <vector>
#include <memory>

#include "modeldb.h"

#ifdef _MSC_VER
#  ifdef ERROR
#    undef ERROR
#  endif
#  ifdef min
#    undef min
#  endif
#  ifdef max
#    undef max
#  endif
#endif

namespace ocx { namespace arm {

    using std::string;
    using std::shared_ptr;

    u64 realtime_ms();

    class core : public ocx::core
    {
    public:
        core() = delete;
        core(env &env, const model* modl);
        virtual ~core();

        // ocx core overrides
        const char* provider() override;

        virtual const char* arch() override;
        virtual const char* arch_gdb() override;
        virtual const char* arch_family() override;

        virtual u64 page_size() override;

        virtual void set_id(u64 procid, u64 coreid) override;

        virtual u64 step(u64 num_insn) override;
        virtual void stop() override;
        virtual u64 insn_count() override;

        virtual void reset() override;
        virtual void interrupt(u64 irq, bool set) override;

        virtual void notified(u64 eventid) override;

        virtual u64 pc_regid() override;
        virtual u64 sp_regid() override;
        virtual u64 num_regs() override;

        virtual size_t      reg_size(u64 reg) override;
        virtual const char* reg_name(u64 reg) override;

        virtual bool read_reg(u64 regid, void* buf) override;
        virtual bool write_reg(u64 reg, const void* buf) override;

        virtual bool add_breakpoint(u64 addr) override;
        virtual bool remove_breakpoint(u64 addr) override;

        virtual bool add_watchpoint(u64 addr, u64 size, bool iswr) override;
        virtual bool remove_watchpoint(u64 addr, u64 size, bool iswr) override;

        virtual bool trace_basic_blocks(bool on) override;

        virtual bool virt_to_phys(u64 paddr, u64& vaddr) override;

        virtual void handle_syscall(int callno, shared_ptr<void> arg) override;

        virtual u64 disassemble(u64 addr, char* buf, size_t bufsz) override;

        virtual void invalidate_page_ptrs() override;
        virtual void invalidate_page_ptr(u64 pgaddr) override;

        virtual void tb_flush() override;
        virtual void tb_flush_page(u64 start, u64 end) override;

    private:
        class semihosting {
        public:
            semihosting(core& parent) : m_core(parent) {}
            u64 execute(u32 call);

        private:
            string rd_string(u64 addr, size_t n);
            u64    rd_reg(unsigned int no);
            u64    rd_field(int n);

        private:
            core& m_core;
        };

        class disassembler {
        public:
            disassembler(core& parent);
            ~disassembler();
            u64 disassemble(u64 addr, char* buf, size_t bufsz);
            
        private:
            csh lookup_disassembler() const;

        private:
            core& m_core;
            csh   m_cap_aarch64;
            csh   m_cap_aarch32;
            csh   m_cap_thumb;
        };

    private:
        uc_engine*   m_uc;
        env&         m_env;
        const model* m_model;
        u64          m_num_insn;
        u64          m_start_time_ms;
        u64          m_procid;
        u64          m_coreid;
        semihosting  m_semihosting;
        disassembler m_disassembler;

        bool is_aarch64() const;
        bool is_aarch32() const;
        bool is_thumb()   const;

        u64 get_program_counter() const;

        size_t read_mem_virt(u64 addr, void* buf, size_t bufsz);
        size_t write_mem_virt(u64 addr, const void* buf, size_t bufsz);
        size_t access_mem_phys(u64 addr, u8* buf, size_t bufsz, bool iswr);

        // unicorn callbacks
        static uint64_t helper_time(void* cpu, u64 clock);
        static void helper_time_irq(void* cpu, int idx, int set);
        static void helper_schedule(void* cpu, int idx, u64 clock, u64 ticks);

        static bool helper_dmi(void* arg, u64 addr, unsigned char** dmiptr,
                               int* prot);
        static void helper_pgprot(void* arg, unsigned char* p, uint64_t addr);

        static uc_tx_result_t helper_transport(uc_engine* uc, void* cpu,
                                               uc_mmio_tx_t* tx);

        static void helper_tlb_cluster_flush(void* cpu);
        static void helper_tlb_cluster_flush_page(void* cpu, u64 addr);
        static void helper_tlb_cluster_flush_mmuidx(void* cpu, uint16_t map);
        static void helper_tlb_cluster_flush_page_mmuidx(void* cpu, u64 addr,
                                                         uint16_t map);

        static void helper_breakpoint(void* cpu, u64 addr);
        static void helper_watchpoint(void* cpu, u64 addr, u64 size, u64 data,
                                      bool iswr);

        static void helper_trace_bb(void* cpu, u64 pc);

        static void helper_hint(void* opaque, uc_hint_t hint);
        static u64 helper_semihosting(void* opaque, u32 call);

        static const char* helper_config(void* opaque, const char* config);
    };

}};

#endif