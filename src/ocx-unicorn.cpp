/******************************************************************************
 * Copyright (C) 2019 Synopsys, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 ******************************************************************************/

#include <ocx/ocx.h>

#include <unicorn/arm64.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

#include <algorithm>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <utility>
#include <time.h>
#include <fcntl.h>

#include "common.h"
#include "modeldb.h"

#define PS_PER_SEC 1000000000000ull
#define UNICORN_PAGE_SIZE 4096
#define AARCH64_ADDRESS_RANGE (1ull << 48)

namespace unicorn {

    using namespace ocx;
    using namespace std;

    static u64 gen_mask(u64 width) {
        ERROR_ON(width > 64, "cannot create masks wider than 64bit");
        if (width == 64)
            return ~0ull;
        return (1ull << width) - 1;
    }

    static u64 realtime_ms() {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
    }

    static uc_tx_result_t translate_response(response resp) {
        switch (resp) {
        case RESP_OK:
        case RESP_NOT_EXCLUSIVE:
            return UC_TX_OK;

        case RESP_FAILED:
        case RESP_COMMAND_ERROR:
            return UC_TX_ERROR;

        case RESP_ADDRESS_ERROR:
            return UC_TX_ADDRESS_ERROR;

        default:
            ERROR("unexpected response (%d)", resp);
            return UC_TX_ERROR;
        }
    }

    class core_arm : public core
    {
    private:
        uc_engine*   m_uc;
        env&         m_env;
        const model* m_model;
        csh          m_cap_aarch64;
        csh          m_cap_aarch32;
        csh          m_cap_thumb;
        u64          m_num_insn;
        u64          m_start_time_ms;

        enum semihosting_call {
            SHC_OPEN    = 0x01,
            SHC_CLOSE   = 0x02,
            SHC_WRITEC  = 0x03,
            SHC_WRITE0  = 0x04,
            SHC_WRITE   = 0x05,
            SHC_READ    = 0x06,
            SHC_READC   = 0x07,
            SHC_ISERR   = 0x08,
            SHC_ISTTY   = 0x09,
            SHC_SEEK    = 0x0a,
            SHC_FLEN    = 0x0c,
            SHC_TMPNAM  = 0x0d,
            SHC_REMOVE  = 0x0e,
            SHC_RENAME  = 0x0f,
            SHC_CLOCK   = 0x10,
            SHC_TIME    = 0x11,
            SHC_SYSTEM  = 0x12,
            SHC_ERRNO   = 0x13,
            SHC_CMDLINE = 0x15,
            SHC_HEAP    = 0x16,
            SHC_EXIT    = 0x18,
            SHC_EXIT2   = 0x20,
            SHC_ELAPSED = 0x30,
            SHC_TICKFQ  = 0x31,
        };

        enum syscallno {
            TLB_FLUSH               = 0x01,
            TLB_FLUSH_PAGE          = 0x02,
            TLB_FLUSH_MMUIDX        = 0x03,
            TLB_FLUSH_PAGE_MMUIDX   = 0x04,
        };

        enum arm_generic_timer_type {
            ARM_TIMER_PHYS = 0,
            ARM_TIMER_VIRT = 1,
            ARM_TIMER_HYP  = 2,
            ARM_TIMER_SEC  = 3,
            ARM_TIMER_NUM  = 4,
        };

        bool is_aarch64() const;
        bool is_aarch32() const;
        bool is_thumb()   const;

    public:
        core_arm(env &env, const model* modl);
        ~core_arm();

        struct register_info;

        // ocx overrides
        const char* provider() override;

        virtual const char* arch() override;
        virtual const char* arch_gdb() override;
        virtual const char* arch_family() override;

        u64 step(u64 num_insn) override;
        void stop() override;
        u64 insn_count() override;

        void reset() override;
        void interrupt(u64 irq, bool set) override;

        void notified(u64 eventid) override;

        u64 page_size() override;
        bool virt_to_phys(u64 paddr, u64& vaddr) override;

        virtual void set_id(u64 procid, u64 coreid) override;

        u64 pc_regid() override;
        u64 sp_regid() override;
        u64 num_regs() override;

        size_t      reg_size(u64 reg) override;
        const char* reg_name(u64 reg) override;

        bool read_reg(u64 regid, void *buf) override;
        bool write_reg(u64 reg, const void *buf) override;

        bool add_breakpoint(u64 addr) override;
        bool remove_breakpoint(u64 addr) override;

        bool add_watchpoint(u64 addr, u64 size, bool iswr) override;
        bool remove_watchpoint(u64 addr, u64 size, bool iswr) override;

        bool trace_basic_blocks(bool on) override;

        void handle_syscall(int callno, void *arg) override;

        u64 disassemble(const void* src, size_t srcsz,
                        char* buf, size_t bufsz) override;

        void invalidate_page_ptrs() override;
        void invalidate_page_ptr(u64 page_addr) override;

    private:
        u64 get_program_counter() const;
        u64 semihost_get_reg(unsigned int no);
        u64 semihosting(u32 call);
        u64 semihost_read_field(int n);
        string semihost_read_string(u64 addr, size_t n);

        size_t read_mem(u64 addr, void *buf, size_t bufsz);

        // unicorn callbacks
        static uint64_t timer_timefunc(void* opaque, uint64_t clock);
        static void timer_irqfunc(void* opaque, int idx, int set);
        static void timer_schedfunc(void* opaque, int idx, uint64_t clock,
                                    uint64_t ticks);
        static bool dmifunc(uc_engine* uc, void* arg, uint64_t page_addr,
                            unsigned char** dmiptr, int* prot);

        static uc_tx_result_t txfunc(uc_engine* uc, void* arg, uc_mmio_tx_t* tx);

        static void tlb_cluster_flush(void* opaque);
        static void tlb_cluster_flush_page(void* opaque, uint64_t addr);
        static void tlb_cluster_flush_mmuidx(void* opaque, uint16_t idxmap);
        static void tlb_cluster_flush_page_mmuidx(void* opaque, uint64_t addr,
                                                  uint16_t idxmap);

        static void breakpoint_hit_func(void* opaque, uint64_t addr);
        static void watchpoint_hit_func(void* opaque, uint64_t addr, uint64_t size,
                                        uint64_t data, bool iswr);

        static void hint_func(void* opaque, uc_hint_t hint);
        static uint64_t do_semihosting(void* opaque, uint32_t call);

        static void trace_basic_block_func(void* opaque, uint64_t pc);
        static const char* get_config_func(void* opaque, const char* config);
    };

    bool core_arm::is_aarch64() const {
        if (!m_model->has_aarch64())
            return false;

        u32 state = 0;
        if (uc_reg_read(m_uc, UC_ARM64_VREG_AA64, &state) != UC_ERR_OK)
            ERROR("failed to read program state");
        return state;
    }

    bool core_arm::is_aarch32() const {
        return !is_aarch64();
    }

    bool core_arm::is_thumb() const {
        if (is_aarch64())
            return false;

        u32 state = 0;
        if (uc_reg_read(m_uc, UC_ARM_VREG_THUMB, &state) != UC_ERR_OK)
            ERROR("failed to read program state");
        return state;
    }

    core_arm::core_arm(env &env, const model* modl) :
        core(),
        m_uc(),
        m_env(env),
        m_model(modl),
        m_cap_aarch64(),
        m_cap_aarch32(),
        m_cap_thumb(),
        m_num_insn(0),
        m_start_time_ms(realtime_ms()) {
        uc_err ret = uc_open(m_model->name, this, &get_config_func, &m_uc);
        ERROR_ON(ret != UC_ERR_OK, "unicorn error: %s", uc_strerror(ret));

        ret = uc_setup_timer(m_uc, this, &timer_timefunc, &timer_irqfunc,
                             &timer_schedfunc);
        ERROR_ON(ret != UC_ERR_OK, "unicorn error: %s", uc_strerror(ret));

        // setup callback for MMIO
        ret = uc_mem_map_io(m_uc, 0, AARCH64_ADDRESS_RANGE, &txfunc, this);
        ERROR_ON(ret != UC_ERR_OK, "cannot map io: %s", uc_strerror(ret));

        // setup callback for PORTIO
        ret = uc_mem_map_portio(m_uc, &txfunc, this);
        ERROR_ON(ret != UC_ERR_OK, "cannot map ports: %s", uc_strerror(ret));

        // setup callback for DMI
        ret = uc_setup_dmi(m_uc, this, &dmifunc);
        ERROR_ON(ret != UC_ERR_OK, "dmi failed: %s", uc_strerror(ret));

        // setup cluster callbacks
        ret = uc_register_tlb_cluster(m_uc, this, &tlb_cluster_flush,
                                      &tlb_cluster_flush_page,
                                      &tlb_cluster_flush_mmuidx,
                                      &tlb_cluster_flush_page_mmuidx);
        ERROR_ON(ret != UC_ERR_OK, "cannot setup cluster callbacks: %s",
                      uc_strerror(ret));

        // setup debug callbacks
        uc_cbbreakpoint_setup(m_uc, this, &breakpoint_hit_func);
        uc_cbwatchpoint_setup(m_uc, this, &watchpoint_hit_func);

        // setup hint callback
        uc_setup_hint(m_uc, this, &hint_func);

        // setup semihosting callback
        uc_setup_semihosting(m_uc, this, &do_semihosting);

        // setup disassemblers
        if (modl->has_aarch64()) {
            cs_arch arch = CS_ARCH_ARM64;
            cs_mode mode = CS_MODE_LITTLE_ENDIAN;
            cs_err ret = cs_open(arch, mode, &m_cap_aarch64);
            ERROR_ON(ret != CS_ERR_OK, "error starting capstone disassembler");
        }

        if (modl->has_aarch32()) {
            cs_arch arch = CS_ARCH_ARM;
            cs_mode mode = CS_MODE_LITTLE_ENDIAN;
            cs_err ret = cs_open(arch, mode, &m_cap_aarch32);
            ERROR_ON(ret != CS_ERR_OK, "error starting capstone disassembler");

            arch = CS_ARCH_ARM;
            mode = CS_MODE_THUMB;
            ret = cs_open(arch, mode, &m_cap_thumb);
            ERROR_ON(ret != CS_ERR_OK, "error starting capstone disassembler");
        }
    }

    core_arm::~core_arm() {
        if (m_uc) {
            uc_close(m_uc);
            m_uc = nullptr;
        }

        if (m_cap_aarch64)
            cs_close(&m_cap_aarch64);

        if (m_cap_aarch32)
            cs_close(&m_cap_aarch32);

        if (m_cap_thumb)
            cs_close(&m_cap_thumb);
    }

    const char* core_arm::provider() {
        return "qemu/unicorn/yuzu - " __DATE__;
    }

    const char* core_arm::arch() {
        return m_model->name;
    }

    const char* core_arm::arch_gdb() {
        return m_model->has_aarch64() ? "aarch64" : "arm";
    }

    const char* core_arm::arch_family() {
        return m_model->arch;
    }

    u64 core_arm::get_program_counter() const {
        u64 val = is_aarch64() ? ~0ull : ~0u;
        int reg = is_aarch64() ? (int)UC_ARM64_REG_PC : (int)UC_ARM_REG_PC;
        uc_err r = uc_reg_read(m_uc, reg, &val);
        ERROR_ON(r != UC_ERR_OK, "failed to read program counter");
        return val;
    }

    u64 core_arm::semihost_get_reg(unsigned int no) {
        ERROR_ON(no > 1, "unexpected semihost reg read %u", no);
        u64 val = ~0ull;
        no = (is_aarch64() ? (int)UC_ARM64_REG_X0 : (int)UC_ARM_REG_R0) + no;
        uc_err r = uc_reg_read(m_uc, no, &val);
        ERROR_ON(r != UC_ERR_OK, "failed to read reg %u", no);
        return val;
    }

    void core_arm::handle_syscall(int callno, void *arg) {
        uc_err ret;
        switch(callno) {
        case TLB_FLUSH:
            ret = uc_tlb_flush(m_uc);
            ERROR_ON(ret != UC_ERR_OK, "failed to flush TLB");
            break;
        case TLB_FLUSH_PAGE:
            ret = uc_tlb_flush_page(m_uc, *(uint64_t*)arg);
            ERROR_ON(ret != UC_ERR_OK, "failed to flush TLB entry");
            break;
        case TLB_FLUSH_MMUIDX:
            ret = uc_tlb_flush_mmuidx(m_uc, *(uint16_t*)arg);
            ERROR_ON(ret != UC_ERR_OK, "failed to flush TLB");
            break;
        case TLB_FLUSH_PAGE_MMUIDX: {
            pair<u64, uint16_t> args(*(pair<u64, uint16_t>*)arg);
            ret = uc_tlb_flush_page_mmuidx(m_uc, args.first, args.second);
            ERROR_ON(ret != UC_ERR_OK, "failed to flush TLB entry");
            break;
        }
        default:
            ERROR("unknown syscall id (%d)", callno);
            break;
        }
    }

    u64 core_arm::step(u64 num_insn) {
        u64 pc = get_program_counter();

        if (is_thumb())
            pc |= 1;

        uc_err ret = uc_emu_start(m_uc, pc, ~0ull, 0, num_insn);

        switch (ret) {
        case UC_ERR_OK:
        case UC_ERR_YIELD:
        case UC_ERR_BREAKPOINT: // for single stepping
            break;

            break;

        case UC_ERR_WATCHPOINT:
            ERROR("unexpected return value (%d)", ret);
            break;

        default:
            ERROR("unicorn error: %s", uc_strerror(ret));
        }

        u64 executed = uc_instruction_count(m_uc);
        m_num_insn += executed;
        return executed;
    }

    void core_arm::stop() {
        uc_emu_stop(m_uc);
    }

    u64 core_arm::insn_count() {
        return uc_instruction_count(m_uc);
    }

    void core_arm::reset() {
        u64 rvbaraddr = ~0ull;
        uc_reg_read(m_uc, UC_ARM64_REG_PC, &rvbaraddr);
        uc_reg_write(m_uc, UC_ARM64_REG_RVBAR, &rvbaraddr);
    }

    static const int irqmap[] = {
        UC_IRQID_AARCH64_NIRQ, // NIRQ on line 0
        UC_IRQID_AARCH64_FIRQ, // FIRQ on line 1
        UC_IRQID_AARCH64_VIRQ, // VIRQ on line 2
        UC_IRQID_AARCH64_VFIQ, // VFIQ on line 3
    };

    void core_arm::interrupt(u64 irq, bool set) {
        if (irq >= sizeof(irqmap) / sizeof(irqmap[0]))
            return;
        uc_err ret = uc_interrupt(m_uc, irqmap[irq], set);
        ERROR_ON(ret != UC_ERR_OK, "error dispatching irq (%llu)", irq);
    }

    void core_arm::notified(u64 eventid) {
        if (eventid < ARM_TIMER_PHYS || eventid > ARM_TIMER_SEC)
            ERROR("invalid timer index %llu", eventid);
        uc_err ret = uc_update_timer(m_uc, eventid);
        ERROR_ON(ret != UC_ERR_OK, "timer update: %s", uc_strerror(ret));
    }

    u64 core_arm::page_size() {
        return UNICORN_PAGE_SIZE;
    }

    bool core_arm::virt_to_phys(u64 vaddr, u64& paddr) {
        uc_err ret = uc_va2pa(m_uc, vaddr, (uint64_t *)&paddr);
        return ret == UC_ERR_OK;
    }

    void core_arm::invalidate_page_ptr(u64 page_addr) {
        uc_err ret = uc_dmi_invalidate(m_uc, page_addr, page_addr + UNICORN_PAGE_SIZE - 1);
        ERROR_ON(ret != UC_ERR_OK, "failed to invalidate dmi ptr");
    }

    void core_arm::invalidate_page_ptrs() {
        uc_err ret = uc_dmi_invalidate(m_uc, 0ull, ~0ull);
        ERROR_ON(ret != UC_ERR_OK, "failed to invalidate all dmi");
    }

    void core_arm::set_id(u64 procid, u64 coreid) {
        uc_err ret;

        if (m_model->has_aarch32()) {
            u32 id = ((procid & 0x0f) << 8) | (coreid & 0x0f);
            ret = uc_reg_write(m_uc, UC_ARM_REG_MPIDR, &id);
            ERROR_ON(ret != UC_ERR_OK, "error setting aarch32 core id");
        }

        if (m_model->has_aarch64()) {
            u64 id = ((procid & 0xff) << 8) | (coreid & 0xff);
            ret = uc_reg_write(m_uc, UC_ARM64_REG_MPIDR, &id);
            ERROR_ON(ret != UC_ERR_OK, "error setting aarch64 core id");
            ret = uc_reg_write(m_uc, UC_ARM64_REG_VMPIDR, &id);
            ERROR_ON(ret != UC_ERR_OK, "error setting aarch64 vcore id");
        }
    }

    u64 core_arm::num_regs() {
        return m_model->nregs;
    };

    bool core_arm::read_reg(u64 idx, void* buf) {
        ERROR_ON(idx >= num_regs(), "register index %llu out of bounds", idx);

        const reg& r = m_model->registers[idx];
        const u64 mask = gen_mask(r.width);
        const u64 size = reg_size(idx);

        u64 buffer = 0;
        if (uc_reg_read(m_uc, r.id, &buffer) != UC_ERR_OK)
            return false;

        buffer = (buffer >> r.offset) & mask;
        memcpy(buf, &buffer, size);

        return true;
    }

    bool core_arm::write_reg(u64 idx, const void *buf) {
        ERROR_ON(idx >= num_regs(), "register index %llu out of bounds", idx);

        const reg& r = m_model->registers[idx];
        const u64 mask = gen_mask(r.width);
        const u64 size = reg_size(idx);

        u64 oldval = 0ull;
        if (uc_reg_read(m_uc, r.id, &oldval) != UC_ERR_OK)
            return false;

        u64 newval = 0ull;
        memcpy(&newval, buf, size);
        newval  = (newval & mask) << r.offset;
        newval |= oldval & ~(mask << r.offset);

        if (uc_reg_write(m_uc, r.id, &newval) != UC_ERR_OK)
            return false;

        return true;
    }

    u64 core_arm::pc_regid() {
        return m_model->has_aarch64() ? 32 : 15;
    }

    u64 core_arm::sp_regid() {
        return m_model->has_aarch64() ? 31 : 13;
    }

    size_t core_arm::reg_size(u64 reg) {
        ERROR_ON(reg >= num_regs(), "register index %llu out of bounds", reg);
        return max(m_model->registers[reg].width / 8, 1);
    }

    const char* core_arm::reg_name(u64 reg) {
        ERROR_ON(reg >= num_regs(), "register index %llu out of bounds", reg);
        return m_model->registers[reg].name;
    };

    bool core_arm::add_breakpoint(u64 addr) {
        uc_err ret = uc_cbbreakpoint_insert(m_uc, addr);
        return ret == UC_ERR_OK;
    }

    bool core_arm::remove_breakpoint(u64 addr) {
        uc_err ret = uc_cbbreakpoint_remove(m_uc, addr);
        return ret == UC_ERR_OK;
    }

    bool core_arm::add_watchpoint(u64 addr, u64 size, bool iswr) {
        int rw = UC_WP_BEFORE | (iswr ? UC_WP_WRITE : UC_WP_READ);
        uc_err ret = uc_cbwatchpoint_insert(m_uc, addr, size, (int)rw);
        return ret == UC_ERR_OK;
    }

    bool core_arm::remove_watchpoint(u64 addr, u64 size, bool iswr) {
        int rw = UC_WP_BEFORE | (iswr ? UC_WP_WRITE : UC_WP_READ);
        uc_err ret = uc_cbwatchpoint_remove(m_uc, addr, size, rw);
        return ret == UC_ERR_OK;
    }

    bool core_arm::trace_basic_blocks(bool on) {
        uc_trace_basic_block_t func = on ? trace_basic_block_func : NULL;
        return uc_setup_basic_block_trace(m_uc, this, func);
    }

    static u64 disas_helper(csh handle, u32 insn, char* buf, size_t sz) {
        cs_insn* sym;
        if (cs_disasm(handle, (const u8 *)&insn, 4, 0, 1, &sym) == 0)
            return 0;

        snprintf(buf, sz, "%s %s", sym->mnemonic, sym->op_str);
        u64 len = sym->size;
        cs_free(sym, 1);
        return len;
    }

    u64 core_arm::disassemble(const void* src, size_t srcsz, char* buf,
                              size_t bufsz) {
        ERROR_ON(srcsz == 0, "unexpected zero srcsz");
        ERROR_ON(bufsz == 0, "unexpected zero bufsz");

        const u32* pinsn = (const u32*)src;
        std::vector<csh> disassemblers;

        if (is_aarch64()) {
            disassemblers.push_back(m_cap_aarch64);
            if (m_model->has_aarch32()) {
                disassemblers.push_back(m_cap_aarch32);
                disassemblers.push_back(m_cap_thumb);
            }
        } else if (is_thumb()) {
            disassemblers.push_back(m_cap_thumb);
            disassemblers.push_back(m_cap_aarch32);
            if (m_model->has_aarch64())
                disassemblers.push_back(m_cap_aarch64);
        } else {
            disassemblers.push_back(m_cap_aarch32);
            disassemblers.push_back(m_cap_thumb);
            if (m_model->has_aarch64())
                disassemblers.push_back(m_cap_aarch64);
        }

        for (auto dis : disassemblers) {
            u64 len = disas_helper(dis, *pinsn, buf, bufsz);
            if (len > 0)
                return len;
        }

        return 0;
    }

    size_t core_arm::read_mem(u64 addr, void *buf, size_t bufsz) {
        uc_err ret;
        uint64_t phys = 0;
        const size_t pgsz = page_size();
        u8* bbuf = (u8*)buf;

        size_t bytes_read = 0;
        size_t bytes_remaining = bufsz;

        while (bytes_remaining > 0) {
            ret = uc_va2pa(m_uc, addr, &phys);
            if (ret != UC_ERR_OK)
                return bytes_read;

            size_t page_remaining = pgsz - (phys & (pgsz - 1));
            size_t size = std::min(bytes_remaining, page_remaining);

            try {
                ret = uc_mem_read(m_uc, phys, bbuf, size);
                if (ret != UC_ERR_OK)
                    return bytes_read;
            } catch (...) {
                fprintf(stderr, "error reading memory at %016llx\n", (u64)phys);
                return bytes_read;
            }

            addr += size;
            bbuf += size;
            bytes_read += size;
            bytes_remaining-= size;
        }

        return bytes_read;
    }

    /* unicorn callback functions */

    uint64_t core_arm::timer_timefunc(void* opaque, uint64_t clock) {
        core_arm* cpu = (core_arm*)opaque;
        u128 ticks = (u128)cpu->m_env.get_time_ps() * (u128)clock / PS_PER_SEC;
        ERROR_ON(ticks > ~0ull, "ticks out of bounds");
        return ticks;
    }

    void core_arm::timer_irqfunc(void* opaque, int idx, int set) {
        core_arm* cpu = (core_arm*)opaque;
        cpu->m_env.signal(idx, set);
    }

    void core_arm::timer_schedfunc(void* opaque, int idx, uint64_t clock,
                                   uint64_t ticks) {
        if (idx < ARM_TIMER_PHYS || idx > ARM_TIMER_SEC)
            ERROR("invalid timer index %d", idx);

        core_arm* cpu = (core_arm*)opaque;

        if (ticks == ~0ull) {
            cpu->m_env.cancel(idx);
            return;
        }

        u128 time_ps = (u128)ticks * (u128)PS_PER_SEC / (u128)clock;
        if (time_ps > UINT64_MAX)
            time_ps = UINT64_MAX;
        cpu->m_env.notify(idx, (u64)time_ps);
    }

    uc_tx_result_t core_arm::txfunc(uc_engine* uc, void* p, uc_mmio_tx_t* tx) {
        core_arm* cpu = (core_arm*)p;

        transaction xt = {
            .addr = tx->addr,
            .size = tx->size,
            .data = (u8*)tx->data,
            .is_read = tx->is_read,
            .is_user = tx->is_user,
            .is_secure = tx->is_secure,
            .is_insn = false,
            .is_excl = uc_is_excl(cpu->m_uc),
            .is_lock = false,
            .is_port = tx->is_io,
            .is_debug = uc_is_debug(cpu->m_uc)
        };

        response resp = cpu->m_env.transport(xt);
        if (resp == RESP_NOT_EXCLUSIVE)
            uc_clear_excl(cpu->m_uc);
        return translate_response(resp);
    }

    bool core_arm::dmifunc(uc_engine* uc, void* arg, uint64_t page_addr,
                        unsigned char** dmiptr, int* prot) {
        core_arm* cpu = (core_arm*)arg;

        u8 *read = cpu->m_env.get_page_ptr_r(page_addr);
        if (!read)
            return false;

        *prot = UC_PROT_READ | UC_PROT_EXEC;
        u8 *write = cpu->m_env.get_page_ptr_w(page_addr);

        if (read == write)
            *prot |= UC_PROT_WRITE;

        *dmiptr = read;
        return true;
    }

    void core_arm::tlb_cluster_flush(void* opaque) {
        core_arm* cpu = (core_arm*)opaque;
        cpu->m_env.broadcast_syscall(TLB_FLUSH, nullptr);
    }

    void core_arm::tlb_cluster_flush_page(void* opaque, uint64_t addr) {
        core_arm* cpu = (core_arm*)opaque;
        cpu->m_env.broadcast_syscall(TLB_FLUSH_PAGE, &addr);
    }

    void core_arm::tlb_cluster_flush_mmuidx(void* opaque, uint16_t idxmap) {
        core_arm* cpu = (core_arm*)opaque;
        cpu->m_env.broadcast_syscall(TLB_FLUSH_MMUIDX, &idxmap);
    }

    void core_arm::tlb_cluster_flush_page_mmuidx(void* opaque, uint64_t addr,
                                              uint16_t idxmap) {
        pair<u64, uint16_t> arg(addr, idxmap);
        core_arm* cpu = (core_arm*)opaque;
        cpu->m_env.broadcast_syscall(TLB_FLUSH_PAGE_MMUIDX, &arg);
    }

    void core_arm::breakpoint_hit_func(void* opaque, uint64_t addr) {
        core_arm* cpu = (core_arm*)opaque;
        if (cpu->m_env.handle_breakpoint(addr)) {
            uc_emu_stop(cpu->m_uc);
        }
    }

    void core_arm::watchpoint_hit_func(void* opaque, uint64_t addr,
                                              uint64_t size, uint64_t data,
                                              bool iswr) {
        core_arm* cpu = (core_arm*)opaque;
        if (cpu->m_env.handle_watchpoint(addr, size, data, iswr)) {
            uc_emu_stop(cpu->m_uc);
        }
    }

    void core_arm::hint_func(void* opaque, uc_hint_t hint) {
        core_arm* cpu = (core_arm*)opaque;
        env &e = cpu->m_env;

        switch (hint) {
        case UC_HINT_YIELD:
            e.hint(HINT_YIELD);
            uc_emu_stop(cpu->m_uc);
            break;

        case UC_HINT_WFE:
            e.hint(HINT_WFE);
            break;

        case UC_HINT_WFI:
            e.hint(HINT_WFI);
            break;

        case UC_HINT_SEV:
            e.hint(HINT_SEV);
            break;

        case UC_HINT_SEVL:
            e.hint(HINT_SEVL);
            break;

        case UC_HINT_NOP:
        case UC_HINT_HINT:
            // ignored
            break;

        default:
            ERROR("invalid processor hint (%d)", hint);
        }
    }

    u64 core_arm::semihost_read_field(int n) {
        const u64 size = is_aarch64() ? sizeof(u64) : sizeof(u32);
        u64 addr = semihost_get_reg(1) + n * size;
        u64 field = 0;

        if (read_mem(addr, (unsigned char*)&field, size) != size)
            ERROR("failed to read address 0x%016llx", addr);

        return field;
    }

    string core_arm::semihost_read_string(u64 addr, size_t n) {
        string result;
        char buffer = ~0;
        while (n-- && buffer != '\0') {
            if (read_mem(addr++, (unsigned char*)&buffer, 1) != 1)
                ERROR("failed to read char at 0x%016llx", addr - 1);
            result += buffer;
        }

        return result;
    }

    uint64_t core_arm::do_semihosting(void* opaque, uint32_t call) {
        core_arm *cpu = (core_arm *)opaque;
        return cpu->semihosting(call);
    }

    u64 core_arm::semihosting(u32 call) {
        switch (call) {
        case SHC_CLOCK:
            return (realtime_ms() - m_start_time_ms) / 10;

        case SHC_TIME:
            return time(NULL);

        case SHC_ELAPSED:
            return m_num_insn + uc_instruction_count(m_uc);

        case SHC_TICKFQ:
            return CLOCKS_PER_SEC;

        case SHC_EXIT:
            INFO("xcore_unicore: software exit request");
            exit(semihost_get_reg(1));

        case SHC_EXIT2:
            INFO("xcore_unicorn: software exit request");
            exit(semihost_get_reg(1) >> 32);

        case SHC_READC:
            return getchar();

        case SHC_ERRNO:
            return errno;

        case SHC_WRITEC: {
            unsigned char c;
            u64 addr = semihost_get_reg(1);
            if (read_mem(addr, &c, sizeof(c)) != sizeof(c))
                return ~0ull;
            putchar(c);
            return c;
        }

        case SHC_WRITE0: {
            unsigned char c;
            u64 addr = semihost_get_reg(1);
            do {
                if (read_mem(addr++, &c, sizeof(c)) != sizeof(c))
                    break;
                if (c != '\0')
                    putchar(c);
            } while (c != '\0');
            return addr;
        }

        case SHC_OPEN: {
            u64 addr = semihost_read_field(0);
            u64 mode = semihost_read_field(1);
            u64 size = semihost_read_field(2);

            string file = semihost_read_string(addr, size);

            if (file == ":tt")
                return (mode < 4) ? STDIN_FILENO : STDERR_FILENO;
            return open(file.c_str(), mode);
        }

        case SHC_CLOSE: {
            u64 file = semihost_read_field(0);
            close(file);
            return 0;
        }

        case SHC_WRITE: {
            u64 file = semihost_read_field(0);
            u64 addr = semihost_read_field(1);
            u64 size = semihost_read_field(2);

            while (size > 0) {
                unsigned char buffer = 0;
                if (read_mem(addr, &buffer, 1) != 1)
                    return size;

                if (write(file, &buffer, 1) != 1)
                    return size;

                size--;
                addr++;
            }

            return 0;
        }

        case SHC_ISTTY: {
            u64 file = semihost_read_field(0);
            return isatty(file);
        }

        case SHC_READ:
        case SHC_SEEK:
        case SHC_FLEN:
        case SHC_TMPNAM:
        case SHC_REMOVE:
        case SHC_RENAME:
        case SHC_SYSTEM:
        case SHC_ISERR:
        case SHC_CMDLINE:
        case SHC_HEAP:

        default:
            INFO("unsupported semihosting call %u", call);
            break;
        }

        return ~0ull;
    }

    void core_arm::trace_basic_block_func(void* opaque, uint64_t pc) {
        core_arm* cpu = (core_arm*)opaque;
        cpu->m_env.handle_begin_basic_block(pc);
    }

    const char* core_arm::get_config_func(void* opaque, const char* config) {
        core_arm* cpu = (core_arm*)opaque;
        return cpu->m_env.get_param(config);
    }

}

namespace ocx {

    core* create_instance(u64 api_version, env& e, const char* variant) {
        if (api_version != OCX_API_VERSION) {
            INFO("OCX_API_VERSION mismatch: requested %llu - "
                 "expected %llu", api_version, OCX_API_VERSION);
            return nullptr;
        }

        const unicorn::model* model = unicorn::lookup_model(variant);
        if (model == nullptr) {
            INFO("model not '%s' supported", variant);
            return nullptr;
        }

        return new unicorn::core_arm(e, model);
    }

    void delete_instance(core* c) {
        unicorn::core_arm *p = dynamic_cast<unicorn::core_arm*>(c);
        ERROR_ON(p == nullptr, "calling delete_instance with foreign core");
        delete p;
    }
}

