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

#include "modeldb.h"

#define INFO(...)                                                             \
    do {                                                                      \
        fprintf(stderr, "%s:%d ", __FILE__, __LINE__);                        \
        fprintf(stderr, __VA_ARGS__);                                         \
        fprintf(stderr, "\n");                                                \
    } while (0)


#define ERROR(...)                                                            \
    do {                                                                      \
        INFO(__VA_ARGS__);                                                    \
        abort();                                                              \
    } while (0)

#define ERROR_ON(cond, ...)                                                   \
    do {                                                                      \
        if (cond) {                                                           \
            ERROR(__VA_ARGS__);                                               \
        }                                                                     \
    } while (0)

namespace ocx { namespace arm {

    using std::max;
    using std::string;
    using std::pair;

    const u64 PS_PER_SEC = 1000000000000ull;

    const u64 PAGE_BITS = 12;
    const u64 PAGE_SIZE = 1ull << PAGE_BITS;

    const u64 ADDR_BITS = 48;
    const u64 ADDR_SIZE = 1ull << ADDR_BITS;

    static const int IRQMAP[] = {
        UC_IRQID_AARCH64_NIRQ, // NIRQ on line 0
        UC_IRQID_AARCH64_FIRQ, // FIRQ on line 1
        UC_IRQID_AARCH64_VIRQ, // VIRQ on line 2
        UC_IRQID_AARCH64_VFIQ, // VFIQ on line 3
    };

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

        virtual void handle_syscall(int callno, void *arg) override;

        virtual u64 disassemble(u64 addr, char* buf, size_t bufsz) override;

        virtual void invalidate_page_ptrs() override;
        virtual void invalidate_page_ptr(u64 pgaddr) override;

    private:
        uc_engine*   m_uc;
        env&         m_env;
        const model* m_model;
        csh          m_cap_aarch64;
        csh          m_cap_aarch32;
        csh          m_cap_thumb;
        u64          m_num_insn;
        u64          m_start_time_ms;

        bool is_aarch64() const;
        bool is_aarch32() const;
        bool is_thumb()   const;

        csh lookup_disassembler() const;
        u64 get_program_counter() const;

        size_t read_mem(u64 addr, void *buf, size_t bufsz);
        string semihosting_read_string(u64 addr, size_t n);

        u64 semihosting_get_reg(unsigned int no);
        u64 semihosting_read_field(int n);
        u64 semihosting(u32 call);

        // unicorn callbacks
        static uint64_t helper_time(void* cpu, u64 clock);
        static void helper_time_irq(void* cpu, int idx, int set);
        static void helper_schedule(void* cpu, int idx, u64 clock, u64 ticks);

        static bool helper_dmi(uc_engine* uc, void* arg, u64 page_addr,
                               unsigned char** dmiptr, int* prot);

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

    core::core(env &env, const model* modl) :
        ocx::core(),
        m_uc(),
        m_env(env),
        m_model(modl),
        m_cap_aarch64(),
        m_cap_aarch32(),
        m_cap_thumb(),
        m_num_insn(0),
        m_start_time_ms(realtime_ms()) {
        uc_err ret = uc_open(m_model->name, this, &helper_config, &m_uc);
        ERROR_ON(ret != UC_ERR_OK, "unicorn error: %s", uc_strerror(ret));

        ret = uc_setup_timer(m_uc, this, &helper_time, &helper_time_irq,
                             &helper_schedule);
        ERROR_ON(ret != UC_ERR_OK, "unicorn error: %s", uc_strerror(ret));

        // setup callback for MMIO
        ret = uc_mem_map_io(m_uc, 0, ADDR_SIZE, &helper_transport, this);
        ERROR_ON(ret != UC_ERR_OK, "cannot map io: %s", uc_strerror(ret));

        // setup callback for PORTIO
        ret = uc_mem_map_portio(m_uc, &helper_transport, this);
        ERROR_ON(ret != UC_ERR_OK, "cannot map ports: %s", uc_strerror(ret));

        // setup callback for DMI
        ret = uc_setup_dmi(m_uc, this, &helper_dmi);
        ERROR_ON(ret != UC_ERR_OK, "dmi failed: %s", uc_strerror(ret));

        // setup cluster callbacks
        ret = uc_register_tlb_cluster(m_uc, this, &helper_tlb_cluster_flush,
                                      &helper_tlb_cluster_flush_page,
                                      &helper_tlb_cluster_flush_mmuidx,
                                      &helper_tlb_cluster_flush_page_mmuidx);
        ERROR_ON(ret != UC_ERR_OK, "cannot setup cluster callbacks: %s",
                      uc_strerror(ret));

        // setup debug callbacks
        uc_cbbreakpoint_setup(m_uc, this, &helper_breakpoint);
        uc_cbwatchpoint_setup(m_uc, this, &helper_watchpoint);

        // setup hint callback
        uc_setup_hint(m_uc, this, &helper_hint);

        // setup semihosting callback
        uc_setup_semihosting(m_uc, this, &helper_semihosting);

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

    core::~core() {
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

    const char* core::provider() {
        return "qemu/unicorn/yuzu - " __DATE__;
    }

    const char* core::arch() {
        return m_model->name;
    }

    const char* core::arch_gdb() {
        return m_model->has_aarch64() ? "aarch64" : "arm";
    }

    const char* core::arch_family() {
        return m_model->arch;
    }

    u64 core::page_size() {
        return PAGE_SIZE;
    }

    void core::set_id(u64 procid, u64 coreid) {
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

    u64 core::step(u64 num_insn) {
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

    void core::stop() {
        uc_emu_stop(m_uc);
    }

    u64 core::insn_count() {
        return uc_instruction_count(m_uc);
    }

    void core::reset() {
        u64 rvbaraddr = ~0ull;
        uc_reg_read(m_uc, UC_ARM64_REG_PC, &rvbaraddr);
        uc_reg_write(m_uc, UC_ARM64_REG_RVBAR, &rvbaraddr);
    }

    void core::interrupt(u64 irq, bool set) {
        if (irq >= sizeof(IRQMAP) / sizeof(IRQMAP[0]))
            return;
        uc_err ret = uc_interrupt(m_uc, IRQMAP[irq], set);
        ERROR_ON(ret != UC_ERR_OK, "error dispatching irq (%lu)", irq);
    }

    void core::notified(u64 eventid) {
        if (eventid < ARM_TIMER_PHYS || eventid > ARM_TIMER_SEC)
            ERROR("invalid timer index %lu", eventid);
        uc_err ret = uc_update_timer(m_uc, eventid);
        ERROR_ON(ret != UC_ERR_OK, "timer update: %s", uc_strerror(ret));
    }

    u64 core::pc_regid() {
        return m_model->has_aarch64() ? 32 : 15;
    }

    u64 core::sp_regid() {
        return m_model->has_aarch64() ? 31 : 13;
    }

    u64 core::num_regs() {
        return m_model->nregs;
    };

    size_t core::reg_size(u64 reg) {
        ERROR_ON(reg >= num_regs(), "register index %lu out of bounds", reg);
        return max(m_model->registers[reg].width / 8, 1);
    }

    const char* core::reg_name(u64 reg) {
        ERROR_ON(reg >= num_regs(), "register index %lu out of bounds", reg);
        return m_model->registers[reg].name;
    };

    bool core::read_reg(u64 idx, void* buf) {
        ERROR_ON(idx >= num_regs(), "register index %lu out of bounds", idx);

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

    bool core::write_reg(u64 idx, const void *buf) {
        ERROR_ON(idx >= num_regs(), "register index %lu out of bounds", idx);

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

    bool core::add_breakpoint(u64 addr) {
        uc_err ret = uc_cbbreakpoint_insert(m_uc, addr);
        return ret == UC_ERR_OK;
    }

    bool core::remove_breakpoint(u64 addr) {
        uc_err ret = uc_cbbreakpoint_remove(m_uc, addr);
        return ret == UC_ERR_OK;
    }

    bool core::add_watchpoint(u64 addr, u64 size, bool iswr) {
        int rw = UC_WP_BEFORE | (iswr ? UC_WP_WRITE : UC_WP_READ);
        uc_err ret = uc_cbwatchpoint_insert(m_uc, addr, size, rw);
        return ret == UC_ERR_OK;
    }

    bool core::remove_watchpoint(u64 addr, u64 size, bool iswr) {
        int rw = UC_WP_BEFORE | (iswr ? UC_WP_WRITE : UC_WP_READ);
        uc_err ret = uc_cbwatchpoint_remove(m_uc, addr, size, rw);
        return ret == UC_ERR_OK;
    }

    bool core::trace_basic_blocks(bool on) {
        uc_trace_basic_block_t func = on ? helper_trace_bb : NULL;
        return uc_setup_basic_block_trace(m_uc, this, func);
    }

    bool core::virt_to_phys(u64 vaddr, u64& paddr) {
        uc_err ret = uc_va2pa(m_uc, vaddr, (uint64_t *)&paddr);
        return ret == UC_ERR_OK;
    }

    void core::handle_syscall(int callno, void *arg) {
        uc_err ret;
        switch (callno) {
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

    u64 core::disassemble(u64 addr, char* buf, size_t bufsz) {
        ERROR_ON(bufsz == 0, "unexpected zero bufsz");

        u32 insn = 0;
        u64 size = is_thumb() ? 2 : 4;

        if (read_mem(addr, &insn, size) != size)
            return 0;

        cs_insn* sym;
        csh disas = lookup_disassembler();
        ERROR_ON(!disas, "no disassembler available");

        if (cs_disasm(disas, (const u8*)&insn, size, 0, 1, &sym)) {
            snprintf(buf, bufsz, "%s %s", sym->mnemonic, sym->op_str);
            u64 len = sym->size;
            cs_free(sym, 1);
            return len;
        }

        // show as data, resize is until next aligned address
        snprintf(buf, bufsz, ".data");
        return ((addr + size) & ~(size - 1)) - addr;
    }

    void core::invalidate_page_ptrs() {
        uc_err ret = uc_dmi_invalidate(m_uc, 0ull, ~0ull);
        ERROR_ON(ret != UC_ERR_OK, "failed to invalidate all dmi");
    }

    void core::invalidate_page_ptr(u64 pgaddr) {
        uc_err ret = uc_dmi_invalidate(m_uc, pgaddr, pgaddr + PAGE_SIZE - 1);
        ERROR_ON(ret != UC_ERR_OK, "failed to invalidate dmi ptr");
    }

    bool core::is_aarch64() const {
        if (!m_model->has_aarch64())
            return false;

        u32 state = 0;
        if (uc_reg_read(m_uc, UC_ARM64_VREG_AA64, &state) != UC_ERR_OK)
            ERROR("failed to read program state");
        return state;
    }

    bool core::is_aarch32() const {
        return !is_aarch64() && !is_thumb();
    }

    bool core::is_thumb() const {
        if (is_aarch64())
            return false;

        u32 state = 0;
        if (uc_reg_read(m_uc, UC_ARM_VREG_THUMB, &state) != UC_ERR_OK)
            ERROR("failed to read program state");
        return state;
    }

    csh core::lookup_disassembler() const {
        if (is_thumb())
            return m_cap_thumb;
        if (is_aarch32())
            return m_cap_aarch32;
        if (is_aarch64())
            return m_cap_aarch64;
        return 0;
    }

    u64 core::get_program_counter() const {
        u64 val = is_aarch64() ? ~0ull : ~0u;
        int reg = is_aarch64() ? (int)UC_ARM64_REG_PC : (int)UC_ARM_REG_PC;
        uc_err r = uc_reg_read(m_uc, reg, &val);
        ERROR_ON(r != UC_ERR_OK, "failed to read program counter");
        return val;
    }

    size_t core::read_mem(u64 addr, void *buf, size_t bufsz) {
        uc_err ret;
        u64 phys = 0;
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
                fprintf(stderr, "error reading memory at %016lx\n", phys);
                return bytes_read;
            }

            addr += size;
            bbuf += size;
            bytes_read += size;
            bytes_remaining-= size;
        }

        return bytes_read;
    }

    string core::semihosting_read_string(u64 addr, size_t n) {
        string result;
        char buffer = ~0;
        while (n-- && buffer != '\0') {
            if (read_mem(addr++, (unsigned char*)&buffer, 1) != 1)
                ERROR("failed to read char at 0x%016lx", addr - 1);
            result += buffer;
        }

        return result;
    }

    u64 core::semihosting_get_reg(unsigned int no) {
        ERROR_ON(no > 1, "unexpected semihost reg read %u", no);
        u64 val = ~0ull;
        no = (is_aarch64() ? (int)UC_ARM64_REG_X0 : (int)UC_ARM_REG_R0) + no;
        uc_err r = uc_reg_read(m_uc, no, &val);
        ERROR_ON(r != UC_ERR_OK, "failed to read reg %u", no);
        return val;
    }

    u64 core::semihosting_read_field(int n) {
        const u64 size = is_aarch64() ? sizeof(u64) : sizeof(u32);
        u64 addr = semihosting_get_reg(1) + n * size;
        u64 field = 0;

        if (read_mem(addr, (unsigned char*)&field, size) != size)
            ERROR("failed to read address 0x%016lx", addr);

        return field;
    }

    u64 core::semihosting(u32 call) {
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
            INFO("arm semihosting: software exit request");
            exit(semihosting_get_reg(1));

        case SHC_EXIT2:
            INFO("arm semihosting: software exit request");
            exit(semihosting_get_reg(1) >> 32);

        case SHC_READC:
            return getchar();

        case SHC_ERRNO:
            return errno;

        case SHC_WRITEC: {
            unsigned char c;
            u64 addr = semihosting_get_reg(1);
            if (read_mem(addr, &c, sizeof(c)) != sizeof(c))
                return ~0ull;
            putchar(c);
            return c;
        }

        case SHC_WRITE0: {
            unsigned char c;
            u64 addr = semihosting_get_reg(1);
            do {
                if (read_mem(addr++, &c, sizeof(c)) != sizeof(c))
                    break;
                if (c != '\0')
                    putchar(c);
            } while (c != '\0');
            return addr;
        }

        case SHC_OPEN: {
            u64 addr = semihosting_read_field(0);
            u64 mode = semihosting_read_field(1);
            u64 size = semihosting_read_field(2);

            string file = semihosting_read_string(addr, size);

            if (file == ":tt")
                return (mode < 4) ? STDIN_FILENO : STDERR_FILENO;
            return open(file.c_str(), mode);
        }

        case SHC_CLOSE: {
            u64 file = semihosting_read_field(0);
            close(file);
            return 0;
        }

        case SHC_WRITE: {
            u64 file = semihosting_read_field(0);
            u64 addr = semihosting_read_field(1);
            u64 size = semihosting_read_field(2);

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
            u64 file = semihosting_read_field(0);
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
            INFO("arm semihosting: unsupported call %u", call);
            break;
        }

        return ~0ull;
    }

    uint64_t core::helper_time(void* opaque, u64 clock) {
        core* cpu = (core*)opaque;
        u128 ticks = (u128)cpu->m_env.get_time_ps() * (u128)clock / PS_PER_SEC;
        ERROR_ON(ticks > ~0ull, "ticks out of bounds");
        return ticks;
    }

    void core::helper_time_irq(void* opaque, int idx, int set) {
        core* cpu = (core*)opaque;
        cpu->m_env.signal(idx, set);
    }

    void core::helper_schedule(void* opaque, int idx, u64 clock, u64 ticks) {
        if (idx < ARM_TIMER_PHYS || idx > ARM_TIMER_SEC)
            ERROR("invalid timer index %d", idx);

        core* cpu = (core*)opaque;

        if (ticks == ~0ull) {
            cpu->m_env.cancel(idx);
            return;
        }

        u128 time_ps = (u128)ticks * (u128)PS_PER_SEC / (u128)clock;
        if (time_ps > UINT64_MAX)
            time_ps = UINT64_MAX;
        cpu->m_env.notify(idx, (u64)time_ps);
    }

    uc_tx_result_t core::helper_transport(uc_engine* uc, void* opaque,
                                          uc_mmio_tx_t* tx) {
        core* cpu = (core*)opaque;

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

    bool core::helper_dmi(uc_engine* uc, void* opaque, u64 page_addr,
                          unsigned char** dmiptr, int* prot) {
        core* cpu = (core*)opaque;

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

    void core::helper_tlb_cluster_flush(void* opaque) {
        core* cpu = (core*)opaque;
        cpu->m_env.broadcast_syscall(TLB_FLUSH, nullptr);
    }

    void core::helper_tlb_cluster_flush_page(void* opaque, u64 addr) {
        core* cpu = (core*)opaque;
        cpu->m_env.broadcast_syscall(TLB_FLUSH_PAGE, &addr);
    }

    void core::helper_tlb_cluster_flush_mmuidx(void* opaque, uint16_t idxmap) {
        core* cpu = (core*)opaque;
        cpu->m_env.broadcast_syscall(TLB_FLUSH_MMUIDX, &idxmap);
    }

    void core::helper_tlb_cluster_flush_page_mmuidx(void* opaque, u64 addr,
                                                    uint16_t idxmap) {
        pair<u64, uint16_t> arg(addr, idxmap);
        core* cpu = (core*)opaque;
        cpu->m_env.broadcast_syscall(TLB_FLUSH_PAGE_MMUIDX, &arg);
    }

    void core::helper_breakpoint(void* opaque, u64 addr) {
        core* cpu = (core*)opaque;
        if (cpu->m_env.handle_breakpoint(addr)) {
            uc_emu_stop(cpu->m_uc);
        }
    }

    void core::helper_watchpoint(void* opaque, u64 addr, u64 size, u64 data,
                                 bool iswr) {
        core* cpu = (core*)opaque;
        if (cpu->m_env.handle_watchpoint(addr, size, data, iswr)) {
            uc_emu_stop(cpu->m_uc);
        }
    }

    void core::helper_trace_bb(void* opaque, u64 pc) {
        core* cpu = (core*)opaque;
        cpu->m_env.handle_begin_basic_block(pc);
    }

    void core::helper_hint(void* opaque, uc_hint_t hint) {
        core* cpu = (core*)opaque;
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

    u64 core::helper_semihosting(void* opaque, u32 call) {
        core* cpu = (core*)opaque;
        return cpu->semihosting(call);
    }

    const char* core::helper_config(void* opaque, const char* config) {
        core* cpu = (core*)opaque;
        return cpu->m_env.get_param(config);
    }

    } // namespace arm

    core* create_instance(u64 api_version, env& e, const char* variant) {
        if (api_version != OCX_API_VERSION) {
            INFO("OCX_API_VERSION mismatch: requested %lu - "
                 "expected %llu", api_version, OCX_API_VERSION);
            return nullptr;
        }

        const arm::model* model = arm::lookup_model(variant);
        if (model == nullptr) {
            INFO("model not '%s' supported", variant);
            return nullptr;
        }

        return new arm::core(e, model);
    }

    void delete_instance(core* c) {
        arm::core* cpu = dynamic_cast<arm::core*>(c);
        ERROR_ON(cpu == nullptr, "calling delete_instance with foreign core");
        delete cpu;
    }

}

