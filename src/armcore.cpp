/******************************************************************************
 * Copyright (C) 2019 Synopsys, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 ******************************************************************************/

#include "armcore.h"
#include "common.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <utility>
#include <time.h>
#include <fcntl.h>

#ifdef _MSC_VER
#include <intrin.h>
#include <immintrin.h>
#include <xmmintrin.h>
#else
#  pragma GCC diagnostic ignored "-Wformat"
#endif

namespace ocx { namespace arm {

    using std::max;
    using std::move;

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
        }
    }

    struct flush_page_mmuidx_args {
        u64 addr;
        uint16_t idxmap;
    };

    u64 realtime_ms() {
        using namespace std::chrono;
        auto now = high_resolution_clock::now();
        return time_point_cast<milliseconds>(now).time_since_epoch().count();
    }

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

    core::core(env &env, const model* modl) :
        ocx::core(),
        m_uc(),
        m_env(env),
        m_model(modl),
        m_num_insn(0),
        m_start_time_ms(realtime_ms()),
        m_procid(0),
        m_coreid(0),
        m_semihosting(*this),
        m_disassembler(*this) {
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
        ret = uc_setup_dmi(m_uc, this, &helper_dmi, &helper_pgprot);
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
    }

    core::~core() {
        if (m_uc) {
            uc_close(m_uc);
            m_uc = nullptr;
        }
    }

    const char* core::provider() {
        static char buf[256] = {};
        if (strlen(buf) == 0)
            snprintf(buf, sizeof(buf), "qemu/unicorn/yuzu - %s", uc_gitrev());
        return buf;
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

        m_procid = procid;
        m_coreid = coreid;
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

        // pc has already been reset to what reset_pc specifies, copy that
        // address into RVBAR
        uc_reg_read(m_uc, UC_ARM64_REG_PC, &rvbaraddr);
        uc_reg_write(m_uc, UC_ARM64_REG_RVBAR, &rvbaraddr);

        // actually reset cpu, PC gets set to RVBAR, which is why we updated
        // that above; this also resets EL, PSTATE, etc.
        uc_reset_cpu(m_uc);

        // restore (V-)MPIDR values
        set_id(m_procid, m_coreid);
    }

    void core::interrupt(u64 irq, bool set) {
        if (irq >= sizeof(IRQMAP) / sizeof(IRQMAP[0]))
            return;
        uc_err ret = uc_interrupt(m_uc, IRQMAP[irq], set);
        ERROR_ON(ret != UC_ERR_OK, "error dispatching irq (%llu)", irq);
    }

    void core::notified(u64 eventid) {
        static_assert(ARM_TIMER_PHYS == 0, "unexpected ARM_TIMER_PHYS value");
        if (eventid > ARM_TIMER_SEC)
            ERROR("invalid timer index %llu", eventid);
        uc_err ret = uc_update_timer(m_uc, (int)eventid);
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
        ERROR_ON(reg >= num_regs(), "register index %llu out of bounds", reg);
        return max(m_model->registers[reg].width / 8, 1);
    }

    const char* core::reg_name(u64 reg) {
        ERROR_ON(reg >= num_regs(), "register index %llu out of bounds", reg);
        return m_model->registers[reg].name;
    };

    bool core::read_reg(u64 idx, void* buf) {
        ERROR_ON(idx >= num_regs(), "register index %llu out of bounds", idx);

        const reg& r = m_model->registers[idx];
        const u64 size = reg_size(idx);

        if (size > sizeof(u64)) {
            ERROR_ON(r.offset, "cannot handle offsets with vector registers");
            return uc_reg_read(m_uc, r.id, buf) == UC_ERR_OK;
        }

        u64 buffer = 0;
        if (uc_reg_read(m_uc, r.id, &buffer) != UC_ERR_OK)
            return false;

        const u64 mask = gen_mask(r.width);
        buffer = (buffer >> r.offset) & mask;
        memcpy(buf, &buffer, size);

        return true;
    }

    bool core::write_reg(u64 idx, const void *buf) {
        ERROR_ON(idx >= num_regs(), "register index %llu out of bounds", idx);

        const reg& r = m_model->registers[idx];
        const u64 size = reg_size(idx);

        if (size > sizeof(u64)) {
            ERROR_ON(r.offset, "cannot handle offsets with vector registers");
            return uc_reg_write(m_uc, r.id, buf) == UC_ERR_OK;
        }

        u64 oldval = 0ull;
        if (uc_reg_read(m_uc, r.id, &oldval) != UC_ERR_OK)
            return false;

        const u64 mask = gen_mask(r.width);
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
        int rw = iswr ? UC_WP_WRITE : UC_WP_READ;
        uc_err ret = uc_cbwatchpoint_insert(m_uc, addr, size, rw);
        return ret == UC_ERR_OK;
    }

    bool core::remove_watchpoint(u64 addr, u64 size, bool iswr) {
        int rw = iswr ? UC_WP_WRITE : UC_WP_READ;
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

    void core::handle_syscall(int callno, shared_ptr<void> arg) {
        uc_err ret;
        switch (callno) {
        case TLB_FLUSH:
            ret = uc_tlb_flush(m_uc);
            ERROR_ON(ret != UC_ERR_OK, "failed to flush TLB");
            break;

        case TLB_FLUSH_PAGE:
            ret = uc_tlb_flush_page(m_uc, *(u64*)arg.get());
            ERROR_ON(ret != UC_ERR_OK, "failed to flush TLB entry");
            break;

        case TLB_FLUSH_MMUIDX:
            ret = uc_tlb_flush_mmuidx(m_uc, *(uint16_t*)arg.get());
            ERROR_ON(ret != UC_ERR_OK, "failed to flush TLB");
            break;

        case TLB_FLUSH_PAGE_MMUIDX: {
            flush_page_mmuidx_args* tmp = (flush_page_mmuidx_args*)(arg.get());
            ret = uc_tlb_flush_page_mmuidx(m_uc, tmp->addr, tmp->idxmap);
            ERROR_ON(ret != UC_ERR_OK, "failed to flush TLB entry");
            break;
        }
        default:
            ERROR("unknown syscall id (%d)", callno);
            break;
        }
    }

    u64 core::disassemble(u64 addr, char* buf, size_t bufsz) {
        return m_disassembler.disassemble(addr, buf, bufsz);
    }

    void core::invalidate_page_ptrs() {
        uc_err ret = uc_dmi_invalidate(m_uc, 0ull, ~0ull);
        ERROR_ON(ret != UC_ERR_OK, "failed to invalidate all dmi");
    }

    void core::invalidate_page_ptr(u64 pgaddr) {
        uc_err ret = uc_dmi_invalidate(m_uc, pgaddr, pgaddr + PAGE_SIZE - 1);
        ERROR_ON(ret != UC_ERR_OK, "failed to invalidate dmi ptr");
    }

    void core::tb_flush() {
        uc_err ret = uc_tb_flush(m_uc);
        ERROR_ON(ret != UC_ERR_OK, "failed to flush TBs");
    }

    void core::tb_flush_page(u64 start, u64 end) {
        uc_err ret = uc_tb_flush_page(m_uc, start, end);
        ERROR_ON(ret != UC_ERR_OK, "failed to flush TB page rage");
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

    u64 core::get_program_counter() const {
        u64 val = is_aarch64() ? ~0ull : ~0u;
        int reg = is_aarch64() ? (int)UC_ARM64_REG_PC : (int)UC_ARM_REG_PC;
        uc_err r = uc_reg_read(m_uc, reg, &val);
        ERROR_ON(r != UC_ERR_OK, "failed to read program counter");
        return val;
    }

    size_t core::access_mem_phys(u64 addr, u8 *buf, size_t bufsz, bool iswr) {
        transaction tx;
        tx.addr = addr;
        tx.size = bufsz;
        tx.data = buf;
        tx.is_read = !iswr;
        tx.is_debug = true;
        tx.is_user = false;
        tx.is_secure = false;
        tx.is_insn = false;
        tx.is_excl = false;
        tx.is_lock = false;
        tx.is_port = false;

        if (m_env.transport(tx) != RESP_OK)
            return 0;

        return tx.size;
    }

    size_t core::read_mem_virt(u64 addr, void *buf, size_t bufsz) {
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
                size_t page_read = access_mem_phys(phys, bbuf, size, false);
                if (page_read != size)
                    return bytes_read + page_read;
            } catch (...) {
                fprintf(stderr, "error reading memory at %016llx\n", phys);
                return bytes_read;
            }

            addr += size;
            bbuf += size;
            bytes_read += size;
            bytes_remaining-= size;
        }

        return bytes_read;
    }

    size_t core::write_mem_virt(u64 addr, const void* buf, size_t bufsz) {
        uc_err ret;
        u64 phys = 0;
        const size_t pgsz = page_size();
        u8* bbuf = (u8*)buf;

        size_t bytes_written = 0;
        size_t bytes_remaining = bufsz;
        while (bytes_remaining > 0) {
            ret = uc_va2pa(m_uc, addr, &phys);
            if (ret != UC_ERR_OK)
                return bytes_written;

            size_t page_remaining = pgsz - (phys & (pgsz - 1));
            size_t size = std::min(bytes_remaining, page_remaining);

            try {
                 size_t page_written = access_mem_phys(phys, bbuf, size, true);
                 if (page_written != size)
                     return bytes_written + page_written;
             } catch (...) {
                 fprintf(stderr, "error writing memory at %016llx\n", phys);
                 return bytes_written;
             }

             addr += size;
             bbuf += size;
             bytes_written += size;
             bytes_remaining-= size;
         }

         return bytes_written;
    }

#ifdef _MSC_VER
    // MSVC does not support 128bit integral types, and the _udiv128 intrinsic
    // is not what we need, but we link with the mingw libgcc.a lib anyway so we
    // use __udivti3 from there

    extern "C" __m128 __udivti3(__m128* dividend, __m128* divisor);

    inline u64 mult_div_128(u64 mult1, u64 mult2, u64 quot, bool& overflow) {
        __m128 p, q;
        p.m128_u64[0] = _umul128(mult1, mult2, &p.m128_u64[1]);
        q.m128_u64[0] = quot;
        q.m128_u64[1] = 0;
        __m128 r = __udivti3(&p, &q);
        overflow = (bool)r.m128_u64[1];
        return r.m128_u64[0];
    }
#else
    inline u64 mult_div_128(u64 mult1, u64 mult2, u64 quot, bool& overflow) {
        typedef unsigned __int128 u128;
        u128 result = (u128)mult1 * (u128)mult2 / quot;
        overflow = (bool)(u64)(result >> 64);
        return (u64)result;
    }
#endif

    //
    // unicorn helper callbacks
    //

    uint64_t core::helper_time(void* opaque, u64 clock) {
        core* cpu = (core*)opaque;
        u64 ticks;
        bool overflow;
        ticks = mult_div_128(cpu->m_env.get_time_ps(), clock, PS_PER_SEC, overflow);
        ERROR_ON(overflow, "ticks out of bounds");
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

        if (ticks == UINT64_MAX) {
            cpu->m_env.cancel(idx);
            return;
        }

        if (ticks == (u64)INT64_MAX) {
            cpu->m_env.notify(idx, UINT64_MAX);
            return;
        }

        bool overflow;
        u64 time_ps = mult_div_128(ticks, PS_PER_SEC, clock, overflow);
        if (overflow)
            time_ps = UINT64_MAX;
        cpu->m_env.notify(idx, time_ps);
    }

    uc_tx_result_t core::helper_transport(uc_engine* uc, void* opaque,
                                          uc_mmio_tx_t* tx) {
        (void)uc;
        core* cpu = (core*)opaque;

        transaction xt = {
            /*.addr = */        tx->addr,
            /*.size = */        tx->size,
            /*.data = */        (u8*)tx->data,
            /*.is_read = */     tx->is_read,
            /*.is_user = */     tx->is_user,
            /*.is_secure = */   tx->is_secure,
            /*.is_insn = */     false,
            /*.is_excl = */     uc_is_excl(cpu->m_uc),
            /*.is_lock = */     false,
            /*.is_port = */     tx->is_io,
            /*.is_debug = */    uc_is_debug(cpu->m_uc)
        };

        response resp = cpu->m_env.transport(xt);
        if (resp == RESP_NOT_EXCLUSIVE)
            uc_clear_excl(cpu->m_uc);
        return translate_response(resp);
    }

    bool core::helper_dmi(void* opaque, u64 page, unsigned char** dmiptr,
                          int* prot) {
        core* cpu = (core*)opaque;

        u8* r = nullptr;
        u8* w = nullptr;

        if (!prot || !*prot)
            return false;

        if (*prot == -1) { // mmu is off
            *dmiptr = cpu->m_env.get_page_ptr_w(page);
            return *dmiptr != nullptr;
        }

        if (*prot & (UC_PROT_READ | UC_PROT_EXEC)) {
            if (!(r = cpu->m_env.get_page_ptr_r(page)))
                return false;
        }

        if (*prot & UC_PROT_WRITE) {
            if (!(w = cpu->m_env.get_page_ptr_w(page)))
                return false;
        }

        if (w && r && w != r)
            return false;

        *dmiptr = r ? r : w;
        return true;
    }

    void core::helper_pgprot(void* opaque, unsigned char* ptr, uint64_t addr) {
        core* cpu = (core*)opaque;
        cpu->m_env.protect_page(ptr, addr);
    }

    void core::helper_tlb_cluster_flush(void* opaque) {
        core* cpu = (core*)opaque;
        shared_ptr<void> arg(nullptr);
        cpu->m_env.broadcast_syscall(TLB_FLUSH, move(arg), true);
    }

    void core::helper_tlb_cluster_flush_page(void* opaque, u64 addr) {
        core* cpu = (core*)opaque;
        shared_ptr<void> arg(new u64(addr));
        cpu->m_env.broadcast_syscall(TLB_FLUSH_PAGE, move(arg), true);
    }

    void core::helper_tlb_cluster_flush_mmuidx(void* opaque, uint16_t idxmap) {
        core* cpu = (core*)opaque;
        shared_ptr<void> arg(new uint16_t(idxmap));
        cpu->m_env.broadcast_syscall(TLB_FLUSH_MMUIDX, move(arg), true);
    }

    void core::helper_tlb_cluster_flush_page_mmuidx(void* opaque, u64 addr,
                                                    uint16_t idxmap) {
        core* cpu = (core*)opaque;
        shared_ptr<void> arg(new flush_page_mmuidx_args { addr, idxmap });
        cpu->m_env.broadcast_syscall(TLB_FLUSH_PAGE_MMUIDX, move(arg), true);
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
        return cpu->m_semihosting.execute(call);
    }

    const char* core::helper_config(void* opaque, const char* config) {
        core* cpu = (core*)opaque;
        return cpu->m_env.get_param(config);
    }

    } // namespace arm

    //
    // ocx factory methods
    //

    core* create_instance(u64 api_version, env& e, const char* variant) {
        if (api_version != OCX_API_VERSION) {
            INFO("OCX_API_VERSION mismatch: requested %llu - "
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
