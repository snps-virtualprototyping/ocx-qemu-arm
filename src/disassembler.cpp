/******************************************************************************
 * Copyright (C) 2019 Synopsys, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 ******************************************************************************/

#include "armcore.h"
#include "common.h"

namespace ocx { namespace arm {

    core::disassembler::disassembler(core& parent)
    : m_core(parent),
      m_cap_aarch64(),
      m_cap_aarch32(),
      m_cap_thumb()
    {
        if (m_core.m_model->has_aarch64()) {
            cs_arch arch = CS_ARCH_ARM64;
            cs_mode mode = CS_MODE_LITTLE_ENDIAN;
            cs_err cs_ret = cs_open(arch, mode, &m_cap_aarch64);
            ERROR_ON(cs_ret != CS_ERR_OK, "error starting capstone disassembler");
        }

        if (m_core.m_model->has_aarch32()) {
            cs_arch arch = CS_ARCH_ARM;
            cs_mode mode = CS_MODE_LITTLE_ENDIAN;
            cs_err cs_ret = cs_open(arch, mode, &m_cap_aarch32);
            ERROR_ON(cs_ret != CS_ERR_OK, "error starting capstone disassembler");

            arch = CS_ARCH_ARM;
            mode = CS_MODE_THUMB;
            cs_ret = cs_open(arch, mode, &m_cap_thumb);
            ERROR_ON(cs_ret != CS_ERR_OK, "error starting capstone disassembler");
        }
    }

    csh core::disassembler::lookup_disassembler() const {
        if (m_core.is_thumb())
            return m_cap_thumb;
        if (m_core.is_aarch32())
            return m_cap_aarch32;
        if (m_core.is_aarch64())
            return m_cap_aarch64;
        return 0;
    }

    u64 core::disassembler::disassemble(u64 addr, char* buf, size_t bufsz) {
        ERROR_ON(bufsz == 0, "unexpected zero bufsz");

        u32 insn = 0;
        u64 size = m_core.read_mem_virt(addr, &insn, 4);

        if (!m_core.is_thumb() && size != 4)
            return 0;

        if (m_core.is_thumb() && size != 2 && size != 4)
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

    core::disassembler::~disassembler() {
        if (m_cap_aarch64)
            cs_close(&m_cap_aarch64);

        if (m_cap_aarch32)
            cs_close(&m_cap_aarch32);

        if (m_cap_thumb)
            cs_close(&m_cap_thumb);
    }

}}
