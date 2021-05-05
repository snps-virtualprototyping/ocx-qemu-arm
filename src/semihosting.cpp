/******************************************************************************
 * Copyright (C) 2019 Synopsys, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 ******************************************************************************/

#include "armcore.h"
#include "common.h"

#include <ctime>
#include <fcntl.h>

#ifdef _MSC_VER
#include <io.h>
#  define STDIN_FILENO  0
#  define STDOUT_FILENO 1
#  define STDERR_FILENO 2
#  pragma warning(disable: 4505 4800 4996)
#endif

namespace ocx { namespace arm {

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

    static int modeflags(int mode) {
        // bit 0 of mode stores "b" info, which is not needed for open
        switch (mode >> 1) {
        case 0: return O_RDONLY; // "r" and "rb"
        case 1: return O_RDWR;   // "r+" and "r+b"
        case 2: return O_WRONLY | O_CREAT | O_TRUNC;  // "w" and "wb"
        case 3: return O_RDWR   | O_CREAT | O_TRUNC;  // "w+" and "w+b"
        case 4: return O_WRONLY | O_CREAT | O_APPEND; // "a" and "ab"
        case 5: return O_RDWR   | O_CREAT | O_APPEND; // "a+" and "a+b"
        default:
            ERROR("illegal open mode %d", mode);
        }
    }

    string core::semihosting::rd_string(u64 addr, size_t n) {
        string result;
        char buffer = ~0;
        while (n-- && buffer != '\0') {
            if (m_core.read_mem_virt(addr++, (unsigned char*)&buffer, 1) != 1)
                ERROR("failed to read char at 0x%016llx", addr - 1);
            result += buffer;
        }

        return result;
    }

    u64 core::semihosting::rd_reg(unsigned int no) {
        ERROR_ON(no > 1, "unexpected semihost reg read %u", no);
        u64 val = ~0ull;
        no += (m_core.is_aarch64() ? (int)UC_ARM64_REG_X0 : (int)UC_ARM_REG_R0);
        uc_err r = uc_reg_read(m_core.m_uc, no, &val);
        ERROR_ON(r != UC_ERR_OK, "failed to read reg %u", no);
        return val;
    }

    u64 core::semihosting::rd_field(int n) {
        const u64 size = m_core.is_aarch64() ? sizeof(u64) : sizeof(u32);
        u64 addr = rd_reg(1) + n * size;
        u64 field = 0;

        if (m_core.read_mem_virt(addr, (unsigned char*)&field, size) != size)
            ERROR("failed to read address 0x%016llx", addr);

        return field;
    }

    u64 core::semihosting::execute(u32 call) {
        switch (call) {
        case SHC_CLOCK:
            return (realtime_ms() - m_core.m_start_time_ms) / 10;

        case SHC_TIME:
            return time(NULL);

        case SHC_ELAPSED:
            return m_core.m_num_insn + uc_instruction_count(m_core.m_uc);

        case SHC_TICKFQ:
            return CLOCKS_PER_SEC;

        case SHC_EXIT:
            INFO("arm semihosting: software exit request");
            exit((int)rd_reg(1));

        case SHC_EXIT2:
            INFO("arm semihosting: software exit request");
            exit((int)(rd_reg(1) >> 32));

        case SHC_READC:
            return getchar();

        case SHC_ERRNO:
            return errno;

        case SHC_WRITEC: {
            unsigned char c;
            u64 addr = rd_reg(1);
            if (m_core.read_mem_virt(addr, &c, sizeof(c)) != sizeof(c))
                return ~0ull;
            putchar(c);
            return c;
        }

        case SHC_WRITE0: {
            unsigned char c;
            u64 addr = rd_reg(1);
            do {
                if (m_core.read_mem_virt(addr++, &c, sizeof(c)) != sizeof(c))
                    break;
                if (c != '\0')
                    putchar(c);
            } while (c != '\0');
            return addr;
        }

        case SHC_OPEN: {
            u64 addr = rd_field(0);
            u64 mode = rd_field(1);
            u64 size = rd_field(2);

            string file = rd_string(addr, size);

            if (file == ":tt") {
                return (mode < 4) ? STDIN_FILENO :
                       (mode < 8) ? STDOUT_FILENO : STDERR_FILENO;
            }

            return open(file.c_str(), modeflags((int)mode));
        }

        case SHC_CLOSE: {
            u64 file = rd_field(0);
            close((int)file);
            return 0;
        }

        case SHC_WRITE: {
            u64 file = rd_field(0);
            u64 addr = rd_field(1);
            u64 size = rd_field(2);

            while (size > 0) {
                unsigned char buffer = 0;
                if (m_core.read_mem_virt(addr, &buffer, 1) != 1)
                    return size;

                if (write((int)file, &buffer, 1) != 1)
                    return size;

                size--;
                addr++;
            }

            return 0;
        }

        case SHC_ISTTY: {
            u64 file = rd_field(0);
            return isatty((int)file);
        }

        case SHC_FLEN: {
            int fd = (int)rd_field(0);
            off_t curr = lseek(fd, 0, SEEK_CUR);
            if (curr == -1) return (u64)-1;
            off_t size = lseek(fd, 0, SEEK_END);
            if (size == -1) return (u64)-1;
            off_t res = lseek(fd, curr, SEEK_SET);
            if (res == -1) return (u64)-1;
            return size;
        }

        case SHC_READ: {
            u64 file = rd_field(0);
            u64 addr = rd_field(1);
            u64 size = rd_field(2);

            u8 buffer[4096];
            size_t bytes_read = 0;
            size_t bytes_todo = size;

            while (bytes_todo > 0) {
                size_t sz = bytes_todo;
                if (sz > sizeof(buffer))
                    sz = sizeof(buffer);

                ssize_t n = read((int)file, buffer, (unsigned int)sz);
                if (n < 0) {
                    INFO("arm semihosting read failure %s", strerror(errno));
                    return bytes_todo;
                }

                if (n == 0)
                    return bytes_todo;

                if (m_core.write_mem_virt(addr + bytes_read, buffer, n) != 
                    (size_t)n) {
                    INFO("arm semihosting store failure");
                    return bytes_todo;
                }

                bytes_read += n;
                bytes_todo -= n;
            }

            return bytes_todo;
        }

        case SHC_SEEK: {
            u64 file = rd_field(0);
            u64 offset = rd_field(1);
            if (lseek((int)file, (long)offset, SEEK_SET) != (off_t)offset)
                return (u64)-1;
            return 0;
        }

        case SHC_ISERR: {
            u64 status = rd_field(0);
            return status ? (u64)-1  : 0; // assume 0 means "success"
        }

        case SHC_CMDLINE: {
            u64 addr = rd_field(0);
            u64 size = rd_field(1);

            const char* cmdline_str = m_core.m_env.get_param("command_line");
            if (!cmdline_str)
                return (u64)-1;

            string cmdline(cmdline_str);
            if (cmdline.empty())
                return (u64)-1;

            size_t length = cmdline.length();
            if (length >= size)
                length = size - 1;

            u8 zero = 0;
            const char* data = cmdline.c_str();

            if (m_core.write_mem_virt(addr, data, length) != length)
                return (u64)-1;

            if (m_core.write_mem_virt(addr + length, &zero, 1) != 1)
                return (u64)-1;

            return 0;
        }

        case SHC_TMPNAM:
        case SHC_REMOVE:
        case SHC_RENAME:
        case SHC_SYSTEM:
        case SHC_HEAP:
        default:
            INFO("arm semihosting: unsupported call %x", call);
            break;
        }

        return ~0ull;
    }

}}
