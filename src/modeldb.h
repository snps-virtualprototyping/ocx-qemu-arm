/******************************************************************************
 * Copyright Synopsys, licensed under the MIT license, see LICENSE for detail
 ******************************************************************************/

#ifndef MODELDB_H
#define MODELDB_H

namespace ocx { namespace arm {

    struct reg {
        const int    id;
        const int    offset;
        const int    width;
        const char*  name;
    };

    struct model {
        const char* name;
        const char* arch;

        int bits;

        const reg* registers;
        unsigned int nregs;

        bool has_aarch32() const { return bits >= 32; }
        bool has_aarch64() const { return bits >= 64; }
    };

    const model* lookup_model(const char* name);

}}

#endif
