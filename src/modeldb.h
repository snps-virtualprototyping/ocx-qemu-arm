/******************************************************************************
 * Copyright (C) 2019 Synopsys, Inc.
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 ******************************************************************************/

#ifndef MODELDB_H
#define MODELDB_H

#include <string.h>

namespace unicorn {

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
}

#endif
