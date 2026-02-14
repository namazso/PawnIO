//  PawnIO Headers - Headers for writing PawnIO modules.
//  Copyright (C) 2025  namazso <admin@namazso.eu>
//  
//  Permission to use, copy, modify, and/or distribute this software for any
//  purpose with or without fee is hereby granted.
//  
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
//  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
//  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
//  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
//  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
//  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
//  PERFORMANCE OF THIS SOFTWARE.
//  
//  SPDX-License-Identifier: 0BSD

#include "core.inc"
#include "util.inc"
#include "ntstatus.inc"
#include "native.inc"
#include "extra.inc"

/// Define an IOCTL function.
/// @param %1 Name of the IOCTL function, must start with ioctl_
#define DEFINE_IOCTL(%1) \
    forward NTSTATUS:%1(in[], in_size, out[], out_size); \
    public NTSTATUS:%1(in[], in_size, out[], out_size)

/// Define an IOCTL function with static buffer sizes.
/// @param %1 Name of the IOCTL function, must start with ioctl_
/// @param %2 Size of the input buffer
/// @param %3 Size of the output buffer
#define DEFINE_IOCTL_SIZED(%1,%2,%3) \
    forward NTSTATUS:%1(in[%2], in_size, out[%3], out_size); \
    public NTSTATUS:%1(in[%2], in_size, out[%3], out_size) \
        if (((%2) != 0 && in_size != (%2)) || ((%3) != 0 && out_size != (%3))) \
            return STATUS_INVALID_PARAMETER; \
        else

NTSTATUS:main();

/// Executed on module unload.
forward NTSTATUS:unload();
