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

// Implementation of some of Pawn's core functions. Normally these would be
// natives, but they're easily implemented in Pawn itself.

stock tolower(c) {
    return (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c;
}

stock toupper(c) {
    return (c >= 'a' && c <= 'z') ? (c - ('a' - 'A')) : c;
}

stock swapchars(c) {
    const cellbytes = cellbits / 8;
    for (new i = 0; i < cellbytes / 2; i++) {
        new low = (c >>> (i * 8)) & 0xff;
        new high = (c >>> ((cellbytes - 1 - i) * 8)) & 0xff;
        c &= ~((0xff << (i * 8)) | (0xff << ((cellbytes - 1 - i) * 8)));
        c |= (low << ((cellbytes - 1 - i) * 8)) | (high << (i * 8));
    }
    return c;
}

stock min(a, b) {
    return a < b ? a : b;
}

stock max(a, b) {
    return a > b ? a : b;
}

stock clamp(value, min=cellmin, max=cellmax) {
    return value < min ? min : (value > max ? max : value);
}
