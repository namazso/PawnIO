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

#define cellbytes (cellbits / 8)

#define BIT(%1) (1 << (%1))

#define SIGN_EXTEND(%1,%2) (((%1) << (cellbits - (%2))) >> (cellbits - (%2)))
#define SIGN_EXTEND8(%1) (SIGN_EXTEND(%1, 8))
#define SIGN_EXTEND16(%1) (SIGN_EXTEND(%1, 16))
#define SIGN_EXTEND32(%1) (SIGN_EXTEND(%1, 32))

#define CHAR1_CONST(%1) (%1)
#define CHAR2_CONST(%1,%2) (CHAR1_CONST(%1) | ((%2) << 8))
#define CHAR3_CONST(%1,%2,%3) (CHAR2_CONST(%1, %2) | ((%3) << 16))
#define CHAR4_CONST(%1,%2,%3,%4) (CHAR3_CONST(%1, %2, %3) | ((%4) << 24))
#define CHAR5_CONST(%1,%2,%3,%4,%5) (CHAR4_CONST(%1, %2, %3, %4) | ((%5) << 32))
#define CHAR6_CONST(%1,%2,%3,%4,%5,%6) (CHAR5_CONST(%1, %2, %3, %4, %5) | ((%6) << 40))
#define CHAR7_CONST(%1,%2,%3,%4,%5,%6,%7) (CHAR6_CONST(%1, %2, %3, %4, %5, %6) | ((%7) << 48))
#define CHAR8_CONST(%1,%2,%3,%4,%5,%6,%7,%8) (CHAR7_CONST(%1, %2, %3, %4, %5, %6, %7) | ((%8) << 56))

/// Divide two numbers and round up.
///
/// @param x Dividend
/// @param y Divisor
/// @return The result of the division, rounded up (round towards +infinity)
/// @note The divide operator, "/", truncates (round towards zero)
stock div_ceil(x, y) {
    new quotientPositive = (y >= 0) == (x >= 0);
    return x / y + _:(x % y != 0 && quotientPositive);
}

/// Divide two numbers and round down.
///
/// @param x Dividend
/// @param y Divisor
/// @return The result of the division, rounded down (round towards -infinity)
/// @note The divide operator, "/", truncates (round towards zero)
stock div_floor(x, y) {
    new quotientNegative = (y < 0) != (x < 0);
    return x / y - _:(x % y != 0 && quotientNegative);
}

/// Divide two numbers and round away from zero.
///
/// @param x Dividend
/// @param y Divisor
/// @return The result of the division, rounded away from zero
/// @note The divide operator, "/", truncates (round towards zero)
stock div_away(x, y) {
    new quotientSgn = ((x > 0) - (x < 0)) * ((y > 0) - (y < 0));
    return x / y + _:(x % y != 0) * quotientSgn;
}

/// Divide two numbers and round towards zero.
///
/// @param x Dividend
/// @param y Divisor
/// @return The result of the division, rounded towards zero
/// @note This is just operator "/"
stock div_trunc(x, y) {
    return x / y;
}

/// Unpack bytes packed into cells.
///
/// @param src Source array
/// @param dst Destination array
/// @param size Count of bytes to unpack
/// @param src_offs Source offset, in bytes
/// @param dst_offs Destination offset, in cells
stock Void:unpack_bytes_le(const src[], dst[], size, src_offs = 0, dst_offs = 0) {
    for (new i = 0; i < size; i++) {
        new src_idx = src_offs + i;
        new src_cell = src[src_idx / cellbytes];
        new byte = (src_cell >>> ((src_idx % cellbytes) * 8)) & 0xff;
        dst[dst_offs + i] = byte;
    }
}

/// Pack bytes into cells
///
/// @param src Source array
/// @param dst Destination array
/// @param size Count of bytes to pack
/// @param src_offs Source offset, in cells
/// @param dst_offs Destination offset, in bytes
stock Void:pack_bytes_le(const src[], dst[], size, src_offs = 0, dst_offs = 0) {
    for (new i = 0; i < size; i++) {
        new byte = src[src_offs + i] & 0xff;
        new dst_idx = dst_offs + i;
        dst[dst_idx / cellbytes] &= ~(0xff << ((dst_idx % cellbytes) * 8));
        dst[dst_idx / cellbytes] |= byte << ((dst_idx % cellbytes) * 8);
    }
}

/// Get individual bytes from a cell.
///
/// @param src Source cell
/// @param idx Byte index in cell
stock get_byte_le(src, idx) {
    return((src >>> ((idx % cellbytes) * 8)) & 0xff);
}

#define GET_BYTE_LE(%1,%2) (get_byte_le((%1[(%2) / cellbytes]), ((%2) % cellbytes)))

/// Set an individual byte in a cell.
///
/// @param dst Destination cell
/// @param idx Byte index in cell
/// @param val Byte value to set
stock set_byte_le(&dst, idx, val) {
    new shift = ((idx % cellbytes) * 8);
    dst &= ~(0xff << shift);
    dst |= ((val & 0xff) << shift);
}

#define SET_BYTE_LE(%1,%2,%3) (set_byte_le((%1[(%2) / cellbytes]), ((%2) % cellbytes), (%3)))

/// Copy memory from one array to another.
///
/// @param dst Destination array
/// @param src Source array
/// @param size Number of cells to copy
/// @param dst_offs Destination offset, in cells
/// @param src_offs Source offset, in cells
/// @param dst_size Size of the destination array, in cells
/// @return Number of cells copied
stock copy(dst[], const src[], size, dst_offs = 0, src_offs = 0, dst_size = sizeof dst) {
    new i;
    for (i = 0; i < size; i++) {
        new idx = dst_offs + i;
        if (idx < 0 || idx >= dst_size)
            break;
        dst[dst_offs + i] = src[src_offs + i];
    }
    return i;
}

/// FNV-1a 64-bit hash basis
const fnv1_basis = 0xcbf29ce484222325;

/// FNV-1a hash a byte.
///
/// @param b Byte to hash
/// @param h Previous hash value, or fnv1_basis for the first byte
/// @return Updated hash value
stock fnv1ab(b, h = fnv1_basis) {
    h ^= b & 0xff;
    // no unsigned multiply, so use shifts and adds
    return (h << 40) + (h << 8) + (h << 7) + (h << 5) + (h << 4) + (h << 1) + h;
}

/// FNV-1a hash a word.
///
/// @param w Word to hash
/// @param h Previous hash value, or fnv1_basis for the first byte
/// @return Updated hash value
stock fnv1aw(w, h = fnv1_basis) {
    return fnv1ab((w >>> 8) & 0xff, fnv1ab(w & 0xff, h));
}

/// FNV-1a hash a dword.
///
/// @param d Dword to hash
/// @param h Previous hash value, or fnv1_basis for the first byte
/// @return Updated hash value
stock fnv1ad(d, h = fnv1_basis) {
    return fnv1aw((d >>> 16) & 0xffff, fnv1aw(d & 0xffff, h));
}

/// FNV-1a hash a qword.
///
/// @param q Qword to hash
/// @param h Previous hash value, or fnv1_basis for the first byte
/// @return Updated hash value
stock fnv1aq(q, h = fnv1_basis) {
    return fnv1ad((q >>> 32) & 0xffffffff, fnv1ad(q & 0xffffffff, h));
}
