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

// Windows or PawnIO specific extra functions.

#define PAGE_SIZE (0x1000)

const CpuVendor: {
    CpuVendor_AMD   = 0xc0e946f161868306, // AuthenticAMD
    CpuVendor_Intel = 0x0d4770f6cacd93a6, // GenuineIntel
    CpuVendor_VIA   = 0xc3feac365a7e42f0, // CentaurHauls
    CpuVendor_Hygon = 0x4fc576e4f1b66033, // HygonGenuine
};

/// Get CPU vendor.
///
/// @return CPU vendor
stock CpuVendor:get_cpu_vendor() {
    new vendor[4];
    cpuid(0, 0, vendor);
    return CpuVendor:(fnv1ad(vendor[2], fnv1ad(vendor[3], fnv1ad(vendor[1]))));
}

/// Get CPU family, model, and stepping.
///
/// @return CPU family (bits 16-23), model (bits 8-15), and stepping (bits 0-7)
stock get_cpu_fms() {
    new procinfo[4];
    cpuid(1, 0, procinfo);
    new family = ((procinfo[0] & 0x0FF00000) >>> 20) + ((procinfo[0] & 0x0F00) >> 8);
    new model = ((procinfo[0] & 0x0F0000) >>> 12) | ((procinfo[0] & 0xF0) >> 4);
    new stepping = procinfo[0] & 0x0F;
    return (family << 16) | (model << 8) | stepping;
}

/// Get CPU family from FMS.
///
/// @param fms CPU family, model, and stepping as returned by get_cpu_fms()
/// @return CPU family (bits 16-23)
stock cpu_fms_family(fms) {
    return (fms >>> 16) & 0xFF;
}

/// Get CPU model from FMS.
///
/// @param fms CPU family, model, and stepping as returned by get_cpu_fms()
/// @return CPU model (bits 8-15)
stock cpu_fms_model(fms) {
    return (fms >>> 8) & 0xFF;
}

/// Get CPU stepping from FMS.
///
/// @param fms CPU family, model, and stepping as returned by get_cpu_fms()
/// @return CPU stepping (bits 0-7)
stock cpu_fms_stepping(fms) {
    return fms & 0xFF;
}

const VA:KUSER_SHARED_DATA = 0xFFFFF78000000000;

/// Get tick count.
///
/// @return Tick count
stock get_tick_count() {
    new value;
    new multiplier;
    // KUSER_SHARED_DATA->TickCountQuad
    virtual_read_qword(KUSER_SHARED_DATA + 0x0320, value);
    virtual_read_dword(KUSER_SHARED_DATA + 0x0004, multiplier);
    return (value * multiplier) >>> 24;
}
