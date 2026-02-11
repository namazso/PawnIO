// PawnIO - Input-output driver
// Copyright (C) 2026  namazso <admin@namazso.eu>
// 
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
// 
// Linking PawnIO statically or dynamically with other modules is making a
// combined work based on PawnIO. Thus, the terms and conditions of the GNU
// General Public License cover the whole combination.
// 
// In addition, as a special exception, the copyright holders of PawnIO give
// you permission to combine PawnIO program with free software programs or
// libraries that are released under the GNU LGPL and with independent modules
// that communicate with PawnIO solely through the device IO control
// interface. You may copy and distribute such a system following the terms of
// the GNU GPL for PawnIO and the licenses of the other code concerned,
// provided that you include the source code of that other code when and as
// the GNU GPL requires distribution of source code.
// 
// Note that this exception does not include programs that communicate with
// PawnIO over the Pawn interface. This means that all modules loaded into
// PawnIO must be compatible with this licence, including the earlier
// exception clause. We recommend using the GNU Lesser General Public License
// version 2.1 to fulfill this requirement.
// 
// For alternative licensing options, please contact the copyright holder at
// admin@namazso.eu.
// 
// Note that people who make modified versions of PawnIO are not obligated to
// grant this special exception for their modified versions; it is their
// choice whether to do so. The GNU General Public License gives permission
// to release a modified version without this exception; this exception also
// makes it possible to release a modified version which carries forward this
// exception.

#pragma once

#include "arch_detect.h"

using cell = unsigned long long;
using scell = long long;

static_assert(sizeof(cell) == sizeof(void*));

cell get_arch();

cell cpu_count();
cell cpu_set_affinity(cell which, std::array<cell, 2>& old);
cell cpu_restore_affinity(std::array<cell, 2> old);

cell msr_read(cell msr, cell& value);
cell msr_write(cell msr, cell value);

void interrupts_disable();
void interrupts_enable();

cell physical_read_byte(cell pa, cell& value);
cell physical_read_word(cell pa, cell& value);
cell physical_read_dword(cell pa, cell& value);
cell physical_read_qword(cell pa, cell& value);

cell physical_write_byte(cell pa, cell value);
cell physical_write_word(cell pa, cell value);
cell physical_write_dword(cell pa, cell value);
cell physical_write_qword(cell pa, cell value);

cell io_space_map(cell pa, cell size);
void io_space_unmap(cell va, cell size);

cell virtual_read_byte(cell va, cell& value);
cell virtual_read_word(cell va, cell& value);
cell virtual_read_dword(cell va, cell& value);
cell virtual_read_qword(cell va, cell& value);

cell virtual_write_byte(cell va, cell value);
cell virtual_write_word(cell va, cell value);
cell virtual_write_dword(cell va, cell value);
cell virtual_write_qword(cell va, cell value);

cell virtual_cmpxchg_byte2(cell va, cell exchange, cell comparand);
cell virtual_cmpxchg_word2(cell va, cell exchange, cell comparand);
cell virtual_cmpxchg_dword2(cell va, cell exchange, cell comparand);
cell virtual_cmpxchg_qword2(cell va, cell exchange, cell comparand);

cell virtual_alloc(cell size);
void virtual_free(cell va);

cell pci_config_read_byte(cell bus, cell device, cell function, cell offset, cell& value);
cell pci_config_read_word(cell bus, cell device, cell function, cell offset, cell& value);
cell pci_config_read_dword(cell bus, cell device, cell function, cell offset, cell& value);
cell pci_config_read_qword(cell bus, cell device, cell function, cell offset, cell& value);

cell pci_config_write_byte(cell bus, cell device, cell function, cell offset, cell value);
cell pci_config_write_word(cell bus, cell device, cell function, cell offset, cell value);
cell pci_config_write_dword(cell bus, cell device, cell function, cell offset, cell value);
cell pci_config_write_qword(cell bus, cell device, cell function, cell offset, cell value);

cell get_proc_address(const char* name);

cell invoke(
  cell address,
  cell& retval,
  cell a0,
  cell a1,
  cell a2,
  cell a3,
  cell a4,
  cell a5,
  cell a6,
  cell a7,
  cell a8,
  cell a9,
  cell a10,
  cell a11,
  cell a12,
  cell a13,
  cell a14,
  cell a15
);

cell microsleep(cell us);
cell microsleep2(cell us);

cell qpc(cell& frequency);

#if defined(ARCH_A64)

#elif defined(ARCH_X64)

// order: eax ecx edx ebx esi edi
cell query_dell_smm(std::array<cell, 6> in, std::array<cell, 6>& out);

void io_out_byte(cell port, cell value);
void io_out_word(cell port, cell value);
void io_out_dword(cell port, cell value);

cell io_in_byte(cell port);
cell io_in_word(cell port);
cell io_in_dword(cell port);

void llwpcb(cell addr);
cell slwpcb();

// order: eax ebx ecx edx
void cpuid(cell leaf, cell subleaf, std::array<cell, 4>& out);

cell cr_read(cell cr);
void cr_write(cell cr, cell value);

cell dr_read(cell dr);
void dr_write(cell dr, cell value);

cell xcr_read(cell xcr, cell& value);
cell xcr_write(cell xcr, cell value);

void invlpg(cell va);
void invpcid(cell type, cell descriptor);

cell readpmc(cell pmc, cell& value);

cell rdtsc();
cell rdtscp(cell& pid);

cell rdrand(cell& v);
cell rdseed(cell& v);

void lidt(cell limit, cell base);
void sidt(cell& limit, cell& base);

void lgdt(cell limit, cell base);
void sgdt(cell& limit, cell& base);

cell mxcsr_read();
void mxcsr_write(cell v);

void stac();
void clac();

void halt();

void ud2();

void int3();

void int2c();

void wbinvd();

#endif
