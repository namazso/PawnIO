#pragma once
#include <array>

#include "arch_detect.h"

using cell = unsigned long long;

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

cell virtual_cmpxchg_byte(cell va, cell exchange, cell comparand);
cell virtual_cmpxchg_word(cell va, cell exchange, cell comparand);
cell virtual_cmpxchg_dword(cell va, cell exchange, cell comparand);
cell virtual_cmpxchg_qword(cell va, cell exchange, cell comparand);

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
