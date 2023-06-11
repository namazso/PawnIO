// PawnIO - Input-output driver
// Copyright (C) 2023  namazso <admin@namazso.eu>
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

#include <intrin.h>
#include <ntddk.h>
#include "natives_impl.h"

cell get_arch()
{
  return ARCH;
}

cell cpu_count()
{
  return KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
}

cell cpu_set_affinity(cell which, std::array<cell, 2>& old)
{
  PROCESSOR_NUMBER pnum{};
  const auto status = KeGetProcessorNumberFromIndex((ULONG)which, &pnum);
  if (!NT_SUCCESS(status))
    return (cell)status;

  GROUP_AFFINITY ga{}, old_ga{};
  ga.Group = pnum.Group;
  ga.Mask = 1ull << pnum.Number;
  KeSetSystemGroupAffinityThread(&ga, &old_ga);
  static_assert(sizeof(old_ga) == sizeof(cell[2]), "!!!");
  memcpy(old.data(), &old_ga, sizeof(old_ga));
  return (cell)(old_ga.Group == 0 && old_ga.Mask == 0 ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS);
}

cell cpu_restore_affinity(std::array<cell, 2> old)
{
  GROUP_AFFINITY ga{};
  static_assert(sizeof(ga) == sizeof(cell[2]), "!!!");
  memcpy(&ga, old.data(), sizeof(ga));
  if (ga.Group == 0 && ga.Mask == 0)
    return (cell)STATUS_UNSUCCESSFUL; // some idiot passed in the output of a failed cpu_set_affinity
  KeRevertToUserGroupAffinityThread(&ga);
  return (cell)STATUS_SUCCESS;
}

void interrupts_disable() { _disable(); }
void interrupts_enable() { _enable(); }

template <typename T>
cell physical_read(cell pa, cell& v)
{
  PHYSICAL_ADDRESS phys{};
  phys.QuadPart = (LONGLONG)pa;
  const auto va = MmGetVirtualForPhysical(phys);
  if (!va)
    return (cell)STATUS_UNSUCCESSFUL;
  __try
  {
    v = (cell)*(T*)va;
    return STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

template <typename T>
cell physical_write(cell pa, cell v)
{
  PHYSICAL_ADDRESS phys{};
  phys.QuadPart = (LONGLONG)pa;
  const auto va = MmGetVirtualForPhysical(phys);
  if (!va)
    return (cell)STATUS_UNSUCCESSFUL;
  __try
  {
    *(T*)va = (T)v;
    return STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

cell physical_read_byte(cell pa, cell& value) { return physical_read<UCHAR>(pa, value); }
cell physical_read_word(cell pa, cell& value) { return physical_read<USHORT>(pa, value); }
cell physical_read_dword(cell pa, cell& value) { return physical_read<ULONG>(pa, value); }
cell physical_read_qword(cell pa, cell& value) { return physical_read<ULONG64>(pa, value); }

cell physical_write_byte(cell pa, cell value) { return physical_write<UCHAR>(pa, value); }
cell physical_write_word(cell pa, cell value) { return physical_write<USHORT>(pa, value); }
cell physical_write_dword(cell pa, cell value) { return physical_write<ULONG>(pa, value); }
cell physical_write_qword(cell pa, cell value) { return physical_write<ULONG64>(pa, value); }

cell io_space_map(cell pa, cell size)
{
  PHYSICAL_ADDRESS physical;
  physical.QuadPart = pa;
  return (cell)MmMapIoSpace(physical, size, MmNonCached);
}

void io_space_unmap(cell va, cell size)
{
  MmUnmapIoSpace((PVOID)va, size);
}

template <typename T>
cell virtual_read(cell va, cell& v)
{
  __try
  {
    v = (cell)*(T*)va;
    return STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

template <typename T>
cell virtual_write(cell va, cell v)
{
  __try
  {
    *(T*)va = (T)v;
    return STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

template <typename T>
cell virtual_cmpxchg(cell va, cell exchange, cell comparand)
{
  __try
  {
    switch (sizeof(T))
    {
    case 1:
      _InterlockedCompareExchange8((char volatile*)va, (char)exchange, (char)comparand);
      break;
    case 2:
      _InterlockedCompareExchange16((short volatile*)va, (short)exchange, (short)comparand);
      break;
    case 4:
      _InterlockedCompareExchange((long volatile*)va, (long)exchange, (long)comparand);
      break;
    case 8:
      _InterlockedCompareExchange64((int64_t volatile*)va, (int64_t)exchange, (int64_t)comparand);
      break;
    }
    return STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

cell virtual_read_byte(cell va, cell& value) { return virtual_read<UCHAR>(va, value); }
cell virtual_read_word(cell va, cell& value) { return virtual_read<USHORT>(va, value); }
cell virtual_read_dword(cell va, cell& value) { return virtual_read<ULONG>(va, value); }
cell virtual_read_qword(cell va, cell& value) { return virtual_read<ULONG64>(va, value); }

cell virtual_write_byte(cell va, cell value) { return virtual_write<UCHAR>(va, value); }
cell virtual_write_word(cell va, cell value) { return virtual_write<USHORT>(va, value); }
cell virtual_write_dword(cell va, cell value) { return virtual_write<ULONG>(va, value); }
cell virtual_write_qword(cell va, cell value) { return virtual_write<ULONG64>(va, value); }

cell virtual_cmpxchg_byte(cell va, cell exchange, cell comparand) { return virtual_cmpxchg<UCHAR>(va, exchange, comparand); }
cell virtual_cmpxchg_word(cell va, cell exchange, cell comparand) { return virtual_cmpxchg<USHORT>(va, exchange, comparand); }
cell virtual_cmpxchg_dword(cell va, cell exchange, cell comparand) { return virtual_cmpxchg<ULONG>(va, exchange, comparand); }
cell virtual_cmpxchg_qword(cell va, cell exchange, cell comparand) { return virtual_cmpxchg<ULONG64>(va, exchange, comparand); }

cell virtual_alloc(cell size)
{
  return (cell)ExAllocatePoolZero(NonPagedPoolNx, size, 'nwaP');
}

void virtual_free(cell va)
{
  ExFreePoolWithTag((PVOID)va, 'nwaP');
}

#pragma warning(push)
#pragma warning(disable: 4996)

NTSTATUS pci_config_read_raw(ULONG bus, ULONG device, ULONG function, ULONG offset, PVOID buffer, ULONG length)
{
  if (length == 0)
    return STATUS_INVALID_PARAMETER;

  PCI_SLOT_NUMBER slot{};
  slot.u.bits.DeviceNumber = device;
  slot.u.bits.FunctionNumber = function;

  USHORT vendor_id{};
  auto result = HalGetBusDataByOffset(
    PCIConfiguration,
    bus,
    slot.u.AsULONG,
    &vendor_id,
    0,
    sizeof(vendor_id)
  );

  if (result == 0)
    return STATUS_NOT_FOUND;

  if (result == 2 && vendor_id == PCI_INVALID_VENDORID)
    return STATUS_DEVICE_DOES_NOT_EXIST;

  result = HalGetBusDataByOffset(
    PCIConfiguration,
    bus,
    slot.u.AsULONG,
    buffer,
    offset,
    length
  );

  if (result == 0)
    return STATUS_NOT_FOUND;

  if (result == 2 && length != 2)
    return STATUS_DEVICE_DOES_NOT_EXIST;

  if (result != length)
    return STATUS_UNSUCCESSFUL;

  return STATUS_SUCCESS;
}

NTSTATUS pci_config_write_raw(ULONG bus, ULONG device, ULONG function, ULONG offset, PVOID buffer, ULONG length)
{
  if (length == 0)
    return STATUS_INVALID_PARAMETER;

  PCI_SLOT_NUMBER slot{};
  slot.u.bits.DeviceNumber = device;
  slot.u.bits.FunctionNumber = function;

  USHORT vendor_id{};
  auto result = HalGetBusDataByOffset(
    PCIConfiguration,
    bus,
    slot.u.AsULONG,
    &vendor_id,
    0,
    sizeof(vendor_id)
  );

  if (result == 0)
    return STATUS_NOT_FOUND;

  if (result == 2 && vendor_id == PCI_INVALID_VENDORID)
    return STATUS_DEVICE_DOES_NOT_EXIST;

  result = HalSetBusDataByOffset(
    PCIConfiguration,
    bus,
    slot.u.AsULONG,
    buffer,
    offset,
    length
  );

  if (result != length)
    return STATUS_UNSUCCESSFUL;

  return STATUS_SUCCESS;
}

#pragma warning(pop)

template <typename T>
cell pci_config_read(cell bus, cell device, cell function, cell offset, cell& value)
{
  T t{};
  const auto status = pci_config_read_raw((ULONG)bus, (ULONG)device, (ULONG)function, (ULONG)offset, &t, sizeof(t));
  value = t;
  return status;
}

template <typename T>
cell pci_config_write(cell bus, cell device, cell function, cell offset, cell value)
{
  T t{(T)value};
  return pci_config_write_raw((ULONG)bus, (ULONG)device, (ULONG)function, (ULONG)offset, &t, sizeof(t));
}

cell pci_config_read_byte(cell bus, cell device, cell function, cell offset, cell& value) { return pci_config_read<UCHAR>(bus, device, function, offset, value); }
cell pci_config_read_word(cell bus, cell device, cell function, cell offset, cell& value) { return pci_config_read<USHORT>(bus, device, function, offset, value); }
cell pci_config_read_dword(cell bus, cell device, cell function, cell offset, cell& value) { return pci_config_read<ULONG>(bus, device, function, offset, value); }
cell pci_config_read_qword(cell bus, cell device, cell function, cell offset, cell& value) { return pci_config_read<ULONG64>(bus, device, function, offset, value); }

cell pci_config_write_byte(cell bus, cell device, cell function, cell offset, cell value) { return pci_config_write<UCHAR>(bus, device, function, offset, value); }
cell pci_config_write_word(cell bus, cell device, cell function, cell offset, cell value) { return pci_config_write<USHORT>(bus, device, function, offset, value); }
cell pci_config_write_dword(cell bus, cell device, cell function, cell offset, cell value) { return pci_config_write<ULONG>(bus, device, function, offset, value); }
cell pci_config_write_qword(cell bus, cell device, cell function, cell offset, cell value) { return pci_config_write<ULONG64>(bus, device, function, offset, value); }

cell get_proc_address(const char* name)
{
  const auto len = strlen(name);
  wchar_t name_w[1024]{};
  const auto maxlen = min(len, std::size(name_w) - 1);
  for (size_t i = 0; i < maxlen; ++i)
    name_w[i] = name[i];
  UNICODE_STRING ustr;
  RtlInitUnicodeString(&ustr, name_w);
  return (cell)MmGetSystemRoutineAddress(&ustr);
}

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
)
{
  const auto p = (uintptr_t(*)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t))address;
  __try
  {
    retval = p(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15);
    return STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

#if defined(ARCH_A64)

unsigned arm_mrs(unsigned instruction);
void arm_msr(unsigned instruction, unsigned v);

cell msr_read(cell msr, cell& value)
{
  value = 0;
  if ((msr & 0xFFFFFFFFFFF00000) != 0xD5300000)
  {
    return (cell)STATUS_INVALID_PARAMETER;
  }
  __try
  {
    value = (cell)arm_mrs((ULONG)msr);
    return (cell)STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

cell msr_write(cell msr, cell value)
{
  if ((msr & 0xFFFFFFFFFFF00000) != 0xD5300000)
  {
    return (cell)STATUS_INVALID_PARAMETER;
  }

  __try
  {
    arm_msr((ULONG)msr, (ULONG)value);
    return (cell)STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

#endif

#if defined(ARCH_X64)

extern "C" ULONG __fastcall _dell(ULONG* smm);

cell query_dell_smm(std::array<cell, 6> in, std::array<cell, 6>& out)
{
  ULONG regs[6];
  for (auto i = 0; i < 6; ++i)
    regs[i] = (ULONG)in[i];
  const auto result = _dell(regs);
  for (auto i = 0; i < 6; ++i)
    out[i] = regs[i];
  return (result != 0 || (regs[0] & 0xFFFF) == 0xFFFF || regs[0] == (ULONG)in[0]) ? false : true;
}

void io_out_byte(cell port, cell value) { __outbyte((USHORT)port, (UCHAR)value); }
void io_out_word(cell port, cell value) { __outword((USHORT)port, (USHORT)value); }
void io_out_dword(cell port, cell value) { __outdword((USHORT)port, (ULONG)value); }

cell io_in_byte(cell port) { return __inbyte((USHORT)port); }
cell io_in_word(cell port) { return __inword((USHORT)port); }
cell io_in_dword(cell port) { return __indword((USHORT)port); }

void llwpcb(cell addr) { __llwpcb((void*)addr); }
cell slwpcb() { return (cell)__slwpcb(); }

cell msr_read(cell msr, cell& value)
{
  // clamp before the security check
  msr = (ULONG)msr;

  // noone should need these
  /*constexpr static ULONG disallowed_msrs[] = {
    0xC0000081, // STAR
    0xC0000082, // LSTAR
    0xC0000083, // CSTAR
    0xC0000084, // SF_MASK
    0xC0000100, // FS.Base
    0xC0000101, // GS.Base
    0xC0000102, // KernelGSbase
    0x00000174, // SYSENTER_CS
    0x00000175, // SYSENTER_ESP
    0x00000176, // SYSENTER_EIP
  };

  for (auto e : disallowed_msrs)
    if (msr == e)
      return (cell)STATUS_ACCESS_DENIED;*/

  value = 0;
  __try
  {
    value = __readmsr((ULONG)msr);
    return (cell)STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

cell msr_write(cell msr, cell value)
{
  // clamp before the security check
  msr = (ULONG)msr;

  // noone should need these
  /*constexpr static ULONG disallowed_msrs[] = {
    0xC0000081, // STAR
    0xC0000082, // LSTAR
    0xC0000083, // CSTAR
    0xC0000084, // SF_MASK
    0xC0000100, // FS.Base
    0xC0000101, // GS.Base
    0xC0000102, // KernelGSbase
    0x00000174, // SYSENTER_CS
    0x00000175, // SYSENTER_ESP
    0x00000176, // SYSENTER_EIP
  };

  for (auto e : disallowed_msrs)
    if (msr == e)
      return (cell)STATUS_ACCESS_DENIED;*/

  __try
  {
    __writemsr((ULONG)msr, value);
    return (cell)STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

void cpuid(cell leaf, cell subleaf, std::array<cell, 4>& out)
{
  int out32[4];
  __cpuidex(out32, (int)leaf, (int)subleaf);
  for (size_t i = 0; i < 4; ++i)
    out[i] = out32[i];
}

extern "C" cell _crdr(cell id, cell v);

cell crdr_wrap(cell v, cell idx, bool is_cr, bool is_wr)
{
  return _crdr((idx & 0xF) << 3 | (cell)is_cr << 7 | (cell)is_wr << 8, v);
}

cell cr_read(cell cr) { return crdr_wrap(0, cr, true, false); }
void cr_write(cell cr, cell value) { crdr_wrap(value, cr, true, true); }

cell dr_read(cell dr) { return crdr_wrap(0, dr, false, false); }
void dr_write(cell dr, cell value) { crdr_wrap(value, dr, false, true); }

cell xcr_read(cell xcr, cell& value)
{
  value = 0;
  __try
  {
    value = _xgetbv((ULONG)xcr);
    return (cell)STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

cell xcr_write(cell xcr, cell value)
{
  __try
  {
    _xsetbv((ULONG)xcr, value);
    return (cell)STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

void invlpg(cell va) { __invlpg((void*)va); }
void invpcid(cell type, cell descriptor) { _invpcid((unsigned)type, (void*)descriptor); }

cell readpmc(cell pmc, cell& value)
{
  value = 0;
  __try
  {
    value = __readpmc((ULONG)pmc);
    return (cell)STATUS_SUCCESS;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return (cell)GetExceptionCode();
  }
}

cell rdtsc() { return __rdtsc(); }

cell rdtscp(cell& pid)
{
  unsigned _pid{};
  const auto res = __rdtscp(&_pid);
  pid = _pid;
  return res;
}

cell rdrand(cell& v) { return _rdrand64_step(&v); }
cell rdseed(cell& v) { return _rdseed64_step(&v); }

#include <pshpack1.h>
struct idtrgdtr
{
  uint16_t limit;
  uintptr_t base;
};
#include <poppack.h>

void lidt(cell limit, cell base)
{
  idtrgdtr v{};
  v.limit = (uint16_t)limit;
  v.base = base;
  __lidt(&v);
}

void sidt(cell& limit, cell& base)
{
  idtrgdtr v{};
  __sidt(&v);
  limit = v.limit;
  base = v.base;
}

void lgdt(cell limit, cell base)
{
  idtrgdtr v{};
  v.limit = (uint16_t)limit;
  v.base = base;
  _lgdt(&v);
}

void sgdt(cell& limit, cell& base)
{
  idtrgdtr v{};
  _sgdt(&v);
  limit = v.limit;
  base = v.base;
}

cell mxcsr_read() { return _mm_getcsr(); }
void mxcsr_write(cell v) { _mm_setcsr((unsigned)v); }

void stac() { _stac(); }
void clac() { _clac(); }

void halt() { __halt(); }

void ud2() { __ud2(); }

void int3() { __debugbreak(); }

void int2c() { __int2c(); }

void wbinvd() { __wbinvd(); }

#endif
