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

#include "stdafx.h"

// the msr and mrs instructions only allow immediates for selecting the architecture specific registers to act on so in
// order to provide arbitrary register access to the VM without metamorphism (which is disallowed by HVCI) we simply
// generate stubs for all possible registers into an array, and shove them into an executable section.  Note that this
// must be constexpr so that it can go into a read-only section because W^X is enforced
//
// arguments to (mrs|msr) instruction:
//
// [ 0: 4] <Xt> (x0 for us)
// [ 5: 7] op2
// [ 8:11] crm
// [12:15] crn
// [16:18] op1
// [19:19] op0
//
// so we need to iterate over all possible values in [5:19], meaning 0x8000 functions for both instruction

template <bool Mrs>
constexpr std::array<uint64_t, 0x8000> generate_msrmrs() {
  constexpr auto mrs = 0xD5300000; // mrs x0, <reg>
  constexpr auto msr = 0xD5100000; // msr <reg>, x0

  constexpr auto ret = 0xD65F03C0;

  constexpr auto magic = (Mrs ? mrs : msr) | ((uint64_t)ret << 32);

  std::array<uint64_t, 0x8000> arr{};
  for (auto i = 0u; i < 0x8000; ++i)
    arr[i] = magic | (i << 5);
  return arr;
}

#pragma section (".msrmrs", read, execute)

__declspec(allocate(".msrmrs")) constexpr auto k_mrsfn = generate_msrmrs<true>();
__declspec(allocate(".msrmrs")) constexpr auto k_msrfn = generate_msrmrs<false>();

// convenience functions where you only need to pass the assembled instruction

__declspec(guard(nocf)) unsigned arm_mrs(unsigned instruction) {
  return ((uint32_t(*)())&k_mrsfn[(instruction >> 5) & 0x7FFF])();
}

 __declspec(guard(nocf)) void arm_msr(unsigned instruction, unsigned v) {
  ((void(*)(uint32_t))&k_msrfn[(instruction >> 5) & 0x7FFF])(v);
}
