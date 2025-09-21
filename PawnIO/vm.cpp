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

#include "vm.h"

#define LITTLE_ENDIAN
#include "amx_loader.h"
#include "callbacks.h"
#include "natives_impl.h"
#include "signature.h"
#include "public.h"

using amx64 = amx::amx<uint64_t, amx::memory_manager_harvard<amx::memory_backing_contignous_buffer, amx::memory_backing_paged_buffers<5>>>;
using amx64_loader = amx::loader<amx64>;

static_assert(std::is_same_v<cell, amx64::cell>, "cell mismatch");

template <typename ArgT, size_t Index>
class arg_wrapper {};

template <size_t Index>
class arg_wrapper<cell&, Index> {
  cell* p{};

public:
  FORCEINLINE arg_wrapper() = default;

  FORCEINLINE amx::error init(amx64* amx, cell, cell argv) {
    p = amx->data_v2p(argv + Index * sizeof(cell));
    if (!p)
      return amx::error::access_violation;
    p = amx->mem.data().translate(*p);
    if (!p)
      return amx::error::access_violation;
    return amx::error::success;
  }

  cell value{};

  FORCEINLINE ~arg_wrapper() {
    if (p)
      *p = value;
  }
};

template <size_t Index>
class arg_wrapper<cell, Index> {
public:
  FORCEINLINE arg_wrapper() = default;

  FORCEINLINE amx::error init(amx64* amx, cell, cell argv) {
    const auto p = amx->data_v2p(argv + Index * sizeof(cell));
    if (!p)
      return amx::error::access_violation;
    value = *p;
    return amx::error::success;
  }

  cell value{};
  FORCEINLINE ~arg_wrapper() = default;
};

template <size_t N, size_t Index>
class arg_wrapper<std::array<cell, N>&, Index> {
  std::array<cell*, N> ps{};

public:
  FORCEINLINE arg_wrapper() = default;

  FORCEINLINE amx::error init(amx64* amx, cell, cell argv) {
    const auto p = amx->data_v2p(argv + Index * sizeof(cell));
    if (!p)
      return amx::error::access_violation;
    const auto arr_base = *p;
    for (size_t i = 0; i < N; ++i) {
      const auto elem = amx->mem.data().translate(arr_base + i * sizeof(cell));
      if (!elem) {
        ps = {};
        return amx::error::access_violation;
      }
      ps[i] = elem;
      value[i] = *elem;
    }
    return amx::error::success;
  }

  std::array<cell, N> value{};

  FORCEINLINE ~arg_wrapper() {
    for (size_t i = 0; i < N; ++i)
      *(ps[i]) = value[i];
  }
};

template <size_t N, size_t Index>
class arg_wrapper<std::array<cell, N>, Index> {
public:
  FORCEINLINE arg_wrapper() = default;

  FORCEINLINE amx::error init(amx64* amx, cell, cell argv) {
    const auto p = amx->data_v2p(argv + Index * sizeof(cell));
    if (!p)
      return amx::error::access_violation;
    const auto arr_base = *p;
    for (size_t i = 0; i < N; ++i) {
      const auto elem = amx->mem.data().translate(arr_base + i * sizeof(cell));
      if (!elem)
        return amx::error::access_violation;
      value[i] = *elem;
    }
    return amx::error::success;
  }

  std::array<cell, N> value{};
  FORCEINLINE ~arg_wrapper() = default;
};

// Implement wrapped tuple type.
//
namespace impl {
  template <typename Tp, typename Ti>
  struct wtuple;

  template <typename Tp, size_t... Ix>
  struct wtuple<Tp, std::index_sequence<Ix...>> {
    using type = std::tuple<arg_wrapper<std::tuple_element_t<Ix, Tp>, Ix>...>;
  };

  template <typename... Tx>
  using wtuple_t = typename wtuple<std::tuple<Tx...>, std::make_index_sequence<sizeof...(Tx)>>::type;

  template <size_t N, typename T>
  FORCEINLINE amx::error init_wtuple(amx64* amx, cell argc, cell argv, T& tuple) {
    if constexpr (N == std::tuple_size_v<T>) {
      return {};
    } else {
      auto& wrapper = std::get<N>(tuple);
      if (auto err = wrapper.init(amx, argc, argv); err != amx::error::success)
        return err;
      else
        return init_wtuple<N + 1, T>(amx, argc, argv, tuple);
    }
  }

  template <typename... Tx>
  FORCEINLINE std::pair<wtuple_t<Tx...>, amx::error> init_wtuple(amx64* amx, cell argc, cell argv) {
    std::pair<wtuple_t<Tx...>, amx::error> result = {};
    result.second = init_wtuple<0>(amx, argc, argv, result.first);
    return result;
  }
};

template <auto* Fn, typename Ret, typename... Args>
FORCEINLINE amx::error native_callback_wrapper2(
  amx64* amx,
  amx64_loader* loader,
  void* user,
  cell argc,
  cell argv,
  cell& retval,
  Ret (*)(Args...)
) {
  UNREFERENCED_PARAMETER(loader);
  UNREFERENCED_PARAMETER(user);

  if (argc != sizeof...(Args))
    return amx::error::invalid_operand;

  auto&& [wtuple, err] = impl::init_wtuple<Args...>(amx, argc, argv);

  if (err != amx::error::success)
    return err;

  if constexpr (std::is_same_v<Ret, void>) {
    retval = 0;
    std::apply(
      [&](auto&... wr) -> void {
        Fn(wr.value...);
      },
      wtuple
    );
  } else {
    retval = std::apply(
      [&](auto&... wr) -> Ret {
        return Fn(wr.value...);
      },
      wtuple
    );
  }

  // rest of the bullshit
  return amx::error::success;
}

template <auto* Fn>
amx::error native_callback_wrapper(amx64* amx, amx64_loader* loader, void* user, cell argc, cell argv, cell& retval) {
  return native_callback_wrapper2<Fn>(amx, loader, user, argc, argv, retval, Fn);
}

amx::error debug_print(amx64* amx, amx64_loader* loader, void* user, cell argc, cell argv, cell& retval) {
  UNREFERENCED_PARAMETER(loader);
  UNREFERENCED_PARAMETER(user);

  retval = 0;

  if (argc == 0)
    return amx::error::invalid_operand;
  char message[1024] = "[PawnIO] debug_print: ";
  cell args[64]{};
  const auto pvfmt = amx->data_v2p(argv);
  if (!pvfmt)
    return amx::error::access_violation;
  const auto vfmt = *pvfmt;
  const auto last = std::begin(message) + std::size(message);
  auto it = message + strlen(message);
  auto vit = vfmt;
  size_t arg_count = 0;
  bool in_escape = false;
  while (true) {
    const auto pc = amx->mem.data().translate(vit);
    vit += sizeof(cell);
    if (!pc)
      return amx::error::access_violation;
    const auto c = (char)*pc;
    char to_cat[10]{};
    if (in_escape)
      switch (c) {
      case '%':
        to_cat[0] = '%';
        to_cat[1] = '%';
        in_escape = false;
        break;
      case 'd':
      case 'i':
      case 'u':
      case 'o':
      case 'x':
      case 'X':
        to_cat[0] = '%';
        to_cat[1] = 'l';
        to_cat[2] = 'l';
        to_cat[3] = c;
        ++arg_count;
        in_escape = false;
        break;
      default:
        return amx::error::invalid_operand;
      }
    else
      switch (c) {
      case '%':
        in_escape = true;
        break;
      case 0:
        goto leave;
      default:
        to_cat[0] = c;
        break;
      }

    {
      const auto len = strlen(to_cat);
      if (it + len >= last)
        break; // just truncate

      memcpy(it, to_cat, len);
      it[len] = 0;
      it += len;

      continue;
    }

leave:
    break;
  }

  if (arg_count > argc - 1)
    return amx::error::invalid_operand;

  if (arg_count > std::size(args))
    return amx::error::invalid_operand;

  for (size_t i = 0; i < arg_count; ++i) {
    const auto pparg = amx->data_v2p(argv + (i + 1) * sizeof(cell));
    if (!pparg)
      return amx::error::invalid_operand;
    const auto parg = amx->mem.data().translate(*pparg);
    if (!parg)
      return amx::error::invalid_operand;
    args[i] = *parg;
  }

  vDbgPrintEx(DPFLTR_DEFAULT_ID, 3, message, (va_list)args);
  return amx::error::success;
}

static ptrdiff_t amx_strcpy(char* dst, size_t dst_len, amx64* amx, cell vfmt) {
  auto vit = vfmt;
  size_t idx = 0;
  while (true) {
    const auto pc = amx->mem.data().translate(vit);
    vit += sizeof(cell);
    if (!pc)
      return -1;
    const auto c = (char)*pc;

    if (dst_len != 0)
      dst[idx] = c;

    ++idx;

    if (!c)
      break;

    if (idx == dst_len) {
      dst[dst_len - 1] = 0;
      break;
    }
  }
  
  return (ptrdiff_t)idx - 1;
}

amx::error get_proc_address_wrap(amx64* amx, amx64_loader* loader, void* user, cell argc, cell argv, cell& retval) {
  UNREFERENCED_PARAMETER(loader);
  UNREFERENCED_PARAMETER(user);

  retval = 0;

  char func_name[1024]{};

  if (argc == 0)
    return amx::error::invalid_operand;
  const auto pvfmt = amx->data_v2p(argv);
  if (!pvfmt)
    return amx::error::access_violation;
  const auto vfmt = *pvfmt;

  const auto res = amx_strcpy(func_name, std::size(func_name), amx, vfmt);
  if (res == 0)
    return amx::error::invalid_operand;
  if (res == -1)
    return amx::error::access_violation;

  retval = get_proc_address(func_name);

  return amx::error::success;
}

amx::error get_public(amx64* amx, amx64_loader* loader, void* user, cell argc, cell argv, cell& retval) {
  UNREFERENCED_PARAMETER(user);

  retval = 0;

  char func_name[33]{};

  if (argc == 0)
    return amx::error::invalid_operand;
  const auto pvfmt = amx->data_v2p(argv);
  if (!pvfmt)
    return amx::error::access_violation;
  const auto vfmt = *pvfmt;

  const auto res = amx_strcpy(func_name, std::size(func_name), amx, vfmt);
  if (res == 0)
    return amx::error::invalid_operand;
  if (res == -1)
    return amx::error::access_violation;

  retval = loader->get_public(func_name);

  return amx::error::success;
}

const static amx64_loader::native_arg NATIVES[] =
{
  {"debug_print", &debug_print},
  {"get_proc_address", &get_proc_address_wrap},
  {"get_public", &get_public},

#define DEFINE_NATIVE(name) { #name, &native_callback_wrapper<&name> }

  DEFINE_NATIVE(get_arch),

  DEFINE_NATIVE(cpu_count),
  DEFINE_NATIVE(cpu_set_affinity),
  DEFINE_NATIVE(cpu_restore_affinity),

  DEFINE_NATIVE(msr_read),
  DEFINE_NATIVE(msr_write),

  DEFINE_NATIVE(interrupts_disable),
  DEFINE_NATIVE(interrupts_enable),

  DEFINE_NATIVE(physical_read_byte),
  DEFINE_NATIVE(physical_read_word),
  DEFINE_NATIVE(physical_read_dword),
  DEFINE_NATIVE(physical_read_qword),

  DEFINE_NATIVE(physical_write_byte),
  DEFINE_NATIVE(physical_write_word),
  DEFINE_NATIVE(physical_write_dword),
  DEFINE_NATIVE(physical_write_qword),

  DEFINE_NATIVE(io_space_map),
  DEFINE_NATIVE(io_space_unmap),

  DEFINE_NATIVE(virtual_read_byte),
  DEFINE_NATIVE(virtual_read_word),
  DEFINE_NATIVE(virtual_read_dword),
  DEFINE_NATIVE(virtual_read_qword),

  DEFINE_NATIVE(virtual_write_byte),
  DEFINE_NATIVE(virtual_write_word),
  DEFINE_NATIVE(virtual_write_dword),
  DEFINE_NATIVE(virtual_write_qword),

  DEFINE_NATIVE(virtual_cmpxchg_byte2),
  DEFINE_NATIVE(virtual_cmpxchg_word2),
  DEFINE_NATIVE(virtual_cmpxchg_dword2),
  DEFINE_NATIVE(virtual_cmpxchg_qword2),

  DEFINE_NATIVE(virtual_alloc),
  DEFINE_NATIVE(virtual_free),

  DEFINE_NATIVE(pci_config_read_byte),
  DEFINE_NATIVE(pci_config_read_word),
  DEFINE_NATIVE(pci_config_read_dword),
  DEFINE_NATIVE(pci_config_read_qword),

  DEFINE_NATIVE(pci_config_write_byte),
  DEFINE_NATIVE(pci_config_write_word),
  DEFINE_NATIVE(pci_config_write_dword),
  DEFINE_NATIVE(pci_config_write_qword),

  DEFINE_NATIVE(invoke),

  DEFINE_NATIVE(microsleep),
  DEFINE_NATIVE(microsleep2),

  DEFINE_NATIVE(qpc),

#if defined(ARCH_A64)

#elif defined(ARCH_X64)

  DEFINE_NATIVE(query_dell_smm),

  DEFINE_NATIVE(io_out_byte),
  DEFINE_NATIVE(io_out_word),
  DEFINE_NATIVE(io_out_dword),

  DEFINE_NATIVE(io_in_byte),
  DEFINE_NATIVE(io_in_word),
  DEFINE_NATIVE(io_in_dword),

  DEFINE_NATIVE(llwpcb),
  DEFINE_NATIVE(slwpcb),

  DEFINE_NATIVE(cpuid),

  DEFINE_NATIVE(cr_read),
  DEFINE_NATIVE(cr_write),

  DEFINE_NATIVE(dr_read),
  DEFINE_NATIVE(dr_write),

  DEFINE_NATIVE(xcr_read),
  DEFINE_NATIVE(xcr_write),

  DEFINE_NATIVE(invlpg),
  DEFINE_NATIVE(invpcid),

  DEFINE_NATIVE(readpmc),

  DEFINE_NATIVE(rdtsc),
  DEFINE_NATIVE(rdtscp),

  DEFINE_NATIVE(rdrand),
  DEFINE_NATIVE(rdseed),

  DEFINE_NATIVE(lidt),
  DEFINE_NATIVE(sidt),

  DEFINE_NATIVE(lgdt),
  DEFINE_NATIVE(sgdt),

  DEFINE_NATIVE(mxcsr_read),
  DEFINE_NATIVE(mxcsr_write),

  DEFINE_NATIVE(stac),
  DEFINE_NATIVE(clac),

  DEFINE_NATIVE(halt),

  DEFINE_NATIVE(ud2),

  DEFINE_NATIVE(int3),

  DEFINE_NATIVE(int2c),

  DEFINE_NATIVE(wbinvd),

#endif

#undef DEFINE_NATIVE
};

void __cdecl operator delete(void*, size_t) {
  __debugbreak();
}

struct context {
  std::aligned_storage_t<sizeof(amx64_loader), alignof(amx64_loader)> loader_storage;
  amx64_loader* loader;
  const uint8_t* original_buf;
  size_t original_buf_size;
  FAST_MUTEX mutex;
};

constexpr static uint8_t k_pubkey_namazso_2023[] = {0x52, 0x53, 0x41, 0x31, 0x00, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xB5, 0x45, 0xB8, 0x15, 0xF0, 0x2A, 0xEB, 0xCA, 0xC9, 0x35, 0x8F, 0x54, 0x15, 0x83, 0x12, 0x2C, 0xC3, 0xF3, 0x5E, 0x1E, 0xE7, 0xFB, 0xD3, 0xE1, 0x68, 0x73, 0x3B, 0x36, 0xC0, 0x5C, 0x6F, 0xD3, 0xBA, 0xF4, 0xD0, 0xA9, 0x9B, 0x6E, 0x9C, 0x66, 0x43, 0x2F, 0xC9, 0xB2, 0x82, 0xDF, 0x24, 0x6D, 0x8F, 0x5F, 0x45, 0xAF, 0x02, 0xDD, 0x6A, 0xEF, 0x04, 0x01, 0x74, 0x69, 0xC3, 0x20, 0x70, 0xDB, 0x3F, 0x05, 0x97, 0x9E, 0xE6, 0x01, 0x6B, 0x9E, 0x28, 0x53, 0x03, 0x59, 0x02, 0x98, 0x4C, 0x41, 0xAB, 0xB2, 0x56, 0x5F, 0xD6, 0x24, 0x98, 0xD1, 0xB3, 0xF9, 0xF8, 0x46, 0xC7, 0x21, 0x4B, 0xDF, 0xFD, 0xF2, 0x88, 0x2A, 0xCE, 0xDC, 0x75, 0x36, 0x40, 0xC2, 0x5E, 0x0B, 0x26, 0x17, 0x7A, 0x3D, 0xD6, 0x34, 0xD7, 0x47, 0xD6, 0x61, 0xE1, 0x33, 0xD7, 0x7A, 0x00, 0x7E, 0x9F, 0xEB, 0x92, 0x33, 0x52, 0x65, 0x8E, 0xF8, 0x7C, 0x49, 0xD4, 0x22, 0xB8, 0x22, 0xBD, 0x59, 0x56, 0xBC, 0xD5, 0x1B, 0x64, 0x4C, 0x91, 0x50, 0xAB, 0x1F, 0x67, 0x9F, 0x84, 0xDD, 0x8B, 0x4F, 0xFC, 0x28, 0x26, 0x52, 0x36, 0x49, 0x67, 0x0D, 0x6C, 0xA4, 0xA1, 0xAA, 0xEC, 0x2B, 0xB0, 0x05, 0x09, 0x08, 0x20, 0x38, 0x82, 0xAE, 0x47, 0xB9, 0x3C, 0xAE, 0x50, 0xBF, 0x93, 0x69, 0x94, 0xB5, 0x98, 0x7C, 0xA8, 0x2E, 0xA9, 0x8E, 0x7B, 0xC2, 0xB2, 0x12, 0xB9, 0xB1, 0x62, 0x46, 0x3C, 0xED, 0x24, 0x9C, 0x89, 0xE0, 0xB8, 0x46, 0x26, 0x1A, 0x5A, 0x08, 0xD6, 0xF0, 0x2A, 0xA3, 0x28, 0xB6, 0x73, 0x60, 0xAE, 0xC3, 0x2D, 0x4C, 0x5A, 0x24, 0xF1, 0x58, 0x4C, 0x51, 0xD2, 0x66, 0xE9, 0xD9, 0x61, 0x98, 0x4D, 0xDE, 0x94, 0xD8, 0x44, 0x1F, 0x62, 0xF6, 0x4E, 0xF9, 0x73, 0x44, 0xA4, 0x7A, 0x2C, 0x2D, 0xC1, 0xDB, 0x4F, 0x58, 0xD6, 0x70, 0xB2, 0x6E, 0xE8, 0xD9, 0x50, 0x01, 0x35, 0x4F, 0x39, 0x49, 0x2E, 0x09, 0x76, 0x47, 0x9C, 0x3C, 0x7E, 0x72, 0x33, 0xCA, 0x13, 0xD7, 0x29, 0x82, 0xFB, 0x14, 0xAD, 0x4E, 0xC3, 0xA6, 0xC6, 0x4C, 0x18, 0x84, 0xB5, 0x83, 0x7A, 0xF0, 0x99, 0xBA, 0x1D, 0x56, 0xD2, 0xA2, 0xDF, 0x14, 0x34, 0x01, 0x6F, 0x83, 0x8D, 0xB8, 0xA0, 0x16, 0x2C, 0x36, 0x90, 0x0F, 0x96, 0x2D, 0x3B, 0x80, 0x58, 0x5C, 0xE7, 0x9D, 0x0D, 0x73, 0x38, 0xCA, 0xEE, 0x43, 0xF7, 0xC0, 0x37, 0xA4, 0xEA, 0xDD, 0x76, 0xCC, 0xA2, 0xF3, 0x54, 0xC8, 0x45, 0xC9, 0xBE, 0x3F, 0xCE, 0xAA, 0x98, 0x2F, 0x4C, 0x97, 0x87, 0x56, 0x00, 0x81, 0x6A, 0x7A, 0x41, 0x52, 0xF7, 0xF9, 0x0D, 0xEE, 0x5D, 0xB6, 0x05, 0x1F, 0x40, 0x9F, 0xDE, 0x75, 0x97, 0xD5, 0x8F, 0x28, 0x04, 0xDA, 0x57, 0xA2, 0x76, 0x52, 0x49, 0x35, 0xAC, 0x54, 0xF3, 0x09, 0xA6, 0x68, 0xEC, 0x84, 0xB8, 0x87, 0xD9, 0xBE, 0x26, 0xED, 0xFD, 0x75, 0x7D, 0x2A, 0x1B, 0x55, 0x18, 0x31, 0xA7, 0xA0, 0x44, 0xC5, 0x4A, 0x05, 0xD2, 0x55, 0x44, 0x70, 0x1D, 0x35, 0xE4, 0x61, 0x03, 0x5D, 0x82, 0x3C, 0x48, 0x40, 0x5F, 0x58, 0x64, 0x4E, 0xFF, 0xA6, 0xA1, 0x24, 0x7A, 0xAC, 0xF0, 0xF8, 0x3F, 0x9E, 0x9B, 0xE0, 0x53, 0x04, 0x55, 0xB1, 0xED, 0xDC, 0xC0, 0xC9, 0x9E, 0x5E, 0x31, 0x46, 0x09, 0x83, 0x51, 0x41, 0xBD, 0x41, 0x73, 0xC0, 0xD8, 0x36, 0x23, 0xAE, 0x0B, 0xDF, 0x89, 0x67, 0x2A, 0xC7, 0x56, 0x36, 0xA8, 0xE2, 0x76, 0xB8, 0xCB, 0x75, 0xA1, 0xF0, 0x7C, 0xAC, 0x4D, 0xCD, 0x56, 0xBB, 0x6A, 0x03, 0xCA, 0x7A, 0x89, 0xD2, 0x06, 0xE9, 0x02, 0x48, 0x17, 0x2F, 0xCF, 0xBC, 0xC1, 0xB6, 0xF7, 0xBF, 0x8A, 0xC1, 0xA7, 0x9B};

constexpr static trusted_pubkey k_trusted_keys[] = {
  {k_pubkey_namazso_2023, sizeof(k_pubkey_namazso_2023)},
  {}
};

const trusted_pubkey* pawnio_trusted_keys() {
  return k_trusted_keys;
}

static NTSTATUS check_signature(const void* mem, size_t len, const uint8_t* sig, size_t sig_len) {
  sha256_buf sha256;
  auto status = calculate_sha256(mem, len, &sha256);
  if (!NT_SUCCESS(status))
    return status;

  for (auto it = k_trusted_keys; it->data; ++it) {
    status = verify_sig(sha256, sig, sig_len, it->data, it->len);
    if (NT_SUCCESS(status))
      break;
  }

  return status;
}

static NTSTATUS vm_load_binary_internal(context** ctx, PVOID buffer, SIZE_T size) {
  *ctx = nullptr;

  if (size < 4)
    return STATUS_INVALID_PARAMETER;
  const auto sig_len = *(PULONG)buffer;
  if (sig_len > (size - 4))
    return STATUS_INVALID_PARAMETER;

  const auto mem = (uint8_t*)buffer + 4 + sig_len;
  const auto len = size - 4 - sig_len;

  auto status = check_signature(mem, len, (uint8_t*)buffer + 4, sig_len);

#ifdef PAWNIO_UNRESTRICTED
  DbgPrint("[PawnIO] Signature check result: %X\n", status);
  status = STATUS_SUCCESS;
#endif

  if (NT_SUCCESS(status)) {
    // extra copy
    const auto copy = (uint8_t*)ExAllocatePoolZero(NonPagedPoolNxCacheAligned, size, 'cpmA');
    if (!copy) {
      status = STATUS_NO_MEMORY;
    } else {
      // load
      const auto my_ctx = (context*)ExAllocatePoolZero(NonPagedPoolNxCacheAligned, sizeof(context), 'OIwP');
      if (!my_ctx) {
        status = STATUS_NO_MEMORY;
      } else {
        memcpy(copy, buffer, size);
        my_ctx->original_buf = copy;
        my_ctx->original_buf_size = size;
        ExInitializeFastMutex(&my_ctx->mutex);
        const auto loader = new(&my_ctx->loader_storage) amx64_loader();
        my_ctx->loader = loader;

        constexpr static amx64_loader::callbacks_arg callbacks
        {
          NATIVES,
          std::size(NATIVES),
          nullptr,
          nullptr,
          nullptr
        };

        const auto result = loader->init(mem, len, callbacks);

        if (result != amx::loader_error::success) {
          status = STATUS_UNSUCCESSFUL;
        } else {
          *ctx = my_ctx;
          return STATUS_SUCCESS;
        }

        loader->~amx64_loader();
        ExFreePool(my_ctx);
      }

      ExFreePool(copy);
    }
  }
  return status;
}

static NTSTATUS vm_destroy_internal(context* ctx) {
  const auto loader = ctx->loader;
  const auto copy = const_cast<uint8_t*>(ctx->original_buf);
  loader->~amx64_loader();
  ExFreePool(ctx);
  ExFreePool(copy);
  return STATUS_SUCCESS;
}

NTSTATUS vm_load_binary(PVOID* ctx, PVOID buffer, SIZE_T size) {
  *ctx = nullptr;

  context* my_ctx{};
  auto status = vm_load_binary_internal(&my_ctx, buffer, size);
  if (!NT_SUCCESS(status))
    return status;

  status = vm_callback_created(my_ctx);
  if (NT_SUCCESS(status)) {
    const auto loader = my_ctx->loader;
    if (const auto main = loader->get_main()) {
      status = vm_callback_precall(my_ctx, main);
      if (NT_SUCCESS(status)) {
        cell ret{};
        const auto res = loader->amx.call(main, ret);
        vm_callback_postcall(my_ctx);

        if (res != amx::error::success)
          status = STATUS_UNSUCCESSFUL;
        else
          status = (NTSTATUS)ret;
      }
    }
  }

  if (!NT_SUCCESS(status)) {
    vm_callback_destroyed(my_ctx);
    vm_destroy_internal(my_ctx);
    return status;
  }

  *ctx = my_ctx;
  return status;
}

NTSTATUS vm_execute_function(PVOID ctx, PVOID in_buffer, SIZE_T in_size, PVOID out_buffer, SIZE_T out_size) {
  if (in_size < 32)
    return STATUS_INVALID_PARAMETER;
  char arr[33];
  arr[32] = 0;
  memcpy(arr, in_buffer, 32);
  if (strlen(arr) == 32)
    return STATUS_INVALID_PARAMETER;

  if (strncmp(arr, "ioctl_", 6) != 0)
    return STATUS_INVALID_PARAMETER;

  if (!ctx)
    return STATUS_DEVICE_NOT_READY;

  // call function
  const auto my_ctx = (context*)ctx;
  const auto loader = my_ctx->loader;
  const auto fn = loader->get_public(arr);
  if (!fn)
    return STATUS_OBJECT_NAME_NOT_FOUND;

  auto& amx = loader->amx;

  const auto cell_in_buffer = (cell*)in_buffer + 4;
  const auto cell_in_count = in_size / sizeof(cell) - 4;
  cell cell_in_va{};

  const auto cell_out_buffer = (cell*)out_buffer;
  const auto cell_out_count = out_size / sizeof(cell);
  cell cell_out_va{};

  NTSTATUS status = STATUS_SUCCESS;

  ExAcquireFastMutex(&my_ctx->mutex);

  if (amx.mem.data().map(cell_in_buffer, cell_in_count, cell_in_va)) {
    if (amx.mem.data().map(cell_out_buffer, cell_out_count, cell_out_va)) {
      status = vm_callback_precall(my_ctx, fn);
      if (NT_SUCCESS(status)) {
        amx64::cell out{};
        const auto DAT = loader->amx.DAT;
        const auto ret = loader->amx.call(fn, out, {cell_in_va - DAT, cell_in_count, cell_out_va - DAT, cell_out_count});
        vm_callback_postcall(my_ctx);
        if (ret != amx::error::success) {
          DbgPrint("[PawnIO] Call to %s failed: %X\n", arr, ret);
          status = STATUS_UNSUCCESSFUL;
        } else {
          status = (NTSTATUS)out;
        }
      }

      amx.mem.data().unmap(cell_out_va, cell_out_count);
    } else {
      status = STATUS_UNSUCCESSFUL;
    }
    amx.mem.data().unmap(cell_in_va, cell_in_count);
  } else {
    status = STATUS_UNSUCCESSFUL;
  }

  ExReleaseFastMutex(&my_ctx->mutex);

  return status;
}

NTSTATUS vm_destroy(PVOID ctx) {
  if (ctx) {
    const auto my_ctx = (context*)ctx;
    const auto loader = my_ctx->loader;
    const auto fn = loader->get_public("unload");
    if (fn) {
      auto status = vm_callback_precall(my_ctx, fn);
      if (NT_SUCCESS(status)) {
        cell ret{};
        loader->amx.call(fn, ret);
        vm_callback_postcall(my_ctx);
      }
    }
    vm_callback_destroyed(my_ctx);
    return vm_destroy_internal(my_ctx);
  }

  return STATUS_SUCCESS;
}
