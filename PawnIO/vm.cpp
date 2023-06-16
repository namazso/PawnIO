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

#include <ntddk.h>
#include <cstdint>
#include <algorithm>
#include <tuple>
#define LITTLE_ENDIAN
#include "amx_loader.h"
#include "natives_impl.h"

#include "vm.h"

using amx64 = amx::amx<uint64_t, amx::memory_manager_neumann<amx::memory_backing_paged_buffers<5>>>;
using amx64_loader = amx::loader<amx64>;

static_assert(std::is_same_v<cell, amx64::cell>, "cell mismatch");

template <typename ArgT, size_t Index>
class arg_wrapper{};

template <size_t Index>
class arg_wrapper<cell&, Index>
{
  cell* p{};
public:
  arg_wrapper() = default;
  amx::error init(amx64* amx, cell, cell argv)
  {
    p = amx->data_v2p(argv + Index * sizeof(cell));
    if (!p)
      return amx::error::access_violation;
    p = amx->mem.data().translate(*p);
    if (!p)
      return amx::error::access_violation;
    return amx::error::success;
  }
  cell value{};
  ~arg_wrapper()
  {
    if (p)
      *p = value;
  }
};

template <size_t Index>
class arg_wrapper<cell, Index>
{
public:
  arg_wrapper() = default;
  amx::error init(amx64* amx, cell, cell argv)
  {
    const auto p = amx->data_v2p(argv + Index * sizeof(cell));
    if (!p)
      return amx::error::access_violation;
    value = *p;
    return amx::error::success;
  }
  cell value{};
  ~arg_wrapper() = default;
};

template <size_t N, size_t Index>
class arg_wrapper<std::array<cell, N>&, Index>
{
  std::array<cell*, N> ps{};
public:
  arg_wrapper() = default;
  amx::error init(amx64* amx, cell, cell argv)
  {
    const auto p = amx->data_v2p(argv + Index * sizeof(cell));
    if (!p)
      return amx::error::access_violation;
    const auto arr_base = *p;
    for (size_t i = 0; i < N; ++i)
    {
      const auto elem = amx->mem.data().translate(arr_base + i * sizeof(cell));
      if (!elem)
      {
        ps = {};
        return amx::error::access_violation;
      }
      ps[i] = elem;
      value[i] = *elem;
    }
    return amx::error::success;
  }
  std::array<cell, N> value{};
  ~arg_wrapper()
  {
    for (size_t i = 0; i < N; ++i)
      *(ps[i]) = value[i];
  }
};

template <size_t N, size_t Index>
class arg_wrapper<std::array<cell, N>, Index>
{
public:
  arg_wrapper() = default;
  amx::error init(amx64* amx, cell, cell argv)
  {
    const auto p = amx->data_v2p(argv + Index * sizeof(cell));
    if (!p)
      return amx::error::access_violation;
    const auto arr_base = *p;
    for (size_t i = 0; i < N; ++i)
    {
      const auto elem = amx->mem.data().translate(arr_base + i * sizeof(cell));
      if (!elem)
        return amx::error::access_violation;
      value[i] = *elem;
    }
    return amx::error::success;
  }
  std::array<cell, N> value{};
  ~arg_wrapper() = default;
};

// Implement wrapped tuple type.
//
namespace impl
{
  template<typename Tp, typename Ti>
  struct wtuple;
  template<typename Tp, size_t... Ix>
  struct wtuple<Tp, std::index_sequence<Ix...>> {
    using type = std::tuple<arg_wrapper<std::tuple_element_t<Ix, Tp>, Ix>...>;
  };
  template<typename... Tx>
  using wtuple_t = typename wtuple<std::tuple<Tx...>, std::make_index_sequence<sizeof...(Tx)>>::type;

  template<size_t N, typename T>
  __forceinline  amx::error init_wtuple(amx64* amx, cell argc, cell argv, T& tuple)
  {
    if constexpr (N == std::tuple_size_v<T>) {
      return {};
    }
    else {
      auto& wrapper = std::get<N>(tuple);
      if (auto err = wrapper.init(amx, argc, argv); err != amx::error::success)
        return err;
      else
        return init_wtuple<N + 1, T>(amx, argc, argv, tuple);
    }
  }

  template<typename... Tx>
  __forceinline  std::pair<wtuple_t<Tx...>, amx::error> init_wtuple(amx64* amx, cell argc, cell argv)
  {
    std::pair<wtuple_t<Tx...>, amx::error> result = {};
    result.second = init_wtuple<0>(amx, argc, argv, result.first);
    return result;
  }
};

template <auto* Fn, typename Ret, typename... Args>
__forceinline amx::error native_callback_wrapper2(
  amx64* amx,
  amx64_loader* loader,
  void* user,
  cell argc,
  cell argv,
  cell& retval,
  Ret(*)(Args...)
)
{
  UNREFERENCED_PARAMETER(loader);
  UNREFERENCED_PARAMETER(user);

  if (argc != sizeof...(Args))
    return amx::error::invalid_operand;

  auto&& [wtuple, err] = impl::init_wtuple<Args...>(amx, argc, argv);

  if (err != amx::error::success)
    return err;

  if constexpr (std::is_same_v<Ret, void>)
  {
    retval = 0;
    std::apply(
      [&](auto&... wr) -> void
      {
        Fn(wr.value...);
      },
      wtuple
    );
  }
  else
  {
    retval = std::apply(
      [&](auto&... wr) -> Ret
      {
        return Fn(wr.value...);
      },
      wtuple
    );
  }

  // rest of the bullshit
  return amx::error::success;
}

template <auto* Fn>
amx::error native_callback_wrapper(amx64* amx, amx64_loader* loader, void* user, cell argc, cell argv, cell& retval)
{
  return native_callback_wrapper2<Fn>(amx, loader, user, argc, argv, retval, Fn);
}

amx::error debug_print(amx64* amx, amx64_loader* loader, void* user, cell argc, cell argv, cell& retval)
{
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
  while (true)
  {
    const auto pc = amx->mem.data().translate(vit);
    vit += sizeof(cell);
    if (!pc)
      return amx::error::access_violation;
    const auto c = (char)*pc;
    char to_cat[10]{};
    if (in_escape)
      switch (c)
      {
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
      switch (c)
      {
      case '%':
        in_escape = true;
        break;
      case 0:
        goto leave;
      default:
        to_cat[0] = c;
        break;
      }

    const auto len = strlen(to_cat);
    if (it + len >= last)
      break; // just truncate

    memcpy(it, to_cat, len);
    it[len] = 0;
    it += len;

    continue;

  leave:
    break;
  }

  if (arg_count > argc - 1)
    return amx::error::invalid_operand;

  if (arg_count > std::size(args))
    return amx::error::invalid_operand;

  for (size_t i = 0; i < arg_count; ++i)
  {
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

amx::error get_proc_address_wrap(amx64* amx, amx64_loader* loader, void* user, cell argc, cell argv, cell& retval)
{
  UNREFERENCED_PARAMETER(loader);
  UNREFERENCED_PARAMETER(user);

  retval = 0;

  char func_name[1024]{};
  size_t idx = 0;

  if (argc == 0)
    return amx::error::invalid_operand;
  const auto pvfmt = amx->data_v2p(argv);
  if (!pvfmt)
    return amx::error::access_violation;
  const auto vfmt = *pvfmt;
  auto vit = vfmt;
  while (true)
  {
    const auto pc = amx->mem.data().translate(vit);
    vit += sizeof(cell);
    if (!pc)
      return amx::error::access_violation;
    const auto c = (char)*pc;

    func_name[idx++] = c;

    if (!c)
      break;

    if (idx == std::size(func_name))
      return amx::error::access_violation;
  }

  retval = get_proc_address(func_name);

  return amx::error::success;
}

const static amx64_loader::native_arg NATIVES[] =
{
  { "debug_print", &debug_print },
  { "get_proc_address", &get_proc_address_wrap },

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

  DEFINE_NATIVE(virtual_cmpxchg_byte),
  DEFINE_NATIVE(virtual_cmpxchg_word),
  DEFINE_NATIVE(virtual_cmpxchg_dword),
  DEFINE_NATIVE(virtual_cmpxchg_qword),

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

void __cdecl operator delete(void*, size_t)
{
  __debugbreak();
}

struct context
{
  std::aligned_storage_t<sizeof(amx64_loader), alignof(amx64_loader)> loader_storage;
  amx64_loader* loader;
  FAST_MUTEX mutex;
};

NTSTATUS check_signature(const void* mem, size_t len, const uint8_t* sig, size_t sig_len);

NTSTATUS vm_load_binary(PVOID& ctx, PVOID buffer, SIZE_T size)
{
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
  
  if (!NT_SUCCESS(status))
    return status;

  // load
  const auto my_ctx = (context*)ExAllocatePoolZero(NonPagedPoolNxCacheAligned, sizeof(context), 'OIwP');
  if (!my_ctx)
    return STATUS_NO_MEMORY;

  const auto loader = new (&my_ctx->loader_storage) amx64_loader();
  my_ctx->loader = loader;

  const amx64_loader::callbacks_arg callbacks
  {
    NATIVES,
    std::size(NATIVES),
    nullptr,
    nullptr,
    nullptr
  };

  const auto result = loader->init(mem, len, callbacks);

  if (result != amx::loader_error::success)
  {
    loader->~amx64_loader();
    ExFreePool(my_ctx);
    return STATUS_UNSUCCESSFUL;
  }

  const auto main = loader->get_main();
  if (main)
  {
    cell ret{};
    const auto res = loader->amx.call(main, ret);

    if (res != amx::error::success)
      status = STATUS_UNSUCCESSFUL;
    else
      status = (NTSTATUS)ret;

    if (!NT_SUCCESS(status))
    {
      loader->~amx64_loader();
      ExFreePool(my_ctx);
      return status;
    }
  }

  ExInitializeFastMutex(&my_ctx->mutex);

  ctx = (PVOID)my_ctx;
  return STATUS_SUCCESS;
}

NTSTATUS vm_execute_function(PVOID ctx, PVOID in_buffer, SIZE_T in_size, PVOID out_buffer, SIZE_T out_size)
{
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

  const auto cell_in_buffer = (cell*)in_buffer;
  const auto cell_in_count = in_size / sizeof(cell);
  cell cell_in_va{};

  const auto cell_out_buffer = (cell*)out_buffer;
  const auto cell_out_count = out_size / sizeof(cell);
  cell cell_out_va{};

  NTSTATUS status = STATUS_SUCCESS;

  ExAcquireFastMutex(&my_ctx->mutex);

  if (amx.mem.data().map(cell_in_buffer, cell_in_count, cell_in_va))
  {
    if (amx.mem.data().map(cell_out_buffer, cell_out_count, cell_out_va))
    {
      amx64::cell out{};
      const auto DAT = loader->amx.DAT;
      const auto ret = loader->amx.call(fn, out, { cell_in_va - DAT, cell_in_count, cell_out_va - DAT, cell_out_count });
      if (ret != amx::error::success)
      {
        DbgPrint("[PawnIO] Call to %s failed: %X\n", arr, ret);
        status = STATUS_UNSUCCESSFUL;
      }
      else
        status = (NTSTATUS)out;

      amx.mem.data().unmap(cell_out_va, cell_out_count);
    }
    else
    {
      status = STATUS_UNSUCCESSFUL;
    }
    amx.mem.data().unmap(cell_in_va, cell_in_count);
  }
  else
  {
    status = STATUS_UNSUCCESSFUL;
  }

  ExReleaseFastMutex(&my_ctx->mutex);
  
  return status;
}

NTSTATUS vm_destroy(PVOID ctx)
{
  if (ctx)
  {
    const auto my_ctx = (context*)ctx;
    my_ctx->loader->~amx64_loader();
    ExFreePool(my_ctx);
  }

  return STATUS_SUCCESS;
}
