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

#ifndef AMX_ASSERT
#define AMX_ASSERT(cond) ((cond) ? (void)0 : __fastfail(FAST_FAIL_FATAL_APP_EXIT))
#endif

#include <amx.h>

namespace amx {
  enum class loader_error {
    success,
    invalid_file,
    unsupported_file_version,
    unsupported_amx_version,
    feature_not_supported,
    wrong_cell_size,
    native_not_resolved,
    unknown,
    out_of_memory
  };

  namespace detail {
    template <typename T>
    static T byteswap(T t) {
      for (size_t i = 0; i < sizeof(t) / 2; ++i)
        std::swap(*(((char*)&t) + i), *((char*)&t + sizeof(t) - 1 - i));
      return t;
    }

    template <typename T>
    static T from_le(T t) {
#if defined(BIG_ENDIAN)
      return byteswap(t);
#elif defined(LITTLE_ENDIAN)
      return t;
#else
#error Define either BIG_ENDIAN or LITTLE_ENDIAN
#endif
    }

    template <typename T>
    static T read_le(const uint8_t* p) {
      T t{};
      memcpy(&t, p, sizeof(t));
      t = from_le(t);
      return t;
    }

    template <typename T>
    static T align_up(T value, size_t align) {
      return (T)((value + align - 1) / align * align);
    }

    template <typename Fn>
    static bool iter_valarray(
      const uint8_t* buf,
      size_t buf_size,
      size_t begin_offset,
      size_t end_offset,
      size_t entry_size,
      Fn fn = {}
    ) {
      if (begin_offset > buf_size || end_offset > buf_size)
        return false;
      if (begin_offset > end_offset)
        return false;
      const auto size = end_offset - begin_offset;
      if (size % entry_size != 0)
        return false;

      const auto begin = buf + begin_offset;
      for (size_t i = 0; i < size / entry_size; ++i)
        if (!fn(begin + i * entry_size))
          return false;
      return true;
    }

    static bool count_valarray(
      const uint8_t* buf,
      size_t buf_size,
      size_t begin_offset,
      size_t end_offset,
      size_t entry_size,
      size_t& count
    ) {
      // local to help the compiler optimize
      size_t count_local{};
      const auto ret = iter_valarray(
        buf,
        buf_size,
        begin_offset,
        end_offset,
        entry_size,
        [&count_local](const uint8_t*) {
          ++count_local;
          return true;
        });
      count = count_local;
      return ret;
    }

    constexpr static size_t max_name_length = 63;

    static bool find_name_end(const uint8_t* buf, size_t buf_size, uint32_t nameofs, size_t& nameend) {
      if (nameofs >= buf_size)
        return false;
      const auto limit = (std::min)(buf_size, (size_t)nameofs + max_name_length + 1);
      for (nameend = nameofs; nameend < limit; ++nameend)
        if (!buf[nameend])
          return true;
      return false;
    }

    template <typename T>
    static void alloc_from_buffer_aligned(
      uint8_t*& buf,
      T*& alloc_out_buf,
      size_t& alloc_out_count,
      size_t alloc_count
    ) {
      alloc_out_buf = (T*)buf;
      alloc_out_count = alloc_count;
      buf += align_up(alloc_count * sizeof(*alloc_out_buf), MEMORY_ALLOCATION_ALIGNMENT);
    }
  }

  template <typename Amx>
  class loader {
  public:
    using amx_t = Amx;

    using cell = typename amx_t::cell;
    using scell = typename amx_t::scell;
    constexpr static size_t cell_bits = amx_t::cell_bits;

  private:
    constexpr static uint16_t expected_magic =
      cell_bits == 32 ? 0xF1E0 : cell_bits == 64 ? 0xF1E1 : cell_bits == 16 ? 0xF1E2 : 0;

    enum : uint32_t {
      flag_overlay = 1 << 0,
      flag_debug = 1 << 1,
      flag_nochecks = 1 << 2,
      flag_sleep = 1 << 3,
      flag_crypt = 1 << 4,
      flag_dseg_init = 1 << 5,
    };

    constexpr static uint32_t max_stack_heap = 16 * 1024 * 1024;

    cell* _code_ptr{};
    size_t _code_count{};
    cell* _data_ptr{};
    size_t _data_count{};

  public:
    amx_t amx{&amx_callback_wrapper, this};

    using native_fn = error(*)(amx_t* amx, loader* loader, void* user, cell argc, cell argv, cell& retval);
    using single_step_fn = error(*)(amx_t* amx, loader* loader, void* user);
    using break_fn = error(*)(amx_t* amx, loader* loader, void* user);

    struct native_arg {
      const char* name;
      native_fn callback;
    };

    struct callbacks_arg {
      const native_arg* natives;
      size_t natives_count;
      single_step_fn on_single_step;
      break_fn on_break;
      void* user_data;
    };

  private:
    single_step_fn _on_single_step{};
    break_fn _on_break{};
    void* _callback_user_data{};

    native_fn* _natives_ptr{};
    size_t _natives_count{};

    std::pair<const char*, cell>* _publics_ptr{};
    size_t _publics_count{};

    std::pair<const char*, cell>* _pubvars_ptr{};
    size_t _pubvars_count{};

    cell _main{};
    cell _code_base{};
    cell _data_base{};
    bool _mapped{};

    void* _alloc{};

  public:
    cell get_public(const char* v) {
      const auto begin = _publics_ptr;
      const auto end = begin + _publics_count;
      const auto result = std::find_if(
        begin,
        end,
        [v](std::pair<const char*, cell>& a) {
          return 0 == strcmp(v, a.first);
        });

      return result == end ? 0 : result->second;
    }

    cell get_pubvar(const char* v) {
      const auto begin = _pubvars_ptr;
      const auto end = begin + _pubvars_count;
      const auto result = std::find_if(
        begin,
        end,
        [v](std::pair<const char*, cell>& a) {
          return 0 == strcmp(v, a.first);
        });

      return result == end ? 0 : result->second;
    }

    cell get_main() { return _main; }

  private:
    error amx_callback(cell index, cell stk, cell& pri) {
      if (index == amx_t::cbid_single_step)
        return _on_single_step ? _on_single_step(&amx, this, _callback_user_data) : error::success;
      if (index == amx_t::cbid_break)
        return _on_break ? _on_break(&amx, this, _callback_user_data) : error::success;
      if (index >= _natives_count)
        return error::invalid_operand;
      const auto pargc = amx.data_v2p(stk);
      if (!pargc)
        return error::access_violation;
      return _natives_ptr[(size_t)index](&amx, this, _callback_user_data, (*pargc / sizeof(cell)), stk + sizeof(cell), pri);
    }

    static error amx_callback_wrapper(amx_t*, void* user_data, cell index, cell stk, cell& pri) {
      return ((loader*)user_data)->amx_callback(index, stk, pri);
    }

    static loader_error check_code_is_core(const uint8_t* code, size_t count) {
      constexpr static uint8_t operand_counts[]{
        0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1,
        0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0,
        0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 0, 0, 0
      };
      constexpr static cell op_casetbl = 74;
      constexpr static cell op_last_defined = 174;

      size_t i = 0;
      while (i < count) {
        const auto opcode = detail::read_le<cell>(code + i * sizeof(cell));
        if (opcode == op_casetbl) {
          if (count - i < 3)
            return loader_error::invalid_file;
          const auto records = detail::read_le<cell>(code + (i + 1) * sizeof(cell));
          if ((uint64_t)records > (uint64_t)((count - i - 3) / 2))
            return loader_error::invalid_file;
          i += 3 + 2 * (size_t)records;
        } else if (opcode < sizeof(operand_counts)) {
          i += (size_t)1 + operand_counts[(size_t)opcode];
        } else if (opcode <= op_last_defined) {
          return loader_error::feature_not_supported;
        } else {
          return loader_error::invalid_file;
        }
      }
      if (i != count)
        return loader_error::invalid_file;
      return loader_error::success;
    }

  public:
    loader_error init(const uint8_t* buf, size_t buf_size, const callbacks_arg& callbacks) {
      static_assert(expected_magic != 0, "unsupported cell size");
      using namespace detail;

      if (buf_size < 60)
        return loader_error::invalid_file;

      const auto size = read_le<uint32_t>(buf);
      const auto magic = read_le<uint16_t>(buf + 4);
      const auto file_version = *(buf + 6);
      const auto amx_version = *(buf + 7);
      const auto flags = read_le<uint16_t>(buf + 8);
      const auto defsize = read_le<uint16_t>(buf + 10);
      const auto cod = read_le<uint32_t>(buf + 12);
      const auto dat = read_le<uint32_t>(buf + 16);
      const auto hea = read_le<uint32_t>(buf + 20);
      const auto stp = read_le<uint32_t>(buf + 24);
      const auto cip = read_le<uint32_t>(buf + 28);
      const auto publics = read_le<uint32_t>(buf + 32);
      const auto natives = read_le<uint32_t>(buf + 36);
      const auto libraries = read_le<uint32_t>(buf + 40);
      const auto pubvars = read_le<uint32_t>(buf + 44);
      const auto tags = read_le<uint32_t>(buf + 48);
      //const auto nametable = read_le<uint32_t>(buf + 52);
      //const auto overlays = read_le<uint32_t>(buf + 56);
      if (magic != expected_magic) {
        switch (magic) {
        case 0xF1E0:
        case 0xF1E1:
        case 0xF1E2:
          return loader_error::wrong_cell_size;
        default:
          return loader_error::invalid_file;
        }
      }
      if (size < 60 || size > buf_size)
        return loader_error::invalid_file;
      if (file_version != 11)
        return loader_error::unsupported_file_version;
      if (amx_version > amx_t::version)
        return loader_error::unsupported_amx_version;
      if (flags & flag_overlay || flags & flag_sleep || flags & flag_crypt)
        return loader_error::feature_not_supported;
      if (defsize < 8)
        return loader_error::invalid_file;
      if (cod < 60 || cod > dat || dat > hea || hea > size || stp < hea)
        return loader_error::invalid_file;
      if (stp - hea > max_stack_heap)
        return loader_error::invalid_file;
      if ((dat - cod) % sizeof(cell) != 0 || (hea - dat) % sizeof(cell) != 0 || (stp - hea) % sizeof(cell) != 0)
        return loader_error::invalid_file;
      if ((dat - cod) / sizeof(cell) > (cell)~(cell)0 / sizeof(cell))
        return loader_error::invalid_file;
      if ((stp - dat) / sizeof(cell) > (cell)~(cell)0 / sizeof(cell))
        return loader_error::invalid_file;
      if (publics < 60 || publics > natives || natives > libraries || libraries > pubvars || pubvars > tags || tags > cod)
        return loader_error::invalid_file;
      if (libraries != pubvars)
        return loader_error::feature_not_supported;
      if (cip != (uint32_t)-1 && (cip % sizeof(cell) != 0 || cip >= dat - cod))
        return loader_error::invalid_file;

      size_t code_count{};
      if (!count_valarray(buf, size, cod, dat, sizeof(cell), code_count))
        return loader_error::invalid_file;

      const auto code_check = check_code_is_core(buf + cod, code_count);
      if (code_check != loader_error::success)
        return code_check;

      size_t data_count{};
      if (!count_valarray(buf, size, dat, hea, sizeof(cell), data_count))
        return loader_error::invalid_file;

      const auto data_alloc_count = data_count + (stp - hea) / sizeof(cell);

      const auto main = (cell)(cip == (uint32_t)-1 ? 0 : cip);

      size_t string_buffer_size{};

      size_t publics_count{};

      auto success = iter_valarray(
        buf,
        size,
        publics,
        natives,
        defsize,
        [&](const uint8_t* p) {
          const auto address = read_le<uint32_t>(p);
          const auto nameofs = read_le<uint32_t>(p + 4);
          if (address % sizeof(cell) != 0 || address >= dat - cod)
            return false;
          size_t nameend{};
          if (!find_name_end(buf, size, nameofs, nameend))
            return false;
          ++publics_count;
          string_buffer_size += nameend - nameofs + 1;
          return true;
        }
      );

      if (!success)
        return loader_error::invalid_file;

      size_t natives_count{};
      bool native_not_found = false;
      success = iter_valarray(
        buf,
        size,
        natives,
        libraries,
        defsize,
        [&](const uint8_t* p) {
          const auto nameofs = read_le<uint32_t>(p + 4);
          size_t nameend{};
          if (!find_name_end(buf, size, nameofs, nameend))
            return false;
          const auto begin = (const char*)buf + nameofs;

          const auto callbacks_natives_end = callbacks.natives + callbacks.natives_count;
          const auto result = std::find_if(
            callbacks.natives,
            callbacks_natives_end,
            [&begin](const native_arg& current) { return 0 == strcmp(begin, current.name); }
          );
          if (result == callbacks_natives_end) {
            native_not_found = true;
            return false;
          }
          ++natives_count;
          return true;
        }
      );

      if (!success)
        return native_not_found ? loader_error::native_not_resolved : loader_error::invalid_file;

      size_t pubvars_count{};
      success = iter_valarray(
        buf,
        size,
        pubvars,
        tags,
        defsize,
        [&](const uint8_t* p) {
          const auto address = read_le<uint32_t>(p);
          const auto nameofs = read_le<uint32_t>(p + 4);
          if (address % sizeof(cell) != 0 || address >= hea - dat)
            return false;
          size_t nameend{};
          if (!find_name_end(buf, size, nameofs, nameend))
            return false;
          ++pubvars_count;
          string_buffer_size += nameend - nameofs + 1;
          return true;
        }
      );

      if (!success)
        return loader_error::invalid_file;

      const size_t alloc_size = 0
                                + align_up(code_count * sizeof(cell), MEMORY_ALLOCATION_ALIGNMENT)
                                + align_up(data_alloc_count * sizeof(cell), MEMORY_ALLOCATION_ALIGNMENT)
                                + align_up(publics_count * sizeof(*_publics_ptr), MEMORY_ALLOCATION_ALIGNMENT)
                                + align_up(pubvars_count * sizeof(*_pubvars_ptr), MEMORY_ALLOCATION_ALIGNMENT)
                                + align_up(natives_count * sizeof(*_natives_ptr), MEMORY_ALLOCATION_ALIGNMENT)
                                + string_buffer_size;

      const auto alloc = ExAllocatePoolZero(NonPagedPoolNx, alloc_size, 'LxmA');
      if (!alloc)
        return loader_error::out_of_memory;

      cell* code_ptr{};
      size_t code_ptr_count{};
      cell* data_ptr{};
      size_t data_ptr_count{};
      std::pair<const char*, cell>* publics_ptr{};
      size_t publics_ptr_count{};
      std::pair<const char*, cell>* pubvars_ptr{};
      size_t pubvars_ptr_count{};
      native_fn* natives_ptr{};
      size_t natives_ptr_count{};

      auto alloc_it = (uint8_t*)alloc;

      alloc_from_buffer_aligned(alloc_it, code_ptr, code_ptr_count, code_count);
      alloc_from_buffer_aligned(alloc_it, data_ptr, data_ptr_count, data_alloc_count);
      alloc_from_buffer_aligned(alloc_it, publics_ptr, publics_ptr_count, publics_count);
      alloc_from_buffer_aligned(alloc_it, pubvars_ptr, pubvars_ptr_count, pubvars_count);
      alloc_from_buffer_aligned(alloc_it, natives_ptr, natives_ptr_count, natives_count);

      auto string_buffer = (char*)alloc_it;

      // safe since it was checked when counting
      memcpy(code_ptr, buf + cod, dat - cod);
      for (size_t i = 0; i < code_ptr_count; ++i)
        code_ptr[i] = from_le(code_ptr[i]);

      // safe since it was checked when counting
      memcpy(data_ptr, buf + dat, hea - dat);
      for (size_t i = 0; i < data_count; ++i)
        data_ptr[i] = from_le(data_ptr[i]);

      // safe since it was checked when counting
      size_t publics_counter{};
      iter_valarray(
        buf,
        size,
        publics,
        natives,
        defsize,
        [&](const uint8_t* p) {
          const auto address = read_le<uint32_t>(p);
          const auto nameofs = read_le<uint32_t>(p + 4);
          size_t nameend{};
          if (!find_name_end(buf, size, nameofs, nameend))
            return false;

          char* name = string_buffer;
          string_buffer += nameend - nameofs + 1;
          memcpy(name, buf + nameofs, nameend - nameofs + 1);

          publics_ptr[publics_counter++] = {name, address};
          return true;
        }
      );

      // safe since it was checked when counting
      size_t natives_counter{};
      iter_valarray(
        buf,
        size,
        natives,
        libraries,
        defsize,
        [&](const uint8_t* p) {
          const auto nameofs = read_le<uint32_t>(p + 4);
          size_t nameend{};
          if (!find_name_end(buf, size, nameofs, nameend))
            return false;
          const auto begin = (const char*)buf + nameofs;

          const auto callbacks_natives_end = callbacks.natives + callbacks.natives_count;
          const auto result_it = std::find_if(
            callbacks.natives,
            callbacks_natives_end,
            [&begin](const native_arg& current) { return 0 == strcmp(begin, current.name); }
          );
          if (result_it == callbacks_natives_end) {
            native_not_found = true;
            return false;
          }
          natives_ptr[natives_counter++] = result_it->callback;
          return true;
        }
      );

      // safe since it was checked when counting
      size_t pubvars_counter{};
      iter_valarray(
        buf,
        size,
        pubvars,
        tags,
        defsize,
        [&](const uint8_t* p) {
          const auto address = read_le<uint32_t>(p);
          const auto nameofs = read_le<uint32_t>(p + 4);
          size_t nameend{};
          if (!find_name_end(buf, size, nameofs, nameend))
            return false;

          char* name = string_buffer;
          string_buffer += nameend - nameofs + 1;
          memcpy(name, buf + nameofs, nameend - nameofs + 1);

          pubvars_ptr[pubvars_counter++] = {name, address};
          return true;
        }
      );

      // something went very very wrong
      if (string_buffer > (char*)alloc + alloc_size) {
        ExFreePool(alloc);
        return loader_error::unknown;
      }

      _on_single_step = callbacks.on_single_step;
      _on_break = callbacks.on_break;
      _callback_user_data = callbacks.user_data;

      if (_mapped) {
        amx.mem.code().unmap(_code_base, _code_count);
        amx.mem.data().unmap(_data_base, _data_count);
        _mapped = false;
      }

      if (_alloc)
        ExFreePool(_alloc);

      _alloc = alloc;
      _code_ptr = code_ptr;
      _code_count = code_ptr_count;
      _data_ptr = data_ptr;
      _data_count = data_ptr_count;
      _publics_ptr = publics_ptr;
      _publics_count = publics_ptr_count;
      _pubvars_ptr = pubvars_ptr;
      _pubvars_count = pubvars_ptr_count;
      _natives_ptr = natives_ptr;
      _natives_count = natives_ptr_count;
      _main = main;

      cell code_base{};
      if (!amx.mem.code().map(_code_ptr, _code_count, code_base))
        return loader_error::unknown;

      cell data_base{};
      if (!amx.mem.data().map(_data_ptr, _data_count, data_base)) {
        amx.mem.code().unmap(code_base, _code_count);
        return loader_error::unknown;
      }

      _code_base = code_base;
      _data_base = data_base;
      _mapped = true;

      amx.COD = code_base;
      amx.DAT = data_base;

      amx.PRI = amx.ALT = amx.FRM = amx.CIP = 0;
      amx.STK = amx.STP = (cell)(_data_count * sizeof(cell));
      amx.HEA = (cell)(data_count * sizeof(cell));

      return loader_error::success;
    }

    loader() = default;

    ~loader() {
      if (_alloc)
        ExFreePool(_alloc);
    }

    loader(const loader&) = delete;
    loader(loader&&) = delete;

    loader& operator=(const loader&) = delete;
    loader& operator=(loader&&) = delete;
  };
}
