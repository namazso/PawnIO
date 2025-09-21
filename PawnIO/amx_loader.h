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

#pragma once
#include "../PawnPP/amx.h"

namespace amx {
  enum class loader_error {
    success,
    invalid_file,
    unsupported_file_version,
    unsupported_amx_version,
    feature_not_supported,
    wrong_cell_size,
    native_not_resolved,
    unknown
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
      const auto begin = buf + begin_offset;
      const auto end = buf + end_offset;
      const auto size = (size_t)(end - begin);
      const auto buf_end = buf + buf_size;

      if (begin < buf || begin > buf_end)
        return false;
      if (end < buf || end > buf_end)
        return false;
      if (begin > end || size % entry_size != 0)
        return false;

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
      flag_dseg_init = 1 << 5,
    };

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

  public:
    loader_error init(const uint8_t* buf, size_t buf_size, const callbacks_arg& callbacks) {
      static_assert(expected_magic != 0, "unsupported cell size");
      using namespace detail;

      _on_single_step = callbacks.on_single_step;
      _on_break = callbacks.on_break;
      _callback_user_data = callbacks.user_data;

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
      if (size > buf_size)
        return loader_error::invalid_file;
      if (file_version != 11)
        return loader_error::unsupported_file_version;
      if (amx_version > amx_t::version)
        return loader_error::unsupported_amx_version;
      if (flags & flag_overlay || flags & flag_sleep)
        return loader_error::feature_not_supported;
      if (defsize < 8)
        return loader_error::invalid_file;

      size_t code_count{};
      if (!count_valarray(buf, buf_size, cod, dat, sizeof(cell), code_count))
        return loader_error::invalid_file;

      size_t data_count{};
      if (!count_valarray(buf, buf_size, dat, hea, sizeof(cell), data_count))
        return loader_error::invalid_file;

      const auto extra_size = (stp - hea) + sizeof(cell) - 1;
      const auto data_alloc_count = data_count + extra_size / sizeof(cell);

      _main = (cip == (uint32_t)-1 ? 0 : cip);

      size_t string_buffer_size{};

      size_t publics_count{};

      auto success = iter_valarray(
        buf,
        buf_size,
        publics,
        natives,
        defsize,
        [&](const uint8_t* p) {
          //const auto address = read_le<uint32_t>(p);
          const auto nameofs = read_le<uint32_t>(p + 4);
          auto nameend = nameofs;
          for (; nameend < buf_size; ++nameend)
            if (!buf[nameend])
              break;
          if (nameend >= buf_size)
            return false;
          const auto begin = (const char*)buf + nameofs;
          const auto end = (const char*)buf + nameend;
          ++publics_count;
          string_buffer_size += end - begin + 1;
          //std::string name{ begin, end };
          //this->_publics[name] = address;
          return true;
        }
      );

      if (!success)
        return loader_error::invalid_file;

      size_t natives_count{};
      bool native_not_found = false;
      success = iter_valarray(
        buf,
        buf_size,
        natives,
        libraries,
        defsize,
        [&](const uint8_t* p) {
          const auto nameofs = read_le<uint32_t>(p + 4);
          auto nameend = nameofs;
          for (; nameend < buf_size; ++nameend)
            if (!buf[nameend])
              break;
          if (nameend >= buf_size)
            return false;
          const auto begin = (const char*)buf + nameofs;
          //const auto end = (const char*)buf + nameend;

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
          //this->_natives.push_back(result->callback);
          return true;
        }
      );

      if (!success)
        return native_not_found ? loader_error::native_not_resolved : loader_error::invalid_file;

      if (libraries != pubvars)
        return loader_error::feature_not_supported;

      size_t pubvars_count{};
      success = iter_valarray(
        buf,
        buf_size,
        pubvars,
        tags,
        defsize,
        [&](const uint8_t* p) {
          //const auto address = read_le<uint32_t>(p);
          const auto nameofs = read_le<uint32_t>(p + 4);
          auto nameend = nameofs;
          for (; nameend < buf_size; ++nameend)
            if (!buf[nameend])
              break;
          if (nameend >= buf_size)
            return false;
          const auto begin = (const char*)buf + nameofs;
          const auto end = (const char*)buf + nameend;
          ++pubvars_count;
          string_buffer_size += end - begin + 1;
          //std::string name{ begin, end };
          //this->_pubvars[name] = address;
          return true;
        }
      );

      if (!success)
        return loader_error::invalid_file;

      const size_t alloc_size = 0
                                + align_up(code_count * sizeof(cell), MEMORY_ALLOCATION_ALIGNMENT)
                                + align_up(data_alloc_count * sizeof(cell), MEMORY_ALLOCATION_ALIGNMENT)
                                + align_up(publics_count * sizeof(*_publics_ptr), MEMORY_ALLOCATION_ALIGNMENT)
                                + align_up(pubvars_count * sizeof(*_publics_ptr), MEMORY_ALLOCATION_ALIGNMENT)
                                + align_up(natives_count * sizeof(*_publics_ptr), MEMORY_ALLOCATION_ALIGNMENT)
                                + string_buffer_size;

      const auto alloc = ExAllocatePoolZero(NonPagedPoolNxCacheAligned, alloc_size, 'LxmA');
      if (!alloc)
        return loader_error::unknown;

      memset(alloc, 0, alloc_size);

      _alloc = alloc;

      auto alloc_it = (uint8_t*)alloc;

      alloc_from_buffer_aligned(alloc_it, _code_ptr, _code_count, code_count);
      alloc_from_buffer_aligned(alloc_it, _data_ptr, _data_count, data_alloc_count);
      alloc_from_buffer_aligned(alloc_it, _publics_ptr, _publics_count, publics_count);
      alloc_from_buffer_aligned(alloc_it, _pubvars_ptr, _pubvars_count, pubvars_count);
      alloc_from_buffer_aligned(alloc_it, _natives_ptr, _natives_count, natives_count);

      auto string_buffer = (char*)alloc_it;

      // safe since it was checked when counting
      memcpy(_code_ptr, buf + cod, dat - cod);
      for (size_t i = 0; i < _code_count; ++i)
        _code_ptr[i] = from_le(_code_ptr[i]);

      // safe since it was checked when counting
      memcpy(_data_ptr, buf + dat, hea - dat);
      for (size_t i = 0; i < _code_count; ++i)
        _data_ptr[i] = from_le(_data_ptr[i]);

      cell code_base{};
      bool result = amx.mem.code().map(_code_ptr, _code_count, code_base);
      if (!result)
        return loader_error::unknown;

      cell data_base{};
      result = amx.mem.data().map(_data_ptr, _data_count, data_base);
      if (!result)
        return loader_error::unknown;

      // safe since it was checked when counting
      size_t publics_counter{};
      iter_valarray(
        buf,
        buf_size,
        publics,
        natives,
        defsize,
        [&](const uint8_t* p) {
          const auto address = read_le<uint32_t>(p);
          const auto nameofs = read_le<uint32_t>(p + 4);
          auto nameend = nameofs;
          for (; nameend < buf_size; ++nameend)
            if (!buf[nameend])
              break;
          if (nameend >= buf_size)
            return false;
          const auto begin = (const char*)buf + nameofs;
          const auto end = (const char*)buf + nameend;

          char* name = string_buffer;
          string_buffer += end - begin + 1;
          memcpy(name, begin, end - begin);

          this->_publics_ptr[publics_counter++] = {name, address};
          return true;
        }
      );

      // safe since it was checked when counting
      size_t natives_counter{};
      iter_valarray(
        buf,
        buf_size,
        natives,
        libraries,
        defsize,
        [&](const uint8_t* p) {
          const auto nameofs = read_le<uint32_t>(p + 4);
          auto nameend = nameofs;
          for (; nameend < buf_size; ++nameend)
            if (!buf[nameend])
              break;
          if (nameend >= buf_size)
            return false;
          const auto begin = (const char*)buf + nameofs;
          //const auto end = (const char*)buf + nameend;

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
          this->_natives_ptr[natives_counter++] = result_it->callback;
          return true;
        }
      );

      // safe since it was checked when counting
      size_t pubvars_counter{};
      iter_valarray(
        buf,
        buf_size,
        pubvars,
        tags,
        defsize,
        [&](const uint8_t* p) {
          const auto address = read_le<uint32_t>(p);
          const auto nameofs = read_le<uint32_t>(p + 4);
          auto nameend = nameofs;
          for (; nameend < buf_size; ++nameend)
            if (!buf[nameend])
              break;
          if (nameend >= buf_size)
            return false;
          const auto begin = (const char*)buf + nameofs;
          const auto end = (const char*)buf + nameend;
          ++pubvars_count;
          string_buffer_size += end - begin + 1;

          char* name = string_buffer;
          string_buffer += end - begin + 1;
          memcpy(name, begin, end - begin);

          this->_pubvars_ptr[pubvars_counter++] = {name, address};
          return true;
        }
      );

      // something went very very wrong
      if (string_buffer >= (char*)alloc + alloc_size)
        return loader_error::unknown;

      amx.COD = code_base;
      amx.DAT = data_base;

      amx.STK = amx.STP = (cell)((_data_count - 1) * sizeof(cell));
      amx.HEA = (cell)(data_count * sizeof(cell));

      return loader_error::success;
    }

    loader() = default;

    loader(const uint8_t* buf, size_t buf_size, const callbacks_arg& callbacks) {
      init(buf, buf_size, callbacks);
    }

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
