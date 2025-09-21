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

template <typename T, POOL_TYPE PoolType = NonPagedPoolNx>
class kallocator {
  static constexpr ULONG k_tag = 'olAk';

public:
  // Standard allocator typedefs
  using value_type = T;
  using pointer = T*;
  using const_pointer = const T*;
  using reference = T&;
  using const_reference = const T&;
  using size_type = size_t;
  using difference_type = ptrdiff_t;
  using propagate_on_container_move_assignment = std::true_type;
  using is_always_equal = std::true_type;

  FORCEINLINE constexpr kallocator() noexcept = default;
  FORCEINLINE constexpr kallocator(const kallocator&) noexcept = default;
  FORCEINLINE constexpr kallocator(kallocator&&) noexcept = default;
  FORCEINLINE constexpr kallocator& operator=(const kallocator&) noexcept = default;
  FORCEINLINE constexpr kallocator& operator=(kallocator&&) noexcept = default;
  FORCEINLINE ~kallocator() = default;

  // Rebind for allocating other types
  template <typename U>
  struct rebind {
    using other = kallocator<U, PoolType>;
  };

  // Copy constructor
  template <typename U>
  FORCEINLINE kallocator(const kallocator<U, PoolType>&) noexcept {}

  // Required allocator functions
  FORCEINLINE pointer allocate(size_type n) {
    // Allocate n objects of type T from kernel pool
    const size_t bytes = n * sizeof(T);

    void* p = ExAllocatePoolZero(PoolType, bytes, k_tag);
    /*if (!p) {
      KeBugCheckEx(DRIVER_OVERRAN_STACK_BUFFER, 0, 0, 0, 0);
    }*/
    return static_cast<pointer>(p);
  }

  FORCEINLINE void deallocate(pointer p, size_type) noexcept {
    if (p) {
      ExFreePoolWithTag(p, k_tag);
    }
  }

  // Construction/destruction of objects
  template <typename U, typename... Args>
  FORCEINLINE void construct(U* p, Args&&... args) {
    ::new (static_cast<void*>(p)) U(std::forward<Args>(args)...);
  }

  template <typename U>
  FORCEINLINE void destroy(U* p) {
    p->~U();
  }
};

// Equality comparison operators
template <typename T1, typename T2, POOL_TYPE PoolType>
FORCEINLINE bool operator==(const kallocator<T1, PoolType>&, const kallocator<T2, PoolType>&) noexcept {
  return true;
}

template <typename T1, typename T2, POOL_TYPE PoolType>
FORCEINLINE bool operator!=(const kallocator<T1, PoolType>&, const kallocator<T2, PoolType>&) noexcept {
  return false;
}
