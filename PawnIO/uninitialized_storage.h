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

template <typename T>
struct uninitialized_storage {
private:
  alignas(T) std::array<std::byte, sizeof(T)> storage;

public:
  // Default constructor
  FORCEINLINE constexpr uninitialized_storage() noexcept = default;

  // Forwarding constructor - only for trivially copyable types
  template <typename... Args>
  FORCEINLINE constexpr explicit uninitialized_storage(Args&&... args)
    noexcept(std::is_nothrow_constructible_v<T, Args...>)
    requires(std::is_constructible_v<T, Args...> && std::is_trivially_copyable_v<T>) {
    T temp(std::forward<Args>(args)...);
    storage = std::bit_cast<std::array<std::byte, sizeof(T)>>(temp);
  }

  // Destructor
  FORCEINLINE ~uninitialized_storage() noexcept = default;

  // Base declarations (deleted by default)
  uninitialized_storage(const uninitialized_storage&) = delete;
  uninitialized_storage& operator=(const uninitialized_storage&) = delete;
  uninitialized_storage(uninitialized_storage&&) = delete;
  uninitialized_storage& operator=(uninitialized_storage&&) = delete;

  // Conditionally enable copy constructor for trivially copyable types
  template <typename U = T>
  FORCEINLINE constexpr uninitialized_storage(const uninitialized_storage& other) noexcept
    requires (std::is_trivially_copyable_v<U>) : storage(other.storage) {}

  // Conditionally enable copy assignment for trivially copyable types
  template <typename U = T>
  FORCEINLINE constexpr uninitialized_storage& operator=(const uninitialized_storage& other) noexcept
    requires (std::is_trivially_copyable_v<U>) {
    storage = other.storage;
    return *this;
  }

  // Conditionally enable move constructor for trivially movable types
  template <typename U = T>
  FORCEINLINE constexpr uninitialized_storage(uninitialized_storage&& other) noexcept
    requires (std::is_trivially_move_constructible_v<U>) : storage(std::move(other.storage)) {}

  // Conditionally enable move assignment for trivially movable types
  template <typename U = T>
  FORCEINLINE constexpr uninitialized_storage& operator=(uninitialized_storage&& other) noexcept
    requires (std::is_trivially_move_assignable_v<U>) {
    storage = std::move(other.storage);
    return *this;
  }

  // Construct the object in-place with any arguments
  template <typename... Args>
  FORCEINLINE void construct(Args&&... args)
    noexcept(std::is_nothrow_constructible_v<T, Args...>)
    requires(std::is_constructible_v<T, Args...>) {
    new (address()) T(std::forward<Args>(args)...);
  }

  // Destroy the object
  FORCEINLINE void destroy() noexcept(std::is_nothrow_destructible_v<T>) {
    if constexpr (!std::is_trivially_destructible_v<T>) {
      get().~T();
    }
  }

  // Access the object
  FORCEINLINE T& get() noexcept {
    return *std::launder(reinterpret_cast<T*>(storage.data()));
  }

  FORCEINLINE const T& get() const noexcept {
    return *std::launder(reinterpret_cast<const T*>(storage.data()));
  }

  // Access the object's address
  FORCEINLINE T* address() noexcept {
    return std::launder(reinterpret_cast<T*>(storage.data()));
  }

  FORCEINLINE const T* address() const noexcept {
    return std::launder(reinterpret_cast<const T*>(storage.data()));
  }
};
