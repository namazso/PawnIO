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

#include "callbacks.h"

#include "klist.h"
#include "uninitialized_storage.h"

class wrapped_resource {
  ERESOURCE _resource{};

public:
  FORCEINLINE NTSTATUS init() { return ExInitializeResourceLite(&_resource); }
  FORCEINLINE NTSTATUS destroy() { return ExDeleteResourceLite(&_resource); }

  FORCEINLINE void lock() { ExAcquireResourceExclusiveLite(&_resource, TRUE); }
  FORCEINLINE bool try_lock() { return TRUE == ExAcquireResourceExclusiveLite(&_resource, FALSE); }
  FORCEINLINE void unlock() { ExReleaseResourceLite(&_resource); }

  FORCEINLINE void lock_shared() { ExAcquireResourceSharedLite(&_resource, TRUE); }
  FORCEINLINE bool try_lock_shared() { return TRUE == ExAcquireResourceSharedLite(&_resource, FALSE); }
  FORCEINLINE void unlock_shared() { ExReleaseResourceLite(&_resource); }
};

template <typename Callback>
struct callback_list : std::false_type {};

template <typename Ret, typename... Args>
struct callback_list<Ret(*)(Args...)> {
  using callback_t = Ret(*)(Args...);
  wrapped_resource res{};
  uninitialized_storage<klist<callback_t>> list{};

  FORCEINLINE constexpr callback_list() = default;

  FORCEINLINE NTSTATUS init() {
    list.construct();
    return res.init();
  }

  FORCEINLINE void destroy() {
    res.destroy();
    list.destroy();
  }

  FORCEINLINE PVOID add(callback_t callback) {
    std::unique_lock lock{res};
    auto& l = list.get();
    auto it = l.emplace_front(callback);
    if (it == l.end())
      return nullptr;
    return it.as_entry();
  }

  FORCEINLINE void remove(PVOID cookie) {
    if (!cookie)
      return;
    std::unique_lock lock{res};
    auto& l = list.get();
    l.erase(l.citer_from_entry((PLIST_ENTRY)cookie));
  }

  FORCEINLINE NTSTATUS call_status(Args... args)
    requires(std::is_same_v<Ret, NTSTATUS>) {
    std::shared_lock lock{res};
    NTSTATUS status = STATUS_SUCCESS;
    for (const auto cb : list.get()) {
      status = cb(std::forward<Args>(args)...);
      if (!NT_SUCCESS(status))
        break;
    }
    return status;
  }

  FORCEINLINE void call_void(Args... args)
    requires(std::is_same_v<Ret, void>) {
    std::shared_lock lock{res};
    for (const auto cb : list.get()) {
      cb(std::forward<Args>(args)...);
    }
  }
};

static constinit callback_list<ppawnio_vm_callback_created> s_created;
static constinit callback_list<ppawnio_vm_callback_precall> s_precall;
static constinit callback_list<ppawnio_vm_callback_postcall> s_postcall;
static constinit callback_list<ppawnio_vm_callback_destroyed> s_destroyed;

NTSTATUS vm_callback_init() {
  auto status = s_created.init();
  if (NT_SUCCESS(status)) {
    status = s_precall.init();
    if (NT_SUCCESS(status)) {
      status = s_postcall.init();
      if (NT_SUCCESS(status)) {
        status = s_destroyed.init();
        if (NT_SUCCESS(status)) {
          return STATUS_SUCCESS;
        }
        s_postcall.destroy();
      }
      s_precall.destroy();
    }
    s_created.destroy();
  }
  return status;
}

void vm_callback_destroy() {
  s_created.destroy();
  s_precall.destroy();
  s_postcall.destroy();
  s_destroyed.destroy();
}

NTSTATUS vm_callback_created(PVOID ctx) {
  return s_created.call_status(ctx);
}

NTSTATUS vm_callback_precall(PVOID ctx, UINT_PTR cip) {
  return s_precall.call_status(ctx, cip);
}

void vm_callback_postcall(PVOID ctx) {
  s_postcall.call_void(ctx);
}

void vm_callback_destroyed(PVOID ctx) {
  s_destroyed.call_void(ctx);
}

PVOID pawnio_register_vm_callback_created(ppawnio_vm_callback_created callback) {
  return s_created.add(callback);
}

void pawnio_unregister_vm_callback_created(PVOID cookie) {
  s_created.remove(cookie);
}

PVOID pawnio_register_vm_callback_precall(ppawnio_vm_callback_precall callback) {
  return s_precall.add(callback);
}

void pawnio_unregister_vm_callback_precall(PVOID cookie) {
  s_precall.remove(cookie);
}

PVOID pawnio_register_vm_callback_postcall(ppawnio_vm_callback_postcall callback) {
  return s_postcall.add(callback);
}

void pawnio_unregister_vm_callback_postcall(PVOID cookie) {
  s_postcall.remove(cookie);
}

PVOID pawnio_register_vm_callback_destroyed(ppawnio_vm_callback_destroyed callback) {
  return s_destroyed.add(callback);
}

void pawnio_unregister_vm_callback_destroyed(PVOID cookie) {
  s_destroyed.remove(cookie);
}
