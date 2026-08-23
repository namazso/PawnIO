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

#include "callbacks.h"

namespace {

enum class callback_kind : UCHAR {
  created,
  precall,
  postcall,
  destroyed,
};

constexpr ULONG callback_kind_count = 4;
constexpr ULONG callback_pool_tag = 'bCwP';

union callback_function {
  ppawnio_vm_callback_created created;
  ppawnio_vm_callback_precall precall;
  ppawnio_vm_callback_postcall postcall;
  ppawnio_vm_callback_destroyed destroyed;
};

enum class reclaim_mode : LONG {
  active,
  synchronous,
  deferred,
};

struct callback_registration {
  LIST_ENTRY link;
  KEVENT references_released;
  callback_function callback;
  ULONG_PTR sequence;
  PVOID cookie;
  callback_kind kind;
  volatile LONG references;
  volatile LONG reclaim;
};

struct callback_frame {
  LIST_ENTRY link;
  PETHREAD thread;
};

ERESOURCE s_registry_lock{};
EX_RUNDOWN_REF s_api_rundown{};
LIST_ENTRY s_active[callback_kind_count]{};
LIST_ENTRY s_callback_frames{};
ULONG_PTR s_next_sequence = 0;
volatile LONG s_initialized = 0;
bool s_closing = false;

FORCEINLINE ULONG kind_index(callback_kind kind) {
  return static_cast<ULONG>(kind);
}

FORCEINLINE void lock_registry() {
  KeEnterCriticalRegion();
  (void)ExAcquireResourceExclusiveLite(&s_registry_lock, TRUE);
}

FORCEINLINE void unlock_registry() {
  ExReleaseResourceLite(&s_registry_lock);
  KeLeaveCriticalRegion();
}

bool acquire_api_rundown() {
  if (InterlockedCompareExchange(&s_initialized, 0, 0) == 0)
    return false;

  if (!ExAcquireRundownProtection(&s_api_rundown))
    return false;

  if (InterlockedCompareExchange(&s_initialized, 0, 0) != 0)
    return true;

  ExReleaseRundownProtection(&s_api_rundown);
  return false;
}

class api_guard {
  bool _acquired;

public:
  FORCEINLINE api_guard() : _acquired(acquire_api_rundown()) {}
  FORCEINLINE ~api_guard() {
    if (_acquired)
      ExReleaseRundownProtection(&s_api_rundown);
  }

  api_guard(const api_guard&) = delete;
  api_guard& operator=(const api_guard&) = delete;

  FORCEINLINE explicit operator bool() const { return _acquired; }
};

callback_registration* find_registration_locked(callback_kind kind, PVOID cookie) {
  auto* const head = &s_active[kind_index(kind)];
  for (auto* link = head->Flink; link != head; link = link->Flink) {
    auto* const registration = CONTAINING_RECORD(link, callback_registration, link);
    if (registration->cookie == cookie)
      return registration;
  }
  return nullptr;
}

bool has_callback_frame_locked(PETHREAD thread) {
  for (auto* link = s_callback_frames.Flink;
       link != &s_callback_frames;
       link = link->Flink) {
    const auto* const frame = CONTAINING_RECORD(link, callback_frame, link);
    if (frame->thread == thread)
      return true;
  }
  return false;
}

void move_all_locked(PLIST_ENTRY source, PLIST_ENTRY destination) {
  while (!IsListEmpty(source)) {
    auto* const link = RemoveHeadList(source);
    InsertTailList(destination, link);
  }
}

void drain_registrations(PLIST_ENTRY registrations) {
  while (!IsListEmpty(registrations)) {
    auto* const link = RemoveHeadList(registrations);
    auto* const registration = CONTAINING_RECORD(link, callback_registration, link);
    NT_ASSERT(InterlockedCompareExchange(&registration->references, 0, 0) == 1);
    ExFreePoolWithTag(registration, callback_pool_tag);
  }
}

void release_callback_reference(callback_registration* registration) {
  if (InterlockedDecrement(&registration->references) != 0)
    return;

  const auto mode = static_cast<reclaim_mode>(
      InterlockedCompareExchange(&registration->reclaim, 0, 0));
  NT_ASSERT(mode != reclaim_mode::active);
  if (mode == reclaim_mode::synchronous) {
    KeSetEvent(&registration->references_released, IO_NO_INCREMENT, FALSE);
  } else if (mode == reclaim_mode::deferred) {
    ExFreePoolWithTag(registration, callback_pool_tag);
  }
}

callback_registration* acquire_next_registration(
    callback_kind kind,
    ULONG_PTR ceiling,
    ULONG_PTR cursor,
    callback_frame& frame) {
  callback_registration* selected = nullptr;

  lock_registry();
  auto* const head = &s_active[kind_index(kind)];
  for (auto* link = head->Flink; link != head; link = link->Flink) {
    auto* const registration = CONTAINING_RECORD(link, callback_registration, link);
    if (registration->sequence > ceiling || registration->sequence >= cursor)
      continue;
    InterlockedIncrement(&registration->references);
    frame.thread = PsGetCurrentThread();
    InsertTailList(&s_callback_frames, &frame.link);
    selected = registration;
    break;
  }
  unlock_registry();

  return selected;
}

void finish_callback(callback_registration* registration, callback_frame& frame) {
  lock_registry();
  RemoveEntryList(&frame.link);
  unlock_registry();

  release_callback_reference(registration);
}

ULONG_PTR capture_sequence() {
  lock_registry();
  const auto sequence = s_next_sequence;
  unlock_registry();
  return sequence;
}

template <typename Invoke>
NTSTATUS call_status(callback_kind kind, bool call_all, Invoke&& invoke) {
  api_guard guard;
  if (!guard)
    return STATUS_DELETE_PENDING;

  const auto ceiling = capture_sequence();
  auto cursor = ceiling + 1;
  NTSTATUS status = STATUS_SUCCESS;

  for (;;) {
    callback_frame frame{};
    auto* const registration =
        acquire_next_registration(kind, ceiling, cursor, frame);
    if (!registration)
      break;

    cursor = registration->sequence;
    const auto result = invoke(registration->callback);
    finish_callback(registration, frame);

    if (call_all) {
      if (NT_SUCCESS(status))
        status = result;
    } else {
      status = result;
      if (!NT_SUCCESS(status))
        break;
    }
  }

  return status;
}

template <typename Invoke>
void call_void(callback_kind kind, Invoke&& invoke) {
  api_guard guard;
  if (!guard)
    return;

  const auto ceiling = capture_sequence();
  auto cursor = ceiling + 1;

  for (;;) {
    callback_frame frame{};
    auto* const registration =
        acquire_next_registration(kind, ceiling, cursor, frame);
    if (!registration)
      break;

    cursor = registration->sequence;
    invoke(registration->callback);
    finish_callback(registration, frame);
  }
}

PVOID register_callback(callback_kind kind, callback_function callback) {
  api_guard guard;
  if (!guard)
    return nullptr;

  auto* const registration = static_cast<callback_registration*>(
      ExAllocatePoolZero(NonPagedPoolNx, sizeof(callback_registration), callback_pool_tag));
  if (!registration)
    return nullptr;

  KeInitializeEvent(&registration->references_released, NotificationEvent, FALSE);
  registration->callback = callback;
  registration->kind = kind;
  registration->references = 1;
  registration->reclaim = static_cast<LONG>(reclaim_mode::active);

  lock_registry();
  constexpr auto max_sequence = (~static_cast<ULONG_PTR>(0)) >> 3;
  if (s_closing || s_next_sequence == max_sequence) {
    unlock_registry();
    ExFreePoolWithTag(registration, callback_pool_tag);
    return nullptr;
  }

  registration->sequence = ++s_next_sequence;
  registration->cookie = reinterpret_cast<PVOID>(
      (registration->sequence << 3) |
      (static_cast<ULONG_PTR>(kind_index(kind)) + 1));
  InsertHeadList(&s_active[kind_index(kind)], &registration->link);
  unlock_registry();

  return registration->cookie;
}

void unregister_callback(callback_kind kind, PVOID cookie) {
  if (!cookie)
    return;

  api_guard guard;
  if (!guard)
    return;

  callback_registration* registration = nullptr;
  bool deferred = false;

  lock_registry();
  registration = find_registration_locked(kind, cookie);
  if (registration) {
    RemoveEntryList(&registration->link);
    deferred = has_callback_frame_locked(PsGetCurrentThread());
    registration->reclaim = static_cast<LONG>(
        deferred ? reclaim_mode::deferred : reclaim_mode::synchronous);
  }
  unlock_registry();

  if (registration && deferred) {
    if (InterlockedDecrement(&registration->references) == 0)
      ExFreePoolWithTag(registration, callback_pool_tag);
  } else if (registration) {
    if (InterlockedDecrement(&registration->references) != 0) {
      (void)KeWaitForSingleObject(
          &registration->references_released,
          Executive,
          KernelMode,
          FALSE,
          nullptr);
    }
    ExFreePoolWithTag(registration, callback_pool_tag);
  }
}

} // namespace

NTSTATUS vm_callback_init() {
  const auto status = ExInitializeResourceLite(&s_registry_lock);
  if (!NT_SUCCESS(status))
    return status;

  for (auto& list : s_active)
    InitializeListHead(&list);
  InitializeListHead(&s_callback_frames);
  ExInitializeRundownProtection(&s_api_rundown);
  s_next_sequence = 0;
  s_closing = false;
  InterlockedExchange(&s_initialized, 1);
  return STATUS_SUCCESS;
}

void vm_callback_destroy() {
  if (InterlockedCompareExchange(&s_initialized, 0, 0) == 0)
    return;

  lock_registry();
  if (s_closing) {
    unlock_registry();
    return;
  }
  s_closing = true;
  InterlockedExchange(&s_initialized, 0);
  unlock_registry();

  ExWaitForRundownProtectionRelease(&s_api_rundown);

  LIST_ENTRY registrations;
  InitializeListHead(&registrations);

  lock_registry();
  NT_ASSERT(IsListEmpty(&s_callback_frames));
  for (auto& list : s_active)
    move_all_locked(&list, &registrations);
  unlock_registry();

  drain_registrations(&registrations);
  (void)ExDeleteResourceLite(&s_registry_lock);
}

NTSTATUS vm_callback_created(PVOID ctx) {
  return call_status(callback_kind::created, true, [ctx](const callback_function& callback) {
    return callback.created(ctx);
  });
}

NTSTATUS vm_callback_precall(PVOID ctx, UINT_PTR cip) {
  return call_status(callback_kind::precall, false, [ctx, cip](const callback_function& callback) {
    return callback.precall(ctx, cip);
  });
}

void vm_callback_postcall(PVOID ctx) {
  call_void(callback_kind::postcall, [ctx](const callback_function& callback) {
    callback.postcall(ctx);
  });
}

void vm_callback_destroyed(PVOID ctx) {
  call_void(callback_kind::destroyed, [ctx](const callback_function& callback) {
    callback.destroyed(ctx);
  });
}

PVOID pawnio_register_vm_callback_created(ppawnio_vm_callback_created callback) {
  if (!callback)
    return nullptr;
  callback_function function{};
  function.created = callback;
  return register_callback(callback_kind::created, function);
}

void pawnio_unregister_vm_callback_created(PVOID cookie) {
  unregister_callback(callback_kind::created, cookie);
}

PVOID pawnio_register_vm_callback_precall(ppawnio_vm_callback_precall callback) {
  if (!callback)
    return nullptr;
  callback_function function{};
  function.precall = callback;
  return register_callback(callback_kind::precall, function);
}

void pawnio_unregister_vm_callback_precall(PVOID cookie) {
  unregister_callback(callback_kind::precall, cookie);
}

PVOID pawnio_register_vm_callback_postcall(ppawnio_vm_callback_postcall callback) {
  if (!callback)
    return nullptr;
  callback_function function{};
  function.postcall = callback;
  return register_callback(callback_kind::postcall, function);
}

void pawnio_unregister_vm_callback_postcall(PVOID cookie) {
  unregister_callback(callback_kind::postcall, cookie);
}

PVOID pawnio_register_vm_callback_destroyed(ppawnio_vm_callback_destroyed callback) {
  if (!callback)
    return nullptr;
  callback_function function{};
  function.destroyed = callback;
  return register_callback(callback_kind::destroyed, function);
}

void pawnio_unregister_vm_callback_destroyed(PVOID cookie) {
  unregister_callback(callback_kind::destroyed, cookie);
}
