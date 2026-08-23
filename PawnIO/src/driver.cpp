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

#include <pawnio_km.h>
#include <pawnio_um.h>

#include "callbacks.h"
#include "vm.h"

ULONG pawnio_version() {
  return (PAWNIO_MAJOR << 16) | (PAWNIO_MINOR << 8) | PAWNIO_PATCH;
}

namespace {

enum class pnp_state : LONG {
  not_started,
  started,
  stop_pending,
  stopped,
  remove_pending,
  surprise_removed,
  deleted,
};

constexpr ULONG remove_lock_tag = 'rLwP';
constexpr ULONG file_context_tag = 'fCwP';

struct device_extension;

struct file_context {
  LIST_ENTRY link;
  EX_RUNDOWN_REF io_rundown;
  ERESOURCE io_lock;
  PIO_WORKITEM teardown_work;
  device_extension* device;
  PVOID volatile vm;
  volatile LONG teardown_started;
  volatile LONG references;
  volatile LONG load_state;
  volatile LONG remove_on_teardown_complete;
  BOOLEAN listed;
  BOOLEAN surprise_seen;
  BOOLEAN remove_lock_acquired;
};

struct device_extension {
  PDEVICE_OBJECT lower_device;
  PDEVICE_OBJECT physical_device;
  IO_REMOVE_LOCK remove_lock;
  KSPIN_LOCK state_lock;
  LIST_ENTRY file_contexts;
  pnp_state state;
  pnp_state previous_state;
  BOOLEAN symlink_created;
  BOOLEAN dos_symlink_created;
};

} // namespace

DRIVER_ADD_DEVICE add_device;
DRIVER_UNLOAD driver_unload;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH dispatch_create;
_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH dispatch_cleanup;
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH dispatch_close;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH dispatch_device_control;
_Dispatch_type_(IRP_MJ_PNP)
DRIVER_DISPATCH dispatch_pnp;
_Dispatch_type_(IRP_MJ_POWER)
DRIVER_DISPATCH dispatch_power;
_Dispatch_type_(IRP_MJ_SYSTEM_CONTROL)
DRIVER_DISPATCH dispatch_system_control;

IO_COMPLETION_ROUTINE forward_completion;
IO_WORKITEM_ROUTINE teardown_worker;

namespace {

NTSTATUS complete_irp(PIRP irp, NTSTATUS status) {
  irp->IoStatus.Status = status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return status;
}

NTSTATUS complete_irp_with_remove_lock(
    device_extension* ext,
    PIRP irp,
    NTSTATUS status) {
  complete_irp(irp, status);
  IoReleaseRemoveLock(&ext->remove_lock, irp);
  return status;
}

NTSTATUS state_status_locked(const device_extension* ext) {
  switch (ext->state) {
  case pnp_state::remove_pending:
  case pnp_state::deleted:
    return STATUS_DELETE_PENDING;
  case pnp_state::surprise_removed:
    return STATUS_DEVICE_REMOVED;
  default:
    return STATUS_DEVICE_NOT_READY;
  }
}

void reference_file_context(file_context* context) {
  InterlockedIncrement(&context->references);
}

void dereference_file_context(file_context* context) {
  if (InterlockedDecrement(&context->references) == 0) {
    if (context->teardown_work)
      IoFreeWorkItem(context->teardown_work);
    (void)ExDeleteResourceLite(&context->io_lock);
    auto* const ext = context->device;
    const auto remove_lock_acquired = context->remove_lock_acquired;
    context->remove_lock_acquired = FALSE;
    if (remove_lock_acquired)
      IoReleaseRemoveLock(&ext->remove_lock, context);
    ExFreePoolWithTag(context, file_context_tag);
  }
}

void unlink_file_context(file_context* context);

void finish_file_context_teardown(file_context* context) {
  ExWaitForRundownProtectionRelease(&context->io_rundown);
  InterlockedExchange(&context->load_state, 0);
  auto* const vm = _InterlockedExchangePointer(&context->vm, nullptr);
  if (vm) {
    const auto status = vm_destroy(vm);
    NT_ASSERT(status != STATUS_DEVICE_BUSY);
    UNREFERENCED_PARAMETER(status);
  }
  InterlockedExchange(&context->teardown_started, 2);
  if (InterlockedCompareExchange(
          &context->remove_on_teardown_complete,
          0,
          0) != 0) {
    unlink_file_context(context);
  }
}

void queue_file_context_teardown(file_context* context) {
  reference_file_context(context);
  IoQueueWorkItem(
      context->teardown_work,
      teardown_worker,
      DelayedWorkQueue,
      context);
}

void teardown_file_context(file_context* context, bool remove_when_complete) {
  if (remove_when_complete)
    InterlockedExchange(&context->remove_on_teardown_complete, 1);

  if (InterlockedCompareExchange(&context->teardown_started, 1, 0) != 0) {
    if (InterlockedCompareExchange(&context->teardown_started, 0, 0) == 2 &&
        InterlockedCompareExchange(
            &context->remove_on_teardown_complete,
            0,
            0) != 0) {
      unlink_file_context(context);
    }
    return;
  }

  auto* const vm = _InterlockedCompareExchangePointer(&context->vm, nullptr, nullptr);
  if (ExIsResourceAcquiredExclusiveLite(&context->io_lock) != 0 ||
      vm_owned_by_current_thread(vm)) {
    queue_file_context_teardown(context);
    return;
  }

  finish_file_context_teardown(context);
}

file_context* detach_file_context(
    device_extension* ext,
    PFILE_OBJECT file_object) {
  KIRQL old_irql;
  KeAcquireSpinLock(&ext->state_lock, &old_irql);
  auto* const context = static_cast<file_context*>(file_object->FsContext);
  if (context) {
    reference_file_context(context);
    file_object->FsContext = nullptr;
  }
  KeReleaseSpinLock(&ext->state_lock, old_irql);
  return context;
}

void unlink_file_context(file_context* context) {
  auto* const ext = context->device;
  bool removed = false;
  KIRQL old_irql;
  KeAcquireSpinLock(&ext->state_lock, &old_irql);
  if (context->listed) {
    RemoveEntryList(&context->link);
    context->listed = FALSE;
    removed = true;
  }
  KeReleaseSpinLock(&ext->state_lock, old_irql);

  if (removed)
    dereference_file_context(context);
}

void close_file_context(device_extension* ext, PFILE_OBJECT file_object) {
  auto* const context = detach_file_context(ext, file_object);
  if (!context)
    return;

  teardown_file_context(context, true);
  dereference_file_context(context);
}

file_context* acquire_file_context_for_io(
    device_extension* ext,
    PFILE_OBJECT file_object,
    NTSTATUS* status) {
  file_context* context = nullptr;

  KIRQL old_irql;
  KeAcquireSpinLock(&ext->state_lock, &old_irql);
  if (ext->state == pnp_state::started) {
    context = static_cast<file_context*>(file_object->FsContext);
    if (context && context->listed)
      reference_file_context(context);
    else
      context = nullptr;
    *status = context ? STATUS_SUCCESS : STATUS_FILE_CLOSED;
  } else {
    *status = state_status_locked(ext);
  }
  KeReleaseSpinLock(&ext->state_lock, old_irql);

  if (!context)
    return nullptr;

  if (!ExAcquireRundownProtection(&context->io_rundown)) {
    dereference_file_context(context);
    *status = STATUS_FILE_CLOSED;
    return nullptr;
  }

  KeEnterCriticalRegion();
  (void)ExAcquireResourceExclusiveLite(&context->io_lock, TRUE);

  KeAcquireSpinLock(&ext->state_lock, &old_irql);
  if (ext->state != pnp_state::started)
    *status = state_status_locked(ext);
  KeReleaseSpinLock(&ext->state_lock, old_irql);

  if (!NT_SUCCESS(*status)) {
    ExReleaseResourceLite(&context->io_lock);
    KeLeaveCriticalRegion();
    ExReleaseRundownProtection(&context->io_rundown);
    dereference_file_context(context);
    return nullptr;
  }

  return context;
}

void release_file_context_from_io(file_context* context) {
  ExReleaseResourceLite(&context->io_lock);
  KeLeaveCriticalRegion();
  ExReleaseRundownProtection(&context->io_rundown);
  dereference_file_context(context);
}

void rundown_all_file_contexts(device_extension* ext) {
  for (;;) {
    file_context* context = nullptr;

    KIRQL old_irql;
    KeAcquireSpinLock(&ext->state_lock, &old_irql);
    for (auto* link = ext->file_contexts.Flink;
         link != &ext->file_contexts;
         link = link->Flink) {
      auto* const candidate = CONTAINING_RECORD(link, file_context, link);
      if (!candidate->surprise_seen) {
        candidate->surprise_seen = TRUE;
        reference_file_context(candidate);
        context = candidate;
        break;
      }
    }
    KeReleaseSpinLock(&ext->state_lock, old_irql);

  if (!context)
    break;

    teardown_file_context(context, false);
    dereference_file_context(context);
  }
}

NTSTATUS forward_irp_synchronously(device_extension* ext, PIRP irp) {
  KEVENT event;
  KeInitializeEvent(&event, NotificationEvent, FALSE);

  IoCopyCurrentIrpStackLocationToNext(irp);
  IoSetCompletionRoutine(irp, forward_completion, &event, TRUE, TRUE, TRUE);

  const auto call_status = IoCallDriver(ext->lower_device, irp);
  if (call_status == STATUS_PENDING) {
    (void)KeWaitForSingleObject(
        &event,
        Executive,
        KernelMode,
        FALSE,
        nullptr);
  }

  return irp->IoStatus.Status;
}

static void create_symlinks(PDEVICE_OBJECT pdo, device_extension* ext) {
  // Query the device name from the PDO stack to use as the symlink target
  WCHAR name_buf[256]{};
  ULONG name_len = 0;
  auto status = IoGetDeviceProperty(
    pdo,
    DevicePropertyPhysicalDeviceObjectName,
    sizeof(name_buf),
    name_buf,
    &name_len
  );

  if (NT_SUCCESS(status)) {
    UNICODE_STRING device_name{};
    RtlInitUnicodeString(&device_name, name_buf);

    UNICODE_STRING symlink_path = RTL_CONSTANT_STRING(k_device_path);
    status = IoCreateSymbolicLink(&symlink_path, &device_name);
    ext->symlink_created = NT_SUCCESS(status);

    UNICODE_STRING symlink_dos_path = RTL_CONSTANT_STRING(k_device_dos_path_DEPRECATED);
    status = IoCreateSymbolicLink(&symlink_dos_path, &device_name);
    ext->dos_symlink_created = NT_SUCCESS(status);
  }
  // If symlink creation fails, just ignore it
}

static void delete_symlinks(device_extension* ext) {
  if (ext->symlink_created) {
    UNICODE_STRING symlink_path = RTL_CONSTANT_STRING(k_device_path);
    IoDeleteSymbolicLink(&symlink_path);
    ext->symlink_created = FALSE;
  }
  if (ext->dos_symlink_created) {
    UNICODE_STRING symlink_dos_path = RTL_CONSTANT_STRING(k_device_dos_path_DEPRECATED);
    IoDeleteSymbolicLink(&symlink_dos_path);
    ext->dos_symlink_created = FALSE;
  }
}

void set_state(device_extension* ext, pnp_state state) {
  KIRQL old_irql;
  KeAcquireSpinLock(&ext->state_lock, &old_irql);
  ext->state = state;
  KeReleaseSpinLock(&ext->state_lock, old_irql);
}

NTSTATUS begin_query(device_extension* ext, pnp_state pending_state) {
  NTSTATUS status;
  KIRQL old_irql;
  KeAcquireSpinLock(&ext->state_lock, &old_irql);
  if (ext->state == pnp_state::remove_pending ||
      ext->state == pnp_state::surprise_removed ||
      ext->state == pnp_state::deleted) {
    status = state_status_locked(ext);
  } else if (ext->state == pnp_state::stop_pending) {
    status = STATUS_INVALID_DEVICE_STATE;
  } else if (!IsListEmpty(&ext->file_contexts)) {
    status = STATUS_DEVICE_BUSY;
  } else {
    ext->previous_state = ext->state;
    ext->state = pending_state;
    status = STATUS_SUCCESS;
  }
  KeReleaseSpinLock(&ext->state_lock, old_irql);
  return status;
}

void restore_state(device_extension* ext, pnp_state pending_state) {
  KIRQL old_irql;
  KeAcquireSpinLock(&ext->state_lock, &old_irql);
  if (ext->state == pending_state)
    ext->state = ext->previous_state;
  KeReleaseSpinLock(&ext->state_lock, old_irql);
}

} // namespace

_Use_decl_annotations_
NTSTATUS add_device(
    PDRIVER_OBJECT driver_object,
    PDEVICE_OBJECT physical_device_object) {
  PDEVICE_OBJECT device_object = nullptr;
  auto status = IoCreateDevice(
    driver_object,
    sizeof(device_extension),
    nullptr,
    k_device_type,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &device_object
  );

  if (!NT_SUCCESS(status))
    return status;

  auto* ext = static_cast<device_extension*>(device_object->DeviceExtension);
  RtlZeroMemory(ext, sizeof(device_extension));

  ext->lower_device = IoAttachDeviceToDeviceStack(device_object, physical_device_object);
  if (!ext->lower_device) {
    IoDeleteDevice(device_object);
    return STATUS_NO_SUCH_DEVICE;
  }

  ext->physical_device = physical_device_object;
  IoInitializeRemoveLock(&ext->remove_lock, remove_lock_tag, 0, 0);
  KeInitializeSpinLock(&ext->state_lock);
  InitializeListHead(&ext->file_contexts);
  ext->state = pnp_state::not_started;
  ext->previous_state = pnp_state::not_started;

  device_object->Flags |= DO_BUFFERED_IO;
  device_object->Flags |= ext->lower_device->Flags & DO_POWER_PAGABLE;
  device_object->Flags &= ~DO_DEVICE_INITIALIZING;

  return STATUS_SUCCESS;
}

_Use_decl_annotations_
void driver_unload(PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  vm_callback_destroy();
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);

  vm_init(driver_object);

  auto status = vm_callback_init();
  if (!NT_SUCCESS(status))
    return status;

  driver_object->DriverUnload = driver_unload;
  driver_object->DriverExtension->AddDevice = add_device;

  driver_object->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
  driver_object->MajorFunction[IRP_MJ_CLEANUP] = dispatch_cleanup;
  driver_object->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
  driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_device_control;
  driver_object->MajorFunction[IRP_MJ_PNP] = dispatch_pnp;
  driver_object->MajorFunction[IRP_MJ_POWER] = dispatch_power;
  driver_object->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = dispatch_system_control;

  return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS forward_completion(
    PDEVICE_OBJECT device_object,
    PIRP irp,
    PVOID context) {
  UNREFERENCED_PARAMETER(device_object);
  UNREFERENCED_PARAMETER(irp);
  if (!context)
    return STATUS_MORE_PROCESSING_REQUIRED;
  KeSetEvent(static_cast<PKEVENT>(context), IO_NO_INCREMENT, FALSE);
  return STATUS_MORE_PROCESSING_REQUIRED;
}

_Use_decl_annotations_
void teardown_worker(PDEVICE_OBJECT device_object, PVOID worker_context) {
  UNREFERENCED_PARAMETER(device_object);
  auto* const context = static_cast<file_context*>(worker_context);
  if (!context)
    return;
  finish_file_context_teardown(context);
  const auto work_item = context->teardown_work;
  context->teardown_work = nullptr;
  IoFreeWorkItem(work_item);
  dereference_file_context(context);
}

_Use_decl_annotations_
NTSTATUS dispatch_create(PDEVICE_OBJECT device_object, PIRP irp) {
  auto* const ext = static_cast<device_extension*>(device_object->DeviceExtension);
  irp->IoStatus.Information = 0;

  auto status = IoAcquireRemoveLock(&ext->remove_lock, irp);
  if (!NT_SUCCESS(status))
    return complete_irp(irp, status);

  auto* const context = static_cast<file_context*>(
      ExAllocatePoolZero(NonPagedPoolNx, sizeof(file_context), file_context_tag));
  if (!context)
    return complete_irp_with_remove_lock(ext, irp, STATUS_INSUFFICIENT_RESOURCES);

  status = ExInitializeResourceLite(&context->io_lock);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(context, file_context_tag);
    return complete_irp_with_remove_lock(ext, irp, status);
  }

  context->teardown_work = IoAllocateWorkItem(device_object);
  if (!context->teardown_work) {
    (void)ExDeleteResourceLite(&context->io_lock);
    ExFreePoolWithTag(context, file_context_tag);
    return complete_irp_with_remove_lock(ext, irp, STATUS_INSUFFICIENT_RESOURCES);
  }

  ExInitializeRundownProtection(&context->io_rundown);
  const auto irp_stack = IoGetCurrentIrpStackLocation(irp);
  context->device = ext;
  context->references = 1;

  status = IoAcquireRemoveLock(&ext->remove_lock, context);
  if (!NT_SUCCESS(status)) {
    dereference_file_context(context);
    return complete_irp_with_remove_lock(ext, irp, status);
  }
  context->remove_lock_acquired = TRUE;

  KIRQL old_irql;
  KeAcquireSpinLock(&ext->state_lock, &old_irql);
  if (ext->state == pnp_state::started && !irp_stack->FileObject->FsContext) {
    InsertTailList(&ext->file_contexts, &context->link);
    context->listed = TRUE;
    irp_stack->FileObject->FsContext = context;
    status = STATUS_SUCCESS;
  } else if (ext->state == pnp_state::started) {
    status = STATUS_SHARING_VIOLATION;
  } else {
    status = state_status_locked(ext);
  }
  KeReleaseSpinLock(&ext->state_lock, old_irql);

  if (!NT_SUCCESS(status)) {
    dereference_file_context(context);
  }

  return complete_irp_with_remove_lock(ext, irp, status);
}

_Use_decl_annotations_
NTSTATUS dispatch_cleanup(PDEVICE_OBJECT device_object, PIRP irp) {
  auto* const ext = static_cast<device_extension*>(device_object->DeviceExtension);
  irp->IoStatus.Information = 0;

  const auto status = IoAcquireRemoveLock(&ext->remove_lock, irp);
  if (!NT_SUCCESS(status))
    return complete_irp(irp, status);

  const auto irp_stack = IoGetCurrentIrpStackLocation(irp);
  close_file_context(ext, irp_stack->FileObject);
  return complete_irp_with_remove_lock(ext, irp, STATUS_SUCCESS);
}

_Use_decl_annotations_
NTSTATUS dispatch_close(PDEVICE_OBJECT device_object, PIRP irp) {
  auto* const ext = static_cast<device_extension*>(device_object->DeviceExtension);
  irp->IoStatus.Information = 0;

  const auto status = IoAcquireRemoveLock(&ext->remove_lock, irp);
  if (!NT_SUCCESS(status))
    return complete_irp(irp, status);

  const auto irp_stack = IoGetCurrentIrpStackLocation(irp);
  close_file_context(ext, irp_stack->FileObject);
  return complete_irp_with_remove_lock(ext, irp, STATUS_SUCCESS);
}

_Use_decl_annotations_
NTSTATUS dispatch_pnp(PDEVICE_OBJECT device_object, PIRP irp) {
  auto* ext = static_cast<device_extension*>(device_object->DeviceExtension);
  const auto irp_stack = IoGetCurrentIrpStackLocation(irp);

  const auto lock_status = IoAcquireRemoveLock(&ext->remove_lock, irp);
  if (!NT_SUCCESS(lock_status))
    return complete_irp(irp, lock_status);

  switch (irp_stack->MinorFunction) {
  case IRP_MN_START_DEVICE: {
    const auto status = forward_irp_synchronously(ext, irp);
    if (NT_SUCCESS(status)) {
      create_symlinks(ext->physical_device, ext);
      set_state(ext, pnp_state::started);
    }
    return complete_irp_with_remove_lock(ext, irp, status);
  }

  case IRP_MN_QUERY_STOP_DEVICE:
  case IRP_MN_QUERY_REMOVE_DEVICE: {
    const auto pending_state = irp_stack->MinorFunction == IRP_MN_QUERY_STOP_DEVICE
        ? pnp_state::stop_pending
        : pnp_state::remove_pending;
    auto status = begin_query(ext, pending_state);
    if (!NT_SUCCESS(status))
      return complete_irp_with_remove_lock(ext, irp, status);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(ext->lower_device, irp);
    IoReleaseRemoveLock(&ext->remove_lock, irp);
    return status;
  }

  case IRP_MN_CANCEL_STOP_DEVICE:
  case IRP_MN_CANCEL_REMOVE_DEVICE: {
    const auto pending_state = irp_stack->MinorFunction == IRP_MN_CANCEL_STOP_DEVICE
        ? pnp_state::stop_pending
        : pnp_state::remove_pending;
    (void)forward_irp_synchronously(ext, irp);
    restore_state(ext, pending_state);
    return complete_irp_with_remove_lock(ext, irp, STATUS_SUCCESS);
  }

  case IRP_MN_STOP_DEVICE:
    delete_symlinks(ext);
    set_state(ext, pnp_state::stopped);
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(irp);
    {
      const auto status = IoCallDriver(ext->lower_device, irp);
      IoReleaseRemoveLock(&ext->remove_lock, irp);
      return status;
    }

  case IRP_MN_REMOVE_DEVICE: {
    set_state(ext, pnp_state::deleted);
    delete_symlinks(ext);
    rundown_all_file_contexts(ext);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(irp);
    const auto status = IoCallDriver(ext->lower_device, irp);

    IoReleaseRemoveLockAndWait(&ext->remove_lock, irp);

    NT_ASSERT(IsListEmpty(&ext->file_contexts));
    IoDetachDevice(ext->lower_device);
    IoDeleteDevice(device_object);
    return status;
  }

  case IRP_MN_SURPRISE_REMOVAL:
    set_state(ext, pnp_state::surprise_removed);
    delete_symlinks(ext);
    rundown_all_file_contexts(ext);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(irp);
    {
      const auto status = IoCallDriver(ext->lower_device, irp);
      IoReleaseRemoveLock(&ext->remove_lock, irp);
      return status;
    }

  default:
    IoSkipCurrentIrpStackLocation(irp);
    {
      const auto status = IoCallDriver(ext->lower_device, irp);
      IoReleaseRemoveLock(&ext->remove_lock, irp);
      return status;
    }
  }
}

namespace {

NTSTATUS forward_with_remove_lock(PDEVICE_OBJECT device_object, PIRP irp) {
  auto* ext = static_cast<device_extension*>(device_object->DeviceExtension);
  const auto lock_status = IoAcquireRemoveLock(&ext->remove_lock, irp);
  if (!NT_SUCCESS(lock_status))
    return complete_irp(irp, lock_status);

  IoSkipCurrentIrpStackLocation(irp);
  const auto status = IoCallDriver(ext->lower_device, irp);
  IoReleaseRemoveLock(&ext->remove_lock, irp);
  return status;
}

} // namespace

_Use_decl_annotations_
NTSTATUS dispatch_power(PDEVICE_OBJECT device_object, PIRP irp) {
  return forward_with_remove_lock(device_object, irp);
}

_Use_decl_annotations_
NTSTATUS dispatch_system_control(PDEVICE_OBJECT device_object, PIRP irp) {
  return forward_with_remove_lock(device_object, irp);
}

_Use_decl_annotations_
NTSTATUS dispatch_device_control(PDEVICE_OBJECT device_object, PIRP irp) {
  auto* const ext = static_cast<device_extension*>(device_object->DeviceExtension);

  irp->IoStatus.Information = 0; // written

  const auto irp_stack = IoGetCurrentIrpStackLocation(irp);

  auto status = IoAcquireRemoveLock(&ext->remove_lock, irp);
  if (!NT_SUCCESS(status))
    return complete_irp(irp, status);

  if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    return complete_irp_with_remove_lock(ext, irp, STATUS_INVALID_DEVICE_STATE);

  auto* const context =
      acquire_file_context_for_io(ext, irp_stack->FileObject, &status);
  if (!context)
    return complete_irp_with_remove_lock(ext, irp, status);

  switch (irp_stack->Parameters.DeviceIoControl.IoControlCode) {
  case IOCTL_PIO_LOAD_BINARY: {
    const auto previous_state = InterlockedCompareExchange(&context->load_state, 1, 0);
    if (previous_state == 2) {
      status = STATUS_ALREADY_INITIALIZED;
    } else if (previous_state != 0) {
      status = STATUS_DEVICE_BUSY;
    } else {
      PVOID new_vm{};
      status = vm_load_binary(
        &new_vm,
        irp->AssociatedIrp.SystemBuffer,
        irp_stack->Parameters.DeviceIoControl.InputBufferLength
      );
      if (NT_SUCCESS(status)) {
        (void)_InterlockedExchangePointer(&context->vm, new_vm);
        InterlockedExchange(&context->load_state, 2);
      } else {
        InterlockedExchange(&context->load_state, 0);
      }
    }
    break;
  }

  case IOCTL_PIO_EXECUTE_FN:
    if (InterlockedCompareExchange(&context->load_state, 0, 0) != 2) {
      status = STATUS_INVALID_PARAMETER;
    } else {
      const auto in_length = irp_stack->Parameters.DeviceIoControl.InputBufferLength;
      const auto out_length = irp_stack->Parameters.DeviceIoControl.OutputBufferLength;

      if (out_length > in_length)
        RtlZeroMemory((PUCHAR)irp->AssociatedIrp.SystemBuffer + in_length, out_length - in_length);

      status = vm_execute_function(
        context->vm,
        irp->AssociatedIrp.SystemBuffer,
        in_length,
        irp->AssociatedIrp.SystemBuffer,
        out_length
      );
      if (NT_SUCCESS(status))
        irp->IoStatus.Information = out_length;
    }
    break;

  case IOCTL_PIO_VERSION:
    if (irp_stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(ULONG)) {
      status = STATUS_INVALID_PARAMETER;
    } else {
      *(ULONG*)irp->AssociatedIrp.SystemBuffer = pawnio_version();
      irp->IoStatus.Information = sizeof(ULONG);
      status = STATUS_SUCCESS;
    }
    break;

  default:
    status = STATUS_NOT_IMPLEMENTED;
    break;
  }

  release_file_context_from_io(context);
  return complete_irp_with_remove_lock(ext, irp, status);
}
