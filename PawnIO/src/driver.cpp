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

struct device_extension {
  PDEVICE_OBJECT lower_device;
  BOOLEAN symlink_created;
  BOOLEAN dos_symlink_created;
};

static NTSTATUS dispatch_irp(PDEVICE_OBJECT device_object, PIRP irp);
static NTSTATUS dispatch_pnp(PDEVICE_OBJECT device_object, PIRP irp);
static NTSTATUS dispatch_power(PDEVICE_OBJECT device_object, PIRP irp);

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

static NTSTATUS add_device(PDRIVER_OBJECT driver_object, PDEVICE_OBJECT physical_device_object) {
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

  create_symlinks(physical_device_object, ext);

  device_object->Flags |= DO_BUFFERED_IO;
  device_object->Flags &= ~DO_DEVICE_INITIALIZING;

  return STATUS_SUCCESS;
}

static void driver_unload(PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  vm_callback_destroy();
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);

  auto status = vm_callback_init();
  if (!NT_SUCCESS(status))
    return status;

  driver_object->DriverUnload = driver_unload;
  driver_object->DriverExtension->AddDevice = add_device;

  driver_object->MajorFunction[IRP_MJ_CREATE] = dispatch_irp;
  driver_object->MajorFunction[IRP_MJ_CLOSE] = dispatch_irp;
  driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_irp;
  driver_object->MajorFunction[IRP_MJ_PNP] = dispatch_pnp;
  driver_object->MajorFunction[IRP_MJ_POWER] = dispatch_power;

  return STATUS_SUCCESS;
}

static NTSTATUS dispatch_pnp(PDEVICE_OBJECT device_object, PIRP irp) {
  auto* ext = static_cast<device_extension*>(device_object->DeviceExtension);
  const auto irp_stack = IoGetCurrentIrpStackLocation(irp);

  switch (irp_stack->MinorFunction) {
  case IRP_MN_START_DEVICE:
  case IRP_MN_QUERY_REMOVE_DEVICE:
  case IRP_MN_QUERY_STOP_DEVICE:
  case IRP_MN_CANCEL_REMOVE_DEVICE:
  case IRP_MN_CANCEL_STOP_DEVICE:
  case IRP_MN_STOP_DEVICE:
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(irp);
    return IoCallDriver(ext->lower_device, irp);

  case IRP_MN_REMOVE_DEVICE: {
    delete_symlinks(ext);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(irp);
    auto status = IoCallDriver(ext->lower_device, irp);

    IoDetachDevice(ext->lower_device);
    IoDeleteDevice(device_object);
    return status;
  }

  case IRP_MN_SURPRISE_REMOVAL:
    delete_symlinks(ext);

    irp->IoStatus.Status = STATUS_SUCCESS;
    IoSkipCurrentIrpStackLocation(irp);
    return IoCallDriver(ext->lower_device, irp);

  default:
    IoSkipCurrentIrpStackLocation(irp);
    return IoCallDriver(ext->lower_device, irp);
  }
}

static NTSTATUS dispatch_power(PDEVICE_OBJECT device_object, PIRP irp) {
  auto* ext = static_cast<device_extension*>(device_object->DeviceExtension);
  PoStartNextPowerIrp(irp);
  IoSkipCurrentIrpStackLocation(irp);
  return PoCallDriver(ext->lower_device, irp);
}

NTSTATUS dispatch_irp(PDEVICE_OBJECT device_object, PIRP irp) {
  UNREFERENCED_PARAMETER(device_object);

  irp->IoStatus.Information = 0; // written

  const auto irp_stack = IoGetCurrentIrpStackLocation(irp);

  auto status = STATUS_NOT_IMPLEMENTED;

  switch (irp_stack->MajorFunction) {
  case IRP_MJ_CREATE:
    status = STATUS_SUCCESS;
    break;

  case IRP_MJ_CLOSE:
    if (irp_stack->FileObject->FsContext)
      vm_destroy(irp_stack->FileObject->FsContext);
    status = STATUS_SUCCESS;
    break;

  case IRP_MJ_DEVICE_CONTROL:
    switch (irp_stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_PIO_LOAD_BINARY:
      if (irp_stack->FileObject->FsContext) {
        status = STATUS_ALREADY_INITIALIZED;
      } else {
        PVOID new_ctx{};
        status = vm_load_binary(
          &new_ctx,
          irp->AssociatedIrp.SystemBuffer,
          irp_stack->Parameters.DeviceIoControl.InputBufferLength
        );
        if (NT_SUCCESS(status)) {
          if (nullptr != _InterlockedCompareExchangePointer(&irp_stack->FileObject->FsContext, new_ctx, nullptr)) {
            status = STATUS_UNSUCCESSFUL;
            vm_destroy(new_ctx);
            new_ctx = nullptr;
          }
        }
      }
      break;

    case IOCTL_PIO_EXECUTE_FN:
      if (!irp_stack->FileObject->FsContext) {
        status = STATUS_INVALID_PARAMETER;
      } else {
        status = vm_execute_function(
          irp_stack->FileObject->FsContext,
          irp->AssociatedIrp.SystemBuffer,
          irp_stack->Parameters.DeviceIoControl.InputBufferLength,
          irp->AssociatedIrp.SystemBuffer,
          irp_stack->Parameters.DeviceIoControl.OutputBufferLength
        );
        if (NT_SUCCESS(status))
          irp->IoStatus.Information = irp_stack->Parameters.DeviceIoControl.OutputBufferLength;
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

    default:
      break;
    }
    break;

  default:
    break;
  }

  irp->IoStatus.Status = status;

  IoCompleteRequest(irp, IO_NO_INCREMENT);

  return status;
}
