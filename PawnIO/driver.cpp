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
#include <wdmsec.h>
#include <atomic>

#include "ioctl.h"
#include "vm.h"

static std::atomic<LONG> g_refs = -1;

NTSTATUS dispatch_irp(PDEVICE_OBJECT device_object, PIRP irp);

void driver_unload(PDRIVER_OBJECT driver_object)
{
  const auto device_object = driver_object->DeviceObject;
  UNICODE_STRING device_dospath = RTL_CONSTANT_STRING(k_device_dospath);
  
  IoDeleteSymbolicLink(&device_dospath);

  if (device_object)
    IoDeleteDevice(device_object);
}

const GUID k_device_class = { 0x7c619961, 0xf266, 0x4c1b, { 0x84, 0x72, 0x8d, 0x00, 0x47, 0xd6, 0xd4, 0x7a } };

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
  UNREFERENCED_PARAMETER(registry_path);

  UNICODE_STRING device_path = RTL_CONSTANT_STRING(k_device_path);
  PDEVICE_OBJECT device_object = nullptr;
  auto status = IoCreateDeviceSecure(
    driver_object,
    0,
    &device_path,
    k_device_type,
    0,
    FALSE,
    &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
    &k_device_class,
    &device_object
  );

  if (!NT_SUCCESS(status))
  {
    return status;
  }

  driver_object->DriverUnload = driver_unload;
  
  driver_object->MajorFunction[IRP_MJ_CREATE] = dispatch_irp;
  driver_object->MajorFunction[IRP_MJ_CLOSE] = dispatch_irp;
  driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_irp;

  UNICODE_STRING device_dospath = RTL_CONSTANT_STRING(k_device_dospath);
  status = IoCreateSymbolicLink(&device_dospath, &device_path);

  if (!NT_SUCCESS(status))
  {
    IoDeleteDevice(device_object);
    return status;
  }

  driver_object->Flags &= ~DO_DEVICE_INITIALIZING;

  g_refs = 0;

  return status;
}

NTSTATUS dispatch_irp(PDEVICE_OBJECT device_object, PIRP irp)
{
  UNREFERENCED_PARAMETER(device_object);
  
  irp->IoStatus.Information = 0; // written

  const auto irp_stack = IoGetCurrentIrpStackLocation(irp);
  
  auto status = STATUS_NOT_IMPLEMENTED;
  
  switch (irp_stack->MajorFunction)
  {
  case IRP_MJ_CREATE:
    ++g_refs;
    status = STATUS_SUCCESS;
    break;

  case IRP_MJ_CLOSE:
    if (irp_stack->FileObject->FsContext)
      vm_destroy(irp_stack->FileObject->FsContext);
    --g_refs;
    status = STATUS_SUCCESS;
    break;

  case IRP_MJ_DEVICE_CONTROL:
    switch (irp_stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_PIO_GET_REFCOUNT:
      if(irp_stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(LONG))
      {
        *(PLONG)irp->AssociatedIrp.SystemBuffer = g_refs;
        irp->IoStatus.Information = sizeof(g_refs);
        status = STATUS_SUCCESS;
      }
      else
      {
        status = STATUS_BUFFER_OVERFLOW;
      }
      break;

    case IOCTL_PIO_LOAD_BINARY:
      if (irp_stack->FileObject->FsContext)
      {
        status = STATUS_ALREADY_INITIALIZED;
      }
      else
      {
        status = vm_load_binary(
          irp_stack->FileObject->FsContext,
          irp->AssociatedIrp.SystemBuffer,
          irp_stack->Parameters.DeviceIoControl.InputBufferLength
        );
      }
      break;

    case IOCTL_PIO_EXECUTE_FN:
      if (!irp_stack->FileObject->FsContext)
      {
        status = STATUS_INVALID_PARAMETER;
      }
      else
      {
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
