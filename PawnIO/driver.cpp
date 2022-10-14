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
