#pragma once

NTSTATUS vm_load_binary(PVOID& ctx, PVOID buffer, SIZE_T size);
NTSTATUS vm_execute_function(PVOID ctx, PVOID in_buffer, SIZE_T in_size, PVOID out_buffer, SIZE_T out_size);
NTSTATUS vm_destroy(PVOID ctx);
