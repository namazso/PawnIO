//  PawnIO Headers - Headers for writing PawnIO modules.
//  Copyright (C) 2025  namazso <admin@namazso.eu>
//  
//  Permission to use, copy, modify, and/or distribute this software for any
//  purpose with or without fee is hereby granted.
//  
//  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
//  REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
//  AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
//  INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
//  LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
//  OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
//  PERFORMANCE OF THIS SOFTWARE.
//  
//  SPDX-License-Identifier: 0BSD

// PawnIO native functions for low-level operations.

/// Send a message to the kernel debugger.
///
/// @param fmt Format string, only integers are supported
/// @param ... Arguments to format string
native NTSTATUS:debug_print(const fmt[], ...);

/// Get the address of a public function in current module.
///
/// @param name Function name
/// @return AMX virtual address of function
native AmxCip:get_public(const name[]);

/// Allocate a callback function, calling @p cip when called
///
/// @param cip AMX virtual address which will be called when the callback is invoked
/// @return Virtual address of the callback function
/// @retval 0 Allocation failed
native VAProc:callback_alloc(AmxCip:cip);

/// Free a callback function.
///
/// @param pfn Virtual address of the callback function to free
native Void:callback_free(VAProc:pfn);

const CPUArch: {
    ARCH_X64 = 1,
    ARCH_A64 = 2
};

/// Get the current architecture.
///
/// @return The current architecture
/// @retval ARCH_X64 x86-64
/// @retval ARCH_A64 ARM64
native CPUArch:get_arch();

/// Get total CPU count.
/// @return CPU count
native cpu_count();

/// Set affinity to specific CPU.
///
/// @param which Which CPU to pin to
/// @param old Old affinity, for restoring later
/// @return An NTSTATUS
/// @warning Only takes effect on passive IRQL / interrupts enabled
native NTSTATUS:cpu_set_affinity(which, old[2]);

/// Restore affinity.
///
/// @param old Old affinity to restore
/// @return An NTSTATUS
/// @warning Only takes effect on passive IRQL / interrupts enabled
native NTSTATUS:cpu_restore_affinity(old[2]);

/// Read MSR.
///
/// @param msr MSR Index
/// @param value Output value
/// @return An NTSTATUS
native NTSTATUS:msr_read(msr, &value);

/// Write MSR.
///
/// @param msr MSR Index
/// @param value New value
/// @return An NTSTATUS
native NTSTATUS:msr_write(msr, value);

/// Disable interrupts, effectively raises IRQL to maximum.
native Void:interrupts_disable();

/// Enable interrupts.
native Void:interrupts_enable();

/// Read a byte from physical memory.
///
/// @param pa Physical address
/// @param value Value read
/// @return An NTSTATUS
/// @note Only works on ranges already mapped by the kernel
native NTSTATUS:physical_read_byte(pa, &value);

/// Read a word from physical memory.
///
/// @param pa Physical address
/// @param value Value read
/// @return An NTSTATUS
/// @note Only works on ranges already mapped by the kernel
native NTSTATUS:physical_read_word(pa, &value);

/// Read a double word from physical memory.
///
/// @param pa Physical address
/// @param value Value read
/// @return An NTSTATUS
/// @note Only works on ranges already mapped by the kernel
native NTSTATUS:physical_read_dword(pa, &value);

/// Read a quad word from physical memory.
///
/// @param pa Physical address
/// @param value Value read
/// @return An NTSTATUS
/// @note Only works on ranges already mapped by the kernel
native NTSTATUS:physical_read_qword(pa, &value);

/// Write a byte to physical memory.
///
/// @param pa Physical address
/// @param value Value to write
/// @return An NTSTATUS
/// @note Only works on ranges already mapped by the kernel
native NTSTATUS:physical_write_byte(pa, value);

/// Write a word to physical memory.
///
/// @param pa Physical address
/// @param value Value to write
/// @return An NTSTATUS
/// @note Only works on ranges already mapped by the kernel
native NTSTATUS:physical_write_word(pa, value);

/// Write a double word to physical memory.
///
/// @param pa Physical address
/// @param value Value to write
/// @return An NTSTATUS
/// @note Only works on ranges already mapped by the kernel
native NTSTATUS:physical_write_dword(pa, value);

/// Write a quad word to physical memory.
///
/// @param pa Physical address
/// @param value Value to write
/// @return An NTSTATUS
/// @note Only works on ranges already mapped by the kernel
native NTSTATUS:physical_write_qword(pa, value);

const VA:NULL = VA:0;

stock VA:operator+(VA:a, b) {
    return a + VA:b;
}

stock VA:operator-(VA:a, b) {
    return a - VA:b;
}

stock operator-(VA:a, VA:b) {
    return _:a - _:b;
}

/// Map IO space.
///
/// Map physical memory to virtual, which can be accessed by the `virtual_*`
/// family of functions.
///
/// @param pa Physical address
/// @param size Size to map
/// @return Virtual address
/// @retval 0 Mapping failed, not enough VA space
/// @warning The mapping is a resource that must be freed (unmapped)
native VA:io_space_map(pa, size);

/// Unmap IO space.
///
/// @param pa Physical address
/// @param size Size to unmap
native Void:io_space_unmap(VA:va, size);

/// Read a byte from virtual memory.
///
/// @param va Virtual address
/// @param value Value read
/// @return An NTSTATUS
native NTSTATUS:virtual_read_byte(VA:va, &value);

/// Read a word from virtual memory.
///
/// @param va Virtual address
/// @param value Value read
/// @return An NTSTATUS
native NTSTATUS:virtual_read_word(VA:va, &value);

/// Read a double word from virtual memory.
///
/// @param va Virtual address
/// @param value Value read
/// @return An NTSTATUS
native NTSTATUS:virtual_read_dword(VA:va, &value);

/// Read a quad word from virtual memory.
///
/// @param va Virtual address
/// @param value Value read
/// @return An NTSTATUS
native NTSTATUS:virtual_read_qword(VA:va, &value);

/// Write a byte to virtual memory.
///
/// @param va Virtual address
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:virtual_write_byte(VA:va, value);

/// Write a word to virtual memory.
///
/// @param va Virtual address
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:virtual_write_word(VA:va, value);

/// Write a double word to virtual memory.
///
/// @param va Virtual address
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:virtual_write_dword(VA:va, value);

/// Write a quad word to virtual memory.
///
/// @param va Virtual address
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:virtual_write_qword(VA:va, value);

/// Compare and exchange a byte in virtual memory.
///
/// @param va Virtual address
/// @param exchange Value to exchange
/// @param comparand Value to compare against
/// @return An NTSTATUS
/// @retval STATUS_SUCCESS Exchange successful, comparand was equal to the value at va
/// @retval STATUS_UNSUCCESSFUL Exchange failed, comparand was not equal to the value
native NTSTATUS:virtual_cmpxchg_byte2(VA:va, exchange, comparand);

/// Compare and exchange a word in virtual memory.
///
/// @param va Virtual address
/// @param exchange Value to exchange
/// @param comparand Value to compare against
/// @return An NTSTATUS
/// @retval STATUS_SUCCESS Exchange successful, comparand was equal to the value at va
/// @retval STATUS_UNSUCCESSFUL Exchange failed, comparand was not equal to the value
native NTSTATUS:virtual_cmpxchg_word2(VA:va, exchange, comparand);

/// Compare and exchange a double word in virtual memory.
///
/// @param va Virtual address
/// @param exchange Value to exchange
/// @param comparand Value to compare against
/// @return An NTSTATUS
/// @retval STATUS_SUCCESS Exchange successful, comparand was equal to the value at va
/// @retval STATUS_UNSUCCESSFUL Exchange failed, comparand was not equal to the value
native NTSTATUS:virtual_cmpxchg_dword2(VA:va, exchange, comparand);

/// Compare and exchange a quad word in virtual memory.
///
/// @param va Virtual address
/// @param exchange Value to exchange
/// @param comparand Value to compare against
/// @return An NTSTATUS
/// @retval STATUS_SUCCESS Exchange successful, comparand was equal to the value at va
/// @retval STATUS_UNSUCCESSFUL Exchange failed, comparand was not equal to the value
native NTSTATUS:virtual_cmpxchg_qword2(VA:va, exchange, comparand);

/// Allocate non-paged virtual memory.
///
/// @param size Size to allocate
/// @return Allocation virtual address
/// @retval 0 Out of memory
/// @warning The allocation is a resource that must be freed
native VA:virtual_alloc(size);

/// Free a virtual allocation.
///
/// @param va Allocation virtual address
native virtual_free(VA:va);

/// Read a byte from PCI configuration space.
///
/// @param bus Bus number
/// @param device Device number
/// @param function Function number
/// @param offset Byte offset
/// @param value Output value
/// @return An NTSTATUS
native NTSTATUS:pci_config_read_byte(bus, device, function, offset, &value);

/// Read a word from PCI configuration space.
///
/// @param bus Bus number
/// @param device Device number
/// @param function Function number
/// @param offset Byte offset
/// @param value Output value
/// @return An NTSTATUS
native NTSTATUS:pci_config_read_word(bus, device, function, offset, &value);

/// Read a double word from PCI configuration space.
///
/// @param bus Bus number
/// @param device Device number
/// @param function Function number
/// @param offset Byte offset
/// @param value Output value
/// @return An NTSTATUS
native NTSTATUS:pci_config_read_dword(bus, device, function, offset, &value);

/// Read a quad word from PCI configuration space.
///
/// @param bus Bus number
/// @param device Device number
/// @param function Function number
/// @param offset Byte offset
/// @param value Output value
/// @return An NTSTATUS
native NTSTATUS:pci_config_read_qword(bus, device, function, offset, &value);

/// Write a byte to PCI configuration space.
///
/// @param bus Bus number
/// @param device Device number
/// @param function Function number
/// @param offset Byte offset
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:pci_config_write_byte(bus, device, function, offset, value);

/// Write a word to PCI configuration space.
///
/// @param bus Bus number
/// @param device Device number
/// @param function Function number
/// @param offset Byte offset
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:pci_config_write_word(bus, device, function, offset, value);

/// Write a double word to PCI configuration space.
///
/// @param bus Bus number
/// @param device Device number
/// @param function Function number
/// @param offset Byte offset
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:pci_config_write_dword(bus, device, function, offset, value);

/// Write a quad word to PCI configuration space.
///
/// @param bus Bus number
/// @param device Device number
/// @param function Function number
/// @param offset Byte offset
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:pci_config_write_qword(bus, device, function, offset, value);

/// Get virtual address of a kernel function.
///
/// @param name Function name
/// @return Virtual address of function
/// @retval 0 Function not found
native VAProc:get_proc_address(name[]);

/// Invoke an arbitrary function pointer.
///
/// @param address Function address
/// @param retval Return value
/// @param a0 Parameter to pass through
/// @param a1 Parameter to pass through
/// @param a2 Parameter to pass through
/// @param a3 Parameter to pass through
/// @param a4 Parameter to pass through
/// @param a5 Parameter to pass through
/// @param a6 Parameter to pass through
/// @param a7 Parameter to pass through
/// @param a8 Parameter to pass through
/// @param a9 Parameter to pass through
/// @param a10 Parameter to pass through
/// @param a11 Parameter to pass through
/// @param a12 Parameter to pass through
/// @param a13 Parameter to pass through
/// @param a14 Parameter to pass through
/// @param a15 Parameter to pass through
/// @return NTSTATUS of any exception that occurred, or STATUS_SUCCESS
native NTSTATUS:invoke(VAProc:address, &retval, a0=0, a1=0, a2=0, a3=0, a4=0, a5=0, a6=0, a7=0, a8=0, a9=0, a10=0, a11=0, a12=0, a13=0, a14=0, a15=0);

/// Sleep.
///
/// @param us Microseconds to sleep
/// @return An NTSTATUS
native NTSTATUS:microsleep(us);

/// Busy sleep.
///
/// @param us Microseconds to sleep
/// @return An NTSTATUS
native NTSTATUS:microsleep2(us);

/// Get the current value of the high precision performance counter.
/// @param frequency Performance counter frequency
/// @return Current performance counter value
native qpc(&frequency);

/// Invoke DELL SMM.
///
/// @param in Input registers in order eax ecx edx ebx esi edi
/// @param out Output registers in order eax ecx edx ebx esi edi
/// @return Whether the request succeeded
native bool:query_dell_smm(const in[6], out[6]);

/// Write byte to IO port.
///
/// @param port Port to write to
/// @param value Value to write
native io_out_byte(port, value);

/// Write word to IO port.
///
/// @param port Port to write to
/// @param value Value to write
native io_out_word(port, value);

/// Write double word to IO port.
///
/// @param port Port to write to
/// @param value Value to write
native io_out_dword(port, value);

/// Read byte from IO port.
///
/// @param port Port to read from
/// @return Value read
native io_in_byte(port);

/// Read word from IO port.
///
/// @param port Port to read from
/// @return Value read
native io_in_word(port);

/// Read double word from IO port.
///
/// @param port Port to read from
/// @return Value read
native io_in_dword(port);

// Used to be AMD Lightweight Profiling, however it was discontinued and
//   removed from all supported CPUs due to Spectre.
//native llwpcb(addr);
//native slwpcb();

/// Execute cpuid.
///
/// @param leaf Passed in eax
/// @param subleaf Passed in ecx
/// @param out Output eax, ebc, ecx, edx
native Void:cpuid(leaf, subleaf, out[4]);

/// Read control register.
///
/// @param cr Control register number to read
/// @return Value read
native cr_read(cr);

/// Write control register.
///
/// @param cr Control register number to write
/// @param value Value to write
native Void:cr_write(cr, value);

/// Read debug register.
///
/// @param dr Debug register number to read
/// @return Value read
native dr_read(dr);

/// Write debug register.
///
/// @param dr Debug register number to write
/// @param value Value to write
native Void:dr_write(dr, value);

/// Read extended control register.
///
/// @param xcr Extended control register number to read
/// @param value Value read
/// @return An NTSTATUS
native NTSTATUS:xcr_read(xcr, &value);


/// Write control register.
///
/// @param cr Control register number to write
/// @param value Value to write
/// @return An NTSTATUS
native NTSTATUS:xcr_write(xcr, value);

/// Invalidate TLB.
///
/// @param va Virtual address
native Void:invlpg(va);

/// Invalidate TLB for PCID.
///
/// @param type Type
/// @param descriptor Pointer to descriptor
native Void:invpcid(type, VA:descriptor);

/// Read performance counter.
///
/// @param pmc Performance counter to read
/// @param value Value read
/// @return An NTSTATUS
native NTSTATUS:readpmc(pmc, value);

/// Read TSC.
///
/// @return TSC
native rdtsc();

/// Read TSC and Processor ID
///
/// @param pid Processor ID read
/// @return TSC
native rdtscp(&pid);

/// Invoke 64 bit RDRAND.
///
/// @param v Random number
/// @return Whether the call succeeded
native rdrand(&v);

/// Invoke 64 bit RDSEED.
///
/// @param v Random number
/// @return Whether the call succeeded
native rdseed(&v);

/// Load IDT.
///
/// @param limit Limit
/// @param base Base
native Void:lidt(limit, base);

/// Store IDT.
///
/// @param limit Limit
/// @param base Base
native Void:sidt(&limit, &base);

/// Load GDT.
///
/// @param limit Limit
/// @param base Base
native Void:lgdt(limit, base);

/// Store GDT.
///
/// @param limit Limit
/// @param base Base
native Void:sgdt(&limit, &base);

/// Read MXCSR.
///
/// @return MXCSR
native mxcsr_read();

/// Write MXCSR.
///
/// @param v MXCSR
native Void:mxcsr_write(v);

/// Set AC in EFLAGS.
native Void:stac();

/// Clear AC in EFLAGS.
native Void:clac();

/// Invoke HALT.
native Void:halt();

/// Invoke UD2.
native Void:ud2();

/// Invoke INT3.
native Void:int3();

/// Invoke INT 2C.
native Void:int2c();

/// Write Back and Invalidate Cache.
native Void:wbinvd();
