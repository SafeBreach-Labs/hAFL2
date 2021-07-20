# Technical Details (Background, Implementation)
In this section I'll explain the modifications / parts I've added to the kAFL project in order to enable hypervisor fuzzing.

**A basic virtualization knowledge is required in order to understand the technical details I'll describe during this section   
(e.g. VM-Exit and VM-Entry, Hypercalls, GPA and GVA, etc.)**

- [Technical Details (Background, Implementation)](#technical-details-background-implementation)
	- [Nested Virtualization](#nested-virtualization)
		- [Nested Hypervisor](#nested-hypervisor)
		- [Fuzzing Hypervisors (with hAFL2)](#fuzzing-hypervisors-with-hafl2)
		- [The Hyper-V Fuzzing Scenario and VSPs](#the-hyper-v-fuzzing-scenario-and-vsps)
	- [Code Coverage (Intel PT MSR)](#code-coverage-intel-pt-msr)
		- [Code modification for VM-Entry and VM-Exit](#code-modification-for-vm-entry-and-vm-exit)
		- [Handling EXIT_REASON_TOPA_FULL exit reason](#handling-exit_reason_topa_full-exit-reason)
	- [Harness and Crash Monitoring communication](#harness-and-crash-monitoring-communication)
		- [Hypercalls](#hypercalls)
		- [R/W of Nested VM Memory](#rw-of-nested-vm-memory)
	- [Porting to QEMU 6](#porting-to-qemu-6)
	- [Wrap Up](#wrap-up)
---
## Nested Virtualization
*As kAFL is using the KVM Hypervisor with Intel PT, this paper will only refer the nested virtualization architecture of Intel processors and KVM terminology as well.*

### Nested Hypervisor
*This paper will only be focused on specific scenarios of this field, if you'd like to know more I recommend you to look of [Liran Alon's](https://twitter.com/liran_alon?lang=en) [talk about this topic](https://www.linux-kvm.org/images/3/33/02x03-NestedVirtualization.pdf).*

Nested virtualization is almost entirely implemented within KVM as Intel VMX only supports handling one logical unit of CPU at a time.
It means that KVM must be aware of each one of the nested VMs which are running within a nested hypervisor and almost fully manage each. **This fact is great for us, as we have full control of any nested VM on L2 from within KVM on L0.**  
It actually enables us to fully communicate with a nested VM by:  
1. Handling its hypercalls before the hypercalls are reflected to the L1 hypervisor (for communicating with the nested VM's harness)  
2. Read / Write from/to its memory directly (For transferring fuzzing payloads and crash details)  
3. Specify a certain MSR directly to it (for enabling code coverage for a specific VM)  

We'll get back to these 3 points in the next sections.


### Fuzzing Hypervisors (with hAFL2)
In contrast to kAFL which is using only one level of virtualization (L1, a single VM which is being targeted), hAFL2 is using two levels of virtualization:  
1. L1 - The target hypervisor  
2. L2 - The guest VM which runs within the target hypervisor and executes the harness.  

In this hypervisor fuzzing scenario (excluding Hyper-V which we will talk about in the next paragraph), we would like to:  
1. Send our fuzzing payloads directly to L2's (the child partition VM) harness, which will send the payload  to the target hypervisor.  
2. Retrieve code coverage out of L1 (the target hypervisor)  
3. Monitor crashes on L1 (in order to understand if we crashed the target hypervisor with our payload.)  

### The Hyper-V Fuzzing Scenario and VSPs
When it comes to Hyper-V, things might be a little bit different.  
If we would like to fuzz Hyper-V itself, we won't need to modify a thing.

But, a lot of prior bugs indicated that there is a large attack surface within the [VSPs of Hyper-V](https://msrc-blog.microsoft.com/2019/01/28/fuzzing-para-virtualized-devices-in-hyper-v/).

The L2 layer is consists of two VMs (a.k.a partitions):  
1. Root Partition - The host OS (Which runs the VSPs) - this is our target!  
2. Child Partition - The guest VM, which executes the harness as before.  

In order to fuzz a VSP, we will need to:
1. Send our fuzzing payload to the child partition VM within L2, but this time, our harness will send the payload to the VSP, which means it will send it to the root partition on L2 as well.  
2. Retrieve code coverage out of our target - the root partition - which runs in L2  
3. Monitor crashes on L2 (root partition).  

Now that we understand exactly what the basic blocks of hypervisor fuzzing are, it's time to describe how each part was implemented.

## Code Coverage (Intel PT MSR)
kAFL leverages Intel PT in order to retrieve code coverage.  
Enabling Intel PT is possible by writing specific values to an MSR called `IA32_RTIT_CTL`.  
In order to obtain code coverage only from the root partition VM (instead of retreiving it from the Hyper-V itself or the child partition VM), we need to enable Intel PT only for the root partition VM. To do so, the `IA32_RTIT_CTL` MSR should be enabled for a specific VM.  

KVM is perfectly aware of which VM is being handled right now (nested or not.)
In order to enable code coverage of a nested VM, modification to the VM-Entry and VM-Exit handlers of KVM is required, in addition to enabling / disabling the `IA32_RTIT_CTL` MSR only when we are handling the root partition VM.

### Code modification for VM-Entry and VM-Exit
The modification was added within the `vmx_vcpu_run` function in `arch/x86/kvm/vmx/vmx.c` for VM-Entry (enabling Intel PT):
```C
    [... SNIP ...]
	// HYPERV_CPUID_FEATURES and HV_CPU_MANAGEMENT are pre-defined by KVM.
	bool is_root_partition = cpuid_ebx(HYPERV_CPUID_FEATURES) & HV_CPU_MANAGEMENT;
    if (is_root_partition) {
			if (vmx->vmx_pt_config->should_enable) {
				vmx_pt_enable(vmx->vmx_pt_config, true);
			}
			vmx_pt_vmentry(vmx->vmx_pt_config);
	}

    [ ... SNIP ...]
```

As mentioned before, this modification is working for Hyper-V's root partition, but you can easily modify it to support any other hypervisors, by using this condition instead of `is_root_partition`:
```C
    bool is_target_vm = vmx->nested.last_vpid == X;
```
Just replace the last_vpid with the virtual processor id of your target VM (should be 0 for the targetg hypervisor itself, at least for Hyper-V.)

The same modification was also implemented for VM-Exit (disabling Intel PT) within `vmx_handle_exit_irqoff` function in `arch/x86/kvm/vmx/vmx.c`
```C
    [... SNIP ...]

    bool topa_full = false;
	// HYPERV_CPUID_FEATURES and HV_CPU_MANAGEMENT are pre-defined by KVM.
	bool is_root_partition = cpuid_ebx(HYPERV_CPUID_FEATURES) & HV_CPU_MANAGEMENT;
	if (is_root_partition) {
		topa_full = vmx_pt_vmexit(vmx->vmx_pt_config);
		vmx_pt_disable(vmx->vmx_pt_config, true);
	}

    [ ... SNIP ...]

    if (is_root_partition && topa_full) {
            vmx->exit_reason.basic = EXIT_REASON_TOPA_FULL;
        }

    [ ... SNIP ...]
```

### Handling EXIT_REASON_TOPA_FULL exit reason
kAFL implementation is specifying the `EXIT_REASON_TOPA_FULL` exit reason for a certain VM (in our scenarion it will be the root partition VM), whenever the ToPA buffers of Intel PT are full.    

KVM actually handles the exit reason of a nested VM before it is reflected to the L1 hypervisor. The target hypervisor doesn't know this exit reason as it's implemented by kAFL modifications, therefore we will have to tell KVM not to reflect this exit reason to L1, and eventually it will be handled within KVM.  

This modification was added within the `nested_vmx_reflect_vmexit` function in `arch/x86/kvm/vmx/nested.c`:
```C
    [ ... SNIP ...]
	// Handle EXIT_REASON_TOPA_FULL on L0, don't reflect it.
	if (exit_reason.basic == EXIT_REASON_TOPA_FULL) {
		return false;
	}
    [ ... SNIP ...]
```

## Harness and Crash Monitoring communication

### Hypercalls
kAFL adds a hypercall which enables the guest VM to communicate with KVM directly (e.g. synchronization between the harness and the fuzzer, indicating a crash, etc.)  

A hypercall is causing to a VM-Exit with the `EXIT_REASON_VMCALL` exit reason.  
We need to make sure that this exit reason will be handled within KVM and won't be transferred to the L1 hypervisor. In order to do so, we will modify the following code (the `nested_vmx_reflect_vmexit` function in `arch/x86/kvm/vmx/nested.c`:)
```C
    [... SNIP ...]
    // Handle kAFL-Specific Hypercall in L0, don't reflect to L1.
	if (exit_reason.basic == EXIT_REASON_VMCALL) {
		nr = kvm_rax_read(vcpu);
		if (nr == HYPERCALL_KAFL_RAX_ID) {
			a0 = kvm_rbx_read(vcpu);
			a1 = kvm_rcx_read(vcpu);
			printk(KERN_INFO "[HYPERCALL_KAFL_RAX_ID] a0: 0x%lx, a1: 0x%lx, last_vpid: 0x%x\n",
				a0, a1, vmx->nested.last_vpid);
			return false;
		}
	}
    [... SNIP ...]
```

After the modification, KVM will forward the kAFL-originated hypercalls to QEMU-PT which contains the hypercall handling part of kAFL (the implementation can be found within `qemu-6.0.0/accel/kvm/kvm-all.c`).  

The harness and crash monitoring parts are now completed.

### R/W of Nested VM Memory
kAFL is using QEMU API in order to read/write from/to the guest memory (e.g. reading the target's memory and disassemble it for code coverage, writing the fuzzing payloads to the guest's buffer, etc.)

When it comes to nested virtualization, QEMU is trying to convert the GVA of L2 by using the memory mapping of L1 which ovbiously failed.  

In contrast to QEMU, KVM is actually fully aware of the nested VM memory mapping, so when it tries to convert a GVA to a GPA it actually uses the `vcpu->arch.walk_mmu` struct which is fully aware of any VM memory mapping including nested ones (by leveraging Intel EPT mechanism):  
```C
static void nested_ept_init_mmu_context(struct kvm_vcpu *vcpu)
{
	WARN_ON(mmu_is_nested(vcpu));
    [ ... SNIP ... ]
	vcpu->arch.walk_mmu              = &vcpu->arch.nested_mmu;
    [ ... SNIP ... ]
}
```

The first nested VM memory R/W was originated by the disassembler component of QEMU-PT which tries to disassemble the code of the target as part of its code coverage retrieval. In order to do so, it maps a GVA directly to QEMU, in order to read the target's memory in an efficient manner so it can read it and disassemble it as fast as possible.

KVM implements an IOCTL named `KVM_TRANSLATE` which translates GVA to GPA, which of course works with nested GVAs. All I had to do was modify QEMU-PT so it will translate GVAs by leveraging KVM, instead of doing it on its own (the example is from the `analyse_assembly` function in `qemu-6.0.0/pt/disassembler.c`:)    
```C
    [ ... SNIP ... ]

    kvm_vcpu_ioctl(self->cpu, KVM_TRANSLATE, &translation);
		printf("GVA: 0x%llx, GPA: 0x%llx, valid: 0x%x\n",
					translation.linear_address, translation.physical_address, translation.valid);
	if (translation.physical_address == 0xFFFFFFFFFFFFFFFF) {
		goto out;
	}
	code = mmap_physical_memory(translation.physical_address, self->cpu);

    [ ... SNIP ... ]
```

The second nested VM memory R/W was originated by the QEMU hypercalls handling implementation, e.g., writing the fuzzing payloads to the harness buffers, reading the crash details from the root partition VM, etc.

In order to solve this part, I implemented two KVM IOCTLs: `KVM_VMX_PT_WRITE_TO_GUEST` and `KVM_VMX_PT_READ_FROM_GUEST` which enable QEMU to read/write memory from a nested VM by using KVM instead of trying to perform it on its own.

After implementing both KVM and QEMU parts, the relevant `read_virtual_memory / write_virtual_memory` calls in QEMU were replaced to `read_virtual_memory_via_kvm / write_virtual_memory_via_kvm`.

The implementation of the QEMU-side functions can be found within `qemu-6.0.0/pt/memory_access.c`.
The implementation of the KVM-side functionality can be found within the `kvm_arch_vcpu_ioctl` function in `/arch/x86/kvm/x86.c`.

## Porting to QEMU 6
The original kAFL project supports QEMU 5.0.0.

When I tried to take the final fuzzing snapshot of my target VM (which contains Hyper-V, root partition and a child partition), I've noticed that the guest was freezed when the snapshot was resumed.  
I'm not sure what exactly the problem was, but porting the fuzzer to QEMU-6.0.0 solved the problem.

You may look at the patches in order to understand exactly what modifications were required.


## Wrap Up
The hAFL2 modifications that were added to kAFL within this project enables one to get all of the basic blocks which are required in order to start the fuzzing process for a hypervisor target. I hope the implementation is more clear now but feel free to explore the source code or send me a DM (([@peleghd](https://twitter.com/peleghd)) if you have any doubts.  