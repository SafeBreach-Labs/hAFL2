# hAFL2 Deployment Tutorial for Hyper-V Fuzzing

**Disclaimer**: hAFL2 was used to fuzz Hyper-V’s virtual switch (*vmswitch.sys*). 
The fuzzer can be adjusted to fuzz other target hypervisors, but this tutorial will focus on fuzzing the above-mentioned driver.
# kAFL

This phase will build Linux, KVM-PT and QEMU-PT on your Linux machine.

**Note:** make sure you run the fuzzer on a bare-metal machine with a CPU that supports Intel-PT.

1. Clone this repository.
2. Enter the hAFL2 directory.
3. Execute the following commands by the following order:  
    - `sudo bash install.sh check`
    - `sudo bash install.sh deps`
    - `sudo bash install.sh qemu`
    - `sudo bash install.sh linux`
    - `sudo bash install.sh perms`
    - `sudo bash install.sh targets`
4. Once you're done and everything finished sucessfully, execute the following command and follow the instructions in order to install the modified Linux kernel:  
    - `sudo bash install.sh note`


# Notes
1. hAFL2 was tested only on Ubuntu 20.04
2. During the installation, whenever Windows tries to restart, QEMU might hang with a black screen. If that is the case, quit QEMU (Ctrl+C) and re-run the VM.*
3. Whenever you'll execute `qemu-system-x86_64` you'll see the following warning, just ignore it, everything is fine:  
`qemu-system-x86_64: warning: host doesn't support requested feature: CPUID.07H:EBX.intel-pt [bit 25]`
3. During the tutorial I've used `/root` in some of the paths for convinient, you may use another path but I haven't tested it.
4. Make sure to run all of the commands as a root user.
5. There might be an issue with QEMU and Rocket Lake (Intel 11th Gen) CPUs, I haven't tested it.

# Creating a Root Partition VM
   0. Execute `uname -r` and make sure the output contains `hAFL2`.  
   1. [Obtain a Windows 10 Insider ISO file](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewiso) (21354.1000), we'll be using Windows10_InsiderPreview_Client_x64_en-us_21354.iso (Select `"Windows 10 Insider Preview (Dev Channel) - Build 21354" Edition`).  
      - You may need to register to Windows Insider Program.
   2. Create a QEMU disk image:
    `./hAFL2/qemu-6.0.0/build/qemu-img create -f qcow2 windows.qcow2 100G`
3. Run the machine and install Windows, replace `ISO_FILE_PATH` with the Windows ISO path you've downloaded, replace 6144 (6GB) with the required RAM size, I recommend to use 6144 if it's feasible:  
    `./hAFL2/qemu-6.0.0/build/x86_64-softmmu/qemu-system-x86_64 -cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time,+intel-pt,-hypervisor,+vmx -machine q35 -enable-kvm -m RAM_SIZE -hda ./windows.qcow2 -bios /root/hAFL2/OVMF_CODE-pure-efi.fd -cdrom ISO_FILE_PATH -net none -usbdevice tablet`  
   4. Install Windows 10 Pro, which has Hyper-V capabilities.
   5. Consider do the following:
       - [Disable Windows Defender permanently using local group policy](https://www.windowscentral.com/how-permanently-disable-windows-defender-antivirus-windows-10).
       - Disable Fast Startup from within an elevated command prompt:  
        `REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V HiberbootEnabled /T REG_DWORD /D 1 /F`
   6. Enable Hyper-V on the VM by running the following within a PowerShell console as Administrator:  
    `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All`  
       - Enter 'Y' on console and restart the VM (as I mentioned, you might need to use Ctrl-C and re-execute QEMU as it might hang.)
   7. Make sure the VM was booted properly and shut it down properly (`shutdown -t 0 -s`), this is important as we'll need to mount the HDD of it in a second, and if you won't turn it off properly it won't mount.

## Creating a Child Partition VM

1. Copy the `Windows10_InsiderPreview_Client_x64-en-us_21354.iso` ISO file from a dedicated folder to the root partition VM (wait patiently, it will take a few minutes as it's a large file):  
`copy_files_to_vm.sh [WINDOWS_ISO_FOLDER_PATH] windows.qcow2`  

2. Turn on the Root Partition VM:
```c
./hAFL2/qemu-6.0.0/build/x86_64-softmmu/qemu-system-x86_64 -cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time,+intel-pt,-hypervisor,+vmx -machine q35 -enable-kvm -m 16384 -hda ./windows.qcow2 -bios /root/hAFL2/OVMF_CODE-pure-efi.fd -net none -usbdevice tablet
```  
  
3. From within the Root Partition VM, create a Child Partition VM by using Hyper-V VM creation wizard (2048MB RAM is probably enough):  
    - Make sure to choose "Generation 2 VM"  
    - Set HDD to less than 50GB  
    - Choose the Windows 10 ISO (VM Settings → DVD Drive → Image File)(`Windows10_InsiderPreview_Client_x64-en-us_21354.iso`)  
    - Connect the Child Partition VM to a virtual network switch
    - **Install Windows 10** (21354.1000) on the newly created VM.  
        **Note:** You don't have to use version 21354.1000 for the child partition VM, but it will be easier as the `CPHarness` driver supports this version out-of-the-box. If you'd like to use another Windows 10 version, check out the following paragraph.
### Optional: Using A Custom Windows 10 build for the Child Partition VM (instead of 21354.1000)

The `CPHarness` driver enumerates the NDIS global miniport adapter list of Windows in order to retrieve the VMBus channel pointer of netvsc and use it in order to send packets to the root partition. The offset of this global list is changed between Windows builds, so if you'll use a different version of Windows, make sure to do the following:

1. Use IDA Pro in order to disassemble the`NDIS.sys` of the Windows build you've installed on the child partition VM.
2. Rebase the program address to 0 (`Edit → Segments → Rebase program → 0`)
3. Open the Names window (`Shift+F4`)
4. Look for `ndisMiniportList` and copy its offset.
5. Open `CPFuzzer` source code and change the `MiniportListOffset` (within the `FindOurMiniportChannel`) to the offset you've copied.
6. Don't compile it yet.

## Configuring the Child Partition VM

Note: *Make sure the child partition VM is turned off.*
**Do the following from within the Root Partition VM:**  
    1. open a PowerShell console as an Administrator and execute the following command in order to connect the Network Adapter of the child partition VM:
    `Connect-VMNetworkAdapter -VMName VM -SwitchName "Default Switch"`  
    2. Disable child partition secure boot (from within the root partition VM) by opening an elevated PowerShell console and execute the following:
    `Set-VMFirmware "VM" -EnableSecureBoot Off`  

**Do the following from within the Child Partition VM (Turn it on):**  
    1. make sure to disable Windows Defender permanently.  
    2. Run the following command from within PowerShell:
    `(Get-NetAdapter)[0].InterfaceDescription`  
    3. Modify the `ourName` variable within the CPHarness driver to the output of the previous command, for example, if the output was `Microsoft Hyper-V Network Adapter`, assign the variable with:  
        `UNICODE_STRING ourName = RTL_CONSTANT_STRING(L"Microsoft Hyper-V Network Adapter");`  
    4. Disable Child Partition DSE by running the following from within an elevated command prompt (restart the child partition VM after you're done):  
    `bcdedit /set testsigning on && bcdedit /set nointegritychecks on && bcdedit -set loadoptions DDISABLE_INTEGRITY_CHECKS`  
# Compile Necessary Binaries
You need to compile both the harness and the crash monitoring driver from the hAFL2 codebase. We will be using two of them - packet_sender.exe (the program which triggers the packet-sending IOCTL) and loader.exe (which creates a fuzzing snapshot, loads and executes packet_sender.exe).

1. Compile hAFL2’s fuzzing binaries by executing the following within bash:  
 `pushd ./hAFL2/targets/windows_x86_64 && ./compile.sh && popd`  
2. Use Visual Studio to compile both drivers from within the `hAFL2\drivers` folder.  
    - **CPHarness** (`Child Partition Harness`) - this driver will be installed within the child partition VM, and will send packets of fuzzing payloads to the root partition's VMSwitch.  
    - **CrashMonitoring** - this driver will send root partition crashes to hAFL2 by using an hypercall interface.  
  - **Within VS**:
     * right click on each project -> Properties -> Driver Signing -> General  
     * Change "Sign Mode" to "Test Sign"  
     * Set "File Digest Algorithm" to "SHA1"
     * Then compile.


# **Optimizing the Crash Monitoring and Disabling DSE for Root Partition VM**
1. Execute the Root Partition VM:  
`./hAFL2/qemu-6.0.0/build/x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time,+intel-pt,-hypervisor,+vmx -usbdevice tablet -m 16384 -bios /root/hAFL2/OVMF_CODE-pure-efi.fd -drive file=windows.qcow2 -machine q35 -net none`  
1. In order to make the crash monitoring functionality operate faster, open PowerShell (within the root partition VM) as an Administrator and execute the following command:  
`Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0`  
3. Disable Driver Signature Enforcement from within an elevated command prompt (Restart the root partition VM once you're done):
`bcdedit /set testsigning on &&`  
`bcdedit /set nointegritychecks on &&`  
`bcdedit -set loadoptions DDISABLE_INTEGRITY_CHECKS`  

# Preparing the Root and Child Partition VMs for Fuzzing
1. Enable Driver Verifier for vmswitch.sys on the Root Partition VM:  
`verifier /standard /driver vmswitch.sys`  
2. Turn off the Root Partition VM by executing the `shutdown -t 0 -s` command.  
3. Download / compile the following files (files in bold should be compiled in previous steps) to a dedicated folder on hAFL2 server:  
    - Devcon.exe ([Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/)) - this will install the harness driver.  
    - **CPHarness.sys, CPHarness.inf, CPHarness.cat, CPharness.cer** (`drivers/CPHarness` folder in hAFL2 Repo)  
    - **CrashMonitoringDriver.sys, CrashMonitoringDriver.inf, CrashMonitoringDriver.cat, CrashMonitoringDriver.cer** (`drivers/CrashMonitoringDriver`)  
    - **loader.exe** `(./hAFL2/targets/windows_x86_64/bin/loader/loader.exe`)  
    - **info.exe** (`./hAFL2/targets/windows_x86_64/bin/info/info.exe`)  
    - OSRLoader.exe ([Download from here](https://www.osronline.com/OsrDown.cfm/osrloaderv30.zip))  
        - Extract it from the `\Projects\OsrLoader\kit\WXP\i386\FRE` folder from within the ZIP archive.  
    - DbgView64.exe ([Download from here](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview))  
4. Copy the files from the dedicated folder within hAFL2 server to the Root Partition VM by using:
`./hAFL2/copy_files_to_vm.sh <dedicated_folder_path> windows.qcow2`

**The files will be copied to the C:\ hard drive of the Root Partition VM.**  

## Copy files to the Child Partition VM
Turn on the Root Partition VM (by using the previous QEMU command) and the Child Partition VM from within the Hyper-V GUI.

Once you've copied the listed files to the Root Partition VM, copy the following files from the Root Partition VM (within `C:\`) to the Child Partition VM (if you're using an Hyper-V enhanced session, you can just use Ctrl-C + Ctrl-V to do so):  
   1. CPHarness.sys, CPHarness.inf, CPHarness.cat, CPharness.cer
   2. loader.exe
   3. devcon.exe
   4. DbgView64.exe

**Turn off both Child Partition VM and Root Partition VM after you've copied all of the files.**

# Create a Fuzzing Snapshot

1. Create a VM overlay in a dedicated overlays folder: (Use the absolute path of windows.qcow2!)

`./hAFL2/qemu-6.0.0/build/qemu-img create -f qcow2 -b windows.qcow2 overlay_0.qcow2`

1. Run the VM overlay:

`./hAFL2/qemu-6.0.0/build/x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time,+intel-pt,-hypervisor,+vmx -usbdevice tablet -m 16384 -bios /root/hAFL2/OVMF_CODE-pure-efi.fd -drive file=overlay_0.qcow2 -machine q35` 

### Retrieving VMSwitch.sys address range (Root Partition VM)

1. Open a command prompt as an Administrator **from within the root partition VM.**  
2. Execute `C:\info.exe` as an Administrator.  
3. Check that hAFL2 server now has the `/tmp/kAFL_info.txt` file, and that it contains a loaded modules list of the root partition VM, with loaded address range for each modules.  
    - Copy this file, you'll use it soon.  

### Installing Crash Monitoring Driver (Root Partition VM)
1. Install the Crash Monitoring Driver **on the Root Partition VM**:  
    - Execute OSRLoader.exe  
    - Change the Driver Path to C:\CrashMonitoringDriver.sys  
    - Click on "Register Service"  
    - Click on "Start Service"  
    - You may close the window now.  

### Installing Child Partition Harness Driver (Child Partition VM)
1. Within the Child Partition VM, open `dbgview64.exe` as an Administrator.
Click on the `Capture` Menu, then click on `Capture Kernel`.  
2. Open a command prompt as an Administrator and install the CPHarness driver **on the Child Partition VM** by using devcon.exe (Approve the pop-up.)  
`C:\devcon.exe install CPHarness.inf root\CPHarness`  
3. Check DbgView window, and look for the following log lines:  
`PoolVNC is OK` + `Channel is OK: [ADDRESS]`

If you don't see these log lines, you need to make sure you modified the `ourName` variable within the `CPHarness` driver according to the `NDIS.sys` offset of the Child Partition VM as stated before (explained in the one of the previous section.)  

### Creating the snapshot (Final Step)
**Within the Child Partition VM**, open a command prompt as an Administrator and execute`C:\loader.exe`  

This will create a snapshot to which the fuzzer will return after crashes.

## Optional: Duplicating VM overlays

1. If you’d like to run multiple VM instances to increase the performance of the fuzzing process, duplicate the overlay_0.qcow2 file by executing the following command, replace X with the number of instances you’d like to create in addition to the original overlay_0 file.  

**Make sure all of the overlays files are within the same overlays folder and execute the following command:**

`for f in overlay_{1..X}.qcow2; do cp overlay_0.qcow2 $f; done`

# Sanity Check

1. Run the following command in order to start with the fuzzing process in debug mode. Replace `<start_address>` and `<end_address>` with the output of the `vmswitch.sys` address range you retrieved from the `/tmp/kAFL_info.txt` file.  
Replace the `<SEED_DIR>` with the corpus directory you'd like to use.  

`python3 kAFL-Fuzzer/kafl_fuzz.py -work_dir work --purge -vm_dir <OVERLAY_DIR> -bios OVMF_CODE-pure-efi.fd -mem 16384 -agent targets/windows_x86_64/bin/fuzzer/packet_sender.exe -seed_dir <SEED_DIR> -p <NUMBER_OF_INSTANCES> -ip0 <start_address>-<end_address> --debug -v`  

1. You can run the hAFL2 GUI by executing in a separate terminal (or tmux pane):
`python3 kAFL-Fuzzer/kafl_gui.py work`  
2. Once you verified that everything works properly, you may omit the `-v` and `--debug` flags to save some space on the disk (and not write all of the logs.)  

# Analyzing a Crash
1. Go to the /root/crashes folder  
2. Each crash has a unique hash identifier and consists of two parts:  
    - The stack trace of the crash (a .log file)  
    - A folder which contains the payloads which caused the crash  