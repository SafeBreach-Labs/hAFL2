# hAFL2
[hAFL2](https://github.com/SafeBreach-Labs/hAFL2) is a [kAFL](https://github.com/IntelLabs/kAFL)-based hypervisor fuzzer.  
It is the first open-source fuzzer which is able to target hypervisors natively (including Hyper-V), as it's support nested virtualization, code coverage and detailed crash monitoring.  

![hAFL2 Hyper-V Fuzzing Architecture](https://github.com/SafeBreach-Labs/hAFL2/blob/main/images/Architecture.png?raw=true)

---
1. **The technical details of the project are described within the [```TechnicalDetails.md```](https://github.com/SafeBreach-Labs/hAFL2/blob/main/TechnicalDetails.md) file.**
2. **The setup instructions are described within the [`tutorial.md`](https://github.com/SafeBreach-Labs/hAFL2/blob/main/tutorial.md) file.** 
---
## Disclaimer

1. **I only had 3 weeks in order to implement this project from 0** as I worked at the same time on the [hAFL1](https://github.com/SB-GC-Labs/hAFL1) project & [Black Hat USA 2021 talk](https://www.blackhat.com/us-21/briefings/schedule/#hafl-our-journey-of-fuzzing-hyper-v-and-discovering-a--day-23498),
therefore, I worked in a PoC mode (a.k.a. quick and dirty.) If I had the time, I'd definetly add more features and re-write some of the code, but I decided to release it anyway as it worked end-to-end, and I wanted to provide the infosec community a native hypervisor fuzzer because I didn't find a public one. I believe that it can help other researchers to learn the field of hypervisors internals and start their own hypervisor fuzzer.  

1. I personally used it in order to target the Hyper-V networking VSP (VMSwitch), which means that I retreived code coverage out of the root partition VM (L2), and sent fuzzing inputs directly to the child partition VM (L2) where my harness was executed.  
This behavior can be easily modified (e.g. retreiving code coverage out of the hypervisor itself on L1, etc.) and I explained exactly what needs to be done in order to make it work within the `TechnicalDetails.md` file.

## VMSwitch Harness Gaps
Due to a lack of time, I have provided a **partial harness** for Hyper-V's VMSwitch which provide one the ability to send RNDIS packets from the guest partition to the root partition.  

It's imporant to mention that **there is a major gap in the harness** - it won't provide you an accurate code coverage and I'll try to explain why.  

The harness is responsible for the following:
- Signal (`ACQUIRE`) hAFL2 to start collecting code coverage from the root partition.  
- Send the fuzzing payload to VMSwitch within the root partition.  
- Wait for a VMBus completion packet.  
- Signal (`RELEASE`) hAFL2 to stop collecting code coverage. 

The problem is that VMSwitch processes packets in an asynchronous manner which means that it will call the interesting parsing code (which we'd like to have within our code coverage) AFTER it already sent a completion packet to the child partition's harness, therefore, the code coverage will be partial.  

[@OphirHarpaz](https://twitter.com/ophirharpaz) and I solved a similar problem within [hAFL1](https://github.com/SB-GC-Labs/hAFL1) by disabling PatchGuard and modifying some VMSwitch logic.  
 I believe this can be solved in a similar manner, maybe by patching VMSwitch and modifying the call to [`VmbChannelPacketComplete`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/vmbuskernelmodeclientlibapi/nc-vmbuskernelmodeclientlibapi-fn_vmb_channel_packet_complete) to occur after VMSwitch has finished the processing part.  

Check out the Harness driver of [hAFL1](https://github.com/SB-GC-Labs/hAFL1) in order to understand how we patched VMSwitch.  

## Re-Compile and Reload KVM
If you already installed the hAFL2 Linux kernel (with modified KVM) and you wish to modify some of KVM's code without re-compile the whole kernel, you may use `./compile-kvm.sh 5.12.7` in order to do so.  
The script will also reload the new compiled version of KVM and KVM-intel.
## Credits
- [Ophir Harpaz](https://twitter.com/ophirharpaz) for working together on the [hAFL1](https://github.com/SB-GC-Labs/hAFL1) project which inspired me to implement the hAFL2 project.
- [Saar Amar](https://twitter.com/AmarSaar) for answering a lot of nVMX-related questions during the implementation of this project, which helped me completing this project on time.
- [SafeBreach Labs](https://www.safebreach.com/research/) which provided me the time to learn and implement this project.
- The [kAFL](https://github.com/IntelLabs/kAFL) team (Sergej Schumilo, Cornelius Aschermann, Robert Gawlik, Sebastian Schinzel and Thorsten Holz) for providing a fuzzing infrastructure which I heavily modified in order to target hypervisors.
- The [Nyx](https://www.usenix.org/conference/usenixsecurity21/presentation/schumilo) fuzzer team (Sergej Schumilo, Cornelius Aschermann, Ali Abbasi, Simon Wör­ner, and Thorsten Holz) for telling their own story of implementing a hypervisor fuzzer.
---