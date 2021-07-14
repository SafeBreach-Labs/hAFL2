# hAFL2
[hAFL2](https://github.com/SafeBreach-Labs/hAFL2) is a [kAFL](https://github.com/IntelLabs/kAFL)-based hypervisor fuzzer.  
It is the first open-source fuzzer which is able to target hypervisors natively (including Hyper-V), as it's support nested virtualization, code coverage and detailed crash monitoring.  


## Contact Me
I will do my best in order to provide the best technical explanation regarding this project.  
If you still have any questions or thoughts please **contact me on Twitter: [@peleghd](https://twitter.com/peleghd)**

## Disclaimer

1. **I only had 3 weeks in order to implement this project from 0** as I worked at the same time on the [hAFL1](https://github.com/SB-GC-Labs/hAFL1) project & [Black Hat USA 2021 talk](https://www.blackhat.com/us-21/briefings/schedule/#hafl-our-journey-of-fuzzing-hyper-v-and-discovering-a--day-23498),
therefore, I worked in a PoC mode (a.k.a. quick and dirty.) If I had the time, I'd definetly add more features and re-write some of the code, but I decided to release it anyway as it worked end-to-end, and I wanted to provide the infosec community a native hypervisor fuzzer because I didn't find a public one. I believe that it can help other researchers to learn the field of hypervisors internals and start their own hypervisor fuzzer.  

1. I personally used it in order to target the Hyper-V networking VSP (VMSwitch), which means that I retreived code coverage out of the root partition VM (L2), and sent fuzzing inputs directly to the child partition VM (L2) where my harness was executed.  
This behavior can be easily modified (e.g. retreiving code coverage out of the hypervisor itself on L1, etc.) and I explained exactly what needs to be done in order to make it work within the `TechnicalDetails.md` file.

**You are more than welcome to improve the code of hAFL2 and open pull requests :)**
## Credits
- [Ophir Harpaz](https://twitter.com/ophirharpaz) for working together on the [hAFL1](https://github.com/SB-GC-Labs/hAFL1) project which inspired me to implement the hAFL2 project.
- [Saar Amar](https://twitter.com/AmarSaar) for answering a lot of nVMX-related questions during the implementation of this project, which helped me completing this project on time.
- [SafeBreach Labs](https://www.safebreach.com/research/) which provided me the time to learn and implement this project.
- The [kAFL](https://github.com/IntelLabs/kAFL) team (Sergej Schumilo, Cornelius Aschermann, Robert Gawlik, Sebastian Schinzel and Thorsten Holz) for providing a fuzzing infrastructure which I heavily modified in order to target hypervisors.
- The [Nyx](https://www.usenix.org/conference/usenixsecurity21/presentation/schumilo) fuzzer team (Sergej Schumilo, Cornelius Aschermann, Ali Abbasi, Simon Wör­ner, and Thorsten Holz) for telling their own story of implementing a hypervisor fuzzer.
---

1. **The technical details of the project are described within the ```TechnicalDetails.md``` file in this repository.**
2. **Setup instructions are within the `tutorial.md` file.** 