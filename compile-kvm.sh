if [ "$#" -ne 1 ]; then
    echo "Usage: ./compile.sh [LINUX_KERNEL_VERSION]"
fi

version=$1
jobs=$(nproc)
echo [+] Compiling...
make -j $jobs -C . M=arch/x86/
cp arch/x86/kvm/kvm-intel.ko /lib/modules/$version-kAFL+/kernel/arch/x86/kvm/kvm-intel.ko
cp arch/x86/kvm/kvm.ko /lib/modules/$version-kAFL+/kernel/arch/x86/kvm/kvm.ko
echo [+] Removing mods...
rmmod kvm-intel && rmmod kvm
echo [+] Inserting mods...
modprobe kvm && modprobe kvm-intel
