#!/bin/bash
if [[ $# -eq 0 ]]
  then
    echo "Usage: ./copy_files_to_vm.sh SRC_FOLDER_PATH WINDOWS_VM_PATH"
    exit 1
fi

mkdir -p mnt && 
sudo modprobe nbd && 
sudo qemu-6.0.0/build/qemu-nbd --connect=/dev/nbd0 $2 && 
sleep 1 && 
sudo mount -o rw /dev/nbd0p3 ./mnt && 
cp -r $1/* ./mnt && 
umount ./mnt && 
sudo qemu-6.0.0/build/qemu-nbd --disconnect /dev/nbd0 && 
rm -rf ./mnt