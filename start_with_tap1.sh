make isoimage -j
qemu-system-x86_64 -curses -smp 2 -cdrom nautilus.iso -m 2048 -device virtio-net,netdev=vm0,mac=52:00:01:02:03:05 -netdev tap,id=vm0,ifname=collnet-tap1,script=no,downscript=no -serial file:serial1.out 
