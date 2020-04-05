#!/usr/bin/perl -w

$#ARGV==0 or die "usage: test.pl number_of_nodes\n";

$n=shift;

system "make isoimage -j";

for ($i=0;$i<$n;$i++) {
    $maclast = $i+4;
    $mac=sprintf("52:00:01:02:03:%02x", $maclast);
    $tapnum=$i;
    $serialnum=$i;
    $cmd = "qemu-system-x86_64 -curses -smp 2 -cdrom nautilus.iso -m 2048 -device virtio-net,netdev=vm0,mac=$mac -netdev tap,id=vm0,ifname=collnet-tap$tapnum,script=no,downscript=no -serial file:serial$serialnum.out";
    print $cmd, "\n";
    system "$cmd &";
}

