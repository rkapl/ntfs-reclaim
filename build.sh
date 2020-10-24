#!/bin/bash
set -eux
cargo build --release
cargo build --release --target x86_64-pc-windows-gnu
rm -rf rel || true
mkdir rel -p

# Since its a single file, I hope breaking the convetion for tar folders does
# not hurt

mkdir rel/win-x64 -p
cp target/x86_64-pc-windows-gnu/release/ntfs-reclaim.exe rel/win-x64
strip rel/win-x64/*
(cd rel/win-x64; zip -r ../ntfs-reclaim-win-x64.zip .)

mkdir rel/linux-x64 -p
cp target/release/ntfs-reclaim rel/linux-x64
strip rel/linux-x64/*
(cd rel/linux-x64; tar cvf ../ntfs-reclaim-linux-x64.tar ntfs-reclaim)
xz rel/ntfs-reclaim-linux-x64.tar
