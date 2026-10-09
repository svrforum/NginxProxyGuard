//go:build linux

package service

import "syscall"

// statfsPath is statfs(2). It can block indefinitely on a dead network mount;
// callers measuring an operator-configured path go through statfsGuard.
// Fsid.X__val is the field name on every Linux architecture the release builds
// (amd64 and arm64 verified).
func statfsPath(path string) (rawStatfs, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return rawStatfs{}, err
	}
	return rawStatfs{
		FSID: fsidHex(st.Fsid.X__val[0], st.Fsid.X__val[1]),
		// f_type is 64 bits wide on 64-bit kernels and 32 on 32-bit ones,
		// where the magic numbers above 0x7fffffff come back negative. The
		// magics are 32-bit values, so this reads the same everywhere and
		// matches what `stat -f -c %t` prints.
		Type:   int64(uint32(st.Type)),
		Frsize: uint64(st.Frsize),
		Blocks: st.Blocks,
		Bfree:  st.Bfree,
		Bavail: st.Bavail,
		Files:  st.Files,
	}, nil
}

// linuxFSTypeNames maps statfs f_type magic numbers to names, for the
// filesystems a home server keeps NPG's data on: local disks, the container
// layer, network shares and FUSE pools (mergerfs, Unraid's shfs, virtiofs).
// Values from <linux/magic.h>; ZFS is out of tree (OpenZFS ZFS_SUPER_MAGIC).
var linuxFSTypeNames = map[int64]string{
	0xEF53:         "ext4", // ext2, ext3 and ext4 share it
	0x58465342:     "xfs",
	0x9123683E:     "btrfs",
	0x2FC12FC1:     "zfs",
	0xCA451A4E:     "bcachefs",
	0xF2F52010:     "f2fs",
	0x2011BAB0:     "exfat",
	0x4D44:         "vfat",
	0x01021994:     "tmpfs",
	0x858458F6:     "ramfs",
	overlayFSMagic: "overlay",
	0x73717368:     "squashfs",
	0x6969:         "nfs",
	0xFF534D42:     "cifs",
	0xFE534D42:     "smb2",
	0x517B:         "smb",
	0x65735546:     "fuse",
	0x01021997:     "9p",
	0x00C36400:     "ceph",
	0xF15F:         "ecryptfs",
}

// fsTypeName names a statfs f_type, or "" when unknown.
func fsTypeName(magic int64) string { return linuxFSTypeNames[magic] }
