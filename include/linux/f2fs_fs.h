/**
 * include/linux/f2fs_fs.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _LINUX_F2FS_FS_H
#define _LINUX_F2FS_FS_H

#include <linux/pagemap.h>
#include <linux/types.h>

#define F2FS_SUPER_OFFSET		1024	/* byte-size offset */
#define F2FS_MIN_LOG_SECTOR_SIZE	9	/* 9 bits for 512 bytes */
#define F2FS_MAX_LOG_SECTOR_SIZE	12	/* 12 bits for 4096 bytes */
#define F2FS_LOG_SECTORS_PER_BLOCK	3	/* log number for sector/blk */
#define F2FS_BLKSIZE			4096	/* support only 4KB block */
#define F2FS_BLKSIZE_BITS		12	/* bits for F2FS_BLKSIZE */
#define F2FS_MAX_EXTENSION		64	/* # of extension entries */
#define F2FS_BLK_ALIGN(x)	(((x) + F2FS_BLKSIZE - 1) >> F2FS_BLKSIZE_BITS)

#define NULL_ADDR		((block_t)0)	/* used as block_t addresses */
#define NEW_ADDR		((block_t)-1)	/* used as block_t addresses */

#define F2FS_BYTES_TO_BLK(bytes)	((bytes) >> F2FS_BLKSIZE_BITS)
#define F2FS_BLK_TO_BYTES(blk)		((blk) << F2FS_BLKSIZE_BITS)

/* 0, 1(node nid), 2(meta nid) are reserved node id */
#define F2FS_RESERVED_NODE_NUM		3

#define F2FS_ROOT_INO(sbi)	(sbi->root_ino_num)
#define F2FS_NODE_INO(sbi)	(sbi->node_ino_num)
#define F2FS_META_INO(sbi)	(sbi->meta_ino_num)

/* This flag is used by node and meta inodes, and by recovery */
#define GFP_F2FS_ZERO		(GFP_NOFS | __GFP_ZERO)
#define GFP_F2FS_HIGH_ZERO	(GFP_NOFS | __GFP_ZERO | __GFP_HIGHMEM)

/*
 * For further optimization on multi-head logs, on-disk layout supports maximum
 * 16 logs by default. The number, 16, is expected to cover all the cases
 * enoughly. The implementaion currently uses no more than 6 logs.
 * Half the logs are used for nodes, and the other half are used for data.
 */
#define MAX_ACTIVE_LOGS	16
#define MAX_ACTIVE_NODE_LOGS	8
#define MAX_ACTIVE_DATA_LOGS	8

#define VERSION_LEN	256
#define MAX_VOLUME_NAME		512

/*
 * For superblock
 *
 * 满足4kb的设计
 *
 */
struct f2fs_super_block {
	__le32 magic;			/* Magic Number */
	__le16 major_ver;		/* Major Version */
	__le16 minor_ver;		/* Minor Version */
	__le32 log_sectorsize;		/* log2 sector size in bytes */
	__le32 log_sectors_per_block;	/* log2 # of sectors per block */
	__le32 log_blocksize;		/* log2 block size in bytes */
	__le32 log_blocks_per_seg;	/* log2 # of blocks per segment */
	__le32 segs_per_sec;		/* # of segments per section */
	__le32 secs_per_zone;		/* # of sections per zone */
	__le32 checksum_offset;		/* checksum offset inside super block */
	__le64 block_count;		/* total # of user blocks */
	__le32 section_count;		/* total # of sections */
	__le32 segment_count;		/* total # of segments */
	__le32 segment_count_ckpt;	/* # of segments for checkpoint */
	__le32 segment_count_sit;	/* # of segments for SIT */
	__le32 segment_count_nat;	/* # of segments for NAT */
	__le32 segment_count_ssa;	/* # of segments for SSA */
	__le32 segment_count_main;	/* # of segments for main area */
	__le32 segment0_blkaddr;	/* start block address of segment 0 */
	__le32 cp_blkaddr;		/* start block address of checkpoint */
	__le32 sit_blkaddr;		/* start block address of SIT */
	__le32 nat_blkaddr;		/* start block address of NAT */
	__le32 ssa_blkaddr;		/* start block address of SSA */
	__le32 main_blkaddr;		/* start block address of main area */
	__le32 root_ino;		/* root inode number */
	__le32 node_ino;		/* node inode number */
	__le32 meta_ino;		/* meta inode number */
	__u8 uuid[16];			/* 128-bit uuid for volume */
	__le16 volume_name[MAX_VOLUME_NAME];	/* volume name */
	__le32 extension_count;		/* # of extensions below */
	__u8 extension_list[F2FS_MAX_EXTENSION][8];	/* extension array */
	__le32 cp_payload;
	__u8 version[VERSION_LEN];	/* the kernel version */
	__u8 init_version[VERSION_LEN];	/* the initial kernel version */
	__le32 feature;			/* defined features */
	__u8 encryption_level;		/* versioning level for encryption */
	__u8 encrypt_pw_salt[16];	/* Salt used for string2key algorithm */
	__u8 reserved[867];		/* valid reserved region */
	__le32 crc;				/* checksum of superblock */
} __packed;

/*
 * For checkpoint
 */
#define CP_FASTBOOT_FLAG	0x00000020
#define CP_FSCK_FLAG		0x00000010
#define CP_ERROR_FLAG		0x00000008
#define CP_COMPACT_SUM_FLAG	0x00000004
#define CP_ORPHAN_PRESENT_FLAG	0x00000002
#define CP_UMOUNT_FLAG		0x00000001

#define F2FS_CP_PACKS		2	/* # of checkpoint packs */

struct f2fs_checkpoint {
	__le64 checkpoint_ver;		/* checkpoint block version number */
	__le64 user_block_count;	/* # of user blocks */
	__le64 valid_block_count;	/* # of valid blocks in main area */
	__le32 rsvd_segment_count;	/* # of reserved segments for gc */
	__le32 overprov_segment_count;	/* # of overprovision segments */
	__le32 free_segment_count;	/* # of free segments in main area */

	/* information of current node segments */
	__le32 cur_node_segno[MAX_ACTIVE_NODE_LOGS];
	__le16 cur_node_blkoff[MAX_ACTIVE_NODE_LOGS];
	/* information of current data segments */
	__le32 cur_data_segno[MAX_ACTIVE_DATA_LOGS];
	__le16 cur_data_blkoff[MAX_ACTIVE_DATA_LOGS];
	__le32 ckpt_flags;		/* Flags : umount and journal_present */
	__le32 cp_pack_total_block_count;	/* total # of one cp pack */
	__le32 cp_pack_start_sum;	/* start block number of data summary */
	__le32 valid_node_count;	/* Total number of valid nodes */
	__le32 valid_inode_count;	/* Total number of valid inodes */
	__le32 next_free_nid;		/* Next free node number */
	__le32 sit_ver_bitmap_bytesize;	/* Default value 64 */
	__le32 nat_ver_bitmap_bytesize; /* Default value 256 */
	__le32 checksum_offset;		/* checksum offset inside cp block */
	__le64 elapsed_time;		/* mounted time */
	/* allocation type of current segment */
	unsigned char alloc_type[MAX_ACTIVE_LOGS];

	/* SIT and NAT version bitmap */
	unsigned char sit_nat_version_bitmap[1];
} __packed;

/*
 * For orphan inode management
 */
#define F2FS_ORPHANS_PER_BLOCK	1020

#define GET_ORPHAN_BLOCKS(n)	((n + F2FS_ORPHANS_PER_BLOCK - 1) / \
					F2FS_ORPHANS_PER_BLOCK)

struct f2fs_orphan_block {
	__le32 ino[F2FS_ORPHANS_PER_BLOCK];	/* inode numbers */
	__le32 reserved;	/* reserved */
	__le16 blk_addr;	/* block index in current CP */
	__le16 blk_count;	/* Number of orphan inode blocks in CP */
	__le32 entry_count;	/* Total number of orphan nodes in current CP */
	__le32 check_sum;	/* CRC32 for orphan inode block */
} __packed;

/*
 * For NODE structure
 */
struct f2fs_extent {
	__le32 fofs;		/* start file offset of the extent */
	__le32 blk;		/* start block address of the extent */
	__le32 len;		/* lengh of the extent */
} __packed;

#define F2FS_NAME_LEN		255
#define F2FS_INLINE_XATTR_ADDRS	50	/* 200 bytes for inline xattrs */
#define DEF_ADDRS_PER_INODE	923	/* Address Pointers in an Inode F2FS_MAX_BLOCKS 注意这个 */
#define DEF_NIDS_PER_INODE	5	/* Node IDs in an Inode */
#define ADDRS_PER_INODE(inode)	addrs_per_inode(inode)
#define ADDRS_PER_BLOCK		1018	/* Address Pointers in a Direct Block */
#define NIDS_PER_BLOCK		1018	/* Node IDs in an Indirect Block */

#define ADDRS_PER_PAGE(page, inode)	\
	(IS_INODE(page) ? ADDRS_PER_INODE(inode) : ADDRS_PER_BLOCK)

#define	NODE_DIR1_BLOCK		(DEF_ADDRS_PER_INODE + 1)
#define	NODE_DIR2_BLOCK		(DEF_ADDRS_PER_INODE + 2)
#define	NODE_IND1_BLOCK		(DEF_ADDRS_PER_INODE + 3)
#define	NODE_IND2_BLOCK		(DEF_ADDRS_PER_INODE + 4)
#define	NODE_DIND_BLOCK		(DEF_ADDRS_PER_INODE + 5)

#define F2FS_INLINE_XATTR	0x01	/* file inline xattr flag */
#define F2FS_INLINE_DATA	0x02	/* file inline data flag */
#define F2FS_INLINE_DENTRY	0x04	/* file inline dentry flag */
#define F2FS_DATA_EXIST		0x08	/* file inline data exist flag */
#define F2FS_INLINE_DOTS	0x10	/* file having implicit dot dentries */

/* 最大inline data 的size是3488字节 */
#define MAX_INLINE_DATA		(sizeof(__le32) * (DEF_ADDRS_PER_INODE - \
						F2FS_INLINE_XATTR_ADDRS - 1))

struct f2fs_inode {
	__le16 i_mode;			/* file mode */
	__u8 i_advise;			/* file hints */
	__u8 i_inline;			/* file inline flags */
	__le32 i_uid;			/* user ID */
	__le32 i_gid;			/* group ID */
	__le32 i_links;			/* links count */
	__le64 i_size;			/* file size in bytes */
	__le64 i_blocks;		/* file size in blocks */
	__le64 i_atime;			/* access time */
	__le64 i_ctime;			/* change time */
	__le64 i_mtime;			/* modification time */
	__le32 i_atime_nsec;		/* access time in nano scale */
	__le32 i_ctime_nsec;		/* change time in nano scale */
	__le32 i_mtime_nsec;		/* modification time in nano scale */
	__le32 i_generation;		/* file version (for NFS) */
	__le32 i_current_depth;		/* only for directory depth */
	__le32 i_xattr_nid;		/* nid to save xattr */
	__le32 i_flags;			/* file attributes */
	__le32 i_pino;			/* parent inode number */
	__le32 i_namelen;		/* file name length */
	__u8 i_name[F2FS_NAME_LEN];	/* file name for SPOR */
	__u8 i_dir_level;		/* dentry_level for large dir */

	struct f2fs_extent i_ext;	/* caching a largest extent */


	/* 块寻址方式决定了单个文件的最大尺寸 file inode + 2 * direct_inode + 2 * indirect_inode + double_indirect_iode * 1
	 *                             = (923 + 2 * 1018 + 2 * 1018 * 1018 + 1018 * 1018 * 1018) * 4096 = 3.94GB
	 *
	 * 为什么这么定义：
	 * 1. f2fs设计时限定了一个block的大小是4096字节，无论是data block还是node block都需要满足这个设计原则。
	 * 2. 观察f2fs的node核心结构struct f2fs_node，由一个联合体（f2fs_inode、direct_node、indirect_node）以及footnote完成，
	 * 		一个footnote的大小是24字节，因此为了满足一个node的大小是4096字节，所以提供给索引空间的有4072个字节
	 * 3.第一种情况：f2fs_inode + footnote，f2fs_inode元数据占用了380字节，因此剩下4072-380=3692个字节，一个地址指针是4字节，因此 3692/4=923个地址指针
	 *   第二种情况：direct_node/indirect_inode + footnote，没有其他元数据，因此直接4072/4=1018个地址指针
	 *
	 * 存在的问题：
	 * 1. 显然，很少有单个文件大于3.94TB，因此主要问题集中存储小文件的情况下，如果一个文件小于4kb，那么他仅需要一个数据块既可以保存，那就就浪费了一个同样是4Kb大小的索引结构
	 * 2. 同时访问一个小文件数据块，还需要经过一层索引才能找到data block所在，也降低了效率
	 *
	 * inline data的情况:
	 * i_addr对于小文件，会通过直接将数据存储到i_addr数组的方式减少索引开销和存储空间开销。
	 * 对于inline data的ri->i_addr[0]是保留指针，对于i_addr[1]~i_addr[DEF_ADDRS_PER_INODE - F2FS_INLINE_XATTR_ADDRS - 1]用于直接存储数据，不存储datablock
	 *  */
	__le32 i_addr[DEF_ADDRS_PER_INODE];	/* Pointers to data blocks */

	__le32 i_nid[DEF_NIDS_PER_INODE];	/* direct(2), indirect(2), double_indirect(1) node id */

} __packed;

struct direct_node {
	__le32 addr[ADDRS_PER_BLOCK];	/* array of data block address */
} __packed;

struct indirect_node {
	__le32 nid[NIDS_PER_BLOCK];	/* array of data block address */
} __packed;

enum {
	COLD_BIT_SHIFT = 0,
	FSYNC_BIT_SHIFT,
	DENT_BIT_SHIFT,
	/*
	 * f2fs_inode->i_nid[DEF_NIDS_PER_INODE]; 里面的DEF_NIDS_PER_INODE就是偏移多少
	 * flag >> OFFSET_BIT_SHIFT = 0，就是f2fs_inode->i_addr，表示没有间接映射
	 * flag >> OFFSET_BIT_SHIFT = 1~2，就是f2fs_inode->i_nid[0~1]，表示第一个node和第二个node
	 * flag >> OFFSET_BIT_SHIFT = 3~1018*2+3，就是f2fs_inode->i_nid[2~3]，但是由于是indriect的，所以表示3~1018*2+3
	 * flag >> OFFSET_BIT_SHIFT = 1018*2+4~1018*3+1018*2+4，就是double indirect的
	 * */
	OFFSET_BIT_SHIFT    // f2fs_inode->i_nid[DEF_NIDS_PER_INODE]; 目的找到这是文件里面的第几个node，需要注意的是indirect_node是从3~1018*2+3，double indirect node就是1018*2+4 + 1018 * 3 + 4
};

#define OFFSET_BIT_MASK		(0x07)	/* (0x01 << OFFSET_BIT_SHIFT) - 1 */

struct node_footer {
	__le32 nid;		/* node id 标志当前的node属于哪个nid */
	__le32 ino;		/* 是属于哪个vfs inode，因为有可能是ino不等于nid */
	__le32 flag;		/* flag的第一位是COLD标志，第二位是FSYNC标志，第三位是dentry标志，第四位到第32位，表示inode里面的f2fs_inode->i_nid偏移量 include cold/fsync/dentry marks and offset 冷热的标志 */
	__le64 cp_ver;		/* checkpoint version */
	__le32 next_blkaddr;	/* next node page block address 下一个访问node的地址 */
} __packed;

struct f2fs_node {
	/* can be one of three types: inode, direct, and indirect types */
	union {
		struct f2fs_inode i;  /* 文件inode，直接针对文件 */
		struct direct_node dn; /* 直接inode，指向文件inode */
		struct indirect_node in; /* 简介inode，指向direct inode */
	};
	/*
	 * footer有很多作用，其中一个作用就是判断node的类型，f2fs_node->footer.nid == f2fs_node->footer.ino 代表的是f2fs_inode，否则就是dnode或者idnode
	 * */
	struct node_footer footer;
} __packed;

/*
 * For NAT entries
 */
#define NAT_ENTRY_PER_BLOCK (PAGE_CACHE_SIZE / sizeof(struct f2fs_nat_entry)) // = 4096 / 9 = 455，因此一个block最多存储455 nat entry

struct f2fs_nat_entry {
	__u8 version;		/* 当前NAT的版本号，一般存在两个版本 latest version of cached nat entry */
	__le32 ino;		/* inode号，这是一个唯一的逻辑号 inode number */
	__le32 block_addr;	/* 映射的物理地址，是块号 block address */
} __packed;

struct f2fs_nat_block {
	struct f2fs_nat_entry entries[NAT_ENTRY_PER_BLOCK];
} __packed;

/*
 * For SIT entries
 *
 * Each segment is 2MB in size by default so that a bitmap for validity of
 * there-in blocks should occupy 64 bytes, 512 bits.
 * Not allow to change this.
 */
#define SIT_VBLOCK_MAP_SIZE 64
#define SIT_ENTRY_PER_BLOCK (PAGE_CACHE_SIZE / sizeof(struct f2fs_sit_entry))

/*
 * Note that f2fs_sit_entry->vblocks has the following bit-field information.
 * [15:10] : allocation type such as CURSEG_XXXX_TYPE
 * [9:0] : valid block count
 */
#define SIT_VBLOCKS_SHIFT	10
#define SIT_VBLOCKS_MASK	((1 << SIT_VBLOCKS_SHIFT) - 1)
#define GET_SIT_VBLOCKS(raw_sit)				\
	(le16_to_cpu((raw_sit)->vblocks) & SIT_VBLOCKS_MASK)
#define GET_SIT_TYPE(raw_sit)					\
	((le16_to_cpu((raw_sit)->vblocks) & ~SIT_VBLOCKS_MASK)	\
	 >> SIT_VBLOCKS_SHIFT)

struct f2fs_sit_entry {
	__le16 vblocks;				/* 使用16位表示分配类型和有效数据块个数，0~9表示有效块个数，10~15表示段的类型 reference above */
	__u8 valid_map[SIT_VBLOCK_MAP_SIZE];	/* 因为一个segment等于512blocks，所以使用512bits表示每一个block是否可以使用 bitmap for valid blocks */
	__le64 mtime;				/* segment age for cleaning */
} __packed;

struct f2fs_sit_block {
	struct f2fs_sit_entry entries[SIT_ENTRY_PER_BLOCK];
} __packed;

/*
 * For segment summary
 *
 * One summary block contains exactly 512 summary entries, which represents
 * exactly 2MB segment by default. Not allow to change the basic units.
 *
 * NOTE: For initializing fields, you must use set_summary
 *
 * - If data page, nid represents dnode's nid
 * - If node page, nid represents the node page's nid.
 *
 * The ofs_in_node is used by only data page. It represents offset
 * from node's page's beginning to get a data block address.
 * ex) data_blkaddr = (block_t)(nodepage_start_address + ofs_in_node)
 */
#define ENTRIES_IN_SUM		512
#define	SUMMARY_SIZE		(7)	/* sizeof(struct summary) */
#define	SUM_FOOTER_SIZE		(5)	/* sizeof(struct summary_footer) */
#define SUM_ENTRY_SIZE		(SUMMARY_SIZE * ENTRIES_IN_SUM)

/*
 * a summary entry for a 4KB-sized block in a segment
 *
 * sizeof(struct f2fs_summary) = 7个字节
 *
 * 所以一个summary block = 4096 / 7 = 585个f2fs_summary < 512 个
 *
 * */
struct f2fs_summary {
	__le32 nid;		/* parent node id */
	union {
		__u8 reserved[3];
		struct {
			__u8 version;		/* node version number */
			__le16 ofs_in_node;	/* 数据在node中的偏移 block index in parent node */
		} __packed;
	};
} __packed;

/* summary block type, node or data, is stored to the summary_footer */
#define SUM_TYPE_NODE		(1)
#define SUM_TYPE_DATA		(0)

struct summary_footer {
	unsigned char entry_type;	/* SUM_TYPE_XXX */
	__le32 check_sum;		/* summary checksum */
} __packed;

#define SUM_JOURNAL_SIZE	(F2FS_BLKSIZE - SUM_FOOTER_SIZE -\
				SUM_ENTRY_SIZE)
#define NAT_JOURNAL_ENTRIES	((SUM_JOURNAL_SIZE - 2) /\
				sizeof(struct nat_journal_entry))
#define NAT_JOURNAL_RESERVED	((SUM_JOURNAL_SIZE - 2) %\
				sizeof(struct nat_journal_entry))
#define SIT_JOURNAL_ENTRIES	((SUM_JOURNAL_SIZE - 2) /\
				sizeof(struct sit_journal_entry))
#define SIT_JOURNAL_RESERVED	((SUM_JOURNAL_SIZE - 2) %\
				sizeof(struct sit_journal_entry))

/* Reserved area should make size of f2fs_extra_info equals to
 * that of nat_journal and sit_journal.
 */
#define EXTRA_INFO_RESERVED	(SUM_JOURNAL_SIZE - 2 - 8)

/*
 * frequently updated NAT/SIT entries can be stored in the spare area in
 * summary blocks
 */
enum {
	NAT_JOURNAL = 0,
	SIT_JOURNAL
};

/*
 * nat table数据结构，包括node id 和 nat entry
 * */
struct nat_journal_entry {
	__le32 nid;
	struct f2fs_nat_entry ne;
} __packed;

struct nat_journal {
	struct nat_journal_entry entries[NAT_JOURNAL_ENTRIES];
	__u8 reserved[NAT_JOURNAL_RESERVED];
} __packed;

struct sit_journal_entry {
	__le32 segno;
	struct f2fs_sit_entry se;
} __packed;

struct sit_journal {
	struct sit_journal_entry entries[SIT_JOURNAL_ENTRIES];
	__u8 reserved[SIT_JOURNAL_RESERVED];
} __packed;

struct f2fs_extra_info {
	__le64 kbytes_written;
	__u8 reserved[EXTRA_INFO_RESERVED];
} __packed;


/*
 * f2fs journal机制核心数据结构
 * journal的解决的问题：每次写一个数据块，需要相应更改direct node，NAT和SIT，尤其是NAT和SIT区域，
 * 					 可能仅仅需要修改一个entry几个字节的信息，就要重写整个page，这会严重降低文件系统的性能和SSD的使用寿命
 * journal的实现：f2fs使用了journal的机制来减少NAT和SIT的写次数。
 *               所谓journal，其实就是把NAT和SIT的更改写到f2fs_summary_block中，当写checkpoint时，才把dirty的SIT和NAT区域回写。
 * */
struct f2fs_journal {
	union {
		__le16 n_nats; // nat journal的个数
		__le16 n_sits; // sit journal的个数
	};
	/* spare area is used by NAT or SIT journals or extra info */
	union {
		struct nat_journal nat_j;
		struct sit_journal sit_j;
		struct f2fs_extra_info info;
	};
} __packed;

/* 4KB-sized summary block structure
 *
 * 每一个segment都包含一个f2fs_summary_block，
 *
 * */
struct f2fs_summary_block {
	struct f2fs_summary entries[ENTRIES_IN_SUM];
	struct f2fs_journal journal;
	struct summary_footer footer;
} __packed;

/*
 * For directory operations
 */
#define F2FS_DOT_HASH		0
#define F2FS_DDOT_HASH		F2FS_DOT_HASH
#define F2FS_MAX_HASH		(~((0x3ULL) << 62))
#define F2FS_HASH_COL_BIT	((0x1ULL) << 63)

typedef __le32	f2fs_hash_t;

/* One directory entry slot covers 8bytes-long file name */
#define F2FS_SLOT_LEN		8
#define F2FS_SLOT_LEN_BITS	3

#define GET_DENTRY_SLOTS(x)	((x + F2FS_SLOT_LEN - 1) >> F2FS_SLOT_LEN_BITS)

/* MAX level for dir lookup */
#define MAX_DIR_HASH_DEPTH	63

/* MAX buckets in one level of dir */
#define MAX_DIR_BUCKETS		(1 << ((MAX_DIR_HASH_DEPTH / 2) - 1))

/*
 * space utilization of regular dentry and inline dentry
 *		regular dentry			inline dentry
 * bitmap	1 * 27 = 27			1 * 23 = 23
 * reserved	1 * 3 = 3			1 * 7 = 7
 * dentry	11 * 214 = 2354			11 * 182 = 2002
 * filename	8 * 214 = 1712			8 * 182 = 1456
 * total	4096				3488
 *
 * Note: there are more reserved space in inline dentry than in regular
 * dentry, when converting inline dentry we should handle this carefully.
 */
#define NR_DENTRY_IN_BLOCK	214	/* the number of dentry in a block */
#define SIZE_OF_DIR_ENTRY	11	/* by byte */
#define SIZE_OF_DENTRY_BITMAP	((NR_DENTRY_IN_BLOCK + BITS_PER_BYTE - 1) / \
					BITS_PER_BYTE)
#define SIZE_OF_RESERVED	(PAGE_SIZE - ((SIZE_OF_DIR_ENTRY + \
				F2FS_SLOT_LEN) * \
				NR_DENTRY_IN_BLOCK + SIZE_OF_DENTRY_BITMAP))

/* One directory entry slot representing F2FS_SLOT_LEN-sized file name */
struct f2fs_dir_entry {
	__le32 hash_code;	/* 哈希值 hash code of file name */
	__le32 ino;		/* inode number */
	__le16 name_len;	/* lengh of file name */
	__u8 file_type;		/* file type */
} __packed;

/* 4KB-sized directory entry block
 * 设计上同样满足了一个block大小为4kb的设计原则
 * */
struct f2fs_dentry_block {
	/* validity bitmap for directory entries in each block */
	__u8 dentry_bitmap[SIZE_OF_DENTRY_BITMAP]; // 这里存放的不是普通数据，而是目录项的信息(f2fs_dir_entry)，因此这里bitmap是表示目录项是否有效
	__u8 reserved[SIZE_OF_RESERVED];
	struct f2fs_dir_entry dentry[NR_DENTRY_IN_BLOCK]; // 被这个block管理的dentry项
	__u8 filename[NR_DENTRY_IN_BLOCK][F2FS_SLOT_LEN]; // 文件名数组
} __packed;

/* for inline dir */
#define NR_INLINE_DENTRY	(MAX_INLINE_DATA * BITS_PER_BYTE / \
				((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * \
				BITS_PER_BYTE + 1))
#define INLINE_DENTRY_BITMAP_SIZE	((NR_INLINE_DENTRY + \
					BITS_PER_BYTE - 1) / BITS_PER_BYTE)
#define INLINE_RESERVED_SIZE	(MAX_INLINE_DATA - \
				((SIZE_OF_DIR_ENTRY + F2FS_SLOT_LEN) * \
				NR_INLINE_DENTRY + INLINE_DENTRY_BITMAP_SIZE))

/* inline directory entry structure */
struct f2fs_inline_dentry {
	__u8 dentry_bitmap[INLINE_DENTRY_BITMAP_SIZE];
	__u8 reserved[INLINE_RESERVED_SIZE];
	struct f2fs_dir_entry dentry[NR_INLINE_DENTRY];
	__u8 filename[NR_INLINE_DENTRY][F2FS_SLOT_LEN];
} __packed;

/* file types used in inode_info->flags */
enum {
	F2FS_FT_UNKNOWN,
	F2FS_FT_REG_FILE,
	F2FS_FT_DIR,
	F2FS_FT_CHRDEV,
	F2FS_FT_BLKDEV,
	F2FS_FT_FIFO,
	F2FS_FT_SOCK,
	F2FS_FT_SYMLINK,
	F2FS_FT_MAX
};

#endif  /* _LINUX_F2FS_FS_H */
