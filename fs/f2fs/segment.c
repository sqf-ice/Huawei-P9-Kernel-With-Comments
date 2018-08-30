/*
 * fs/f2fs/segment.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/prefetch.h>
#include <linux/kthread.h>
#include <linux/swap.h>
#include <linux/timer.h>
#include <linux/delay.h>

#include "f2fs.h"
#include "segment.h"
#include "node.h"
#include "trace.h"
#include <trace/events/f2fs.h>

#define __reverse_ffz(x) __reverse_ffs(~(x))

static struct kmem_cache *discard_entry_slab;
static struct kmem_cache *sit_entry_set_slab;
static struct kmem_cache *inmem_entry_slab;

static unsigned long __reverse_ulong(unsigned char *str)
{
	unsigned long tmp = 0;
	int shift = 24, idx = 0;

#if BITS_PER_LONG == 64
	shift = 56;
#endif
	while (shift >= 0) {
		tmp |= (unsigned long)str[idx++] << shift;
		shift -= BITS_PER_BYTE;
	}
	return tmp;
}

/*
 * __reverse_ffs is copied from include/asm-generic/bitops/__ffs.h since
 * MSB and LSB are reversed in a byte by f2fs_set_bit.
 */
static inline unsigned long __reverse_ffs(unsigned long word)
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff00000000UL) == 0)
		num += 32;
	else
		word >>= 32;
#endif
	if ((word & 0xffff0000) == 0)
		num += 16;
	else
		word >>= 16;

	if ((word & 0xff00) == 0)
		num += 8;
	else
		word >>= 8;

	if ((word & 0xf0) == 0)
		num += 4;
	else
		word >>= 4;

	if ((word & 0xc) == 0)
		num += 2;
	else
		word >>= 2;

	if ((word & 0x2) == 0)
		num += 1;
	return num;
}

/*
 * __find_rev_next(_zero)_bit is copied from lib/find_next_bit.c because
 * f2fs_set_bit makes MSB and LSB reversed in a byte.
 * @size must be integral times of unsigned long.
 * Example:
 *                             MSB <--> LSB
 *   f2fs_set_bit(0, bitmap) => 1000 0000
 *   f2fs_set_bit(7, bitmap) => 0000 0001
 */
unsigned long __find_rev_next_bit(const unsigned long *addr,
			unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = size;
	unsigned long tmp;

	if (offset >= size)
		return size;

	size -= (offset & ~(BITS_PER_LONG - 1));
	offset %= BITS_PER_LONG;

	while (1) {
		if (*p == 0)
			goto pass;

		tmp = __reverse_ulong((unsigned char *)p);

		tmp &= ~0UL >> offset;
		if (size < BITS_PER_LONG)
			tmp &= (~0UL << (BITS_PER_LONG - size));
		if (tmp)
			goto found;
pass:
		if (size <= BITS_PER_LONG)
			break;
		size -= BITS_PER_LONG;
		offset = 0;
		p++;
	}
	return result;
found:
	return result - size + __reverse_ffs(tmp);
}

unsigned long __find_rev_next_zero_bit(const unsigned long *addr,
			unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = size;
	unsigned long tmp;

	if (offset >= size)
		return size;

	size -= (offset & ~(BITS_PER_LONG - 1));
	offset %= BITS_PER_LONG;

	while (1) {
		if (*p == ~0UL)
			goto pass;

		tmp = __reverse_ulong((unsigned char *)p);

		if (offset)
			tmp |= ~0UL << (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			tmp |= ~0UL >> size;
		if (tmp != ~0UL)
			goto found;
pass:
		if (size <= BITS_PER_LONG)
			break;
		size -= BITS_PER_LONG;
		offset = 0;
		p++;
	}
	return result;
found:
	return result - size + __reverse_ffz(tmp);
}

int find_next_free_extent(const unsigned long *addr,
			  unsigned long size, unsigned long *offset)
{
	unsigned long pos, pos_zero_bit;

	pos_zero_bit = __find_rev_next_zero_bit(addr, size, *offset);
	if (pos_zero_bit == size)
		return -ENOMEM;

	pos = __find_rev_next_bit(addr, size, pos_zero_bit);
	*offset = pos;

	return (int)(pos - pos_zero_bit);
}

void register_inmem_page(struct inode *inode, struct page *page)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct inmem_pages *new;

	f2fs_trace_pid(page);

	set_page_private(page, (unsigned long)ATOMIC_WRITTEN_PAGE);
	SetPagePrivate(page);

	new = f2fs_kmem_cache_alloc(inmem_entry_slab, GFP_NOFS);

	/* add atomic page indices to the list */
	new->page = page;
	INIT_LIST_HEAD(&new->list);

	/* increase reference count with clean state */
	mutex_lock(&fi->inmem_lock);
	get_page(page);
	list_add_tail(&new->list, &fi->inmem_pages);
	inc_page_count(F2FS_I_SB(inode), F2FS_INMEM_PAGES);
	mutex_unlock(&fi->inmem_lock);

	trace_f2fs_register_inmem_page(page, INMEM);
}

static int __revoke_inmem_pages(struct inode *inode,
				struct list_head *head, bool drop, bool recover)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct inmem_pages *cur, *tmp;
	int err = 0;

	list_for_each_entry_safe(cur, tmp, head, list) {
		struct page *page = cur->page;

		if (drop)
			trace_f2fs_commit_inmem_page(page, INMEM_DROP);

		lock_page(page);

		if (recover) {
			struct dnode_of_data dn;
			struct node_info ni;

			trace_f2fs_commit_inmem_page(page, INMEM_REVOKE);

			set_new_dnode(&dn, inode, NULL, NULL, 0);
			if (get_dnode_of_data(&dn, page->index, LOOKUP_NODE)) {
				err = -EAGAIN;
				goto next;
			}
			get_node_info(sbi, dn.nid, &ni);
			f2fs_replace_block(sbi, &dn, dn.data_blkaddr,
					cur->old_addr, ni.version, true, true);
			f2fs_put_dnode(&dn);
		}
next:
		/* we don't need to invalidate this in the sccessful status */
		if (drop || recover)
			ClearPageUptodate(page);
		set_page_private(page, 0);
		ClearPagePrivate(page);
		f2fs_put_page(page, 1);

		list_del(&cur->list);
		kmem_cache_free(inmem_entry_slab, cur);
		dec_page_count(F2FS_I_SB(inode), F2FS_INMEM_PAGES);
	}
	return err;
}

void drop_inmem_pages(struct inode *inode)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);

	clear_inode_flag(F2FS_I(inode), FI_ATOMIC_FILE);

	mutex_lock(&fi->inmem_lock);
	__revoke_inmem_pages(inode, &fi->inmem_pages, true, false);
	mutex_unlock(&fi->inmem_lock);
}

static int __commit_inmem_pages(struct inode *inode,
					struct list_head *revoke_list)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct inmem_pages *cur, *tmp;
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = DATA,
		.rw = WRITE_SYNC | REQ_PRIO,
		.encrypted_page = NULL,
	};
	bool submit_bio = false;
	int err = 0;

	list_for_each_entry_safe(cur, tmp, &fi->inmem_pages, list) {
		struct page *page = cur->page;

		lock_page(page);
		if (page->mapping == inode->i_mapping) {
			trace_f2fs_commit_inmem_page(page, INMEM);

			set_page_dirty(page);
			f2fs_wait_on_page_writeback(page, DATA, true);
			if (clear_page_dirty_for_io(page))
				inode_dec_dirty_pages(inode);

			fio.page = page;
			err = do_write_data_page(&fio);
			if (err) {
				unlock_page(page);
				break;
			}

			/* record old blkaddr for revoking */
			cur->old_addr = fio.old_blkaddr;

			clear_cold_data(page);
			submit_bio = true;
		}
		unlock_page(page);
		list_move_tail(&cur->list, revoke_list);
	}

	if (submit_bio)
		f2fs_submit_merged_bio_cond(sbi, inode, NULL, 0, DATA, WRITE);

	if (!err)
		__revoke_inmem_pages(inode, revoke_list, false, false);

	return err;
}

int commit_inmem_pages(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct list_head revoke_list;
	int err;

	INIT_LIST_HEAD(&revoke_list);
	f2fs_balance_fs(sbi, true);
	f2fs_lock_op(sbi);

	mutex_lock(&fi->inmem_lock);
	err = __commit_inmem_pages(inode, &revoke_list);
	if (err) {
		int ret;
		/*
		 * try to revoke all committed pages, but still we could fail
		 * due to no memory or other reason, if that happened, EAGAIN
		 * will be returned, which means in such case, transaction is
		 * already not integrity, caller should use journal to do the
		 * recovery or rewrite & commit last transaction. For other
		 * error number, revoking was done by filesystem itself.
		 */
		ret = __revoke_inmem_pages(inode, &revoke_list, false, true);
		if (ret)
			err = ret;

		/* drop all uncommitted pages */
		__revoke_inmem_pages(inode, &fi->inmem_pages, true, false);
	}
	mutex_unlock(&fi->inmem_lock);

	f2fs_unlock_op(sbi);
	return err;
}

int FG_GC_count = 0;

/*
 * This function balances dirty node and dentry pages.
 * In addition, it controls garbage collection.
 * 控制一下数目，如果section不够用，就做一下gc
 */
void f2fs_balance_fs(struct f2fs_sb_info *sbi, bool need)
{
	if (!need)
		return;
	/*
	 * We should do GC or end up with checkpoint, if there are so many dirty
	 * dir/node pages without enough free segments.
	 */
	if (has_not_enough_free_secs(sbi, 0)) { // 是否section不够用
		if ((FG_GC_count++ % 100) == 0) { // 打印信息
			f2fs_msg(sbi->sb, KERN_WARNING,
			"FG_GC: Size=%lldMB,Free=%lldMB,count=%d,free_sec=%d,reserved_sec=%d,node_secs=%d,dent_secs=%d\n",
			(le64_to_cpu(sbi->user_block_count) * sbi->blocksize) /1024/1024,
			(le64_to_cpu(sbi->user_block_count - valid_user_blocks(sbi)) * sbi->blocksize) /1024/1024,
			FG_GC_count, free_sections(sbi), reserved_sections(sbi),
			get_blocktype_secs(sbi, F2FS_DIRTY_NODES), get_blocktype_secs(sbi, F2FS_DIRTY_DENTS));
		}

		mutex_lock(&sbi->gc_mutex);
		/*lint -save -e747*/
		f2fs_gc(sbi, false, false); // 做一下gc
		/*lint -restore*/
	}
}

void f2fs_balance_fs_bg(struct f2fs_sb_info *sbi)
{
	/* try to shrink extent cache when there is no enough memory */
	if (!available_free_memory(sbi, EXTENT_CACHE))
		f2fs_shrink_extent_tree(sbi, EXTENT_CACHE_SHRINK_NUMBER);

	/* check the # of cached NAT entries */
	if (!available_free_memory(sbi, NAT_ENTRIES))
		try_to_free_nats(sbi, NAT_ENTRY_PER_BLOCK);

	if (!available_free_memory(sbi, FREE_NIDS))
		try_to_free_nids(sbi, NAT_ENTRY_PER_BLOCK * FREE_NID_PAGES);
	else
		/*lint -save -e747*/
		build_free_nids(sbi, false);
		/*lint -restore*/

	/* checkpoint is the only way to shrink partial cached entries */
	if (!available_free_memory(sbi, NAT_ENTRIES) ||
			!available_free_memory(sbi, INO_ENTRIES) ||
			excess_prefree_segs(sbi) ||
			excess_dirty_nats(sbi) ||
			f2fs_time_over(sbi, CP_TIME)) {
		if (test_opt(sbi, DATA_FLUSH)) {
			struct blk_plug plug;

			blk_start_plug(&plug);
			sync_dirty_inodes(sbi, FILE_INODE);
			blk_finish_plug(&plug);
		}
		f2fs_sync_fs(sbi->sb, true);
		stat_inc_bg_cp_count(sbi->stat_info);
	}
}

static int issue_flush_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct flush_cmd_control *fcc = SM_I(sbi)->cmd_control_info;
	wait_queue_head_t *q = &fcc->flush_wait_queue;
repeat:
	if (kthread_should_stop())
		return 0;

	if (!llist_empty(&fcc->issue_list)) {
		struct bio *bio;
		struct flush_cmd *cmd, *next;
		int ret;

		bio = f2fs_bio_alloc(0);

		fcc->dispatch_list = llist_del_all(&fcc->issue_list);
		fcc->dispatch_list = llist_reverse_order(fcc->dispatch_list);

		bio->bi_bdev = sbi->sb->s_bdev;
		ret = submit_bio_wait(WRITE_FLUSH, bio);

		llist_for_each_entry_safe(cmd, next,
					  fcc->dispatch_list, llnode) {
			cmd->ret = ret;
			complete(&cmd->wait);
		}
		bio_put(bio);
		fcc->dispatch_list = NULL;
	}

	wait_event_interruptible(*q,
		kthread_should_stop() || !llist_empty(&fcc->issue_list));
	goto repeat;
}

int f2fs_issue_flush(struct f2fs_sb_info *sbi)
{
	struct flush_cmd_control *fcc = SM_I(sbi)->cmd_control_info;
	struct flush_cmd cmd;

	trace_f2fs_issue_flush(sbi->sb, test_opt(sbi, NOBARRIER),
					test_opt(sbi, FLUSH_MERGE));

	if (test_opt(sbi, NOBARRIER))
		return 0;

	if (!test_opt(sbi, FLUSH_MERGE) || blk_flush_async_support(sbi->sb->s_bdev)) {
		struct bio *bio = f2fs_bio_alloc(0);
		int ret;

		bio->bi_bdev = sbi->sb->s_bdev;
		blk_flush_set_async(bio);
		ret = submit_bio_wait(WRITE_FLUSH, bio);
		bio_put(bio);
		return ret;
	}

	init_completion(&cmd.wait);

	llist_add(&cmd.llnode, &fcc->issue_list);

	if (!fcc->dispatch_list)
		wake_up(&fcc->flush_wait_queue);

	wait_for_completion(&cmd.wait);

	return cmd.ret;
}

int create_flush_cmd_control(struct f2fs_sb_info *sbi)
{
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	struct flush_cmd_control *fcc;
	int err = 0;

	fcc = kzalloc(sizeof(struct flush_cmd_control), GFP_KERNEL);
	if (!fcc)
		return -ENOMEM;
	init_waitqueue_head(&fcc->flush_wait_queue);
	init_llist_head(&fcc->issue_list);
	SM_I(sbi)->cmd_control_info = fcc;
	fcc->f2fs_issue_flush = kthread_run(issue_flush_thread, sbi,
				"f2fs_flush-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(fcc->f2fs_issue_flush)) {
		err = PTR_ERR(fcc->f2fs_issue_flush);
		kfree(fcc);
		SM_I(sbi)->cmd_control_info = NULL;
		return err;
	}

	return err;
}

void destroy_flush_cmd_control(struct f2fs_sb_info *sbi)
{
	struct flush_cmd_control *fcc = SM_I(sbi)->cmd_control_info;

	if (fcc && fcc->f2fs_issue_flush)
		kthread_stop(fcc->f2fs_issue_flush);
	kfree(fcc);
	SM_I(sbi)->cmd_control_info = NULL;
}


static void __locate_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno,
		enum dirty_type dirty_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	/* need not be added */
	if (IS_CURSEG(sbi, segno))
		return;

	if (!test_and_set_bit(segno, dirty_i->dirty_segmap[dirty_type]))
		dirty_i->nr_dirty[dirty_type]++;

	if (dirty_type == DIRTY) {
		struct seg_entry *sentry = get_seg_entry(sbi, segno);
		enum dirty_type t = sentry->type;

		if (unlikely(t >= DIRTY)) {
			f2fs_bug_on(sbi, 1);
			return;
		}
		if (!test_and_set_bit(segno, dirty_i->dirty_segmap[t]))
			dirty_i->nr_dirty[t]++;
	}
}

static void __remove_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno,
		enum dirty_type dirty_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (test_and_clear_bit(segno, dirty_i->dirty_segmap[dirty_type]))
		dirty_i->nr_dirty[dirty_type]--;

	if (dirty_type == DIRTY) {
		struct seg_entry *sentry = get_seg_entry(sbi, segno);
		enum dirty_type t = sentry->type;

		if (test_and_clear_bit(segno, dirty_i->dirty_segmap[t]))
			dirty_i->nr_dirty[t]--;

		if (get_valid_blocks(sbi, segno, sbi->segs_per_sec) == 0)
			clear_bit(GET_SECNO(sbi, segno),
						dirty_i->victim_secmap);
	}
}

/*
 * Should not occur error such as -ENOMEM.
 * Adding dirty entry into seglist is not critical operation.
 * If a given segment is one of current working segments, it won't be added.
 *
 * 简单来说就是更新dirty_i里面的seglist表
 *
 */
static void locate_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned short valid_blocks;

	if (segno == NULL_SEGNO || IS_CURSEG(sbi, segno))
		return;

	mutex_lock(&dirty_i->seglist_lock);

	valid_blocks = get_valid_blocks(sbi, segno, 0);

	if (valid_blocks == 0) {
		__locate_dirty_segment(sbi, segno, PRE);
		__remove_dirty_segment(sbi, segno, DIRTY);
	} else if (valid_blocks < sbi->blocks_per_seg) {
		__locate_dirty_segment(sbi, segno, DIRTY);
	} else {
		/* Recovery routine with SSR needs this */
		__remove_dirty_segment(sbi, segno, DIRTY);
	}

	mutex_unlock(&dirty_i->seglist_lock);
}

/*
 * 处理物理设备的discard
 * blkstart：segment entry block的起始位置
 * blklen：需要处理segment entry block的长度
 * */
static int f2fs_issue_discard(struct f2fs_sb_info *sbi,
				block_t blkstart, block_t blklen)
{
	sector_t start = SECTOR_FROM_BLOCK(blkstart);
	sector_t len = SECTOR_FROM_BLOCK(blklen);
	struct seg_entry *se;
	unsigned int offset;
	block_t i;
	int ret;

	for (i = blkstart; i < blkstart + blklen; i++) {
		se = get_seg_entry(sbi, GET_SEGNO(sbi, i)); // 获取segment entry
		offset = GET_BLKOFF_FROM_SEG0(sbi, i); // 计算距离segment 0的长度

		if (!f2fs_test_and_set_bit(offset, se->discard_map))
			sbi->discard_blks--; // 减少需要discard的blk的数目
	}
	trace_f2fs_issue_discard(sbi->sb, blkstart, blklen);
	ret = blkdev_issue_discard(sbi->sb->s_bdev, start, len, GFP_NOFS, 0); // 执行物理设备的discard
	return ret;
}

bool discard_next_dnode(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	int err = -EOPNOTSUPP;

	if (test_opt(sbi, DISCARD)) {
		struct seg_entry *se = get_seg_entry(sbi,
				GET_SEGNO(sbi, blkaddr));
		unsigned int offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

		if (f2fs_test_bit(offset, se->discard_map))
			return false;

		err = f2fs_issue_discard(sbi, blkaddr, 1);
	}

	if (err) {
		update_meta_page(sbi, NULL, blkaddr);
		return true;
	}
	return false;
}

static void __add_discard_entry(struct f2fs_sb_info *sbi,
		struct cp_control *cpc, struct seg_entry *se,
		unsigned int start, unsigned int end)
{
	struct list_head *head = &SM_I(sbi)->discard_list;
	struct discard_entry *new, *last;

	if (!list_empty(head)) {
		last = list_last_entry(head, struct discard_entry, list);
		if (START_BLOCK(sbi, cpc->trim_start) + start == last->blkaddr + last->len) {
			last->len += end - start;
			goto done;
		}
	}

	new = f2fs_kmem_cache_alloc(discard_entry_slab, GFP_NOFS);
	INIT_LIST_HEAD(&new->list);
	new->blkaddr = START_BLOCK(sbi, cpc->trim_start) + start;
	new->len = end - start;
	list_add_tail(&new->list, head);
done:
	SM_I(sbi)->nr_discards += end - start;
}

/*
 * 将当前checkpoint包含的trim信息，加入到SM_I(sbi)->discard_list链表中
 * */
static void add_discard_addrs(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	int max_blocks = sbi->blocks_per_seg;
	struct seg_entry *se = get_seg_entry(sbi, cpc->trim_start); //获得segno对应的seg_entry
	unsigned long *cur_map = (unsigned long *)se->cur_valid_map;
	unsigned long *ckpt_map = (unsigned long *)se->ckpt_valid_map;
	unsigned long *discard_map = (unsigned long *)se->discard_map;
	unsigned long *dmap = SIT_I(sbi)->tmp_map;
	unsigned int start = 0, end = -1;
	bool force = (cpc->reason == CP_DISCARD); // 是否强迫force
	int i;

	if (se->valid_blocks == max_blocks)
		return;

	if (!force) { // 不是force，如果不是极端情况，那就悠着点
		if (!test_opt(sbi, DISCARD) || !se->valid_blocks || SM_I(sbi)->nr_discards >= SM_I(sbi)->max_discards)
			return;
	}

	/* SIT_VBLOCK_MAP_SIZE should be multiple of sizeof(unsigned long) */
	for (i = 0; i < entries; i++)
		dmap[i] = force ?
				~ckpt_map[i] & ~discard_map[i] : // 如果是force，
				(cur_map[i] ^ ckpt_map[i]) & ckpt_map[i];

	while (force || SM_I(sbi)->nr_discards <= SM_I(sbi)->max_discards) {
		start = __find_rev_next_bit(dmap, max_blocks, end + 1);
		if (start >= max_blocks)
			break;

		end = __find_rev_next_zero_bit(dmap, max_blocks, start + 1);
		/*lint -save -e737*/
		if (force && start && end != max_blocks && (end - start) < cpc->trim_minlen)
		/*lint -restore*/
			continue;

		__add_discard_entry(sbi, cpc, se, start, end);
	}
}

void release_discard_addrs(struct f2fs_sb_info *sbi)
{
	struct list_head *head = &(SM_I(sbi)->discard_list);
	struct discard_entry *entry, *this;

	/* drop caches */
	list_for_each_entry_safe(entry, this, head, list) {
		list_del(&entry->list);
		kmem_cache_free(discard_entry_slab, entry);
	}
}

/*
 * Should call clear_prefree_segments after checkpoint is done.
 */
static void set_prefree_as_free_segments(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int segno;

	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[PRE], MAIN_SEGS(sbi))
		__set_test_and_free(sbi, segno);
	mutex_unlock(&dirty_i->seglist_lock);
}

/*
 * 清理prefree的segment
 *
 * prefree_segments() = DIRTY_I(sbi)->nr_dirty[PRE]
 * 作用
 *
 * 1. 遍历prefree_map的每一项，然后清除该segment对应bit位不为dirty
 * 2. 对于discard命令，就强制执行discard，对脏的seg_entry，刷写到磁盘中
 * */
void clear_prefree_segments(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	struct list_head *head = &(SM_I(sbi)->discard_list);
	struct discard_entry *entry, *this;
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned long *prefree_map = dirty_i->dirty_segmap[PRE]; // 获取dirty的map
	unsigned int start = 0, end = -1;
	bool force = (cpc->reason == CP_DISCARD); // force = 1代表强制耍些，一般是trim导致的

	mutex_lock(&dirty_i->seglist_lock);

	// 开始遍历整个所有的segnment的dirty map
	while (1) {
		int i;
		start = find_next_bit(prefree_map, MAIN_SEGS(sbi), end + 1); // 找出对应的dirty segment number
		if (start >= MAIN_SEGS(sbi)) // 超过main area所有的segment就退出
			break;
		end = find_next_zero_bit(prefree_map, MAIN_SEGS(sbi),
								start + 1);

		for (i = start; i < end; i++)
			clear_bit(i, prefree_map); // 清除标志位

		dirty_i->nr_dirty[PRE] -= end - start; // 减少dirty的segment数目

		if (force || !test_opt(sbi, DISCARD))
			continue;

		f2fs_issue_discard(sbi, START_BLOCK(sbi, start),
				(end - start) << sbi->log_blocks_per_seg);
	}
	mutex_unlock(&dirty_i->seglist_lock);

	/* send small discards */
	list_for_each_entry_safe(entry, this, head, list) {
		if (force && entry->len < cpc->trim_minlen)
			goto skip;
		f2fs_issue_discard(sbi, entry->blkaddr, entry->len);
		cpc->trimmed += entry->len;
skip:
		list_del(&entry->list);
		SM_I(sbi)->nr_discards -= entry->len;
		kmem_cache_free(discard_entry_slab, entry);
	}
}

static bool __mark_sit_entry_dirty(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);

	// 如果dirty_sentries_bitmap包含了segno，那就不处理，如果不包含则设置bit位为1,然后增减dirty_sentries的个数
	if (!__test_and_set_bit(segno, sit_i->dirty_sentries_bitmap)) {
		sit_i->dirty_sentries++;
		return false;
	}

	return true;
}

static void __set_sit_entry_type(struct f2fs_sb_info *sbi, int type,
					unsigned int segno, int modified)
{
	struct seg_entry *se = get_seg_entry(sbi, segno);
	se->type = type;
	if (modified)
		__mark_sit_entry_dirty(sbi, segno);
}

/*
 * del的值一般是 1 或者是 -1
 * a) 根据blkaddr找到对应的segno
 * b) 根据segno在sit找到对应的seg_entry
 * !! 根据 del 的值：
 * c) 更新的seg_entry里面的valid_blocks、cur_valid_map、discard_map、ckpt_valid_blocks
 * d) 更新sec_entry里面的valid_blocks
 * e) 更新sbi->sit的written_valid_blocks
 * */
static void update_sit_entry(struct f2fs_sb_info *sbi, block_t blkaddr, int del)
{
	struct seg_entry *se;
	unsigned int segno, offset;
	long int new_vblocks;

	// 如果超出了main area的范围，那么就认为系统出错了，设置需要FSCK的标志
	if (blkaddr < MAIN_BLKADDR(sbi) || blkaddr >= MAX_BLKADDR(sbi)) {
		f2fs_msg(sbi->sb, KERN_ERR, "Invalid blkaddr 0x%x\n", blkaddr);
		set_extra_flag(sbi, EXTRA_NEED_FSCK_FLAG);
		/*lint -save -e730*/
		f2fs_bug_on(sbi, 1);
		/*lint -restore*/
	}

	segno = GET_SEGNO(sbi, blkaddr); // 获取这个blkaddr所在的segno

	se = get_seg_entry(sbi, segno); // 获取这个segnment所在的sengment entry
	new_vblocks = se->valid_blocks + del; // del等于1或者-1
	offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);// 获取从seg0开始的第offset个block

	f2fs_bug_on(sbi, (new_vblocks >> (sizeof(unsigned short) << 3) ||
				(new_vblocks > sbi->blocks_per_seg)));

	se->valid_blocks = new_vblocks; // 更新这个segnment的valid block数目
	se->mtime = get_mtime(sbi); // 更新修改时间
	SIT_I(sbi)->max_mtime = se->mtime;

	/*
	 * Update valid block bitmap
	 * 更新bitmap上的数目
	 * */
	if (del > 0) { // 增加invalid block的数目
		if (f2fs_test_and_set_bit(offset, se->cur_valid_map)) // 设置se->cur_valid_map的offset位为可用
			f2fs_bug_on(sbi, 1);
		if (!f2fs_test_and_set_bit(offset, se->discard_map)) // 设置se->cur_valid_map的offset位为可用
			sbi->discard_blks--; // 设置成功就减少discard block的数目
	} else { // 减少invalid block的数目
		if (!f2fs_test_and_clear_bit(offset, se->cur_valid_map))
			f2fs_bug_on(sbi, 1);
		if (f2fs_test_and_clear_bit(offset, se->discard_map))
			sbi->discard_blks++;
	}
	if (!f2fs_test_bit(offset, se->ckpt_valid_map)) // 设置checkpoint的valid map
		se->ckpt_valid_blocks += del;

	__mark_sit_entry_dirty(sbi, segno);

	/* update total number of valid blocks to be written in ckpt area */
	SIT_I(sbi)->written_valid_blocks += del; // 更新可以被写的块数目

	if (sbi->segs_per_sec > 1)
		get_sec_entry(sbi, segno)->valid_blocks += del;
}

/*
 * 如果new不是NULL_SEGNO，增加可用的数目
 * 如果是old不是NULL_SEGNO，则减少可用的数目
 *
 * 更新valid block和invalid block等信息
 * 然后将这个segment标志为dirty，gc的get_victim会使用到，用来释放一些invalid的page
 * */
void refresh_sit_entry(struct f2fs_sb_info *sbi, block_t old, block_t new)
{
	update_sit_entry(sbi, new, 1); // 根据new在sit找到对应的seg_entry，然后更新里面的信息
	if (GET_SEGNO(sbi, old) != NULL_SEGNO)
		update_sit_entry(sbi, old, -1); // 更新valid block和invalid block等信息

	locate_dirty_segment(sbi, GET_SEGNO(sbi, old));
	locate_dirty_segment(sbi, GET_SEGNO(sbi, new));
}

void invalidate_blocks(struct f2fs_sb_info *sbi, block_t addr)
{
	unsigned int segno = GET_SEGNO(sbi, addr);
	struct sit_info *sit_i = SIT_I(sbi);

	f2fs_bug_on(sbi, addr == NULL_ADDR);
	if (addr == NEW_ADDR)
		return;

	/* add it into sit main buffer */
	mutex_lock(&sit_i->sentry_lock);

	update_sit_entry(sbi, addr, -1);

	/* add it into dirty seglist */
	locate_dirty_segment(sbi, segno);

	mutex_unlock(&sit_i->sentry_lock);
}

bool is_checkpointed_data(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int segno, offset;
	struct seg_entry *se;
	bool is_cp = false;

	if (blkaddr == NEW_ADDR || blkaddr == NULL_ADDR)
		return true;

	mutex_lock(&sit_i->sentry_lock);

	segno = GET_SEGNO(sbi, blkaddr);
	se = get_seg_entry(sbi, segno);
	offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	if (f2fs_test_bit(offset, se->ckpt_valid_map))
		is_cp = true;

	mutex_unlock(&sit_i->sentry_lock);

	return is_cp;
}

/*
 * This function should be resided under the curseg_mutex lock
 */
static void __add_sum_entry(struct f2fs_sb_info *sbi, int type, struct f2fs_summary *sum)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	void *addr = curseg->sum_blk; // summary block的起始位置，注意summary block和summary是不同的，一个sum blk包含了多个f2fs_summary
	// 一个f2fs_summary大小是7字节，所以一个summary block可以存储585个，因此维护512个(一个segment=512block)还是没问题的
	addr += curseg->next_blkoff * sizeof(struct f2fs_summary);
	memcpy(addr, sum, sizeof(struct f2fs_summary)); // 复制summary到summary block的对应位置
}

/*
 * Calculate the number of current summary pages for writing
 */
int npages_for_summary_flush(struct f2fs_sb_info *sbi, bool for_ra)
{
	int valid_sum_count = 0;
	int i, sum_in_page;

	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		if (sbi->ckpt->alloc_type[i] == SSR)
			valid_sum_count += sbi->blocks_per_seg;
		else {
			if (for_ra)
				valid_sum_count += le16_to_cpu(
					F2FS_CKPT(sbi)->cur_data_blkoff[i]);
			else
				valid_sum_count += curseg_blkoff(sbi, i);
		}
	}

	sum_in_page = (PAGE_CACHE_SIZE - 2 * SUM_JOURNAL_SIZE -
			SUM_FOOTER_SIZE) / SUMMARY_SIZE;
	if (valid_sum_count <= sum_in_page)
		return 1;
	else if ((valid_sum_count - sum_in_page) <=
		(PAGE_CACHE_SIZE - SUM_FOOTER_SIZE) / SUMMARY_SIZE)
		return 2;
	return 3;
}

/*
 * Caller should put this summary page
 */
struct page *get_sum_page(struct f2fs_sb_info *sbi, unsigned int segno)
{
	return get_meta_page(sbi, GET_SUM_BLOCK(sbi, segno));
}

void update_meta_page(struct f2fs_sb_info *sbi, void *src, block_t blk_addr)
{
	struct page *page = grab_meta_page(sbi, blk_addr);
	void *dst = page_address(page);

	if (src)
		memcpy(dst, src, PAGE_CACHE_SIZE);
	else
		memset(dst, 0, PAGE_CACHE_SIZE);
	set_page_dirty(page);
	f2fs_put_page(page, 1);
}

static void write_sum_page(struct f2fs_sb_info *sbi,
			struct f2fs_summary_block *sum_blk, block_t blk_addr)
{
	update_meta_page(sbi, (void *)sum_blk, blk_addr);
}

static void write_current_sum_page(struct f2fs_sb_info *sbi,
						int type, block_t blk_addr)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	struct page *page = grab_meta_page(sbi, blk_addr);
	struct f2fs_summary_block *src = curseg->sum_blk;
	struct f2fs_summary_block *dst;

	dst = (struct f2fs_summary_block *)page_address(page);

	mutex_lock(&curseg->curseg_mutex);

	down_read(&curseg->journal_rwsem);
	memcpy(&dst->journal, curseg->journal, SUM_JOURNAL_SIZE);
	up_read(&curseg->journal_rwsem);

	memcpy(dst->entries, src->entries, SUM_ENTRY_SIZE);
	memcpy(&dst->footer, &src->footer, SUM_FOOTER_SIZE);

	mutex_unlock(&curseg->curseg_mutex);

	set_page_dirty(page);
	f2fs_put_page(page, 1);
}

static int is_next_segment_free(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int segno = curseg->segno + 1;
	struct free_segmap_info *free_i = FREE_I(sbi);

	if (segno < MAIN_SEGS(sbi) && segno % sbi->segs_per_sec)
		return !test_bit(segno, free_i->free_segmap);
	return 0;
}

/*
 * Find a new segment from the free segments bitmap to right order
 * This function should be returned with success, otherwise BUG
 */
static void get_new_segment(struct f2fs_sb_info *sbi,
			unsigned int *newseg, bool new_sec, int dir)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int segno, secno, zoneno;
	unsigned int total_zones = MAIN_SECS(sbi) / sbi->secs_per_zone;
	unsigned int hint = *newseg / sbi->segs_per_sec;
	unsigned int old_zoneno = GET_ZONENO_FROM_SEGNO(sbi, *newseg);
	unsigned int left_start = hint;
	bool init = true;
	int go_left = 0;
	int i;

	spin_lock(&free_i->segmap_lock);

	if (!new_sec && ((*newseg + 1) % sbi->segs_per_sec)) {
		segno = find_next_zero_bit(free_i->free_segmap,
				(hint + 1) * sbi->segs_per_sec, *newseg + 1);
		if (segno < (hint + 1) * sbi->segs_per_sec)
			goto got_it;
	}
find_other_zone:
	secno = find_next_zero_bit(free_i->free_secmap, MAIN_SECS(sbi), hint);
	if (secno >= MAIN_SECS(sbi)) {
		if (dir == ALLOC_RIGHT) {
			secno = find_next_zero_bit(free_i->free_secmap,
							MAIN_SECS(sbi), 0);
			f2fs_bug_on(sbi, secno >= MAIN_SECS(sbi));
		} else {
			go_left = 1;
			left_start = hint - 1;
		}
	}
	if (go_left == 0)
		goto skip_left;

	while (test_bit(left_start, free_i->free_secmap)) {
		if (left_start > 0) {
			left_start--;
			continue;
		}
		left_start = find_next_zero_bit(free_i->free_secmap,
							MAIN_SECS(sbi), 0);
		f2fs_bug_on(sbi, left_start >= MAIN_SECS(sbi));
		break;
	}
	secno = left_start;
skip_left:
	hint = secno;
	segno = secno * sbi->segs_per_sec;
	zoneno = secno / sbi->secs_per_zone;

	/* give up on finding another zone */
	if (!init)
		goto got_it;
	if (sbi->secs_per_zone == 1)
		goto got_it;
	if (zoneno == old_zoneno)
		goto got_it;
	if (dir == ALLOC_LEFT) {
		if (!go_left && zoneno + 1 >= total_zones)
			goto got_it;
		if (go_left && zoneno == 0)
			goto got_it;
	}
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		if (CURSEG_I(sbi, i)->zone == zoneno)
			break;

	if (i < NR_CURSEG_TYPE) {
		/* zone is in user, try another */
		if (go_left)
			hint = zoneno * sbi->secs_per_zone - 1;
		else if (zoneno + 1 >= total_zones)
			hint = 0;
		else
			hint = (zoneno + 1) * sbi->secs_per_zone;
		init = false;
		goto find_other_zone;
	}
got_it:
	/* set it as dirty segment in free segmap */
	f2fs_bug_on(sbi, test_bit(segno, free_i->free_segmap));
	__set_inuse(sbi, segno);
	*newseg = segno;
	spin_unlock(&free_i->segmap_lock);
}

static void reset_curseg(struct f2fs_sb_info *sbi, int type, int modified)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	struct summary_footer *sum_footer;

	curseg->segno = curseg->next_segno;
	curseg->zone = GET_ZONENO_FROM_SEGNO(sbi, curseg->segno);
	curseg->next_blkoff = 0;
	curseg->next_segno = NULL_SEGNO;

	sum_footer = &(curseg->sum_blk->footer);
	memset(sum_footer, 0, sizeof(struct summary_footer));
	if (IS_DATASEG(type))
		SET_SUM_TYPE(sum_footer, SUM_TYPE_DATA);
	if (IS_NODESEG(type))
		SET_SUM_TYPE(sum_footer, SUM_TYPE_NODE);
	__set_sit_entry_type(sbi, type, curseg->segno, modified);
}

/*
 * Allocate a current working segment.
 * This function always allocates a free segment in LFS manner.
 */
static void new_curseg(struct f2fs_sb_info *sbi, int type, bool new_sec)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int segno = curseg->segno;
	int dir = ALLOC_LEFT;

	write_sum_page(sbi, curseg->sum_blk,
				GET_SUM_BLOCK(sbi, segno));
	if (type == CURSEG_WARM_DATA || type == CURSEG_COLD_DATA)
		dir = ALLOC_RIGHT;

	if (test_opt(sbi, NOHEAP))
		dir = ALLOC_RIGHT;

	get_new_segment(sbi, &segno, new_sec, dir);
	curseg->next_segno = segno;
	reset_curseg(sbi, type, 1);
	curseg->alloc_type = LFS;
}

static void __next_free_blkoff(struct f2fs_sb_info *sbi,
			struct curseg_info *seg, block_t start)
{
	struct seg_entry *se = get_seg_entry(sbi, seg->segno);
	int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	unsigned long *target_map = SIT_I(sbi)->tmp_map;
	unsigned long *ckpt_map = (unsigned long *)se->ckpt_valid_map;
	unsigned long *cur_map = (unsigned long *)se->cur_valid_map;
	int i, pos;

	for (i = 0; i < entries; i++)
		target_map[i] = ckpt_map[i] | cur_map[i];

	pos = __find_rev_next_zero_bit(target_map, sbi->blocks_per_seg, start);

	seg->next_blkoff = pos;
}

/*
 * If a segment is written by LFS manner, next block offset is just obtained
 * by increasing the current block offset. However, if a segment is written by
 * SSR manner, next block offset obtained by calling __next_free_blkoff
 */
static void __refresh_next_blkoff(struct f2fs_sb_info *sbi,
				struct curseg_info *seg)
{
	if (seg->alloc_type == SSR)
		__next_free_blkoff(sbi, seg, seg->next_blkoff + 1);
	else
		seg->next_blkoff++;
}

/*
 * This function always allocates a used segment(from dirty seglist) by SSR
 * manner, so it should recover the existing segment information of valid blocks
 */
static void change_curseg(struct f2fs_sb_info *sbi, int type, bool reuse)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int new_segno = curseg->next_segno;
	struct f2fs_summary_block *sum_node;
	struct page *sum_page;

	write_sum_page(sbi, curseg->sum_blk,
				GET_SUM_BLOCK(sbi, curseg->segno));
	__set_test_and_inuse(sbi, new_segno);

	mutex_lock(&dirty_i->seglist_lock);
	__remove_dirty_segment(sbi, new_segno, PRE);
	__remove_dirty_segment(sbi, new_segno, DIRTY);
	mutex_unlock(&dirty_i->seglist_lock);

	reset_curseg(sbi, type, 1);
	curseg->alloc_type = SSR;
	__next_free_blkoff(sbi, curseg, 0);

	if (reuse) {
		sum_page = get_sum_page(sbi, new_segno);
		sum_node = (struct f2fs_summary_block *)page_address(sum_page);
		memcpy(curseg->sum_blk, sum_node, SUM_ENTRY_SIZE);
		f2fs_put_page(sum_page, 1);
	}
}

static int get_ssr_segment(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	const struct victim_selection *v_ops = DIRTY_I(sbi)->v_ops;

	if (IS_NODESEG(type) || !has_not_enough_free_secs(sbi, 0))
		return v_ops->get_victim(sbi,
				&(curseg)->next_segno, BG_GC, type, SSR);

	/* For data segments, let's do SSR more intensively */
	for (; type >= CURSEG_HOT_DATA; type--)
		if (v_ops->get_victim(sbi, &(curseg)->next_segno,
						BG_GC, type, SSR))
			return 1;
	return 0;
}

/*
 * flush out current segment and replace it with new segment
 * This function should be returned with success, otherwise BUG
 */
static void allocate_segment_by_default(struct f2fs_sb_info *sbi,
						int type, bool force)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);

	if (force)
		new_curseg(sbi, type, true);
	else if (type == CURSEG_WARM_NODE)
		new_curseg(sbi, type, false);
	else if (curseg->alloc_type == LFS && is_next_segment_free(sbi, type))
		new_curseg(sbi, type, false);
	else if (need_SSR(sbi) && get_ssr_segment(sbi, type))
		change_curseg(sbi, type, true);
	else
		new_curseg(sbi, type, false);

	stat_inc_seg_type(sbi, curseg);
}

static void __allocate_new_segments(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int old_segno;

	old_segno = curseg->segno;
	SIT_I(sbi)->s_ops->allocate_segment(sbi, type, true);
	locate_dirty_segment(sbi, old_segno);
}

void allocate_new_segments(struct f2fs_sb_info *sbi)
{
	int i;

	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++)
		__allocate_new_segments(sbi, i);
}

static const struct segment_allocation default_salloc_ops = {
	.allocate_segment = allocate_segment_by_default,
};

int f2fs_trim_fs(struct f2fs_sb_info *sbi, struct fstrim_range *range)
{
	__u64 start = F2FS_BYTES_TO_BLK(range->start);
	__u64 end = start + F2FS_BYTES_TO_BLK(range->len) - 1;
	unsigned int start_segno, end_segno;
	struct cp_control cpc;
	int err = 0;

	if (start >= MAX_BLKADDR(sbi) || range->len < sbi->blocksize)
		return -EINVAL;

	cpc.trimmed = 0;
	if (end <= MAIN_BLKADDR(sbi))
		goto out;

	/* start/end segment number in main_area */
	start_segno = (start <= MAIN_BLKADDR(sbi)) ? 0 : GET_SEGNO(sbi, start);
	end_segno = (end >= MAX_BLKADDR(sbi)) ? MAIN_SEGS(sbi) - 1 :
						GET_SEGNO(sbi, end);
	cpc.reason = CP_DISCARD;
	cpc.trim_minlen = max_t(__u64, 1, F2FS_BYTES_TO_BLK(range->minlen));

	/* do checkpoint to issue discard commands safely */
	for (; start_segno <= end_segno; start_segno = cpc.trim_end + 1) {
		cpc.trim_start = start_segno;

		if (sbi->discard_blks == 0)
			break;
		else if (sbi->discard_blks < BATCHED_TRIM_BLOCKS(sbi))
			cpc.trim_end = end_segno;
		else
			cpc.trim_end = min_t(unsigned int,
				rounddown(start_segno +
				BATCHED_TRIM_SEGMENTS(sbi),
				sbi->segs_per_sec) - 1, end_segno);

		mutex_lock(&sbi->gc_mutex);
		err = write_checkpoint(sbi, &cpc);
		mutex_unlock(&sbi->gc_mutex);
		if(err)
			break;

		//schedule();
		msleep(50);
	}
out:
	range->len = F2FS_BLK_TO_BYTES(cpc.trimmed);
	return err;
}

static bool __has_curseg_space(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	if (curseg->next_blkoff < sbi->blocks_per_seg)
		return true;
	return false;
}

static int __get_segment_type_2(struct page *page, enum page_type p_type)
{
	if (p_type == DATA)
		return CURSEG_HOT_DATA;
	else
		return CURSEG_HOT_NODE;
}

static int __get_segment_type_4(struct page *page, enum page_type p_type)
{
	if (p_type == DATA) {
		struct inode *inode = page->mapping->host;

		if (S_ISDIR(inode->i_mode))
			return CURSEG_HOT_DATA;
		else
			return CURSEG_COLD_DATA;
	} else {
		if (IS_DNODE(page) && is_cold_node(page))
			return CURSEG_WARM_NODE;
		else
			return CURSEG_COLD_NODE;
	}
}

/*
 * segment分类
 * 有6个log的时候的segment类型分类
 * */
static int __get_segment_type_6(struct page *page, enum page_type p_type)
{
	if (p_type == DATA) {
		struct inode *inode = page->mapping->host;

		if (S_ISDIR(inode->i_mode)) // 文件夹是HOT DATA
			return CURSEG_HOT_DATA;
		else if (is_cold_data(page) || file_is_cold(inode)) // 一般是需要gc的data，检查这个page的flag，如果包含这个flag那就是cold data，这个flag也是由文件系统设置的
			return CURSEG_COLD_DATA;
		else
			return CURSEG_WARM_DATA; // 一般数据就是warm data
	} else { // 针对node
		if (IS_DNODE(page))
			return is_cold_node(page) ? CURSEG_WARM_NODE :
						CURSEG_HOT_NODE;
		else
			return CURSEG_COLD_NODE;
	}
}

/*
 * 获取segment的类型
 * */
static int __get_segment_type(struct page *page, enum page_type p_type)
{
	switch (F2FS_P_SB(page)->active_logs) { // 一般是6
	case 2:
		return __get_segment_type_2(page, p_type);
	case 4:
		return __get_segment_type_4(page, p_type);
	}
	/* NR_CURSEG_TYPE(6) logs by default */
	f2fs_bug_on(F2FS_P_SB(page),
		F2FS_P_SB(page)->active_logs != NR_CURSEG_TYPE);
	return __get_segment_type_6(page, p_type);
}

/*
 * a) 根据curseg以及分配的data的type，计算得到需要新分配的datablock的地址
 * b) 根据新分配的地址，创建一个summary_entry，然后加入到新datablock所在的summary block中
 * c) 更新新datablock对应的sit信息
 * */
void allocate_data_block(struct f2fs_sb_info *sbi, struct page *page,
		block_t old_blkaddr, block_t *new_blkaddr,
		struct f2fs_summary *sum, int type)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *curseg;
	bool direct_io = (type == CURSEG_DIRECT_IO); // 因为curseg不包含CURSEG_DIRECT_IO的curseg_array[6]的信息

	type = direct_io ? CURSEG_WARM_DATA : type; // 所以转化为warm data

	curseg = CURSEG_I(sbi, type); // 获取这个type所在的segment

	mutex_lock(&curseg->curseg_mutex);
	mutex_lock(&sit_i->sentry_lock);

	/* direct_io'ed data is aligned to the segment for better performance */
	if (direct_io && curseg->next_blkoff && !has_not_enough_free_secs(sbi, 0))
		__allocate_new_segments(sbi, type);

	//        !!!!   curseg->next_blkoff 表示的是当前segment的block偏移，范围是 0~511

	*new_blkaddr = NEXT_FREE_BLKADDR(sbi, curseg); // 获得下一个可用的block addr，计算方式是 (当前segment地址 + next_blkoff)

	/*
	 * __add_sum_entry should be resided under the curseg_mutex
	 * because, this function updates a summary entry in the
	 * current summary block.
	 */
	__add_sum_entry(sbi, type, sum); // 根据next_blkoff的，计算得到下一个segment的地址，然后将这个summary复制到这个seg_addr中

	__refresh_next_blkoff(sbi, curseg); // 更新下一个可用的next_blkoff

	stat_inc_block_count(sbi, curseg);

	if (!__has_curseg_space(sbi, type)) // 当前的segnment是否还有空间
		sit_i->s_ops->allocate_segment(sbi, type, false);
	/*
	 * SIT information should be updated before segment allocation,
	 * since SSR needs latest valid block information.
	 * old_blkaddr如果是新创建模式，就是NEW_ADDR
	 */
	refresh_sit_entry(sbi, old_blkaddr, *new_blkaddr); // 更新old_blkaddr和对应new_blkaddr对应的sit table

	mutex_unlock(&sit_i->sentry_lock);

	if (page && IS_NODESEG(type)) // 如果是一般的node，则更新footer
		fill_node_footer_blkaddr(page, NEXT_FREE_BLKADDR(sbi, curseg)); // 更新footer

	mutex_unlock(&curseg->curseg_mutex);
}

static void do_write_page(struct f2fs_summary *sum, struct f2fs_io_info *fio)
{
	int type = __get_segment_type(fio->page, fio->type); // 获取这个data page是hot或者cold
	allocate_data_block(fio->sbi, fio->page, fio->old_blkaddr, &fio->new_blkaddr, sum, type); // 分配一个新的data block
	/* writeout dirty page into bdev */
	f2fs_submit_page_mbio(fio);
}

void write_meta_page(struct f2fs_sb_info *sbi, struct page *page)
{
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = META,
		.rw = WRITE_SYNC | REQ_META | REQ_PRIO,
		.old_blkaddr = page->index,
		.new_blkaddr = page->index,
		.page = page,
		.encrypted_page = NULL,
	};

	if (unlikely(page->index >= MAIN_BLKADDR(sbi)))
		fio.rw &= ~REQ_META;

	set_page_writeback(page);
	f2fs_submit_page_mbio(&fio);
}

void write_node_page(unsigned int nid, struct f2fs_io_info *fio)
{
	struct f2fs_summary sum;

	set_summary(&sum, nid, 0, 0);
	do_write_page(&sum, fio);
}

/*
 * 写一个data page到data block中
 * */
void write_data_page(struct dnode_of_data *dn, struct f2fs_io_info *fio)
{
	struct f2fs_sb_info *sbi = fio->sbi;
	struct f2fs_summary sum;
	struct node_info ni;

	f2fs_bug_on(sbi, dn->data_blkaddr == NULL_ADDR);
	get_node_info(sbi, dn->nid, &ni); // 获取这个page所在的node的info
	set_summary(&sum, dn->nid, dn->ofs_in_node, ni.version); // 初始化一个summary
	do_write_page(&sum, fio);
	f2fs_update_data_blkaddr(dn, fio->new_blkaddr); // 更新node里面的block地址，包括设置为dirty，等待node的信息写回
}

/*
 * 更新数据的模式
 * */
void rewrite_data_page(struct f2fs_io_info *fio)
{
	fio->new_blkaddr = fio->old_blkaddr; // 直接使用旧数据的blkaddr，在这个block更新
	stat_inc_inplace_blocks(fio->sbi);
	f2fs_submit_page_mbio(fio);
}

void __f2fs_replace_block(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
				block_t old_blkaddr, block_t new_blkaddr,
				bool recover_curseg, bool recover_newaddr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *curseg;
	unsigned int segno, old_cursegno;
	struct seg_entry *se;
	int type;
	unsigned short old_blkoff;

	segno = GET_SEGNO(sbi, new_blkaddr);
	se = get_seg_entry(sbi, segno);
	type = se->type;

	if (!recover_curseg) {
		/* for recovery flow */
		if (se->valid_blocks == 0 && !IS_CURSEG(sbi, segno)) {
			if (old_blkaddr == NULL_ADDR)
				type = CURSEG_COLD_DATA;
			else
				type = CURSEG_WARM_DATA;
		}
	} else {
		if (!IS_CURSEG(sbi, segno))
			type = CURSEG_WARM_DATA;
	}

	curseg = CURSEG_I(sbi, type);

	mutex_lock(&curseg->curseg_mutex);
	mutex_lock(&sit_i->sentry_lock);

	old_cursegno = curseg->segno;
	old_blkoff = curseg->next_blkoff;

	/* change the current segment */
	if (segno != curseg->segno) {
		curseg->next_segno = segno;
		change_curseg(sbi, type, true);
	}

	curseg->next_blkoff = GET_BLKOFF_FROM_SEG0(sbi, new_blkaddr);
	__add_sum_entry(sbi, type, sum);

	if (!recover_curseg || recover_newaddr)
		update_sit_entry(sbi, new_blkaddr, 1);
	if (GET_SEGNO(sbi, old_blkaddr) != NULL_SEGNO)
		update_sit_entry(sbi, old_blkaddr, -1);

	locate_dirty_segment(sbi, GET_SEGNO(sbi, old_blkaddr));
	locate_dirty_segment(sbi, GET_SEGNO(sbi, new_blkaddr));

	locate_dirty_segment(sbi, old_cursegno);

	if (recover_curseg) {
		if (old_cursegno != curseg->segno) {
			curseg->next_segno = old_cursegno;
			change_curseg(sbi, type, true);
		}
		curseg->next_blkoff = old_blkoff;
	}

	mutex_unlock(&sit_i->sentry_lock);
	mutex_unlock(&curseg->curseg_mutex);
}

void f2fs_replace_block(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
				block_t old_addr, block_t new_addr,
				unsigned char version, bool recover_curseg,
				bool recover_newaddr)
{
	struct f2fs_summary sum;

	set_summary(&sum, dn->nid, dn->ofs_in_node, version);

	__f2fs_replace_block(sbi, &sum, old_addr, new_addr,
					recover_curseg, recover_newaddr);

	f2fs_update_data_blkaddr(dn, new_addr);
}

/*
 * 等待这个页写回
 * */
void f2fs_wait_on_page_writeback(struct page *page, enum page_type type, bool ordered)
{
	if (PageWriteback(page)) { // 如果页面有page writeback标志，一般不会直接设置writeback表示，一般设置为dirty然后等待writeback机制设置上writeback标志
		struct f2fs_sb_info *sbi = F2FS_P_SB(page);

		f2fs_submit_merged_bio_cond(sbi, NULL, page, 0, type, WRITE); // 提交sbi里面的部分信息
		if (ordered)
			wait_on_page_writeback(page); // 进行页回写完成
		else
			wait_for_stable_page(page);
	}
}

void f2fs_wait_on_encrypted_page_writeback(struct f2fs_sb_info *sbi,
							block_t blkaddr)
{
	struct page *cpage;

	if (blkaddr == NEW_ADDR)
		return;

	f2fs_bug_on(sbi, blkaddr == NULL_ADDR);

	cpage = find_lock_page(META_MAPPING(sbi), blkaddr);
	if (cpage) {
		f2fs_wait_on_page_writeback(cpage, DATA, true);
		f2fs_put_page(cpage, 1);
	}
}

static int read_compacted_summaries(struct f2fs_sb_info *sbi)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct curseg_info *seg_i;
	unsigned char *kaddr;
	struct page *page;
	block_t start;
	int i, j, offset;

	start = start_sum_block(sbi);

	page = get_meta_page(sbi, start++);
	kaddr = (unsigned char *)page_address(page);

	/* Step 1: restore nat cache */
	seg_i = CURSEG_I(sbi, CURSEG_HOT_DATA);
	memcpy(seg_i->journal, kaddr, SUM_JOURNAL_SIZE);

	/* Step 2: restore sit cache */
	seg_i = CURSEG_I(sbi, CURSEG_COLD_DATA);
	memcpy(seg_i->journal, kaddr + SUM_JOURNAL_SIZE, SUM_JOURNAL_SIZE);
	offset = 2 * SUM_JOURNAL_SIZE;

	/* Step 3: restore summary entries */
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		unsigned short blk_off;
		unsigned int segno;

		seg_i = CURSEG_I(sbi, i);
		segno = le32_to_cpu(ckpt->cur_data_segno[i]);
		blk_off = le16_to_cpu(ckpt->cur_data_blkoff[i]);
		seg_i->next_segno = segno;
		reset_curseg(sbi, i, 0);
		seg_i->alloc_type = ckpt->alloc_type[i];
		seg_i->next_blkoff = blk_off;

		if (seg_i->alloc_type == SSR)
			blk_off = sbi->blocks_per_seg;

		for (j = 0; j < blk_off; j++) {
			struct f2fs_summary *s;
			s = (struct f2fs_summary *)(kaddr + offset);
			seg_i->sum_blk->entries[j] = *s;
			offset += SUMMARY_SIZE;
			if (offset + SUMMARY_SIZE <= PAGE_CACHE_SIZE -
						SUM_FOOTER_SIZE)
				continue;

			f2fs_put_page(page, 1);
			page = NULL;

			page = get_meta_page(sbi, start++);
			kaddr = (unsigned char *)page_address(page);
			offset = 0;
		}
	}
	f2fs_put_page(page, 1);
	return 0;
}

static int read_normal_summaries(struct f2fs_sb_info *sbi, int type)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct f2fs_summary_block *sum;
	struct curseg_info *curseg;
	struct page *new;
	unsigned short blk_off;
	unsigned int segno = 0;
	block_t blk_addr = 0;

	/* get segment number and block addr */
	if (IS_DATASEG(type)) {
		segno = le32_to_cpu(ckpt->cur_data_segno[type]);
		blk_off = le16_to_cpu(ckpt->cur_data_blkoff[type -
							CURSEG_HOT_DATA]);
		if (__exist_node_summaries(sbi))
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_TYPE, type);
		else
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_DATA_TYPE, type);
	} else {
		segno = le32_to_cpu(ckpt->cur_node_segno[type -
							CURSEG_HOT_NODE]);
		blk_off = le16_to_cpu(ckpt->cur_node_blkoff[type -
							CURSEG_HOT_NODE]);
		if (__exist_node_summaries(sbi))
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_NODE_TYPE,
							type - CURSEG_HOT_NODE);
		else
			blk_addr = GET_SUM_BLOCK(sbi, segno);
	}

	new = get_meta_page(sbi, blk_addr);
	sum = (struct f2fs_summary_block *)page_address(new);

	if (IS_NODESEG(type)) {
		if (__exist_node_summaries(sbi)) {
			struct f2fs_summary *ns = &sum->entries[0];
			int i;
			for (i = 0; i < sbi->blocks_per_seg; i++, ns++) {
				ns->version = 0;
				ns->ofs_in_node = 0;
			}
		} else {
			int err;

			err = restore_node_summary(sbi, segno, sum);
			if (err) {
				f2fs_put_page(new, 1);
				return err;
			}
		}
	}

	/* set uncompleted segment to curseg */
	curseg = CURSEG_I(sbi, type);
	mutex_lock(&curseg->curseg_mutex);

	/* update journal info */
	down_write(&curseg->journal_rwsem);
	memcpy(curseg->journal, &sum->journal, SUM_JOURNAL_SIZE);
	up_write(&curseg->journal_rwsem);

	memcpy(curseg->sum_blk->entries, sum->entries, SUM_ENTRY_SIZE);
	memcpy(&curseg->sum_blk->footer, &sum->footer, SUM_FOOTER_SIZE);
	curseg->next_segno = segno;
	reset_curseg(sbi, type, 0);
	curseg->alloc_type = ckpt->alloc_type[type];
	curseg->next_blkoff = blk_off;
	mutex_unlock(&curseg->curseg_mutex);
	f2fs_put_page(new, 1);
	return 0;
}

static int restore_curseg_summaries(struct f2fs_sb_info *sbi)
{
	int type = CURSEG_HOT_DATA;
	int err;

	if (is_set_ckpt_flags(F2FS_CKPT(sbi), CP_COMPACT_SUM_FLAG)) {
		int npages = npages_for_summary_flush(sbi, true);

		if (npages >= 2)
			ra_meta_pages(sbi, start_sum_block(sbi), npages,
							META_CP, true);

		/* restore for compacted data summary */
		if (read_compacted_summaries(sbi))
			return -EINVAL;
		type = CURSEG_HOT_NODE;
	}

	if (__exist_node_summaries(sbi))
		ra_meta_pages(sbi, sum_blk_addr(sbi, NR_CURSEG_TYPE, type),
					NR_CURSEG_TYPE - type, META_CP, true);

	for (; type <= CURSEG_COLD_NODE; type++) {
		err = read_normal_summaries(sbi, type);
		if (err)
			return err;
	}

	return 0;
}

static void write_compacted_summaries(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct page *page;
	unsigned char *kaddr;
	struct f2fs_summary *summary;
	struct curseg_info *seg_i;
	int written_size = 0;
	int i, j;

	page = grab_meta_page(sbi, blkaddr++);
	kaddr = (unsigned char *)page_address(page);

	/* Step 1: write nat cache */
	seg_i = CURSEG_I(sbi, CURSEG_HOT_DATA);
	memcpy(kaddr, seg_i->journal, SUM_JOURNAL_SIZE);
	written_size += SUM_JOURNAL_SIZE;

	/* Step 2: write sit cache */
	seg_i = CURSEG_I(sbi, CURSEG_COLD_DATA);
	memcpy(kaddr + written_size, seg_i->journal, SUM_JOURNAL_SIZE);
	written_size += SUM_JOURNAL_SIZE;

	/* Step 3: write summary entries */
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		unsigned short blkoff;
		seg_i = CURSEG_I(sbi, i);
		if (sbi->ckpt->alloc_type[i] == SSR)
			blkoff = sbi->blocks_per_seg;
		else
			blkoff = curseg_blkoff(sbi, i);

		for (j = 0; j < blkoff; j++) {
			if (!page) {
				page = grab_meta_page(sbi, blkaddr++);
				kaddr = (unsigned char *)page_address(page);
				written_size = 0;
			}
			summary = (struct f2fs_summary *)(kaddr + written_size);
			*summary = seg_i->sum_blk->entries[j];
			written_size += SUMMARY_SIZE;

			if (written_size + SUMMARY_SIZE <= PAGE_CACHE_SIZE -
							SUM_FOOTER_SIZE)
				continue;

			set_page_dirty(page);
			f2fs_put_page(page, 1);
			page = NULL;
		}
	}
	if (page) {
		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}
}

static void write_normal_summaries(struct f2fs_sb_info *sbi,
					block_t blkaddr, int type)
{
	int i, end;
	if (IS_DATASEG(type))
		end = type + NR_CURSEG_DATA_TYPE;
	else
		end = type + NR_CURSEG_NODE_TYPE;

	for (i = type; i < end; i++)
		write_current_sum_page(sbi, i, blkaddr + (i - type));
}

void write_data_summaries(struct f2fs_sb_info *sbi, block_t start_blk)
{
	if (is_set_ckpt_flags(F2FS_CKPT(sbi), CP_COMPACT_SUM_FLAG))
		write_compacted_summaries(sbi, start_blk);
	else
		write_normal_summaries(sbi, start_blk, CURSEG_HOT_DATA);
}

void write_node_summaries(struct f2fs_sb_info *sbi, block_t start_blk)
{
	write_normal_summaries(sbi, start_blk, CURSEG_HOT_NODE);
}

/*
 * 搜索当前的journal区域满足特定要求的entry，如果缓存了则返回index，如果没缓存那么可以直接返回或者创建，
 * 其目的在于将修改后的信息放置在内存，等待checkpoint的时候再写入到磁盘当中
 * */
int lookup_journal_in_cursum(struct f2fs_journal *journal, int type,
					unsigned int val, int alloc)
{
	int i;

	if (type == NAT_JOURNAL) {
		for (i = 0; i < nats_in_cursum(journal); i++) {
			if (le32_to_cpu(nid_in_journal(journal, i)) == val) // 如果找到了，那么返回该nid对应的node在nat中的entry的id
				return i;
		}
		if (alloc && __has_cursum_space(journal, 1, NAT_JOURNAL))
			return update_nats_in_cursum(journal, 1);
	} else if (type == SIT_JOURNAL) {
		for (i = 0; i < sits_in_cursum(journal); i++)
			if (le32_to_cpu(segno_in_journal(journal, i)) == val)
				return i;
		if (alloc && __has_cursum_space(journal, 1, SIT_JOURNAL))
			return update_sits_in_cursum(journal, 1);
	}
	return -1;
}

static struct page *get_current_sit_page(struct f2fs_sb_info *sbi,
					unsigned int segno)
{
	return get_meta_page(sbi, current_sit_addr(sbi, segno));
}

static struct page *get_next_sit_page(struct f2fs_sb_info *sbi,
					unsigned int start)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct page *src_page, *dst_page;
	pgoff_t src_off, dst_off;
	void *src_addr, *dst_addr;

	src_off = current_sit_addr(sbi, start);
	dst_off = next_sit_addr(sbi, src_off);

	/* get current sit block page without lock */
	src_page = get_meta_page(sbi, src_off);
	dst_page = grab_meta_page(sbi, dst_off);
	f2fs_bug_on(sbi, PageDirty(src_page));

	src_addr = page_address(src_page);
	dst_addr = page_address(dst_page);
	memcpy(dst_addr, src_addr, PAGE_CACHE_SIZE);

	set_page_dirty(dst_page);
	f2fs_put_page(src_page, 1);

	set_to_next_sit(sit_i, start);

	return dst_page;
}

static struct sit_entry_set *grab_sit_entry_set(void)
{
	struct sit_entry_set *ses =
			f2fs_kmem_cache_alloc(sit_entry_set_slab, GFP_NOFS);

	ses->entry_cnt = 0;
	INIT_LIST_HEAD(&ses->set_list);
	return ses;
}

static void release_sit_entry_set(struct sit_entry_set *ses)
{
	list_del(&ses->set_list);
	kmem_cache_free(sit_entry_set_slab, ses);
}

static void adjust_sit_entry_set(struct sit_entry_set *ses,
						struct list_head *head)
{
	struct sit_entry_set *next = ses;

	if (list_is_last(&ses->set_list, head))
		return;

	list_for_each_entry_continue(next, head, set_list)
		if (ses->entry_cnt <= next->entry_cnt)
			break;

	list_move_tail(&ses->set_list, &next->set_list);
}

static void add_sit_entry(unsigned int segno, struct list_head *head)
{
	struct sit_entry_set *ses;
	unsigned int start_segno = START_SEGNO(segno); // 这个start_segno指的是管理segno的seg_entry开始的第一个segment号，其实就是segment entry的地址

	list_for_each_entry(ses, head, set_list) { // 如果已经存在了就不加入
		if (ses->start_segno == start_segno) {
			ses->entry_cnt++;
			adjust_sit_entry_set(ses, head);
			return;
		}
	}

	ses = grab_sit_entry_set();

	ses->start_segno = start_segno;
	ses->entry_cnt++;
	list_add(&ses->set_list, head);
}

/*
 * 将dirty segment对应的segment entry加入到sit_entry_set
 * */
static void add_sits_in_set(struct f2fs_sb_info *sbi)
{
	struct f2fs_sm_info *sm_info = SM_I(sbi);
	struct list_head *set_list = &sm_info->sit_entry_set;
	unsigned long *bitmap = SIT_I(sbi)->dirty_sentries_bitmap;
	unsigned int segno;

	for_each_set_bit(segno, bitmap, MAIN_SEGS(sbi)) // 循环bit map里面所有是1的bitmap
		add_sit_entry(segno, set_list); // 将dirty的segment加入到dirty list
}

/*
 * 将journal的所有sits转移到sit_info->dirty_sentries_bitmap，然后清空journal的所有sit信息
 * */
static void remove_sits_in_journal(struct f2fs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	struct f2fs_journal *journal = curseg->journal;
	int i;

	down_write(&curseg->journal_rwsem);
	// 循环journal里面所有的sit_entry
	for (i = 0; i < sits_in_cursum(journal); i++) {
		unsigned int segno;
		bool dirtied;

		segno = le32_to_cpu(segno_in_journal(journal, i));
		dirtied = __mark_sit_entry_dirty(sbi, segno); //将这个segno设置为脏，在sbi对应的位置增加标志和个数

		// 然后加入到sit_entry_set中
		if (!dirtied)
			add_sit_entry(segno, &SM_I(sbi)->sit_entry_set);
	}
	update_sits_in_cursum(journal, -i); // 减少journal对应的个数
	up_write(&curseg->journal_rwsem);
}

/*
 * CP calls this function, which flushes SIT entries including sit_journal,
 * and moves prefree segs to free segs.
 *
 * 处理sit table的journal信息，将他们刷写到磁盘中
 *
 */
void flush_sit_entries(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned long *bitmap = sit_i->dirty_sentries_bitmap; // dirtry segment entries bitmap
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	struct f2fs_journal *journal = curseg->journal;
	struct sit_entry_set *ses, *tmp;
	struct list_head *head = &SM_I(sbi)->sit_entry_set; // entry set head
	bool to_journal = true;
	struct seg_entry *se;

	mutex_lock(&sit_i->sentry_lock);

	if (!sit_i->dirty_sentries) // dirty entires > 0
		goto out;

	/*
	 * add and account sit entries of dirty bitmap in sit entry
	 * set temporarily
	 * 将dirty segment对应的segment entry加入到sbi->sit_entry_set
	 */
	add_sits_in_set(sbi);

	/*
	 * if there are no enough space in journal to store dirty sit
	 * entries, remove all entries from journal and add and account
	 * them in sit entry set.
	 * 如果journal已经没空间去存储新的dirty_entries
	 * 清除所有在journal里面sit信息，主要是转移到sbi->sit_i中
	 */
	if (!__has_cursum_space(journal, sit_i->dirty_sentries, SIT_JOURNAL))
		remove_sits_in_journal(sbi);

	/*
	 * there are two steps to flush sit entries:
	 * #1, flush sit entries to journal in current cold data summary block.
	 * #2, flush sit entries to sit page.
	 * 遍历set_list所有的sit_entry，然后
	 */
	list_for_each_entry_safe(ses, tmp, head, set_list) {
		struct page *page = NULL;
		struct f2fs_sit_block *raw_sit = NULL; // 包含多个segment entry
		unsigned int start_segno = ses->start_segno; // 也是sit_entry的index
		unsigned int end = min(start_segno + SIT_ENTRY_PER_BLOCK,
						(unsigned long)MAIN_SEGS(sbi));
		unsigned int segno = start_segno;

		if (to_journal && !__has_cursum_space(journal, ses->entry_cnt, SIT_JOURNAL)) // 如果journal没有足够空间
			to_journal = false;

		if (to_journal) {
			down_write(&curseg->journal_rwsem);
		} else {
			page = get_next_sit_page(sbi, start_segno); // 获取到f2fs_sit_block对应的page
			raw_sit = page_address(page); // 将其转换为f2fs_sit_block的格式
		}

		/*
		 * flush dirty sit entries in region of current sit set
		 * 遍历sit里面的dirty map
		 * */
		for_each_set_bit_from(segno, bitmap, end) {
			int offset, sit_offset;

			se = get_seg_entry(sbi, segno);

			/*
			 * add discard candidates
			 * 如果不是trim模式，就将需要trim的segment加入
			 * */
			if (cpc->reason != CP_DISCARD) {
				cpc->trim_start = segno;
				add_discard_addrs(sbi, cpc); // 将当前checkpoint包含的trim信息，加入到SM_I(sbi)->discard_list链表中
			}

			if (to_journal) { // 如果没有足够的journal空间了
				offset = lookup_journal_in_cursum(journal, SIT_JOURNAL, segno, 1);
				f2fs_bug_on(sbi, offset < 0);
				segno_in_journal(journal, offset) = cpu_to_le32(segno);
				seg_info_to_raw_sit(se, &sit_in_journal(journal, offset));
			} else {
				sit_offset = SIT_ENTRY_OFFSET(sit_i, segno);
				seg_info_to_raw_sit(se, &raw_sit->entries[sit_offset]);
			}

			__clear_bit(segno, bitmap);
			sit_i->dirty_sentries--;
			ses->entry_cnt--;
		}

		if (to_journal)
			up_write(&curseg->journal_rwsem);
		else
			f2fs_put_page(page, 1);

		f2fs_bug_on(sbi, ses->entry_cnt);
		release_sit_entry_set(ses);
	}

	f2fs_bug_on(sbi, !list_empty(head));
	f2fs_bug_on(sbi, sit_i->dirty_sentries);
out:
	if (cpc->reason == CP_DISCARD) {
		for (; cpc->trim_start <= cpc->trim_end; cpc->trim_start++)
			add_discard_addrs(sbi, cpc);
	}
	mutex_unlock(&sit_i->sentry_lock);

	set_prefree_as_free_segments(sbi);
}

static int build_sit_info(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct sit_info *sit_i;
	unsigned int sit_segs, start;
	char *src_bitmap, *dst_bitmap;
	unsigned int bitmap_size;

	/* allocate memory for SIT information */
	sit_i = kzalloc(sizeof(struct sit_info), GFP_KERNEL); // 初始化sit结构
	if (!sit_i)
		return -ENOMEM;

	SM_I(sbi)->sit_info = sit_i;

	sit_i->sentries = f2fs_kvzalloc(MAIN_SEGS(sbi) * sizeof(struct seg_entry), GFP_KERNEL); // 创建segment entries缓存

	if (!sit_i->sentries)
		return -ENOMEM;

	bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));  //单位字节
	sit_i->dirty_sentries_bitmap = f2fs_kvzalloc(bitmap_size, GFP_KERNEL);
	if (!sit_i->dirty_sentries_bitmap)
		return -ENOMEM;

	for (start = 0; start < MAIN_SEGS(sbi); start++) { // 给main_area区域的segment建立实例
		sit_i->sentries[start].cur_valid_map           // 每一个segment管理64个map
			= kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
		sit_i->sentries[start].ckpt_valid_map
			= kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
		sit_i->sentries[start].discard_map
			= kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
		if (!sit_i->sentries[start].cur_valid_map ||
				!sit_i->sentries[start].ckpt_valid_map ||
				!sit_i->sentries[start].discard_map)
			return -ENOMEM;
	}

	sit_i->tmp_map = kzalloc(SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
	if (!sit_i->tmp_map)
		return -ENOMEM;

	if (sbi->segs_per_sec > 1) {
		sit_i->sec_entries = f2fs_kvzalloc(MAIN_SECS(sbi) *
					sizeof(struct sec_entry), GFP_KERNEL);
		if (!sit_i->sec_entries)
			return -ENOMEM;
	}

	/* get information related with SIT */
	sit_segs = le32_to_cpu(raw_super->segment_count_sit) >> 1;

	/* setup SIT bitmap from ckeckpoint pack */
	bitmap_size = __bitmap_size(sbi, SIT_BITMAP);
	src_bitmap = __bitmap_ptr(sbi, SIT_BITMAP);

	dst_bitmap = kmemdup(src_bitmap, bitmap_size, GFP_KERNEL);
	if (!dst_bitmap)
		return -ENOMEM;

	/* init SIT information */
	sit_i->s_ops = &default_salloc_ops;

	sit_i->sit_base_addr = le32_to_cpu(raw_super->sit_blkaddr);
	sit_i->sit_blocks = sit_segs << sbi->log_blocks_per_seg;
	sit_i->written_valid_blocks = le64_to_cpu(ckpt->valid_block_count);
	sit_i->sit_bitmap = dst_bitmap;
	sit_i->bitmap_size = bitmap_size;
	sit_i->dirty_sentries = 0;
	sit_i->sents_per_block = SIT_ENTRY_PER_BLOCK;
	sit_i->elapsed_time = le64_to_cpu(sbi->ckpt->elapsed_time);
	sit_i->mounted_time = CURRENT_TIME_SEC.tv_sec;
	mutex_init(&sit_i->sentry_lock);
	return 0;
}

static int build_free_segmap(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i;
	unsigned int bitmap_size, sec_bitmap_size;

	/* allocate memory for free segmap information */
	free_i = kzalloc(sizeof(struct free_segmap_info), GFP_KERNEL);
	if (!free_i)
		return -ENOMEM;

	SM_I(sbi)->free_info = free_i;

	bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));
	free_i->free_segmap = f2fs_kvmalloc(bitmap_size, GFP_KERNEL);
	if (!free_i->free_segmap)
		return -ENOMEM;

	sec_bitmap_size = f2fs_bitmap_size(MAIN_SECS(sbi));
	free_i->free_secmap = f2fs_kvmalloc(sec_bitmap_size, GFP_KERNEL);
	if (!free_i->free_secmap)
		return -ENOMEM;

	/* set all segments as dirty temporarily */
	memset(free_i->free_segmap, 0xff, bitmap_size); // 设置所有的segment为dirty
	memset(free_i->free_secmap, 0xff, sec_bitmap_size); // 设置所有的section为dirty

	/* init free segmap information */
	free_i->start_segno = GET_SEGNO_FROM_SEG0(sbi, MAIN_BLKADDR(sbi));
	free_i->free_segments = 0;
	free_i->free_sections = 0;
	spin_lock_init(&free_i->segmap_lock);
	return 0;
}

static int build_curseg(struct f2fs_sb_info *sbi)
{
	struct curseg_info *array;
	int i;

	array = kcalloc(NR_CURSEG_TYPE, sizeof(*array), GFP_KERNEL); // 分配长度是  NR_CURSEG_TYPE * sizeof(*array) = 6
	if (!array)
		return -ENOMEM;

	SM_I(sbi)->curseg_array = array;

	for (i = 0; i < NR_CURSEG_TYPE; i++) { // (HOW,WARM,COLD) x (DATA,NODE)  6 types of blocks in total
		mutex_init(&array[i].curseg_mutex);
		array[i].sum_blk = kzalloc(PAGE_CACHE_SIZE, GFP_KERNEL); // 分配一个block空间
		if (!array[i].sum_blk)
			return -ENOMEM;
		init_rwsem(&array[i].journal_rwsem);
		array[i].journal = kzalloc(sizeof(struct f2fs_journal), GFP_KERNEL); // 初始化f2fs_journal
		if (!array[i].journal)
			return -ENOMEM;
		array[i].segno = NULL_SEGNO; // 当前的segment number
		array[i].next_blkoff = 0;
	}
	return restore_curseg_summaries(sbi);
}

/*
 * 构建所有sit entry
 * */
static void build_sit_entries(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	struct f2fs_journal *journal = curseg->journal;
	int sit_blk_cnt = SIT_BLK_CNT(sbi);
	unsigned int i, start, end;
	unsigned int readed, start_blk = 0;
	int nrpages = MAX_BIO_BLOCKS(sbi) * 8;

	do {
		readed = ra_meta_pages(sbi, start_blk, nrpages, META_SIT, true);

		start = start_blk * sit_i->sents_per_block;
		end = (start_blk + readed) * sit_i->sents_per_block;

		for (; start < end && start < MAIN_SEGS(sbi); start++) {
			struct seg_entry *se = &sit_i->sentries[start];
			struct f2fs_sit_block *sit_blk;
			struct f2fs_sit_entry sit;
			struct page *page;

			down_read(&curseg->journal_rwsem);
			for (i = 0; i < sits_in_cursum(journal); i++) {
				if (le32_to_cpu(segno_in_journal(journal, i))
								== start) {
					sit = sit_in_journal(journal, i);
					up_read(&curseg->journal_rwsem);
					goto got_it;
				}
			}
			up_read(&curseg->journal_rwsem);

			page = get_current_sit_page(sbi, start);
			sit_blk = (struct f2fs_sit_block *)page_address(page);
			sit = sit_blk->entries[SIT_ENTRY_OFFSET(sit_i, start)];
			f2fs_put_page(page, 1);
got_it:
			check_block_count(sbi, start, &sit);
			seg_info_from_raw_sit(se, &sit);

			/* build discard map only one time */
			memcpy(se->discard_map, se->cur_valid_map, SIT_VBLOCK_MAP_SIZE);
			sbi->discard_blks += sbi->blocks_per_seg - se->valid_blocks;

			if (sbi->segs_per_sec > 1) {
				struct sec_entry *e = get_sec_entry(sbi, start);
				e->valid_blocks += se->valid_blocks;
			}
		}
		start_blk += readed;
	} while (start_blk < sit_blk_cnt);
}

static void init_free_segmap(struct f2fs_sb_info *sbi)
{
	unsigned int start;
	int type;

	for (start = 0; start < MAIN_SEGS(sbi); start++) {
		struct seg_entry *sentry = get_seg_entry(sbi, start);
		if (!sentry->valid_blocks)
			__set_free(sbi, start);
	}

	/* set use the current segments */
	for (type = CURSEG_HOT_DATA; type <= CURSEG_COLD_NODE; type++) {
		struct curseg_info *curseg_t = CURSEG_I(sbi, type);
		__set_test_and_inuse(sbi, curseg_t->segno);
	}
}

static void init_dirty_segmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int segno = 0, offset = 0;
	unsigned short valid_blocks;

	while (1) {
		/* find dirty segment based on free segmap */
		segno = find_next_inuse(free_i, MAIN_SEGS(sbi), offset);
		if (segno >= MAIN_SEGS(sbi))
			break;
		offset = segno + 1;
		valid_blocks = get_valid_blocks(sbi, segno, 0);
		if (valid_blocks == sbi->blocks_per_seg || !valid_blocks)
			continue;
		if (valid_blocks > sbi->blocks_per_seg) {
			f2fs_bug_on(sbi, 1);
			continue;
		}
		mutex_lock(&dirty_i->seglist_lock);
		__locate_dirty_segment(sbi, segno, DIRTY);
		mutex_unlock(&dirty_i->seglist_lock);
	}
}

static int init_victim_secmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int bitmap_size = f2fs_bitmap_size(MAIN_SECS(sbi));

	dirty_i->victim_secmap = f2fs_kvzalloc(bitmap_size, GFP_KERNEL);
	if (!dirty_i->victim_secmap)
		return -ENOMEM;
	return 0;
}

static int build_dirty_segmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i;
	unsigned int bitmap_size, i;

	/* allocate memory for dirty segments list information */
	dirty_i = kzalloc(sizeof(struct dirty_seglist_info), GFP_KERNEL);
	if (!dirty_i)
		return -ENOMEM;

	SM_I(sbi)->dirty_info = dirty_i;
	mutex_init(&dirty_i->seglist_lock);

	bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));

	for (i = 0; i < NR_DIRTY_TYPE; i++) {
		dirty_i->dirty_segmap[i] = f2fs_kvzalloc(bitmap_size, GFP_KERNEL);
		if (!dirty_i->dirty_segmap[i])
			return -ENOMEM;
	}

	init_dirty_segmap(sbi);
	return init_victim_secmap(sbi);
}

/*
 * Update min, max modified time for cost-benefit GC algorithm
 */
static void init_min_max_mtime(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int segno;

	mutex_lock(&sit_i->sentry_lock);

	sit_i->min_mtime = LLONG_MAX;

	for (segno = 0; segno < MAIN_SEGS(sbi); segno += sbi->segs_per_sec) {
		unsigned int i;
		unsigned long long mtime = 0;

		for (i = 0; i < sbi->segs_per_sec; i++)
			mtime += get_seg_entry(sbi, segno + i)->mtime;

		mtime = div_u64(mtime, sbi->segs_per_sec);

		if (sit_i->min_mtime > mtime)
			sit_i->min_mtime = mtime;
	}
	sit_i->max_mtime = get_mtime(sbi);
	mutex_unlock(&sit_i->sentry_lock);
}

int build_segment_manager(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct f2fs_sm_info *sm_info;
	int err;

	sm_info = kzalloc(sizeof(struct f2fs_sm_info), GFP_KERNEL); // 分配老婆目光看哦阿美
	if (!sm_info)
		return -ENOMEM;

	/* init sm info
	 * 初始化f2fs_sm_info一些参数
	 * segment的块起始点，大小之类的
	 * */
	sbi->sm_info = sm_info;
	sm_info->seg0_blkaddr = le32_to_cpu(raw_super->segment0_blkaddr);
	sm_info->main_blkaddr = le32_to_cpu(raw_super->main_blkaddr);
	sm_info->segment_count = le32_to_cpu(raw_super->segment_count);
	sm_info->reserved_segments = le32_to_cpu(ckpt->rsvd_segment_count);
	sm_info->ovp_segments = le32_to_cpu(ckpt->overprov_segment_count);
	sm_info->main_segments = le32_to_cpu(raw_super->segment_count_main);
	sm_info->ssa_blkaddr = le32_to_cpu(raw_super->ssa_blkaddr);
	sm_info->rec_prefree_segments = sm_info->main_segments *
					DEF_RECLAIM_PREFREE_SEGMENTS / 100;
	sm_info->ipu_policy = 1 << F2FS_IPU_FSYNC;
	sm_info->min_ipu_util = DEF_MIN_IPU_UTIL;
	sm_info->min_fsync_blocks = DEF_MIN_FSYNC_BLOCKS;

	INIT_LIST_HEAD(&sm_info->discard_list);
	sm_info->nr_discards = 0;
	sm_info->max_discards = 0;

	sm_info->trim_sections = DEF_BATCHED_TRIM_SECTIONS;

	INIT_LIST_HEAD(&sm_info->sit_entry_set);

	if (test_opt(sbi, FLUSH_MERGE) && !f2fs_readonly(sbi->sb)) {
		err = create_flush_cmd_control(sbi);
		if (err)
			return err;
	}

	err = build_sit_info(sbi); // 构建segment info table
	if (err)
		return err;
	err = build_free_segmap(sbi); // 主要是创建segment的bitmap
	if (err)
		return err;
	err = build_curseg(sbi); // 构建curseg_info，然后完成current segment的恢复
	if (err)
		return err;

	/* reinit free segmap based on SIT */
	build_sit_entries(sbi); //恢复所有的segment_entry和section_segment

	init_free_segmap(sbi); // 恢复所有free_segmap和free_secmap
	err = build_dirty_segmap(sbi); // 构建dirty_seglist_info
	if (err)
		return err;

	init_min_max_mtime(sbi); // 修改时间
	return 0;
}

static void discard_dirty_segmap(struct f2fs_sb_info *sbi,
		enum dirty_type dirty_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	mutex_lock(&dirty_i->seglist_lock);
	kvfree(dirty_i->dirty_segmap[dirty_type]);
	dirty_i->nr_dirty[dirty_type] = 0;
	mutex_unlock(&dirty_i->seglist_lock);
}

static void destroy_victim_secmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	kvfree(dirty_i->victim_secmap);
}

static void destroy_dirty_segmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	int i;

	if (!dirty_i)
		return;

	/* discard pre-free/dirty segments list */
	for (i = 0; i < NR_DIRTY_TYPE; i++)
		discard_dirty_segmap(sbi, i);

	destroy_victim_secmap(sbi);
	SM_I(sbi)->dirty_info = NULL;
	kfree(dirty_i);
}

static void destroy_curseg(struct f2fs_sb_info *sbi)
{
	struct curseg_info *array = SM_I(sbi)->curseg_array;
	int i;

	if (!array)
		return;
	SM_I(sbi)->curseg_array = NULL;
	for (i = 0; i < NR_CURSEG_TYPE; i++) {
		kfree(array[i].sum_blk);
		kfree(array[i].journal);
	}
	kfree(array);
}

static void destroy_free_segmap(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i = SM_I(sbi)->free_info;
	if (!free_i)
		return;
	SM_I(sbi)->free_info = NULL;
	kvfree(free_i->free_segmap);
	kvfree(free_i->free_secmap);
	kfree(free_i);
}

static void destroy_sit_info(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int start;

	if (!sit_i)
		return;

	if (sit_i->sentries) {
		for (start = 0; start < MAIN_SEGS(sbi); start++) {
			kfree(sit_i->sentries[start].cur_valid_map);
			kfree(sit_i->sentries[start].ckpt_valid_map);
			kfree(sit_i->sentries[start].discard_map);
		}
	}
	kfree(sit_i->tmp_map);

	kvfree(sit_i->sentries);
	kvfree(sit_i->sec_entries);
	kvfree(sit_i->dirty_sentries_bitmap);

	SM_I(sbi)->sit_info = NULL;
	kfree(sit_i->sit_bitmap);
	kfree(sit_i);
}

void destroy_segment_manager(struct f2fs_sb_info *sbi)
{
	struct f2fs_sm_info *sm_info = SM_I(sbi);

	if (!sm_info)
		return;
	destroy_flush_cmd_control(sbi);
	destroy_dirty_segmap(sbi);
	destroy_curseg(sbi);
	destroy_free_segmap(sbi);
	destroy_sit_info(sbi);
	sbi->sm_info = NULL;
	kfree(sm_info);
}

int __init create_segment_manager_caches(void)
{
	discard_entry_slab = f2fs_kmem_cache_create("discard_entry",
			sizeof(struct discard_entry));
	if (!discard_entry_slab)
		goto fail;

	sit_entry_set_slab = f2fs_kmem_cache_create("sit_entry_set",
			sizeof(struct sit_entry_set));
	if (!sit_entry_set_slab)
		goto destory_discard_entry;

	inmem_entry_slab = f2fs_kmem_cache_create("inmem_page_entry",
			sizeof(struct inmem_pages));
	if (!inmem_entry_slab)
		goto destroy_sit_entry_set;
	return 0;

destroy_sit_entry_set:
	kmem_cache_destroy(sit_entry_set_slab);
destory_discard_entry:
	kmem_cache_destroy(discard_entry_slab);
fail:
	return -ENOMEM;
}

void destroy_segment_manager_caches(void)
{
	kmem_cache_destroy(sit_entry_set_slab);
	kmem_cache_destroy(discard_entry_slab);
	kmem_cache_destroy(inmem_entry_slab);
}
