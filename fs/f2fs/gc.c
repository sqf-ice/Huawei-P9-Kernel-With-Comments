/*
 * fs/f2fs/gc.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/init.h>
#include <linux/f2fs_fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/freezer.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "gc.h"
#include <trace/events/f2fs.h>

/*
 * 核心gc线程
 * */
static int gc_thread_func(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct f2fs_gc_kthread *gc_th = sbi->gc_thread;
	wait_queue_head_t *wq = &sbi->gc_thread->gc_wait_queue_head;
	long wait_ms; //记录需要等待多久时间

	wait_ms = gc_th->min_sleep_time; // 30s

	do {
		if (try_to_freeze()){ // 系统准备进入休眠状态，例如 黑屏等操作
			continue;
		}else{
			// 睡眠,直到kthread_should_stop()为真，或msecs_to_jiffies(wait_ms)超时；
			wait_event_interruptible_timeout(*wq, kthread_should_stop(), msecs_to_jiffies(wait_ms));
		}
		if (kthread_should_stop())
			break;

		if (sbi->sb->s_writers.frozen >= SB_FREEZE_WRITE) { // 如果文件系统处于freeze状态
			increase_sleep_time(gc_th, &wait_ms); //增减gc休眠时间
			continue;
		}

		/*
		 * [GC triggering condition]
		 * 0. GC is not conducted currently.
		 * 1. There are enough dirty segments.
		 * 2. IO subsystem is idle by checking the # of writeback pages.
		 * 3. IO subsystem is idle by checking the # of requests in
		 *    bdev's request list.
		 *
		 * Note) We have to avoid triggering GCs frequently.
		 * Because it is possible that some segments can be
		 * invalidated soon after by user update or deletion.
		 * So, I'd like to wait some time to collect dirty segments.
		 */
		if (!mutex_trylock(&sbi->gc_mutex))
			continue;

		if (!is_idle(sbi)) { //如果不是idle状态
			increase_sleep_time(gc_th, &wait_ms); // 再增加一点等待时间
			mutex_unlock(&sbi->gc_mutex);
			continue;
		}

		if (has_enough_invalid_blocks(sbi)) // 如果有很多的无效block，减少gc的等待时间
			decrease_sleep_time(gc_th, &wait_ms);
		else
			increase_sleep_time(gc_th, &wait_ms);

		stat_inc_bggc_count(sbi);

#ifdef CONFIG_F2FS_STAT_FS
		extern int FG_GC_count;
		if ((FG_GC_count != 0) && ((sbi->bg_gc % 500) == 1)) {
			f2fs_msg(sbi->sb, KERN_WARNING,
			"BG_GC: Size=%lldMB,Free=%lldMB,count=%d,free_sec=%d,reserved_sec=%d,node_secs=%d,dent_secs=%d\n",
			(le64_to_cpu(sbi->user_block_count) * sbi->blocksize) /1024/1024,
			(le64_to_cpu(sbi->user_block_count - valid_user_blocks(sbi)) * sbi->blocksize) /1024/1024,
			sbi->bg_gc, free_sections(sbi), reserved_sections(sbi),
			get_blocktype_secs(sbi, F2FS_DIRTY_NODES), get_blocktype_secs(sbi, F2FS_DIRTY_DENTS));
		}
#endif
		/* if return value is not zero, no victim was selected */
		/*lint -save -e747*/
		/* 开始进行gc，如果gc失败了，那么就隔比较长时间再gc
		 * sbi, FORCE_FG_GC是挂载的时候选项，强迫fgc变为bgc，一般情况下是flase的
		 */
		if (f2fs_gc(sbi, test_opt(sbi, FORCE_FG_GC), true))
			wait_ms = gc_th->no_gc_sleep_time;
		/*lint -restore*/

		trace_f2fs_background_gc(sbi->sb, wait_ms, prefree_segments(sbi), free_segments(sbi));

		/* balancing f2fs's metadata periodically */
		f2fs_balance_fs_bg(sbi);

	} while (!kthread_should_stop());
	return 0;
}

int start_gc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_gc_kthread *gc_th;
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	int err = 0;

	gc_th = kmalloc(sizeof(struct f2fs_gc_kthread), GFP_KERNEL);
	if (!gc_th) {
		err = -ENOMEM;
		goto out;
	}

	gc_th->min_sleep_time = DEF_GC_THREAD_MIN_SLEEP_TIME;
	gc_th->max_sleep_time = DEF_GC_THREAD_MAX_SLEEP_TIME;
	gc_th->no_gc_sleep_time = DEF_GC_THREAD_NOGC_SLEEP_TIME;

	gc_th->gc_idle = 0;

	sbi->gc_thread = gc_th;
	init_waitqueue_head(&sbi->gc_thread->gc_wait_queue_head); // 加入系统调用队列
	sbi->gc_thread->f2fs_gc_task = kthread_run(gc_thread_func, sbi, "f2fs_gc-%u:%u", MAJOR(dev), MINOR(dev)); //启动内核线程
	if (IS_ERR(gc_th->f2fs_gc_task)) {
		err = PTR_ERR(gc_th->f2fs_gc_task);
		kfree(gc_th);
		sbi->gc_thread = NULL;
	}
out:
	return err;
}

void stop_gc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_gc_kthread *gc_th = sbi->gc_thread;
	if (!gc_th)
		return;
	kthread_stop(gc_th->f2fs_gc_task);
	kfree(gc_th);
	sbi->gc_thread = NULL;
}


/*
 * 如果
 * gc_type == BG_GC
 * */
static int select_gc_type(struct f2fs_gc_kthread *gc_th, int gc_type)
{
	int gc_mode = (gc_type == BG_GC) ? GC_CB : GC_GREEDY;

	if (gc_th && gc_th->gc_idle) {
		if (gc_th->gc_idle == 1)
			gc_mode = GC_CB;
		else if (gc_th->gc_idle == 2)
			gc_mode = GC_GREEDY;
	}
	return gc_mode;
}


/*
 * 选择使用哪个gc policy
 * SSR && FG_GC or BG_GC : GREEDY模式
 * LFS && BG_GC : COST BALANCE模式
 * LFS && FG_GC : GREEDY模式
 * 以上忽略了gc_thread的idle情形
 * */
static void select_policy(struct f2fs_sb_info *sbi, int gc_type,
			int type, struct victim_sel_policy *p)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (p->alloc_mode == SSR) {
		p->gc_mode = GC_GREEDY;
		p->dirty_segmap = dirty_i->dirty_segmap[type]; // 如果是NO_CHECK_TYPE，那么和DIRTY等效，都是第6个
		p->max_search = dirty_i->nr_dirty[type];
		p->ofs_unit = 1;
	} else {
		p->gc_mode = select_gc_type(sbi->gc_thread, gc_type);
		p->dirty_segmap = dirty_i->dirty_segmap[DIRTY];
		p->max_search = dirty_i->nr_dirty[DIRTY];
		p->ofs_unit = sbi->segs_per_sec;
	}

	if (p->max_search > sbi->max_victim_search)
		p->max_search = sbi->max_victim_search;

	p->offset = sbi->last_victim[p->gc_mode];
}


/*
 * gc的消耗:
 *
 * SSR：每次处理一个segment，因此就是blocks_per_seg
 * LFS: GC_GREEDY就是 sbi->blocks_per_seg，因为(1 segment = 1 section)
 * LFS: GC_CB就是 UINT_MAX
 * */
static unsigned int get_max_cost(struct f2fs_sb_info *sbi,
				struct victim_sel_policy *p)
{
	/* SSR allocates in a segment unit */
	if (p->alloc_mode == SSR)
		return sbi->blocks_per_seg;
	if (p->gc_mode == GC_GREEDY)
		return sbi->blocks_per_seg * p->ofs_unit; // ofs_unit是seg_of_persec
	else if (p->gc_mode == GC_CB)
		return UINT_MAX;
	else /* No other gc_mode */
		return 0;
}

static unsigned int check_bg_victims(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int secno;

	/*
	 * If the gc_type is FG_GC, we can select victim segments
	 * selected by background GC before.
	 * Those segments guarantee they have small valid blocks.
	 *
	 * 所有的section号，在victim_secmap的每一个位去表示，假如有500个section，而victim_secmap是64位数组，那么需要victim_secmap的数组长度是8，因为64*8=512位，每一个位表示一个section
	 *
	 * for_each_set_bit这个宏是用来遍历所有位为1的位数，返回其位置
	 */
	for_each_set_bit(secno, dirty_i->victim_secmap, MAIN_SECS(sbi)) {
		if (sec_usage_check(sbi, secno)) // 如果section号是当前正在处理的section号，那么跳过，因为只回收其他的section
			continue;
		clear_bit(secno, dirty_i->victim_secmap); // 清位图标志位
		return secno * sbi->segs_per_sec; //返回有多少个segment可以进行回收
	}
	return NULL_SEGNO;
}

/*
 * age*(1-u)/(2u)
 * age代表该block最近一次修改时间
 * 1-u代表进行gc后能够获取free page的数目
 * 2u代表gc的开销
 * (1-u)/2u一般可以理解为投入产出比
 * */
static unsigned int get_cb_cost(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int secno = GET_SECNO(sbi, segno);
	unsigned int start = secno * sbi->segs_per_sec;
	unsigned long long mtime = 0;
	unsigned int vblocks;
	unsigned char age = 0;
	unsigned char u;
	unsigned int i;

	/* 计算整个section里面的block的修改时间 */
	for (i = 0; i < sbi->segs_per_sec; i++)
		mtime += get_seg_entry(sbi, start + i)->mtime;

	// 计算这个segment有多少个有效块
	vblocks = get_valid_blocks(sbi, segno, sbi->segs_per_sec);

	mtime = div_u64(mtime, sbi->segs_per_sec); // 平均修改时间
	vblocks = div_u64(vblocks, sbi->segs_per_sec); // 平均有效块

	u = (vblocks * 100) >> sbi->log_blocks_per_seg;

	/*
	 * Handle if the system time has changed by the user
	 * 更新segment information 的修改时间
	 * */
	if (mtime < sit_i->min_mtime)
		sit_i->min_mtime = mtime;
	if (mtime > sit_i->max_mtime)
		sit_i->max_mtime = mtime;
	if (sit_i->max_mtime != sit_i->min_mtime)
		age = 100 - div64_u64(100 * (mtime - sit_i->min_mtime), sit_i->max_mtime - sit_i->min_mtime);

	return UINT_MAX - ((100 * (100 - u) * age) / (100 + u));
}

static inline unsigned int get_gc_cost(struct f2fs_sb_info *sbi,
			unsigned int segno, struct victim_sel_policy *p)
{
	if (p->alloc_mode == SSR)
		return get_seg_entry(sbi, segno)->ckpt_valid_blocks; // 返回这个segment合法的块数目

	/* alloc_mode == LFS */
	if (p->gc_mode == GC_GREEDY)
		return get_valid_blocks(sbi, segno, sbi->segs_per_sec); // 获取这个segment合法的块的个数
	else
		return get_cb_cost(sbi, segno); // 获取 cost-benefit的cost
}

static unsigned int count_bits(const unsigned long *addr,
				unsigned int offset, unsigned int len)
{
	unsigned int end = offset + len, sum = 0;

	while (offset < end) {
		if (test_bit(offset++, addr))
			++sum;
	}
	return sum;
}

/*
 * This function is called from two paths.
 * One is garbage collection and the other is SSR segment selection.
 * When it is called during GC, it just gets a victim segment
 * and it does not remove it from dirty seglist.
 * When it is called from SSR segment selection, it finds a segment
 * which has minimum valid blocks and removes it from dirty seglist.
 *
 * 目的选择一个segno作为victim
 * 这个函数会被两个地方调用：垃圾回收和SSR Segment选择
 *
 * 输入参数一半时 sbi, victim, gc_type, NO_CHECK_TYPE, LFS
 */
static int get_victim_by_default(struct f2fs_sb_info *sbi,
		unsigned int *result, int gc_type, int type, char alloc_mode)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct victim_sel_policy p;
	unsigned int secno, max_cost, last_victim;
	unsigned int last_segment = MAIN_SEGS(sbi); // main area有多少个segment
	unsigned int nsearched = 0;

	mutex_lock(&dirty_i->seglist_lock);

	p.alloc_mode = alloc_mode; // LFS模式或者SSR模式
	select_policy(sbi, gc_type, type, &p); // 根据gc_type设置policy

	p.min_segno = NULL_SEGNO;
	p.min_cost = max_cost = get_max_cost(sbi, &p); // 这里记录最小的合法的块数（初始化为最大的块数），然后通过遍历得到最小的块数

	if (p.max_search == 0)
		goto out;

	last_victim = sbi->last_victim[p.gc_mode]; // 上一个victim

	if (p.alloc_mode == LFS && gc_type == FG_GC) { // 如果是前台gc和LFS模式
		p.min_segno = check_bg_victims(sbi); // 寻找后台gc的victim map，返回第一个可以进行gc的section的起始segment号，然后将这个清除这个Bit
		if (p.min_segno != NULL_SEGNO)
			goto got_it;
	}

	/*
	 * 主要逻辑：
	 * 1. 获取dirty_map第一个dirty的segment的number - segno
	 * 2. 通过segno的增加
	 * 两个条件会跳出循环：
	 * 1. segno的自增，超过了main area的最大segno
	 * 2. 大于最大搜索次数，这个最大搜索次数取决于sbi记录当前有多少个dirty的segment
	 * */
	while (1) {
		unsigned long cost;
		unsigned int segno;

		// last_segment是main area包含的segment的总数，这里第一个参数是要遍历的map，第二个参数是前多少bit是有效的，第三个参数是偏移量
		// 返回segment bitmap索引，通过offset不断增加，从而不断找到dirty_segmap里面的值为1的索引
		segno = find_next_bit(p.dirty_segmap, last_segment, p.offset);

		if (segno >= last_segment) { // last_segment是main area包含的segment的总数，因此如果搜寻的segno超过这个数，那么就准备break
			if (sbi->last_victim[p.gc_mode]) { // 如果dirty_map没有，就再查一次有没有新的的last_victim的加入到dirty_map中
				last_segment = sbi->last_victim[p.gc_mode];
				sbi->last_victim[p.gc_mode] = 0; // 如果上次dirty_map没有遍历到，但是last_victim有，那么就以为这last_victim没有处理
				p.offset = 0;
				continue;
			}
			break;
		}

		p.offset = segno + p.ofs_unit; // ofs_unit一般等于1
		if (p.ofs_unit > 1) {
			p.offset -= segno % p.ofs_unit;
			nsearched += count_bits(p.dirty_segmap, p.offset - p.ofs_unit, p.ofs_unit);
		} else {
			nsearched++; // 搜索次数+1
		}


		secno = GET_SECNO(sbi, segno); // 根据segno获取secno

		if (sec_usage_check(sbi, secno))
			goto next;
		if (gc_type == BG_GC && test_bit(secno, dirty_i->victim_secmap)) // 如果是后台gc
			goto next;

		cost = get_gc_cost(sbi, segno, &p); // 记录了这个segment有多少个有效块个数，因此根据这个原则去选定哪个segment去做gc

		if (p.min_cost > cost) { // 记录了最小的合法的块数
			p.min_segno = segno;
			p.min_cost = cost;
		}
next:
		if (nsearched >= p.max_search) { // 如果超过最大搜索次数
			if (!sbi->last_victim[p.gc_mode] && segno <= last_victim)
				sbi->last_victim[p.gc_mode] = last_victim + 1;
			else
				sbi->last_victim[p.gc_mode] = segno + 1;
			break;
		}
	} // end while
	if (p.min_segno != NULL_SEGNO) {
got_it:
		if (p.alloc_mode == LFS) {
			secno = GET_SECNO(sbi, p.min_segno);
			if (gc_type == FG_GC)
				sbi->cur_victim_sec = secno;
			else
				set_bit(secno, dirty_i->victim_secmap); // 这里将这个secno设置为1？
		}
		*result = (p.min_segno / p.ofs_unit) * p.ofs_unit; // 返回该segment

		trace_f2fs_get_victim(sbi->sb, type, gc_type, &p, sbi->cur_victim_sec, prefree_segments(sbi), free_segments(sbi));
	}
out:
	mutex_unlock(&dirty_i->seglist_lock);

	return (p.min_segno == NULL_SEGNO) ? 0 : 1;
}

static const struct victim_selection default_v_ops = {
	.get_victim = get_victim_by_default,
};

static struct inode *find_gc_inode(struct gc_inode_list *gc_list, nid_t ino)
{
	struct inode_entry *ie;

	ie = radix_tree_lookup(&gc_list->iroot, ino);
	if (ie)
		return ie->inode;
	return NULL;
}

static void add_gc_inode(struct gc_inode_list *gc_list, struct inode *inode)
{
	struct inode_entry *new_ie;

	if (inode == find_gc_inode(gc_list, inode->i_ino)) {
		iput(inode);
		return;
	}
	new_ie = f2fs_kmem_cache_alloc(inode_entry_slab, GFP_NOFS);
	new_ie->inode = inode;

	f2fs_radix_tree_insert(&gc_list->iroot, inode->i_ino, new_ie);
	list_add_tail(&new_ie->list, &gc_list->ilist);
}

static void put_gc_inode(struct gc_inode_list *gc_list)
{
	struct inode_entry *ie, *next_ie;
	list_for_each_entry_safe(ie, next_ie, &gc_list->ilist, list) {
		radix_tree_delete(&gc_list->iroot, ie->inode->i_ino);
		iput(ie->inode);
		list_del(&ie->list);
		kmem_cache_free(inode_entry_slab, ie);
	}
}

static int check_valid_map(struct f2fs_sb_info *sbi, unsigned int segno, int offset)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *sentry;
	int ret;

	mutex_lock(&sit_i->sentry_lock);
	sentry = get_seg_entry(sbi, segno); // 根据segno获取seg_entry
	ret = f2fs_test_bit(offset, sentry->cur_valid_map); // 一个segment一共512blocks，使用了一个8bit数组
	mutex_unlock(&sit_i->sentry_lock);
	return ret;
}

/*
 * This function compares node address got in summary with that in NAT.
 * On validity, copy that node with cold status, otherwise (invalid node)
 * ignore that.
 *
 * 标志这个segment里面所有的block，然后等待写回
 *
 */
static void gc_node_segment(struct f2fs_sb_info *sbi, struct f2fs_summary *sum, unsigned int segno, int gc_type)
{
	bool initial = true;
	struct f2fs_summary *entry;
	block_t start_addr;
	int off;

	start_addr = START_BLOCK(sbi, segno);

next_step:
	entry = sum;

	for (off = 0; off < sbi->blocks_per_seg; off++, entry++) { // 遍历这个segment所有的block
		nid_t nid = le32_to_cpu(entry->nid); // 针对node，所以先获取nid
		struct page *node_page;
		struct node_info ni;

		/* stop BG_GC if there is not enough free sections. */
		if (gc_type == BG_GC && has_not_enough_free_secs(sbi, 0))
			return;

		if (check_valid_map(sbi, segno, off) == 0) // 如果不是有效的block，那就跳过
			continue;

		if (initial) {
			ra_node_page(sbi, nid);
			continue;
		}

		node_page = get_node_page(sbi, nid); // 获取这个summary所在的block
		if (IS_ERR(node_page))
			continue;

		/* block may become invalid during get_node_page */
		if (check_valid_map(sbi, segno, off) == 0) {
			f2fs_put_page(node_page, 1);
			continue;
		}

		get_node_info(sbi, nid, &ni); // 获取node info
		if (ni.blk_addr != start_addr + off) { // 如果地址是空的地址或者其他地址，也跳过
			f2fs_put_page(node_page, 1);
			continue;
		}

		/* set page dirty and write it
		 * 设置为dirty，然后写回
		 *
		 * 如果是前台GC，那就等待写回
		 * */
		if (gc_type == FG_GC) {
			f2fs_wait_on_page_writeback(node_page, NODE, true); //将这个page回写？
			set_page_dirty(node_page);
		} else {
			if (!PageWriteback(node_page))
				set_page_dirty(node_page); // 将这个页设置为脏
		}
		f2fs_put_page(node_page, 1);
		stat_inc_node_blk_count(sbi, 1, gc_type);
	}// end for

	if (initial) {
		initial = false;
		goto next_step;
	}
}

/*
 * Calculate start block index indicating the given node offset.
 * Be careful, caller should give this node offset only indicating direct node
 * blocks. If any node offsets, which point the other types of node blocks such
 * as indirect or double indirect node blocks, are given, it must be a caller's
 * bug.
 *
 * 这个函数只适用于某些indirect node
 * 返回了这个文件的size对应的i_nid的位置，如果是文件的size小于923,则返回0,或者根据size返回，如923,923+1018,923+1018*2,923+1018*2+1018~923+1018*2+1018*1018*1018,
 *
 */
block_t start_bidx_of_node(unsigned int node_ofs, struct inode *inode)
{
	unsigned int indirect_blks = 2 * NIDS_PER_BLOCK + 4; // NIDS_PER_BLOCK = 1018
	unsigned int bidx;

	if (node_ofs == 0)
		return 0;

	if (node_ofs <= 2) { // 针对direct_node，所以的bidx就是-1,对应f2fs_inode->i_nid[0~1]
		bidx = node_ofs - 1;
	} else if (node_ofs <= indirect_blks) { // 针对indirect_node，因为是间接映射，2 * 1018，+4就是因为前面0、1、2都被占用
		int dec = (node_ofs - 4) / (NIDS_PER_BLOCK + 1);
		bidx = node_ofs - 2 - dec;
	} else {
		int dec = (node_ofs - indirect_blks - 3) / (NIDS_PER_BLOCK + 1);
		bidx = node_ofs - 5 - dec;
	}
	return bidx * ADDRS_PER_BLOCK + ADDRS_PER_INODE(inode); // 这里返回这个文件的size对应的block个数
}

/*
 *
 * */
static bool is_alive(struct f2fs_sb_info *sbi, struct f2fs_summary *sum, struct node_info *dni, block_t blkaddr, unsigned int *nofs)
{
	struct page *node_page;
	nid_t nid;
	unsigned int ofs_in_node;
	block_t source_blkaddr;

	nid = le32_to_cpu(sum->nid); // 获取summary block的nid
	ofs_in_node = le16_to_cpu(sum->ofs_in_node);

	node_page = get_node_page(sbi, nid); // 获取一个根据nid获取node page
	if (IS_ERR(node_page))
		return false;

	get_node_info(sbi, nid, dni); // 获取这个node的信息到dni里面

	if (sum->version != dni->version) {
		f2fs_put_page(node_page, 1);
		return false;
	}

	*nofs = ofs_of_node(node_page); // 这个node offset
	source_blkaddr = datablock_addr(node_page, ofs_in_node); // 返回datablock的数组，这个flag的作用?
	f2fs_put_page(node_page, 1);

	if (source_blkaddr != blkaddr)
		return false;
	return true;
}

static void move_encrypted_block(struct inode *inode, block_t bidx)
{
	struct f2fs_io_info fio = {
		.sbi = F2FS_I_SB(inode),
		.type = DATA,
		.rw = READ_SYNC,
		.encrypted_page = NULL,
	};
	struct dnode_of_data dn;
	struct f2fs_summary sum;
	struct node_info ni;
	struct page *page;
	block_t newaddr;
	int err;

	/* do not read out */
	page = f2fs_grab_cache_page(inode->i_mapping, bidx, false);
	if (!page)
		return;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, bidx, LOOKUP_NODE);
	if (err)
		goto out;

	if (unlikely(dn.data_blkaddr == NULL_ADDR)) {
		ClearPageUptodate(page);
		goto put_out;
	}

	/*lint -save -e730*/
	if (unlikely(dn.data_blkaddr == NEW_ADDR)) {
		goto put_out;
	}
	/*lint -restore*/

	/*
	 * don't cache encrypted data into meta inode until previous dirty
	 * data were writebacked to avoid racing between GC and flush.
	 */
	f2fs_wait_on_page_writeback(page, DATA, true);

	get_node_info(fio.sbi, dn.nid, &ni);
	set_summary(&sum, dn.nid, dn.ofs_in_node, ni.version);

	/* read page */
	fio.page = page;
	fio.new_blkaddr = fio.old_blkaddr = dn.data_blkaddr;

	allocate_data_block(fio.sbi, NULL, fio.old_blkaddr, &newaddr,
							&sum, CURSEG_COLD_DATA);

	fio.encrypted_page = pagecache_get_page(META_MAPPING(fio.sbi), newaddr,
					FGP_LOCK | FGP_CREAT, GFP_NOFS);
	if (!fio.encrypted_page) {
		err = -ENOMEM;
		goto recover_block;
	}

	err = f2fs_submit_page_bio(&fio);
	if (err)
		goto put_page_out;

	/* write page */
	lock_page(fio.encrypted_page);

	if (unlikely(!PageUptodate(fio.encrypted_page))) {
		err = -EIO;
		goto put_page_out;
	}
	if (unlikely(fio.encrypted_page->mapping != META_MAPPING(fio.sbi))) {
		err = -EIO;
		goto put_page_out;
	}

	set_page_dirty(fio.encrypted_page);
	f2fs_wait_on_page_writeback(fio.encrypted_page, DATA, true);
	if (clear_page_dirty_for_io(fio.encrypted_page))
		dec_page_count(fio.sbi, F2FS_DIRTY_META);

	set_page_writeback(fio.encrypted_page);

	/* allocate block address */
	f2fs_wait_on_page_writeback(dn.node_page, NODE, true);

	fio.rw = WRITE_SYNC;
	fio.new_blkaddr = newaddr;
	f2fs_submit_page_mbio(&fio);

	f2fs_update_data_blkaddr(&dn, newaddr);
	set_inode_flag(F2FS_I(inode), FI_APPEND_WRITE);
	if (page->index == 0)
		set_inode_flag(F2FS_I(inode), FI_FIRST_BLOCK_WRITTEN);
put_page_out:
	f2fs_put_page(fio.encrypted_page, 1);
recover_block:
	if (err)
		__f2fs_replace_block(fio.sbi, &sum, newaddr, fio.old_blkaddr,
								true, true);
put_out:
	f2fs_put_dnode(&dn);
out:
	f2fs_put_page(page, 1);
}

/*
 *
 * move page简单来说就是将page全部设置为dirty，然后等待写回
 *
 * */
static void move_data_page(struct inode *inode, block_t bidx, int gc_type)
{
	struct page *page;

	page = get_lock_data_page(inode, bidx, true); // 获得一个加锁的page
	if (IS_ERR(page))
		return;

	if (gc_type == BG_GC) { // 如果是BGGC，就这些设置page是dirty，标志是cold
		if (PageWriteback(page))
			goto out;
		set_page_dirty(page);
		set_cold_data(page);
	} else { // 如果是前台GC，那么就要马上回收这些页面
		struct f2fs_io_info fio = {
			.sbi = F2FS_I_SB(inode),
			.type = DATA,
			.rw = WRITE_SYNC,
			.page = page,
			.encrypted_page = NULL,
		};
		bool is_dirty = PageDirty(page);
		int err;

retry:
		set_page_dirty(page);
		f2fs_wait_on_page_writeback(page, DATA, true); // 等待page回写

		if (clear_page_dirty_for_io(page))
			inode_dec_dirty_pages(inode);

		set_cold_data(page);

		err = do_write_data_page(&fio);
		if (err == -ENOMEM && is_dirty) {
			/*lint -save -e747*/
			congestion_wait(BLK_RW_ASYNC, HZ/50);
			/*lint -restore*/
			goto retry;
		}

		clear_cold_data(page);
	}
out:
	f2fs_put_page(page, 1);
}

/*
 * This function tries to get parent node of victim data block, and identifies
 * data block validity. If the block is valid, copy that with cold status and
 * modify parent node.
 * If the parent node is not valid or the data block address is different,
 * the victim data block is ignored.
 *
 * gc data segment
 *
 */
static void gc_data_segment(struct f2fs_sb_info *sbi, struct f2fs_summary *sum, struct gc_inode_list *gc_list, unsigned int segno, int gc_type)
{
	struct super_block *sb = sbi->sb;
	struct f2fs_summary *entry;
	block_t start_addr;
	int off;
	int phase = 0;

	start_addr = START_BLOCK(sbi, segno); // 遍历该segment下的所有的block

/*
 * next_step: 因为phase++，起码循环四次for
 *
 * */
next_step:
	entry = sum;

	for (off = 0; off < sbi->blocks_per_seg; off++, entry++) { //
		struct page *data_page;
		struct inode *inode;
		struct node_info dni; /* dnode info for the data */
		unsigned int ofs_in_node, nofs;
		block_t start_bidx;

		/* stop BG_GC if there is not enough free sections. */
		if (gc_type == BG_GC && has_not_enough_free_secs(sbi, 0))
			return;

		if (check_valid_map(sbi, segno, off) == 0) // 如果这个block是valid
			continue;

		/* 第一次循环　将这个section所有的block预读到sbi->address_space，这里的nid是f2fs_inode，表示着一个块是属于什么node的 */
		if (phase == 0) {
			ra_node_page(sbi, le32_to_cpu(entry->nid));
			continue;
		}

		/* 第二、三、四次循环　先检查合法性，，如果不合法的直接跳过，合法的继续下一步*/
		if (!is_alive(sbi, entry, &dni, start_addr + off, &nofs)) // 查看这个Inode的合法性
			continue; // 如果不valid，则跳过

		/* 第二次循环 再预读一次，这次预读的是inode对应的page，将保存在page_tree当中 */
		if (phase == 1) {
			ra_node_page(sbi, dni.ino);
			continue;
		}

		ofs_in_node = le16_to_cpu(entry->ofs_in_node);// 找到对应的ofs_in_node信息

		/* 第三次循环　 */
		if (phase == 2) {
			inode = f2fs_iget(sb, dni.ino); // 根据ino获取到inode
			if (IS_ERR(inode) || is_bad_inode(inode))
				continue;

			/* if encrypted inode, let's go phase 3 */
			if (f2fs_encrypted_inode(inode) && S_ISREG(inode->i_mode)) {
				add_gc_inode(gc_list, inode);
				continue;
			}

			start_bidx = start_bidx_of_node(nofs, inode); // 获取start block index，返回923,923+1018,923+1018*2,923+1018*2+1018~923+1018*2+1018*1018*1018...

			// 获取对应的data page
			data_page = get_read_data_page(inode, start_bidx + ofs_in_node, READA, true); // 获取start_bidx + ofs_in_node的datablock信息到data page,同时这里也创建了page cache
			if (IS_ERR(data_page)) {
				iput(inode);
				continue;
			}

			f2fs_put_page(data_page, 0); // 结束这个page
			add_gc_inode(gc_list, inode); // 将需要gc的inode加入到gc_list中
			continue;
		}

		/* phase 3 */
		/* 第四步　从gclist中获取到inode，然后然后move_data_page迁移出去，准备gc */
		inode = find_gc_inode(gc_list, dni.ino);
		if (inode) {
			start_bidx = start_bidx_of_node(nofs, inode) + ofs_in_node; // 计算这个文件某个datablock的位置
			if (f2fs_encrypted_inode(inode) && S_ISREG(inode->i_mode))
				move_encrypted_block(inode, start_bidx);
			else
				move_data_page(inode, start_bidx, gc_type); //转移页，注意前面已经将这个segment的全部页都读到了cache中
			stat_inc_data_blk_count(sbi, 1, gc_type);
		}
	}

	if (++phase < 4)
		goto next_step; // 注意返回的next_step是返回到循环之前
}

/*
 * 选择一个合适segno作为victim
 * */
static int __get_victim(struct f2fs_sb_info *sbi, unsigned int *victim, int gc_type)
{
	struct sit_info *sit_i = SIT_I(sbi);
	int ret;

	mutex_lock(&sit_i->sentry_lock);
	ret = DIRTY_I(sbi)->v_ops->get_victim(sbi, victim, gc_type, NO_CHECK_TYPE, LFS); // 后台gc使用LFS的模式选择victim，默认是get_victim_by_default
	mutex_unlock(&sit_i->sentry_lock);
	return ret;
}

/*
 * 刚开始的gclist是空的
 * */
static int do_garbage_collect(struct f2fs_sb_info *sbi, unsigned int start_segno, struct gc_inode_list *gc_list, int gc_type)
{
	struct page *sum_page;
	struct f2fs_summary_block *sum;
	struct blk_plug plug;
	unsigned int segno = start_segno;
	unsigned int end_segno = start_segno + sbi->segs_per_sec; // 读取一个整个segment，一般情况 1 section = 1 segment
	int seg_freed = 0;
	unsigned char type = IS_DATASEG(get_seg_entry(sbi, segno)->type) ?
						SUM_TYPE_DATA : SUM_TYPE_NODE; // 是 data block 还是 node block

	/* readahead multi ssa blocks those have contiguous address */
	if (sbi->segs_per_sec > 1)
		ra_meta_pages(sbi, GET_SUM_BLOCK(sbi, segno), sbi->segs_per_sec, META_SSA, true);

	/*
	 * reference all summary page
	 * 遍历从start_segno开始的，整个section里面的segment所在的summary block，然后进行解锁，以便操作
	 * */
	while (segno < end_segno) {
		sum_page = get_sum_page(sbi, segno++);
		unlock_page(sum_page);
	}

	blk_start_plug(&plug); // 积蓄操作

	// 遍历从start_segno开始的，整个section里面的segment
	// 一般1 section = 1 segment，因此这个循环只会循环一次
	for (segno = start_segno; segno < end_segno; segno++) {

		/* find segment summary of victim */
		sum_page = find_get_page(META_MAPPING(sbi), GET_SUM_BLOCK(sbi, segno)); // 找到segno所在的summary block
		f2fs_bug_on(sbi, !PageUptodate(sum_page));
		f2fs_put_page(sum_page, 0);

		sum = page_address(sum_page); // 转换类型
		f2fs_bug_on(sbi, type != GET_SUM_TYPE((&sum->footer)));

		/*
		 * this is to avoid deadlock:
		 * - lock_page(sum_page)         - f2fs_replace_block
		 *  - check_valid_map()            - mutex_lock(sentry_lock)
		 *   - mutex_lock(sentry_lock)     - change_curseg()
		 *                                  - lock_page(sum_page)
		 */

		if (type == SUM_TYPE_NODE)
			gc_node_segment(sbi, sum->entries, segno, gc_type); // 处理node的gc，　标志这个node里面所有的block为标志，然后等待写回
		else
			gc_data_segment(sbi, sum->entries, gc_list, segno, gc_type); // 处理data的gc, gc_list是一个刚刚在f2fs_gc初始化的

		stat_inc_seg_count(sbi, type, gc_type);

		f2fs_put_page(sum_page, 0);
	}

	if (gc_type == FG_GC) {
		if (type == SUM_TYPE_NODE) {
			struct writeback_control wbc = {
				.sync_mode = WB_SYNC_ALL,
				.nr_to_write = LONG_MAX,
				.for_reclaim = 0,
			};
			sync_node_pages(sbi, 0, &wbc);
		} else {
			f2fs_submit_merged_bio(sbi, DATA, WRITE);
		}
	}

	blk_finish_plug(&plug);

	if (gc_type == FG_GC) {
		while (start_segno < end_segno)
			if (get_valid_blocks(sbi, start_segno++, 1) == 0)
				seg_freed++;
	}

	stat_inc_call_count(sbi->stat_info);

	return seg_freed;
}


/*
 * gc 核心代码
 * sync一般情况是force
 * background一般为true
 *
 * 基本过程
 * 1. 选择victim section，得到segno
 * 2. do_garbage_collect，将这个segno里面包含的所有block全部读取到page cache，然后设置为dirty
 * */
int f2fs_gc(struct f2fs_sb_info *sbi, bool sync, bool background)
{
	unsigned int segno;
	int gc_type = sync ? FG_GC : BG_GC; // sync = true 前台gc ： 否则  后台gc
	int sec_freed = 0, seg_freed;
	int ret = -EINVAL;
	struct cp_control cpc;
	struct gc_inode_list gc_list = {
		.ilist = LIST_HEAD_INIT(gc_list.ilist),
		.iroot = RADIX_TREE_INIT(GFP_NOFS),
	};

	cpc.reason = __get_cp_reason(sbi);
gc_more:
	segno = NULL_SEGNO; //初始化segno

	if (unlikely(!(sbi->sb->s_flags & MS_ACTIVE))) // 如果处于活动状态，就停止
		goto stop;
	if (unlikely(f2fs_cp_error(sbi))) {
		ret = -EIO;
		goto stop;
	}


	if (gc_type == BG_GC && has_not_enough_free_secs(sbi, sec_freed)) { // 如果是后台gc，同时还有足够的free sections
		gc_type = FG_GC; // 如果空间不够，则设置为前台GC
		/*
		 * If there is no victim and no prefree segment but still not
		 * enough free sections, we should flush dent/node blocks and do
		 * garbage collections.
		 *
		 * 如果是前台gc，需要先做prefree，将内存
		 */
		if (__get_victim(sbi, &segno, gc_type) ||  prefree_segments(sbi)) { // 选择victim section，注意这里prefree操作
			write_checkpoint(sbi, &cpc); // 记录checkpoint
			segno = NULL_SEGNO;
		} else if (has_not_enough_free_secs(sbi, 0)) {
			write_checkpoint(sbi, &cpc); // 记录checkpoint
		}
	} else if (gc_type == BG_GC && !background) { // 如果是后台gc，但是不允许后台gc，也停止
		/* f2fs_balance_fs doesn't need to do BG_GC in critical path. */
		goto stop;
	}

	/*
	 * 选择一个segment进行gc
	 * */
	if (segno == NULL_SEGNO && !__get_victim(sbi, &segno, gc_type))
		goto stop;
	ret = 0;

	// 选择了一个无效页最多的segment出来，进行gc
	seg_freed = do_garbage_collect(sbi, segno, &gc_list, gc_type); //处理垃圾回收，返回了释放了多少个segment，非前台gc的时候seg_freed=0

	if (gc_type == FG_GC && seg_freed == sbi->segs_per_sec) // 如果清理的segment的个数等于一个section的个数（清理了整个section）
		sec_freed++;

	if (gc_type == FG_GC)
		sbi->cur_victim_sec = NULL_SEGNO;

	if (!sync) {
		if (has_not_enough_free_secs(sbi, sec_freed))
			goto gc_more;

		if (gc_type == FG_GC)
			write_checkpoint(sbi, &cpc);
	}
stop:
	mutex_unlock(&sbi->gc_mutex);

	put_gc_inode(&gc_list);

	if (sync) // FORCE_FG_GC标志被设置的时候才会判断这个
		ret = sec_freed ? 0 : -EAGAIN;
	return ret;
}

void build_gc_manager(struct f2fs_sb_info *sbi)
{
	DIRTY_I(sbi)->v_ops = &default_v_ops;
}
