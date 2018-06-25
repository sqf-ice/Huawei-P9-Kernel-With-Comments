/*
 * fs/f2fs/inline.c
 * Copyright (c) 2013, Intel Corporation
 * Authors: Huajun Li <huajun.li@intel.com>
 *          Haicheng Li <haicheng.li@intel.com>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/fs.h>
#include <linux/f2fs_fs.h>

#include "f2fs.h"
#include "node.h"

bool f2fs_may_inline_data(struct inode *inode)
{
	if (f2fs_is_atomic_file(inode))
		return false;

	if (!S_ISREG(inode->i_mode) && !S_ISLNK(inode->i_mode))
		return false;

	if (i_size_read(inode) > MAX_INLINE_DATA)
		return false;

	if (f2fs_encrypted_inode(inode) && S_ISREG(inode->i_mode))
		return false;

	return true;
}

bool f2fs_may_inline_dentry(struct inode *inode)
{
	if (!test_opt(F2FS_I_SB(inode), INLINE_DENTRY))
		return false;

	if (!S_ISDIR(inode->i_mode))
		return false;

	return true;
}

/*
 * 根据传入的ipage，转换为f2fs_inode，然后获取i_addr[1]的数据的地址
 * 然后复制到page中
 * */
void read_inline_data(struct page *page, struct page *ipage)
{
	void *src_addr, *dst_addr;

	if (PageUptodate(page))
		return;

	f2fs_bug_on(F2FS_P_SB(page), page->index);

	// 将这个page对应数据，第MAX_INLINE_DATA~PAGE_CACHE_SIZE之间的数据清空为0
	// 将大于MAX_INLINE_DATA部分都清0
	zero_user_segment(page, MAX_INLINE_DATA, PAGE_CACHE_SIZE);

	/* Copy the whole inline data block */
	src_addr = inline_data_addr(ipage);//返回inline data数据开始位置
	dst_addr = kmap_atomic(page);
	memcpy(dst_addr, src_addr, MAX_INLINE_DATA);// 复制inline data到这个page中
	flush_dcache_page(page);
	kunmap_atomic(dst_addr);
	SetPageUptodate(page);
}

bool truncate_inline_inode(struct page *ipage, u64 from)
{
	void *addr;

	if (from >= MAX_INLINE_DATA)
		return false;

	addr = inline_data_addr(ipage); // 返回inline data实际的起始点

	f2fs_wait_on_page_writeback(ipage, NODE, true);
	memset(addr + from, 0, MAX_INLINE_DATA - from);

	return true;
}


/*
 * 根据传入的Inode，返回f2fs扩展的后的f2fs_node结构，结果保存在page中，因为4KB对齐。因此可以使用强制类型转换，将page转化为f2fs_node结构
 * */
int f2fs_read_inline_data(struct inode *inode, struct page *page)
{
	struct page *ipage;

	ipage = get_node_page(F2FS_I_SB(inode), inode->i_ino); // 获取一个存储了f2fs_node结构信息的块(page)
	if (IS_ERR(ipage)) {
		unlock_page(page);
		return PTR_ERR(ipage);
	}

	if (!f2fs_has_inline_data(inode)) {
		f2fs_put_page(ipage, 1);
		return -EAGAIN;
	}

	if (page->index) // 如果page不是一个新的page，只需要填充其余空间
		zero_user_segment(page, 0, PAGE_CACHE_SIZE);
	else // 如果是一个新的page
		read_inline_data(page, ipage); //将ipage转换为f2fs_node再f2fs_inode，然后返回直接寻址块i_addr作为起始地址，这个地址即该f2fs_inode的第一个块(page)的地址

	SetPageUptodate(page);
	f2fs_put_page(ipage, 1);
	unlock_page(page);
	return 0;
}

/*
 * 将一个inline page转化为normal page
 * */
int f2fs_convert_inline_page(struct dnode_of_data *dn, struct page *page)
{
	struct f2fs_io_info fio = {
		.sbi = F2FS_I_SB(dn->inode),
		.type = DATA,
		.rw = WRITE_SYNC | REQ_PRIO,
		.page = page,
		.encrypted_page = NULL,
	};
	int dirty, err;

	if (!f2fs_exist_data(dn->inode)) // 如果不含有数据
		goto clear_out;

	err = f2fs_reserve_block(dn, 0); // 给i_addr[0]分配空间，设置为NEW_ADDR，用于保存convert后的inline data
	if (err)
		return err;

	f2fs_bug_on(F2FS_P_SB(page), PageWriteback(page));

	/*
	 * 注意这个page的分配方式，这个page是通过grab_cache_page(inode->i_mapping, 0)，进行分配，address_space的0,指向了第0个data page
	 * 因此这里实现了inline data到i_addr[0]的转移
	 * */
	read_inline_data(page, dn->inode_page); // 将dn->inode_page的前MAX_INLINE_DATA复制到page中
	set_page_dirty(page);

	/* clear dirty state */
	dirty = clear_page_dirty_for_io(page);

	/* write data page to try to make data consistent */
	set_page_writeback(page);
	fio.old_blkaddr = dn->data_blkaddr; // 设置指向新的NEW_ADDR的地址
	write_data_page(dn, &fio);
	f2fs_wait_on_page_writeback(page, DATA, true);
	if (dirty)
		inode_dec_dirty_pages(dn->inode);

	/* this converted inline_data should be recovered. */
	set_inode_flag(F2FS_I(dn->inode), FI_APPEND_WRITE);

	/*
	 * clear inline data and flag after data writeback
	 *
	 * */
	truncate_inline_inode(dn->inode_page, 0); // 清除inline data空间，即将i_addr[1]~i_addr[xx]清0，这样就有空间存datablock了
clear_out:
	stat_dec_inline_inode(dn->inode);
	f2fs_clear_inline_inode(dn->inode); // 清除inline标志
	sync_inode_page(dn); // 同步一下inode
	f2fs_put_dnode(dn);
	return 0;
}

/*
 * 将这个包含Inline data的inode转化为normal inode
 * */
int f2fs_convert_inline_inode(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct dnode_of_data dn;
	struct page *ipage, *page;
	int err = 0;

	if (!f2fs_has_inline_data(inode)) // 如果没有inline data
		return 0;

	page = grab_cache_page(inode->i_mapping, 0); // 获取这个文件的第0个page，因为inline文件尺寸小于3488个字节，取一个页就好
	if (!page)
		return -ENOMEM;

	f2fs_lock_op(sbi);

	ipage = get_node_page(sbi, inode->i_ino);  // 获取该文件对应的node page
	if (IS_ERR(ipage)) {
		err = PTR_ERR(ipage);
		goto out;
	}

	set_new_dnode(&dn, inode, ipage, ipage, 0); // 初始化dnode_of_data

	if (f2fs_has_inline_data(inode)) // 如果含有inline data
		err = f2fs_convert_inline_page(&dn, page); // 给新的node_page的addr[1]分配一个NEW_ADDR地址

	f2fs_put_dnode(&dn);
out:
	f2fs_unlock_op(sbi);

	f2fs_put_page(page, 1);

	f2fs_balance_fs(sbi, dn.node_changed);

	return err;
}

int f2fs_write_inline_data(struct inode *inode, struct page *page)
{
	void *src_addr, *dst_addr;
	struct dnode_of_data dn;
	int err;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, 0, LOOKUP_NODE); // 将i_addr[0]的数据提取了出来
	if (err)
		return err;

	if (!f2fs_has_inline_data(inode)) {
		f2fs_put_dnode(&dn);
		return -EAGAIN;
	}

	f2fs_bug_on(F2FS_I_SB(inode), page->index);

	f2fs_wait_on_page_writeback(dn.inode_page, NODE, true);
	src_addr = kmap_atomic(page);
	dst_addr = inline_data_addr(dn.inode_page);
	memcpy(dst_addr, src_addr, MAX_INLINE_DATA); // 复制到inline data空间当中
	kunmap_atomic(src_addr);

	set_inode_flag(F2FS_I(inode), FI_APPEND_WRITE); // 设置相应的标志
	set_inode_flag(F2FS_I(inode), FI_DATA_EXIST);

	sync_inode_page(&dn);
	f2fs_put_dnode(&dn);
	return 0;
}

bool recover_inline_data(struct inode *inode, struct page *npage)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode *ri = NULL;
	void *src_addr, *dst_addr;
	struct page *ipage;

	/*
	 * The inline_data recovery policy is as follows.
	 * [prev.] [next] of inline_data flag
	 *    o       o  -> recover inline_data
	 *    o       x  -> remove inline_data, and then recover data blocks
	 *    x       o  -> remove inline_data, and then recover inline_data
	 *    x       x  -> recover data blocks
	 */
	if (IS_INODE(npage))
		ri = F2FS_INODE(npage);

	if (f2fs_has_inline_data(inode) &&
			ri && (ri->i_inline & F2FS_INLINE_DATA)) {
process_inline:
		ipage = get_node_page(sbi, inode->i_ino);
		f2fs_bug_on(sbi, IS_ERR(ipage));

		f2fs_wait_on_page_writeback(ipage, NODE, true);

		src_addr = inline_data_addr(npage);
		dst_addr = inline_data_addr(ipage);
		memcpy(dst_addr, src_addr, MAX_INLINE_DATA);

		set_inode_flag(F2FS_I(inode), FI_INLINE_DATA);
		set_inode_flag(F2FS_I(inode), FI_DATA_EXIST);

		update_inode(inode, ipage);
		f2fs_put_page(ipage, 1);
		return true;
	}

	if (f2fs_has_inline_data(inode)) {
		ipage = get_node_page(sbi, inode->i_ino);
		f2fs_bug_on(sbi, IS_ERR(ipage));
		if (!truncate_inline_inode(ipage, 0))
			return false;
		f2fs_clear_inline_inode(inode);
		update_inode(inode, ipage);
		f2fs_put_page(ipage, 1);
	} else if (ri && (ri->i_inline & F2FS_INLINE_DATA)) {
		if (truncate_blocks(inode, 0, false))
			return false;
		goto process_inline;
	}
	return false;
}

struct f2fs_dir_entry *find_in_inline_dir(struct inode *dir,
			struct fscrypt_name *fname, struct page **res_page,
			struct fscrypt_str *fstr)
{
	struct f2fs_sb_info *sbi = F2FS_SB(dir->i_sb);
	struct f2fs_inline_dentry *inline_dentry;
	struct qstr name = FSTR_TO_QSTR(&fname->disk_name);
	struct f2fs_dir_entry *de;
	struct f2fs_dentry_ptr d;
	struct page *ipage;
	f2fs_hash_t namehash;

	ipage = get_node_page(sbi, dir->i_ino);
	if (IS_ERR(ipage))
		return NULL;

	namehash = f2fs_dentry_hash(&name);

	inline_dentry = inline_data_addr(ipage);

	make_dentry_ptr(NULL, &d, (void *)inline_dentry, 2);
	de = find_target_dentry(dir, fname, namehash, NULL, &d, fstr);
	unlock_page(ipage);
	if (de)
		*res_page = ipage;
	else
		f2fs_put_page(ipage, 0);

	/*
	 * For the most part, it should be a bug when name_len is zero.
	 * We stop here for figuring out where the bugs has occurred.
	 */
	f2fs_bug_on(sbi, d.max < 0);
	return de;
}

struct f2fs_dir_entry *f2fs_parent_inline_dir(struct inode *dir,
							struct page **p)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dir);
	struct page *ipage;
	struct f2fs_dir_entry *de;
	struct f2fs_inline_dentry *dentry_blk;

	ipage = get_node_page(sbi, dir->i_ino);
	if (IS_ERR(ipage))
		return NULL;

	dentry_blk = inline_data_addr(ipage);
	de = &dentry_blk->dentry[1];
	*p = ipage;
	unlock_page(ipage);
	return de;
}

int make_empty_inline_dir(struct inode *inode, struct inode *parent,
							struct page *ipage)
{
	struct f2fs_inline_dentry *dentry_blk;
	struct f2fs_dentry_ptr d;

	dentry_blk = inline_data_addr(ipage);

	make_dentry_ptr(NULL, &d, (void *)dentry_blk, 2);
	do_make_empty_dir(inode, parent, &d);

	set_page_dirty(ipage);

	/* update i_size to MAX_INLINE_DATA */
	if (i_size_read(inode) < MAX_INLINE_DATA) {
		i_size_write(inode, MAX_INLINE_DATA);
		set_inode_flag(F2FS_I(inode), FI_UPDATE_DIR);
		set_inode_flag(F2FS_I(inode), FI_ISIZE_CHANGED);
	}
	return 0;
}

/*
 * NOTE: ipage is grabbed by caller, but if any error occurs, we should
 * release ipage in this function.
 */
static int f2fs_convert_inline_dir(struct inode *dir, struct page *ipage,
				struct f2fs_inline_dentry *inline_dentry)
{
	struct page *page;
	struct dnode_of_data dn;
	struct f2fs_dentry_block *dentry_blk;
	int err;

	page = grab_cache_page(dir->i_mapping, 0);
	if (!page) {
		f2fs_put_page(ipage, 1);
		return -ENOMEM;
	}

	set_new_dnode(&dn, dir, ipage, NULL, 0);
	err = f2fs_reserve_block(&dn, 0);
	if (err)
		goto out;

	f2fs_wait_on_page_writeback(page, DATA, true);
	zero_user_segment(page, MAX_INLINE_DATA, PAGE_CACHE_SIZE);

	dentry_blk = kmap_atomic(page);

	/* copy data from inline dentry block to new dentry block */
	memcpy(dentry_blk->dentry_bitmap, inline_dentry->dentry_bitmap,
					INLINE_DENTRY_BITMAP_SIZE);
	memset(dentry_blk->dentry_bitmap + INLINE_DENTRY_BITMAP_SIZE, 0,
			SIZE_OF_DENTRY_BITMAP - INLINE_DENTRY_BITMAP_SIZE);
	/*
	 * we do not need to zero out remainder part of dentry and filename
	 * field, since we have used bitmap for marking the usage status of
	 * them, besides, we can also ignore copying/zeroing reserved space
	 * of dentry block, because them haven't been used so far.
	 */
	memcpy(dentry_blk->dentry, inline_dentry->dentry,
			sizeof(struct f2fs_dir_entry) * NR_INLINE_DENTRY);
	memcpy(dentry_blk->filename, inline_dentry->filename,
					NR_INLINE_DENTRY * F2FS_SLOT_LEN);

	kunmap_atomic(dentry_blk);
	SetPageUptodate(page);
	set_page_dirty(page);

	/* clear inline dir and flag after data writeback */
	truncate_inline_inode(ipage, 0);

	stat_dec_inline_dir(dir);
	clear_inode_flag(F2FS_I(dir), FI_INLINE_DENTRY);

	if (i_size_read(dir) < PAGE_CACHE_SIZE) {
		i_size_write(dir, PAGE_CACHE_SIZE);
		set_inode_flag(F2FS_I(dir), FI_UPDATE_DIR);
		set_inode_flag(F2FS_I(dir), FI_ISIZE_CHANGED);
	}

	sync_inode_page(&dn);
out:
	f2fs_put_page(page, 1);
	return err;
}

int f2fs_add_inline_entry(struct inode *dir, const struct qstr *new_name,
			const struct qstr *orig_name,
			struct inode *inode, nid_t ino, umode_t mode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dir);
	struct page *ipage;
	unsigned int bit_pos;
	f2fs_hash_t name_hash;
	struct f2fs_inline_dentry *dentry_blk = NULL;
	struct f2fs_dentry_ptr d;
	int slots = GET_DENTRY_SLOTS(new_name->len);
	struct page *page = NULL;
	int err = 0;

	ipage = get_node_page(sbi, dir->i_ino);
	if (IS_ERR(ipage))
		return PTR_ERR(ipage);

	dentry_blk = inline_data_addr(ipage);
	bit_pos = room_for_filename(&dentry_blk->dentry_bitmap,
						slots, NR_INLINE_DENTRY);
	if (bit_pos >= NR_INLINE_DENTRY) {
		err = f2fs_convert_inline_dir(dir, ipage, dentry_blk);
		if (err)
			return err;
		err = -EAGAIN;
		goto out;
	}

	if (inode) {
		down_write(&F2FS_I(inode)->i_sem);
		page = init_inode_metadata(inode, dir, new_name,
										orig_name, ipage);
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			goto fail;
		}
		if (f2fs_encrypted_inode(dir))
			file_set_enc_name(inode);
	}

	f2fs_wait_on_page_writeback(ipage, NODE, true);

	name_hash = f2fs_dentry_hash(new_name);
	make_dentry_ptr(NULL, &d, (void *)dentry_blk, 2);
	f2fs_update_dentry(ino, mode, &d, new_name, name_hash, bit_pos);

	set_page_dirty(ipage);

	/* we don't need to mark_inode_dirty now */
	if (inode) {
		F2FS_I(inode)->i_pino = dir->i_ino;
		update_inode(inode, page);
		f2fs_put_page(page, 1);
	}

	update_parent_metadata(dir, inode, 0);
fail:
	if (inode)
		up_write(&F2FS_I(inode)->i_sem);

	if (is_inode_flag_set(F2FS_I(dir), FI_UPDATE_DIR)) {
		update_inode(dir, ipage);
		clear_inode_flag(F2FS_I(dir), FI_UPDATE_DIR);
	}
out:
	f2fs_put_page(ipage, 1);
	return err;
}

void f2fs_delete_inline_entry(struct f2fs_dir_entry *dentry, struct page *page,
					struct inode *dir, struct inode *inode)
{
	struct f2fs_inline_dentry *inline_dentry;
	int slots = GET_DENTRY_SLOTS(le16_to_cpu(dentry->name_len));
	unsigned int bit_pos;
	int i;

	lock_page(page);
	f2fs_wait_on_page_writeback(page, NODE, true);

	inline_dentry = inline_data_addr(page);
	bit_pos = dentry - inline_dentry->dentry;
	for (i = 0; i < slots; i++)
		__test_and_clear_bit_le(bit_pos + i,
				&inline_dentry->dentry_bitmap);

	set_page_dirty(page);

	dir->i_ctime = dir->i_mtime = CURRENT_TIME;

	if (inode)
		f2fs_drop_nlink(dir, inode, page);

	f2fs_put_page(page, 1);
}

bool f2fs_empty_inline_dir(struct inode *dir)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dir);
	struct page *ipage;
	unsigned int bit_pos = 2;
	struct f2fs_inline_dentry *dentry_blk;

	ipage = get_node_page(sbi, dir->i_ino);
	if (IS_ERR(ipage))
		return false;

	dentry_blk = inline_data_addr(ipage);
	bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
					NR_INLINE_DENTRY,
					bit_pos);

	f2fs_put_page(ipage, 1);

	if (bit_pos < NR_INLINE_DENTRY)
		return false;

	return true;
}

int f2fs_read_inline_dir(struct file *file, struct dir_context *ctx,
				struct fscrypt_str *fstr)
{
	struct inode *inode = file_inode(file);
	struct f2fs_inline_dentry *inline_dentry = NULL;
	struct page *ipage = NULL;
	struct f2fs_dentry_ptr d;

	if (ctx->pos == NR_INLINE_DENTRY)
		return 0;

	ipage = get_node_page(F2FS_I_SB(inode), inode->i_ino);
	if (IS_ERR(ipage))
		return PTR_ERR(ipage);

	inline_dentry = inline_data_addr(ipage);

	make_dentry_ptr(inode, &d, (void *)inline_dentry, 2);

	if (!f2fs_fill_dentries(ctx, &d, 0, fstr))
		ctx->pos = NR_INLINE_DENTRY;

	f2fs_put_page(ipage, 1);
	return 0;
}

int f2fs_inline_data_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo, __u64 start, __u64 len)
{
	__u64 byteaddr, ilen;
	__u32 flags = FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_LAST;
	struct node_info ni;
	struct page *ipage;
	int err = 0;

	ipage = get_node_page(F2FS_I_SB(inode), inode->i_ino); // 获取待查看文件的ino对应的ipage
	if (IS_ERR(ipage))
		return PTR_ERR(ipage);

	if (!f2fs_has_inline_data(inode)) {
		err = -EAGAIN;
		goto out;
	}

	ilen = min_t(size_t, MAX_INLINE_DATA, i_size_read(inode)); // 比较inode的大小，和文件的大小
	if (start >= ilen)
		goto out;
	if (start + len < ilen) // 需要读取的数据仍然在inline data范围以内
		ilen = start + len; //将读取范围更新为start + len
	ilen -= start; // 得到需要读取的时间的范围

	get_node_info(F2FS_I_SB(inode), inode->i_ino, &ni); // 获取node information
	byteaddr = (__u64)ni.blk_addr << inode->i_sb->s_blocksize_bits; // 这个blk_addr，是node的地址，获取起始的地址，注意这个地址是按字节计算的
	byteaddr += (char *)inline_data_addr(ipage) - (char *)F2FS_INODE(ipage); // 加上一些非直接数据的域的大小
	err = fiemap_fill_next_extent(fieinfo, start, byteaddr, ilen, flags);
out:
	f2fs_put_page(ipage, 1);
	return err;
}
