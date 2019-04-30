#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/genhd.h> 
#include <linux/blkdev.h>
#include <linux/hdreg.h> 
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "ram_device.h"
#include "partition.h"

#define RB_DEVICE_SIZE 1024 /*sectors*/
/* So, total device size = 1024 * 512 bytes = 0.5MB */

static u8 *d_data;
static u_int rb_major = 0;

#define RB_FIRST_MINOR 0
#define RB_MINOR_CNT 16
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*a))

#define SECTOR_SIZE 512
#define MBR_SIZE SECTOR_SIZE
#define MBR_DISK_SIGNATURE_OFFSET 442
#define MBR_DISK_SIGNATURE_SIZE 4
#define PARTITION_TABLE_OFFSET 446
#define PARTITION_ENTRY_SIZE 16 
#define PARTITION_TABLE_SIZE 64 
#define MBR_SIGNATURE_OFFSET 510
#define MBR_SIGNATURE_SIZE 2
#define MBR_SIGNATURE 0xAA55
#define BR_SIZE SECTOR_SIZE
#define BR_SIGNATURE_OFFSET 510
#define BR_SIGNATURE_SIZE 2
#define BR_SIGNATURE 0xAA55

typedef struct
{
	unsigned char bootType; 
	unsigned char startHead;
	unsigned char startSec:6;
	unsigned char startCylH:2;
	unsigned char startCyl;
	unsigned char partType;
	unsigned char endHead;
	unsigned char endSec:6;
	unsigned char endCylH:2;
	unsigned char endCyl;
	unsigned int AbsStartSec;
	unsigned int secCtr;
} PartEntry;

typedef PartEntry PartTable[4];

static PartTable def_part_table =
{
	{
		bootType: 0x00,
		startHead: 0x00,
		startSec: 0x2,
		startCyl: 0x00,
		partType: 0x83,
		endHead: 0x00,
		endSec: 0x20,
		endCyl: 0x0E,
		AbsStartSec: 0x00000001,
		secCtr: 0x00000200
	},
	{
		bootType: 0x00,
		startHead: 0x00,
		startSec: 0x1,
		startCyl: 0x0F, 
		partType: 0x83,
		endHead: 0x00,
		endSec: 0x20,
		endCyl: 0x1D,
		AbsStartSec: 0x00000201,
		secCtr: 0x00000200
	}/*,
	{
		bootType: 0x00,
		startHead: 0x00,
		startSec: 0x1,
		startCyl: 0x1E,
		partType: 0x83,
		endHead: 0x00,
		endSec: 0x20,
		endCyl: 0x30,
		AbsStartSec: 0x000003C0,
		secCtr: 0x00000260
	},
	{
		
		bootType: 0x00,
		startHead: 0x00,
		startSec: 0x1,
		startCyl: 0x31,
		partType: 0x83,
		endHead: 0x00,
		endSec: 0x20,
		endCyl: 0x3F,
		AbsStartSec: 0x00000620,
		secCtr: 0x000001E0
	}*/
};
/*static unsigned int def_log_part_br_cyl[] = {0x0F, 0x14, 0x19};
static const PartTable def_log_part_table[] =
{
	{
		{
			bootType: 0x00,
			startHead: 0x00,
			startSec: 0x2,
			startCyl: 0x0F,
			partType: 0x83,
			endHead: 0x00,
			endSec: 0x20,
			endCyl: 0x13,
			AbsStartSec: 0x00000001,
			secCtr: 0x0000009F
		},
		{
			bootType: 0x00,
			startHead: 0x00,
			startSec: 0x1,
			startCyl: 0x14,
			partType: 0x05,
			endHead: 0x00,
			endSec: 0x20,
			endCyl: 0x18,
			AbsStartSec: 0x000000A0,
			secCtr: 0x000000A0
		},
	},
	{
		{
			bootType: 0x00,
			startHead: 0x00,
			startSec: 0x2,
			startCyl: 0x14,
			partType: 0x83,
			endHead: 0x00,
			endSec: 0x20,
			endCyl: 0x18,
			AbsStartSec: 0x00000001,
			secCtr: 0x0000009F
		},
		{
			bootType: 0x00,
			startHead: 0x00,
			startSec: 0x1,
			startCyl: 0x19,
			partType: 0x05,
			endHead: 0x00,
			endSec: 0x20,
			endCyl: 0x1D,
			AbsStartSec: 0x00000140,
			secCtr: 0x000000A0
		},
	},
	{
		{
			bootType: 0x00,
			startHead: 0x00,
			startSec: 0x2,
			startCyl: 0x19,
			partType: 0x83,
			endHead: 0x00,
			endSec: 0x20,
			endCyl: 0x1D,
			AbsStartSec: 0x00000001,
			secCtr: 0x0000009F
		},
	}
};*/

static void copyMbr(u8 *disk)
{
	memset(disk, 0x0, MBR_SIZE);
	*(unsigned long *)(disk + MBR_DISK_SIGNATURE_OFFSET) = 0x36E5756D;
	memcpy(disk + PARTITION_TABLE_OFFSET, &def_part_table, PARTITION_TABLE_SIZE);
	*(unsigned short *)(disk + MBR_SIGNATURE_OFFSET) = MBR_SIGNATURE;
}
static void copyBr(u8 *disk, int startCylinder, const PartTable *part_table)
{
	disk += (startCylinder * 32 * SECTOR_SIZE);
	memset(disk, 0x0, BR_SIZE);
	memcpy(disk + PARTITION_TABLE_OFFSET, part_table,
		PARTITION_TABLE_SIZE);
	*(unsigned short *)(disk + BR_SIGNATURE_OFFSET) = BR_SIGNATURE;
}
void copyMbrBr(u8 *disk)
{
	int i;

	copyMbr(disk);
	/*for (i = 0; i < ARRAY_SIZE(def_log_part_table); i++)
	{
		copyBr(disk, def_log_part_br_cyl[i], &def_log_part_table[i]);
	}*/
}


int ramdevice_init(void)
{
	d_data = vmalloc(RB_DEVICE_SIZE * RB_SECTOR_SIZE);
	if (d_data == NULL)
		return -ENOMEM;
	copyMbrBr(d_data);
	return RB_DEVICE_SIZE;
}

void ramdevice_cleanup(void)
{
	vfree(d_data);
}

void ramdevice_write(sector_t sector_off, u8 *buf, unsigned int sectors)
{
	memcpy(d_data + sector_off * RB_SECTOR_SIZE, buf,
		sectors * RB_SECTOR_SIZE);
}

void ramdevice_read(sector_t sector_off, u8 *buf, unsigned int sectors)
{
	memcpy(buf, d_data + sector_off * RB_SECTOR_SIZE,
		sectors * RB_SECTOR_SIZE);
}

static struct rb_device
{
	unsigned int size;
	spinlock_t lock;
	struct request_queue *rb_queue;
	struct gendisk *rb_disk;
} rb_dev;

static int rb_open(struct block_device *bdev, fmode_t mode)
{
	unsigned unit = iminor(bdev->bd_inode);

	printk(KERN_INFO "dof: Device is opened\n");
	printk(KERN_INFO "dof: Inode number is %d\n", unit);

	if (unit > RB_MINOR_CNT)
		return -ENODEV;
	return 0;
}

/*#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0))
static int rb_close(struct gendisk *disk, fmode_t mode)
{
	printk(KERN_INFO "rb: Device is closed\n");
	return 0;
}
#else*/
static void rb_close(struct gendisk *disk, fmode_t mode)
{
	printk(KERN_INFO "dof: Device is closed\n");
}


static int rb_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	geo->heads = 1;
	geo->cylinders = 64;
	geo->sectors = 32;
	geo->start = 0;
	return 0;
}

static int rb_transfer(struct request *req)
{
	int dir = rq_data_dir(req);
	sector_t start_sector = blk_rq_pos(req);
	unsigned int sector_cnt = blk_rq_sectors(req);

/*#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0))
#define BV_PAGE(bv) ((bv)->bv_page)
#define BV_OFFSET(bv) ((bv)->bv_offset)
#define BV_LEN(bv) ((bv)->bv_len)
	struct bio_vec *bv;
#else*/
#define BV_PAGE(bv) ((bv).bv_page)
#define BV_OFFSET(bv) ((bv).bv_offset)
#define BV_LEN(bv) ((bv).bv_len)
	struct bio_vec bv;

	struct req_iterator iter;

	sector_t sector_offset;
	unsigned int sectors;
	u8 *buffer;

	int ret = 0;

	printk(KERN_INFO "dof: Dir:%d; Sec:%lld; Cnt:%d\n", dir, start_sector, sector_cnt);

	sector_offset = 0;
	rq_for_each_segment(bv, req, iter)
	{
		buffer = page_address(BV_PAGE(bv)) + BV_OFFSET(bv);
		if (BV_LEN(bv) % RB_SECTOR_SIZE != 0)
		{
			printk(KERN_ERR "dof: Should never happen: "
				"bio size (%d) is not a multiple of RB_SECTOR_SIZE (%d).\n"
				"This may lead to data truncation.\n",
				BV_LEN(bv), RB_SECTOR_SIZE);
			ret = -EIO;
		}
		sectors = BV_LEN(bv) / RB_SECTOR_SIZE;
		printk(KERN_INFO "dof: Start Sector: %lld, Sector Offset: %lld; Buffer: %p; Length: %u sectors\n",start_sector, sector_offset, buffer, sectors);
		if (dir == WRITE) 
		{
			ramdevice_write(start_sector + sector_offset, buffer, sectors);
		}
		else 
		{
			ramdevice_read(start_sector + sector_offset, buffer, sectors);
		}
		sector_offset += sectors;
	}
	if (sector_offset != sector_cnt)
	{
		printk(KERN_ERR "dof: bio info doesn't match with the request info");
		ret = -EIO;
	}

	return ret;
}
static void rb_request(struct request_queue *q)
{
	struct request *req;
	int ret;
	while ((req = blk_fetch_request(q)) != NULL)
	{
#if 0
		if (!blk_fs_request(req))
		{
			printk(KERN_NOTICE "rb: Skip non-fs request\n");
			__blk_end_request_all(req, 0);
			//__blk_end_request(req, 0, blk_rq_bytes(req));
			continue;
		}
#endif
		ret = rb_transfer(req);
		__blk_end_request_all(req, ret);
		//__blk_end_request(req, ret, blk_rq_bytes(req));
	}
}

static struct block_device_operations rb_fops =
{
	.owner = THIS_MODULE,
	.open = rb_open,
	.release = rb_close,
	.getgeo = rb_getgeo,
};
static int __init rb_init(void)
{
	int ret;
	if ((ret = ramdevice_init()) < 0)
	{
		return ret;
	}
	rb_dev.size = ret;
	rb_major = register_blkdev(rb_major, "dof");
	if (rb_major <= 0)
	{
		printk(KERN_ERR "dof: Unable to get Major Number\n");
		ramdevice_cleanup();
		return -EBUSY;
	}
	spin_lock_init(&rb_dev.lock);
	rb_dev.rb_queue = blk_init_queue(rb_request, &rb_dev.lock);
	if (rb_dev.rb_queue == NULL)
	{
		printk(KERN_ERR "dof: blk_init_queue failure\n");
		unregister_blkdev(rb_major, "dof");
		ramdevice_cleanup();
		return -ENOMEM;
	}
	rb_dev.rb_disk = alloc_disk(RB_MINOR_CNT);
	if (!rb_dev.rb_disk)
	{
		printk(KERN_ERR "dof: alloc_disk failure\n");
		blk_cleanup_queue(rb_dev.rb_queue);
		unregister_blkdev(rb_major, "dof");
		ramdevice_cleanup();
		return -ENOMEM;
	}

	rb_dev.rb_disk->major = rb_major;
	rb_dev.rb_disk->first_minor = RB_FIRST_MINOR;
	rb_dev.rb_disk->fops = &rb_fops;
	rb_dev.rb_disk->private_data = &rb_dev;
	rb_dev.rb_disk->queue = rb_dev.rb_queue;
	sprintf(rb_dev.rb_disk->disk_name, "dof");
	set_capacity(rb_dev.rb_disk, rb_dev.size);
	add_disk(rb_dev.rb_disk);
	printk(KERN_INFO "dof: Ram Block driver initialised (%d sectors; %d bytes)\n",
		rb_dev.size, rb_dev.size * RB_SECTOR_SIZE);

	return 0;
}

static void __exit rb_cleanup(void)
{
	del_gendisk(rb_dev.rb_disk);
	put_disk(rb_dev.rb_disk);
	blk_cleanup_queue(rb_dev.rb_queue);
	unregister_blkdev(rb_major, "dof");
	ramdevice_cleanup();
}

module_init(rb_init);
module_exit(rb_cleanup);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Ram Block Driver");
MODULE_ALIAS_BLOCKDEV_MAJOR(rb_major);
