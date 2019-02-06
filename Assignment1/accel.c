#include<linux/init.h>
#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/types.h>
#include<linux/kdev_t.h>
#include<linux/fs.h>
#include<linux/device.h>
#include<linux/cdev.h>
#include<linux/random.h>
#include<linux/uaccess.h>
#include<linux/version.h>


static dev_t first; //VARIABLE FOR DEVICE NUMBER
dev_t x;
dev_t y;
dev_t z;
int major,minor;


static struct cdev xc_dev;
static struct cdev yc_dev;
static struct cdev zc_dev;

static struct class *cls;

uint16_t value;

//PERMISSIONS
static int permission(struct device* dev,struct kobj_uevent_env* env)
{
  add_uevent_var(env,"DEVMODE=%#o",0777);
  return 0;
}


//STEP 4: CALLBACK FUNCTIONS
// CALLBACK FUNCTIONS FOR X-AXIS
static int x_open(struct inode *i, struct file *f)
{
	printk(KERN_INFO "x_axis: open()\n");
	return 0;
}
static int x_close(struct inode *i, struct file *f)
{
	printk(KERN_INFO "x_axis: close()\n");
	return 0;
}
static ssize_t x_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{


uint16_t rand;
	get_random_bytes(&rand, sizeof(rand));
	value=rand&0x03FF;
	copy_to_user(buf,&value,sizeof(rand));

	printk(KERN_INFO "x_axis: read()\n");
    	return 0;

}

//CALLBACK FUNCTIONS FOR Y-AXIS
static int y_open(struct inode *i, struct file *f)
{
	printk(KERN_INFO "y_axis: open()\n");
	return 0;
}
static int y_close(struct inode *i, struct file *f)
{
	printk(KERN_INFO "y_axis: close()\n");
	return 0;
}
static ssize_t y_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
	
	uint16_t rand;
	get_random_bytes(&rand, sizeof(rand));
	value=rand&0x03FF;
	copy_to_user(buf,&value,sizeof(rand));

	printk(KERN_INFO "y_axis: read()\n");
    	return 0;
}

//CALLBACK FUNCTIONS FOR Z-AXIS
static int z_open(struct inode *i, struct file *f)
{
	printk(KERN_INFO "z_axis: open()\n");
	return 0;
}
static int z_close(struct inode *i, struct file *f)
{
	printk(KERN_INFO "z_axis: close()\n");
	return 0;
}
static ssize_t z_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
	
	uint16_t rand;
	get_random_bytes(&rand, sizeof(rand));
	value=rand&0x03FF;
	copy_to_user(buf,&value,sizeof(rand));

	printk(KERN_INFO "z_axis: read()\n");
    	return 0;
}


static struct file_operations xops =
				{
					.owner = THIS_MODULE,
					.open = x_open,
					.release = x_close,
					.read = x_read
				};

static struct file_operations yops =
				{
					.owner = THIS_MODULE,
					.open = y_open,
					.release = y_close,
					.read = y_read
				};
static struct file_operations zops =
				{
					.owner = THIS_MODULE,
					.open = z_open,
					.release = z_close,
					.read = z_read
				};


static __init int accelo_init(void)
{
	printk(KERN_INFO "Accelerometer driver registered");


//STEP1:RESERVE<MAJOR,MINOR>

	if ((alloc_chrdev_region(&first, 0, 3, "Accelerometer")) < 0)
	{
		return -1;
	}

	major=MAJOR(first);
	minor=MINOR(first);
	x=MKDEV(major,minor);
	y=MKDEV(major,minor+1);
	z=MKDEV(major,minor+2);

//STEP2:CREATION OF DEVICE FILE	

	if ((cls=class_create(THIS_MODULE, "accelerometer"))==NULL)
	{
		unregister_chrdev_region(first,3);
		return -1;
	}

	cls->dev_uevent = permission;

	if((device_create(cls, NULL, x, NULL, "adxl_x"))==NULL)
	{
		class_destroy(cls);
		unregister_chrdev_region(first,3);
		return -1;
	}
	if((device_create(cls, NULL, y, NULL, "adxl_y"))==NULL)
	{
		class_destroy(cls);
		unregister_chrdev_region(first,3);
		return -1;
	}
	if((device_create(cls, NULL, z, NULL, "adxl_z"))==NULL)
	{
		class_destroy(cls);
		unregister_chrdev_region(first,3);
		return -1;
	}

//STEP 3:LINK FOPS AND CDEV TO DEVICE NODE

	cdev_init(&xc_dev, &xops);
	if(cdev_add(&xc_dev, x, 1)== -1)
	{
		device_destroy(cls, x);
		class_destroy(cls);
		unregister_chrdev_region(first,3);
		return -1;
	}
	cdev_init(&yc_dev, &yops);
	if(cdev_add(&yc_dev, y, 1)== -1)
	{
		device_destroy(cls, x);
		device_destroy(cls, y);
		class_destroy(cls);
		unregister_chrdev_region(first,3);
		return -1;
	}
	cdev_init(&zc_dev, &zops);
	if(cdev_add(&zc_dev, z, 1)== -1)
	{
		device_destroy(cls, x);
		device_destroy(cls, y);
		device_destroy(cls, z);
		class_destroy(cls);
		unregister_chrdev_region(first,3);
		return -1;
}
return 0;
}

static __exit void accelo_exit(void)
{
	
	cdev_del(&xc_dev);
	cdev_del(&yc_dev);
	cdev_del(&zc_dev);
	device_destroy(cls, x);
	device_destroy(cls, y);
	device_destroy(cls, z);
	class_destroy(cls);
	unregister_chrdev_region(first,3);
	printk(KERN_INFO "Accelerometer driver unregistered\n\n");
	
}

module_init(accelo_init);
module_exit(accelo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SAHANA H.G <h20180117@goa.bits-pilani.ac.in>");
MODULE_DESCRIPTION("ACCELEROMETER");
