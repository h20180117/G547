/* Linux device driver to interface L3G4200D GY50 gyroscope sensor via I2C to Raspberry Pi*/


#include <linux/kernel.h>      
#include <linux/module.h>      
#include <linux/fs.h>
#include <asm/uaccess.h>       
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/gpio.h>                 // Required for the GPIO functions


#define DEVICE_NAME "gyro"
#define MAJOR_NO 115

//Definition of L3G4200D registers

#define REG_DEVID 0x0F //WHO_AM_I
#define CTRL_REG1 0x20
#define CTRL_REG2 0x21
#define CTRL_REG3 0x22
#define CTRL_REG4 0x23
#define CTRL_REG5 0x24
#define REG_OUT_X_L 0x28 //X_LSB
#define REG_OUT_X_H 0x29 //X_MSB
#define REG_OUT_Y_L 0x2A //Y_LSB
#define REG_OUT_Y_H 0x2B //Y_MSB
#define REG_OUT_Z_L 0x2C //Z_LSB
#define REG_OUT_Z_H 0x2D //Z_MSB


struct class *cl;
static struct i2c_client * my_client;
struct i2c_adapter * my_adap;
static dev_t first; //Variable for device number
static struct cdev c_dev;
static u8 axis_data[3];

//Function to read internal registers of the client device

static u8 adxl_read(struct i2c_client *client, u8 reg)
{
	int ret;

	ret = i2c_smbus_read_byte_data(client, reg);

	return (u8)ret;
}

//Function to write into internal registers of the client device

static int adxl_write(struct i2c_client *client, u8 reg, u8 data)
{
	int ret;

	ret = i2c_smbus_write_byte_data(client, reg, data);


	return ret;
}

//Call back functions :
//Function to read the output through user space program

static ssize_t my_read(struct file *f, char __user *buf, size_t len, loff_t *off) {	

	printk(KERN_INFO "Driver read()\n");
	
	axis_data[0] = adxl_read(my_client, ((REG_OUT_X_H << 8) | REG_OUT_X_L));
	axis_data[1] = adxl_read(my_client, ((REG_OUT_Y_H << 8) | REG_OUT_Y_L));
	axis_data[2] = adxl_read(my_client, ((REG_OUT_Z_H << 8) | REG_OUT_Z_L));

	
	if (*off == 0)
	{
		if (copy_to_user(buf, &axis_data,3) != 0)
		{
			printk(KERN_INFO "Driver read: Inside if\n");
			return -EFAULT;
		}
		else 
		{
	
			return 3;
		}
	}
	else
		return 0;
}


static int my_open(struct inode *i, struct file *f)
{
	  printk(KERN_INFO "Driver: open()\n");
	    return 0;
}

static int my_close(struct inode *i, struct file *f)
{
	  printk(KERN_INFO "Driver: close()\n");
	    return 0;
}

static ssize_t my_write(struct file *f, const char __user *buf,
		   size_t len, loff_t *off)
{
	  printk(KERN_INFO "Driver: write()\n");
	    return len;
}

static struct file_operations my_dev_ops = {.read = my_read,
						.owner = THIS_MODULE,
						.open = my_open,
						.release = my_close,
						.write = my_write};

//Initialization module

static int __init adxl_init(void)
{


		u8 readvalue,temp; 
        printk(KERN_INFO "Welcome to LG34200D GY50 Gyroscope!\n");
        
       //Step 1 : Reserve <Major,Minor>
        if (alloc_chrdev_region(&first, 0, 1, DEVICE_NAME) < 0) {
        printk(KERN_DEBUG "Can't register device\n");
        return -1;
        }
        
	   //Step 2 : Creation of device file
		if (IS_ERR(cl = class_create(THIS_MODULE, "chardrv"))){
			unregister_chrdev_region(first, 1);
			}

		if (IS_ERR(device_create(cl, NULL, first, NULL, "gyro"))) {
		class_destroy(cl);
		unregister_chrdev_region(first,1);
	}

		//Step 3 :Link FOPS and CDEV to device node
		cdev_init(&c_dev,&my_dev_ops);
		if (cdev_add(&c_dev, first,1) < 0)
		{
		device_destroy(cl, first);
		class_destroy(cl);
		unregister_chrdev_region(first,1);
		return -1;
		}
		
	 //Attaching a temporary device to the I2C adapter
		my_adap = i2c_get_adapter(1); // 1 means i2c-1 bus
		if (!(my_client = i2c_new_dummy(my_adap, 0x69))) //0x69 is the i2c device slave address 
		{ 
		printk(KERN_INFO "Couldn't acquire i2c slave");
		unregister_chrdev(MAJOR_NO, DEVICE_NAME);
		device_destroy(cl, first);
		class_destroy(cl);
		return -1;
	}
		//Detecting the gyroscope by reading it's WHO_M_I register
		readvalue = adxl_read(my_client,0x0F);
		if (readvalue == (0b11010011)) {
		printk("Gyroscope detected, value = %d\r\n",readvalue);
	}
	
	// Enable x, y, z and turn off power down:
	
    temp = adxl_read(my_client,CTRL_REG1);
	temp = temp | (0b00001111);
	adxl_write(my_client, CTRL_REG1, temp);

// If you'd like to adjust/use the HPF, you can edit the line below to configure CTRL_REG2:

	temp = adxl_read(my_client,CTRL_REG2);
	temp = temp & (0b00000000);
	adxl_write(my_client, CTRL_REG2, temp);

	
  // Configure CTRL_REG3 to generate data ready interrupt on INT2
	
	temp = adxl_read(my_client,CTRL_REG3);
	temp = temp | (1<<4);
	adxl_write(my_client, CTRL_REG3, temp);

	// CTRL_REG4 controls the full-scale range, among other things:

	temp = adxl_read(my_client,CTRL_REG4);
	temp = temp & (0b00110000); // Setting Full SCale range to +/_ 2000dps
	adxl_write(my_client, CTRL_REG4, temp);

	//Reading the output X,Y and Z data registers
	axis_data[0] = adxl_read(my_client, ((REG_OUT_X_H << 8) | REG_OUT_X_L));
	axis_data[1] = adxl_read(my_client, ((REG_OUT_Y_H << 8) | REG_OUT_Y_L));
	axis_data[2] = adxl_read(my_client, ((REG_OUT_Z_H << 8) | REG_OUT_Z_L));
	
	printk(KERN_INFO "X axis : %d\n", axis_data[0]);
	printk(KERN_INFO "Y axis : %d\n", axis_data[1]);
	(KERN_INFO "Z axis : %d\n", axis_data[2]);
	return 0;
}
 
//Cleanup module
static void __exit adxl_exit(void)
{
    printk(KERN_INFO "GY50: Removing module");
 	
	i2c_unregister_device(my_client);
    cdev_del(&c_dev);
 	device_destroy(cl, first);
	class_destroy(cl);
	unregister_chrdev_region(first, 1);
        
 
}


module_init(adxl_init);
module_exit(adxl_exit);

MODULE_DESCRIPTION("driver");
MODULE_AUTHOR("SahanaandShaheen");
MODULE_LICENSE("GPL"); 
