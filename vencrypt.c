#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>

#define VE_MAJOR 182
#define VE_MAX_DEVICES 2
#define VE_MINOR_PT 0 // plaintext node
#define VE_MINOR_CT 1 // ciphertext node

typedef struct {
	struct cdev cdev;
	// AES support data...
} vencrypt_device_data_t;

static struct class *vencrypt_class;
static dev_t device_number;

static bool encrypt=true;
module_param(encrypt,bool,0660);
MODULE_PARM_DESC(myshort, "1=encrypt, 0=decrypt");

static char *key="(no key)";
module_param(key,charp,0660);
MODULE_PARM_DESC(key, "AES encryption key");

// device nodes
static struct {
	int minor;
	const char *name;
} nodes[] = { { VE_MINOR_PT, "vencrypt_pt" }, { VE_MINOR_CT, "vencrypt_ct" } };

static int vencrypt_open(struct inode *inode, struct file *fp)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s\n", __func__);

	fp->private_data = vencrypt_data;

	return 0;
}

static ssize_t vencrypt_read(struct file *fp, char __user *user_buffer,
			     size_t size, loff_t *offset)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s\n", __func__);

	return 0;
}

static ssize_t vencrypt_write(struct file *fp, const char *buffer, size_t size,
			      loff_t *offset)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s\n", __func__);

	return 0;
}

static int vencrypt_release(struct inode *node, struct file *fp)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s\n", __func__);
	return 0;
}

vencrypt_device_data_t devs[VE_MAX_DEVICES];

const struct file_operations vencrypt_fops = {
	.owner = THIS_MODULE,
	.open = vencrypt_open,
	.read = vencrypt_read,
	.write = vencrypt_write,
	.release = vencrypt_release,
	//.unlocked_ioctl = vencrypt_ioctl
};

int vencrypt_init(void)
{
	int ind, retval, major;
	dev_t dev;

	printk("VENCRYPT: %s encrypt=%u key=%s\n", __func__, encrypt, key);
	retval = alloc_chrdev_region(&device_number, 0, VE_MAX_DEVICES,
				     "vencrypt");
	if (retval) {
		pr_err("%s: Failed to allocate device number error:%d\n",
		       __func__, retval);
		return retval;
	}

	major = MAJOR(device_number);
	vencrypt_class = class_create(THIS_MODULE, "vencrypt_class");

	for (ind = 0; ind < (sizeof(nodes) / sizeof(nodes[0])); ind++) {
		printk("%s: adding %s\n", __func__, nodes[ind].name);
		dev = MKDEV(major, nodes[ind].minor);
		cdev_init(&devs[nodes[ind].minor].cdev, &vencrypt_fops);
		retval = cdev_add(&devs[nodes[ind].minor].cdev, dev, 1);

		if (retval) {
			pr_info("%s: Failed in adding cdev to subsystem retval:%d\n",
				__func__, retval);
		} else {
			device_create(vencrypt_class, NULL, dev, NULL, "%s",
				      nodes[ind].name);
		}
	}

	return 0;
}

void vencrypt_exit(void)
{
	int ind;
	int major = MAJOR(device_number);
	dev_t dev;
	printk("VENCRYPT: %s\n", __func__);
	for (ind = 0; ind < (sizeof(nodes) / sizeof(nodes[0])); ind++) {
		dev = MKDEV(major, nodes[ind].minor);
		/* release devs[ind] fields */
		cdev_del(&devs[nodes[ind].minor].cdev);
		device_destroy(vencrypt_class, dev);
	}
	class_destroy(vencrypt_class);
	unregister_chrdev_region(device_number, VE_MAX_DEVICES);
}

module_init(vencrypt_init);
module_exit(vencrypt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Darran Hunt <darran@hunt.net.nz>");
MODULE_DESCRIPTION("Virscient AES linux driver challenge");
MODULE_VERSION("1.0");
