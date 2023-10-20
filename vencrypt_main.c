#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include "aes/aes.h"

#define VE_MAX_DEVICES 2
#define VE_MINOR_PT 0 // plaintext node
#define VE_MINOR_CT 1 // ciphertext node

#define VE_BLOCK_SIZE 16 // encrypt / decrypt block size
#define VE_MAX_KEY_SIZE 32 // max AES key size

typedef struct vencrypt_device_data {
	struct cdev cdev;
	// AES support data...
	int nodeId;
	struct AES_ctx ctx;
	unsigned char iv[16];
	unsigned char *output_data;
	size_t output_size;
	size_t output_offset;
	size_t input_processed;
	struct vencrypt_device_data *pt;
	struct vencrypt_device_data *ct;
} vencrypt_device_data_t;

static struct class *vencrypt_class;
static dev_t device_number;
static vencrypt_device_data_t devs[VE_MAX_DEVICES] = {
	0,
};

static bool encrypt = true;
module_param(encrypt, bool, 0660);
MODULE_PARM_DESC(myshort, "1=encrypt, 0=decrypt");

static char *key = "(no key)";
module_param(key, charp, 0660);
MODULE_PARM_DESC(key, "AES encryption key");

// device nodes
static struct {
	int minor;
	const char *name;
} nodes[] = { { VE_MINOR_PT, "vencrypt_pt" }, { VE_MINOR_CT, "vencrypt_ct" } };

static int vencrypt_open(struct inode *inode, struct file *fp)
{
	vencrypt_device_data_t *vencrypt_data =
		container_of(inode->i_cdev, struct vencrypt_device_data, cdev);

	printk("VENCRYPT: %s.%d fp %p data %p\n", __func__, __LINE__, fp,
	       vencrypt_data);

	fp->private_data = vencrypt_data;
	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);

	// clear IV on open
	memset(&vencrypt_data->iv[0], 0, sizeof(vencrypt_data->iv));
	AES_init_ctx_iv(&vencrypt_data->ctx, key, vencrypt_data->iv);

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	return 0;
}

/**
 * Get padding remainder size per PKCS#7
 */
static size_t get_remainder(size_t size, size_t block_size)
{
	size_t remainder = size % block_size;
	if (remainder == 0) {
		// Per PKCS#7 add 16 bytes to enable single byte pad to be recognised
		remainder = block_size;
	}
	return remainder;
}

/**
 * perform cipher operation (encrypt or decrypt)
 */
static ssize_t do_crypt(vencrypt_device_data_t *vencrypt_data, bool encrypt,
			const unsigned char *key_string,
			const unsigned char *input_data, size_t input_size,
			size_t input_offset)
{
	size_t key_size = strlen(key_string) / 2;
	size_t output_size;
	unsigned char key[VE_MAX_KEY_SIZE];
	int ind;
	unsigned char *buf;

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	// check key is appropriately sized
	// XXX fixed size key. 128?
	if (((key_size * 2) != strlen(key_string)) ||
	    (strlen(key_string) > (VE_MAX_KEY_SIZE * 2))) {
		// bad / odd key size
		pr_info("bad key string length %lu\n", strlen(key_string));
		return -EAGAIN;
		//goto out;
	}

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	// convert key to binary
	for (ind = 0; ind < key_size; ind++) {
		char digits[3] = { key_string[ind * 2], key_string[ind * 2 + 1],
				   0 };
		long data;
		int res;

		res = kstrtol(digits, 16, &data);
		if (res) {
			// invalid character(s)
			pr_info("bad key string content at index %d \"%s\"\n",
				ind * 2, digits);
			return -EAGAIN;
			//goto out;
		}
		key[ind] = (unsigned char)data;
	}

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	if (encrypt) {
		// pad using PKCS#7 as needed
		int remainder = get_remainder(input_size, VE_BLOCK_SIZE);
		printk("VENCRYPT: %s.%d remainder %d\n", __func__, __LINE__,
		       remainder);
		buf = vmalloc(input_size + remainder);
		if (buf == NULL) {
			pr_err("%s: Failed to allocate buffer\n", __func__);
			return -EAGAIN;
		}
		printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
		copy_from_user(buf, input_data + input_offset, input_size);
		printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
		// pad
		for (ind = 0; ind < remainder; ind++) {
			// per PKCS#7 use the pad size as the pad value
			buf[input_size + ind] = remainder;
		}
		printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
		AES_CBC_encrypt_buffer(&vencrypt_data->ctx, buf,
				       input_size + remainder);
		vencrypt_data->ct->output_data = buf;
		output_size = input_size + remainder;
		vencrypt_data->ct->output_size = output_size;
	} else {
		int remainder;
		buf = vmalloc(input_size);
		copy_from_user(buf, input_data + input_offset, input_size);
		AES_CBC_decrypt_buffer(&vencrypt_data->ctx, buf, input_size);
		// get padding size
		remainder = buf[input_size - 1];
		vencrypt_data->pt->output_data = buf;
		output_size = input_size - remainder;
		vencrypt_data->pt->output_size = output_size;
	}
	printk("VENCRYPT: %s completed %lu -> %lu bytes\n", __func__,
	       input_size, output_size);

	return output_size;
}

/**
 * Handle a read by the user.
 */
static ssize_t vencrypt_read(struct file *fp, char __user *user_buffer,
			     size_t size, loff_t *offset)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	size_t copy_size = min(vencrypt_data->output_size, size);
	size_t off = (offset == NULL) ? 0 : *offset;
	printk("VENCRYPT: %s\n", __func__);

	if (copy_size == 0) {
		printk("VENCRYPT: %s no data (%lu -> %lu)\n", __func__,
		       vencrypt_data->output_size, size);
		// no data to return
		return 0;
	}

	if (encrypt) {
		if (vencrypt_data != vencrypt_data->ct) {
			// can't read from pt when encrypting
			pr_info("VENCRYPT: %s can't read from pt when encrypting\n",
				__func__);
			return -EACCES;
		}
	} else {
		if (vencrypt_data != vencrypt_data->pt) {
			// can't read from ct when decrypting
			pr_info("VENCRYPT: %s can't read from ct when decrypting\n",
				__func__);
			return -EACCES;
		}
	}

	printk("VENCRYPT: %s copy %lu bytes to user\n", __func__, copy_size);
	copy_to_user(user_buffer + off, vencrypt_data->output_data, copy_size);

	vencrypt_data->output_offset += copy_size;
	vencrypt_data->output_size -= copy_size;

	// this is naive, need to use scatter gather?
	if (vencrypt_data->output_size <= 0) {
		vencrypt_data->output_size = 0;
		vfree(vencrypt_data->output_data);
	}

	return copy_size;
}

/**
 * Handle a write by the user.
 */
static ssize_t vencrypt_write(struct file *fp, const char *buffer, size_t size,
			      loff_t *offset)
{
	size_t output_size;
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s.%d fp %p data %p\n", __func__, __LINE__, fp,
	       vencrypt_data);

	if (encrypt) {
		if (vencrypt_data != vencrypt_data->pt) {
			// can't write to ct when encrypting
			pr_info("VENCRYPT: %s can't write to ct when encrypting\n",
				__func__);
			return -EACCES;
		}
	} else {
		if (vencrypt_data != vencrypt_data->ct) {
			// can't write to pt when decrypting
			pr_info("VENCRYPT: %s can't write to pt when decrypting\n",
				__func__);
			return -EACCES;
		}
	}

	size_t off = (offset != NULL) ? *offset : 0;
	output_size = do_crypt(vencrypt_data, encrypt, key, buffer, size, off);

	return size; // consumed bytes
}

static int vencrypt_release(struct inode *node, struct file *fp)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s\n", __func__);

	// XXX free buffers

	return 0;
}

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
	int minor; // the minor device with aes active

	// set up cipher for CT node
	if (encrypt) {
		minor = nodes[VE_MINOR_PT]
				.minor; // plaintext node will be encrypting
	} else {
		minor = nodes[VE_MINOR_CT]
				.minor; // cyphertext node will be decrypting
	}
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

	// add reference to each node
	devs[nodes[VE_MINOR_CT].minor].ct = &devs[nodes[VE_MINOR_CT].minor];
	devs[nodes[VE_MINOR_CT].minor].pt = &devs[nodes[VE_MINOR_PT].minor];
	devs[nodes[VE_MINOR_PT].minor].ct = &devs[nodes[VE_MINOR_CT].minor];
	devs[nodes[VE_MINOR_PT].minor].pt = &devs[nodes[VE_MINOR_PT].minor];

	// set up the device nodes
	retval = 0;
	for (ind = 0; ind < (sizeof(nodes) / sizeof(nodes[0])); ind++) {
		printk("%s: adding %s\n", __func__, nodes[ind].name);
		dev = MKDEV(major, nodes[ind].minor);
		cdev_init(&devs[nodes[ind].minor].cdev, &vencrypt_fops);
		retval = cdev_add(&devs[nodes[ind].minor].cdev, dev, 1);

		if (retval) {
			pr_info("%s: Failed in adding cdev to subsystem retval:%d\n",
				__func__, retval);
		} else {
			printk("%s: device_create[%d] drvptr = %p\n", __func__,
			       ind, &devs[nodes[ind].minor]);
			device_create(vencrypt_class, NULL, dev,
				      &devs[nodes[ind].minor], "%s",
				      nodes[ind].name);
		}
	}

	return retval;
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
