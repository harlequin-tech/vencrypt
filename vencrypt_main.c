#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/mutex.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include "aes/aes.h"

#define VE_MAX_DEVICES 2
#define VE_MINOR_PT 0 // plaintext node
#define VE_MINOR_CT 1 // ciphertext node

#define VE_BLOCK_SIZE 16 // encrypt / decrypt block size
#define VE_MAX_KEY_SIZE 32 // max AES key size
#define VE_KEY_SIZE_128 16 // 128 bit key

/**
 * list for ouput data blocks
 */
typedef struct vencrypt_data_list {
	struct list_head list;
	unsigned char *data;
	size_t data_size;
	size_t data_offset;
} vencrypt_data_list_t;

/**
 * Main device structure.
 */
typedef struct vencrypt_device_data {
	struct cdev cdev;
	// AES support data...
	int nodeId;
	struct AES_ctx ctx;
	unsigned char key[VE_MAX_KEY_SIZE];
	size_t key_size;
	unsigned char iv[16];
	unsigned char remainder[VE_BLOCK_SIZE]; // left over from last encrypt
	size_t remainder_size; // size of the remainder in bytes
	vencrypt_data_list_t output_list;
	size_t output_size;
	size_t output_padding;
	size_t output_offset;
	size_t input_processed;
	struct vencrypt_device_data *pt;
	struct vencrypt_device_data *ct;
} vencrypt_device_data_t;

static struct mutex vencrypt_mutex;
static bool vencrypt_in_use;

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

    mutex_lock(&vencrypt_mutex);
    if (vencrypt_in_use) {
        mutex_unlock(&vencrypt_mutex);
        // driver is already open
        return -EBUSY;
    }
    vencrypt_in_use = true;
    mutex_unlock(&vencrypt_mutex);

	fp->private_data = vencrypt_data;

	// clear IV on open
	memset(&vencrypt_data->iv[0], 0, sizeof(vencrypt_data->iv));
	vencrypt_data->remainder_size = 0;
	AES_init_ctx_iv(&vencrypt_data->ctx, vencrypt_data->key,
			vencrypt_data->iv);

	return 0;
}

/**
 * Get padding remainder size per PKCS#7
 */
static size_t get_padding(size_t size, size_t block_size)
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
			const unsigned char *input_data,
			const unsigned char *local_data, size_t input_size,
			size_t input_offset)
{
	size_t output_size;
	unsigned char *buf;

	if (encrypt) {
		size_t remainder = 0;
		vencrypt_data_list_t *entry = NULL;
		unsigned long res;

		if ((vencrypt_data->remainder_size + input_size) <
		    VE_BLOCK_SIZE) {
			// not enough data to encrypt, save it
			if ((res = copy_from_user(
				     &vencrypt_data->remainder
					      [vencrypt_data->remainder_size],
				     input_data + input_offset, input_size)) !=
			    0) {
				pr_info("VECRYPT: %s.%d failed to copy from user res=%lu\n",
					__func__, __LINE__, res);
				return -ENOSPC;
			}
			vencrypt_data->remainder_size += input_size;
			return input_size;
		}

		buf = vmalloc(input_size + vencrypt_data->remainder_size);
		if (buf == NULL) {
			pr_err("%s: Failed to allocate buffer\n", __func__);
			return -ENOMEM;
		}

		// include left-over if any
		if (vencrypt_data->remainder_size) {
			memcpy(buf, vencrypt_data->remainder,
			       vencrypt_data->remainder_size);
			if (local_data) {
				memcpy(buf + vencrypt_data->remainder_size,
				       local_data, input_size);
			} else {
				if ((res = copy_from_user(
					     buf + vencrypt_data->remainder_size,
					     input_data + input_offset,
					     input_size)) != 0) {
					pr_info("VECRYPT: %s.%d failed to copy from user res=%lu\n",
						__func__, __LINE__, res);
					return -ENOSPC;
				}
			}
		} else {
			if (local_data) {
				memcpy(buf, local_data, input_size);
			} else {
				if ((res = copy_from_user(
					     buf, input_data + input_offset,
					     input_size)) != 0) {
					pr_info("VECRYPT: %s.%d failed to copy from user res=%lu,"
						"input offset = %lu \n",
						__func__, __LINE__, res,
						input_offset);
					return -ENOSPC;
				}
			}
		}

		if (((input_size + vencrypt_data->remainder_size) %
		     VE_BLOCK_SIZE) != 0) {
			// trim new remainder
			remainder =
				((input_size + vencrypt_data->remainder_size) %
				 VE_BLOCK_SIZE);
			memcpy(vencrypt_data->remainder,
			       input_data + input_offset + input_size -
				       remainder,
			       remainder);
		} else {
			remainder = 0;
		}
		vencrypt_data->remainder_size = remainder;

		AES_CBC_encrypt_buffer(&vencrypt_data->ctx, buf,
				       input_size - remainder);
		output_size = input_size - remainder;
		vencrypt_data->ct->output_size += output_size;

		entry = vmalloc(sizeof(vencrypt_data_list_t));
		if (entry == NULL) {
			pr_info("VENCRYPT: %s - failed to allocate entry\n",
				__func__);
			return -ENOMEM;
		}
		entry->data = buf;
		entry->data_size = output_size;
		list_add_tail(&entry->list,
			      &vencrypt_data->ct->output_list.list);
	} else {
		vencrypt_data_list_t *entry =
			vmalloc(sizeof(vencrypt_data_list_t));
		if (entry == NULL) {
			pr_info("VENCRYPT: %s.%d - failed to allocate entry\n",
				__func__, __LINE__);
			return -ENOMEM;
		}

		buf = vmalloc(input_size);
		if (buf == NULL) {
			pr_err("%s: Failed to allocate buffer\n", __func__);
			return -ENOMEM;
		}

		if (local_data == NULL) {
			if (copy_from_user(buf, input_data + input_offset,
					   input_size) != 0) {
				pr_info("VECRYPT: %s.%d failed to copy from user\n",
					__func__, __LINE__);
				return -ENOSPC;
			}
		} else {
			// not from user buffer
			memcpy(buf, local_data + input_offset, input_size);
		}
		AES_CBC_decrypt_buffer(&vencrypt_data->ctx, buf, input_size);

		output_size = input_size;
		vencrypt_data->pt->output_size += output_size;

		entry->data = buf;
		entry->data_size = output_size;
		list_add_tail(&entry->list,
			      &vencrypt_data->pt->output_list.list);
	}

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
	size_t to_copy = copy_size; // amount of data left to copy to user
	vencrypt_data_list_t *entry;

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

	entry = list_first_entry(&vencrypt_data->output_list.list,
				 struct vencrypt_data_list, list);
	while (entry != NULL && (to_copy > 0)) {
		vencrypt_data_list_t *next;
		if (entry == list_last_entry(&vencrypt_data->output_list.list,
					     struct vencrypt_data_list, list)) {
			if (!encrypt) {
				// strip any padding
				int padding;
				if (entry->data_size == 0) {
					// empty entry!
				} else {
					padding = entry->data[entry->data_size -
							      1];
					if (padding > VE_BLOCK_SIZE) {
						pr_info("VENCRYPT: %s.%d invalid padding size %d\n",
							__func__, __LINE__,
							padding);
						return -EINVAL;
					}
					if (padding > entry->data_size) {
						pr_info("VENCRYPT: %s.%d invalid padding size %d > data size %lu\n",
							__func__, __LINE__,
							padding,
							entry->data_size);
						return -EINVAL;
					}
				}
#if 0
                if (padding == 0) {
                    // XXX HACK
                    padding = 16;
                }
#endif
				entry->data_size -= padding;
				if (entry->data_size == 0) {
					// nothing left
					vfree(entry->data);
					list_del(&entry->list);
					vfree(entry);
					copy_size = 0;
					break;  // done
				}
			}
		}
		if (entry->data_size == 0) {
			printk("VENCRYPT: %s.%d got zero data\n", __func__,
			       __LINE__);
			list_del(&entry->list);
			to_copy = 0;
			copy_size = 0;
			break;
		}
		if (entry->data_size <= to_copy) {
			// want all of it
			if (copy_to_user(user_buffer + off,
					 entry->data + entry->data_offset,
					 entry->data_size) != 0) {
				pr_info("VECRYPT: %s.%d failed to copy to user\n",
					__func__, __LINE__);
				return -ENOSPC;
			}
			to_copy -= entry->data_size;
			off += entry->data_size;
			vfree(entry->data);
			next = list_next_entry(entry, list);
			list_del(&entry->list);
			// only free if not the head entry
			if (next != NULL) {
				vfree(entry);
			}
			entry = next;
		} else {
			// partial copy
			if (copy_to_user(user_buffer + off,
					 entry->data + entry->data_offset,
					 to_copy) != 0) {
				pr_info("VECRYPT: %s.%d failed to copy to user\n",
					__func__, __LINE__);
				return -ENOSPC;
			}
			entry->data_offset += to_copy;
			entry->data_size -= to_copy;
			to_copy = 0;
			break;
		}
	}

	vencrypt_data->output_offset += copy_size;
	vencrypt_data->output_size -= copy_size;

	return copy_size;
}

/**
 * Handle a write by the user.
 */
static ssize_t vencrypt_write(struct file *fp, const char *buffer, size_t size,
			      loff_t *offset)
{
	ssize_t output_size;
	size_t off;

	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;

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

	off = (offset != NULL) ? *offset : 0;
	output_size = do_crypt(vencrypt_data, encrypt, buffer, NULL, size, off);

	if (output_size < 0) {
		return output_size;
	} else {
		return size; // consumed bytes
	}
}

static int vencrypt_release(struct inode *node, struct file *fp)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;

	// handle padding
	if (encrypt) {
		// add final padding and encrypt if needed
		int padding = get_padding(vencrypt_data->remainder_size,
					  VE_BLOCK_SIZE);
		ssize_t output_size;
		if (padding) {
			vencrypt_data_list_t *entry;
			// should always be 1 to 16 pad bytes
			memset(&vencrypt_data->remainder
					[vencrypt_data->remainder_size],
			       padding, padding);
			output_size = do_crypt(vencrypt_data, encrypt, NULL,
					       vencrypt_data->remainder,
					       VE_BLOCK_SIZE, 0);
			if (output_size < 0) {
				return output_size;
			}
			entry = list_last_entry(
				&vencrypt_data->output_list.list,
				struct vencrypt_data_list, list);
			entry = list_last_entry(
				&vencrypt_data->pt->output_list.list,
				struct vencrypt_data_list, list);
			entry = list_last_entry(
				&vencrypt_data->ct->output_list.list,
				struct vencrypt_data_list, list);
		}
	}

    // done with driver
    mutex_lock(&vencrypt_mutex);
    vencrypt_in_use = false;
    mutex_unlock(&vencrypt_mutex);

	return 0;
}

const struct file_operations vencrypt_fops = {
	.owner = THIS_MODULE,
	.open = vencrypt_open,
	.read = vencrypt_read,
	.write = vencrypt_write,
	.release = vencrypt_release,
};

static int set_key(const char *key, unsigned char *dest, size_t *size)
{
	size_t key_size = strlen(key) / 2;
	int ind;
	// check key is appropriately sized
	if (((key_size * 2) != strlen(key)) ||
	    (strlen(key) > (VE_MAX_KEY_SIZE * 2))) {
		// bad / odd key size
		pr_info("bad key string length %lu\n", strlen(key));
		return -EAGAIN;
	}

	if (key_size != VE_KEY_SIZE_128) {
		pr_info("Only support 128 bit keys\n");
		return -EAGAIN;
	}

	// convert key to binary
	for (ind = 0; ind < key_size; ind++) {
		char digits[3] = { key[ind * 2], key[ind * 2 + 1], 0 };
		long data;
		int res;

		res = kstrtol(digits, 16, &data);
		if (res) {
			// invalid character(s)
			pr_info("bad key string content at index %d \"%s\"\n",
				ind * 2, digits);
			return -EAGAIN;
		}
		dest[ind] = (unsigned char)data;
	}
	if (size) {
		*size = key_size;
	}

	return 0;
}

int vencrypt_init(void)
{
	int ind, retval, major;
	dev_t dev;
	int minor; // the minor device with aes active
	unsigned char aes_key[VE_MAX_KEY_SIZE];
	size_t aes_key_size;

    mutex_init(&vencrypt_mutex);

	// set up cipher for CT node
	if (encrypt) {
		minor = nodes[VE_MINOR_PT]
				.minor; // plaintext node will be encrypting
	} else {
		minor = nodes[VE_MINOR_CT]
				.minor; // cyphertext node will be decrypting
	}

	// check key
	retval = set_key(key, aes_key, &aes_key_size);
	if (retval < 0) {
		// invalid key
		pr_info("VENCRYPT: %s invalid AES key\n", __func__);
		return -EAGAIN;
	}

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
			device_create(vencrypt_class, NULL, dev,
				      &devs[nodes[ind].minor], "%s",
				      nodes[ind].name);
			INIT_LIST_HEAD(
				&devs[nodes[ind].minor].output_list.list);
		}

		// include AES key for encrypt / decrypt
		memcpy(devs[nodes[ind].minor].key, aes_key, aes_key_size);
	}

    vencrypt_in_use = false;    // ready for open

	return retval;
}

void vencrypt_exit(void)
{
	int ind;
	int major = MAJOR(device_number);
	dev_t dev;
	for (ind = 0; ind < (sizeof(nodes) / sizeof(nodes[0])); ind++) {
		dev = MKDEV(major, nodes[ind].minor);
		/* release devs[ind] fields */
		cdev_del(&devs[nodes[ind].minor].cdev);
		device_destroy(vencrypt_class, dev);
	}
	class_destroy(vencrypt_class);
	unregister_chrdev_region(device_number, VE_MAX_DEVICES);

    mutex_destroy(&vencrypt_mutex);
}

module_init(vencrypt_init);
module_exit(vencrypt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Darran Hunt <darran@hunt.net.nz>");
MODULE_DESCRIPTION("Virscient AES linux driver challenge");
MODULE_VERSION("1.0");
