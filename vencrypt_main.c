#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <crypto/if_alg.h>
#include <crypto/drbg.h>

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
	struct crypto_skcipher *skcipher;
	unsigned char iv[16];
	unsigned char *output_data;
	size_t output_size;
	size_t input_processed;
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

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	return 0;
}

typedef struct {
	struct scatterlist sg_in;
	struct scatterlist sg_out;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct crypto_wait wait;
} skcipher_def_t;

/**
 * perform cipher operation
 */

#if 0
static int do_crypt(vencrypt_device_data_t *vencrypt_data, bool encrypt,
		    const unsigned char *key_string,
		    const unsigned char *input_data, size_t input_size)
{
	struct AES_ctx ctx;
	size_t key_size = strlen(key_string) / 2;
	unsigned char key[VE_MAX_KEY_SIZE];
	int ind;
	int remainder;
	unsigned char *buf;

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	// check key is appropriately sized
	// XXX fixed size key. 256?
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

	// pad using PKCS#7 as needed
	remainder = input_size % VE_BLOCK_SIZE;
	if (remainder == 0) {
		// Per PKCS#7 add 16 bytes to enable single byte pad to be recognised
		remainder = VE_BLOCK_SIZE;
	}

	buf = kmalloc(input_size + remainder, GFP_KERNEL);
	if (buf == NULL) {
		pr_err("%s: Failed to allocate buffer\n", __func__);
		return -EAGAIN;
	}
	memcpy(buf, input_data, input_size);
	// pad
	for (ind = 0; ind < remainder; ind++) {
		// per PKCS#7 use the pad size as the pad
		buf[input_size + ind] = remainder;
	}

	AES_init_ctx_iv(&ctx, key, vencrypt_data->iv);
	AES_CBC_encrypt_buffer(&ctx, buf, input_size + remainder);
	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	printk("VENCRYPT: %s completed\n", __func__);

	return 0;
}

#else
static int do_crypt(vencrypt_device_data_t *vencrypt_data,
             bool encrypt, const unsigned char *key_string,
			 const unsigned char *input_data, size_t input_size)
{
	int ret = -EFAULT;
	int ind;
	struct crypto_skcipher *skcipher = vencrypt_data->skcipher;
	struct skcipher_request *req = NULL;
	size_t key_size = strlen(key_string) / 2;
	unsigned char key[VE_MAX_KEY_SIZE];
	skcipher_def_t sk;
    unsigned char buf[VE_BLOCK_SIZE];

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);

	if (((key_size * 2) != strlen(key_string)) ||
	    (strlen(key_string) > (VE_MAX_KEY_SIZE * 2))) {
		// bad / odd key size
		pr_info("bad key string length %lu\n", strlen(key_string));
		ret = -EAGAIN;
		goto out;
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
			ret = -EAGAIN;
			goto out;
		}
		key[ind] = (unsigned char)data;
	}

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &sk.wait);

	printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	if (crypto_skcipher_setkey(skcipher, key, key_size)) {
		pr_info("key could not be set for size %lu. Key size should be 16, 24, or 32.\n",
			key_size);
		ret = -EAGAIN;
		goto out;
	}

	sk.tfm = skcipher;
	sk.req = req;

	/* do the encrypt / decrypt of the supplied data */
#if 0
	for (ind = 0; ind < input_size / VE_BLOCK_SIZE; ind++) {
        printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
		sg_init_one(&sk.sg_in, &input_data[ind * VE_BLOCK_SIZE],
			    VE_BLOCK_SIZE);
		sg_init_one(&sk.sg_out, &buf, VE_BLOCK_SIZE);
		skcipher_request_set_crypt(req, &sk.sg_in, &sk.sg_out,
					   VE_BLOCK_SIZE, vencrypt_data->iv);
        printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
		crypto_init_wait(&sk.wait); // synchronous

		/* encrypt data */
		if (encrypt) {
            printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
			ret = crypto_wait_req(crypto_skcipher_encrypt(sk.req),
					      &sk.wait);
			if (!ret) {
				pr_info("%s: Block %d encrypted successfully\n",
					__func__, ind);
			}
		} else {
            printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
			ret = crypto_wait_req(crypto_skcipher_decrypt(sk.req),
					      &sk.wait);
			if (!ret) {
				pr_info("%s: Block %d decrypted successfully\n",
					__func__, ind);
			}
		}
	}
	// handle partial block
	// - need to keep data incase more arrives
	// - need to incorporate it into the next rounds
	// - keep one partial bock in dev, use to start rounds
#else
    printk("VENCRYPT: %s.%d init sg_in input_size %lu\n", __func__, __LINE__, input_size);
    sg_init_one(&sk.sg_in, input_data, input_size);
    sg_init_one(&sk.sg_out, vencrypt_data->output_data, vencrypt_data->output_size);
    skcipher_request_set_crypt(req, &sk.sg_in, &sk.sg_out, input_size,
            vencrypt_data->iv);
    crypto_init_wait(&sk.wait); // synchronous

    /* encrypt data */
    if (encrypt) {
            printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
#if 0
            ret = crypto_wait_req(crypto_skcipher_encrypt(sk.req),
                                  &sk.wait);
#else
            ret = 0;
#endif
            printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
            if (!ret) {
                    pr_info("%s: buffer encrypted successfully\n",
                            __func__);
            }
    } else {
            printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
            ret = crypto_wait_req(crypto_skcipher_decrypt(sk.req),
                                  &sk.wait);
            printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
            if (!ret) {
                    pr_info("%s: Buffer decrypted successfully\n",
                            __func__);
            }
    }

    if (!ret) {
        printk("VENCRYPT: %s.%d success\n", __func__, __LINE__);
    }
#endif

    //sg_copy_to_buffer(&mgc->sg, 1, ciphertext, datasize);

    printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	if (!ret) {
		pr_info("Encryption triggered successfully\n");
	}

out:
    printk("VENCRYPT: %s.%d\n", __func__, __LINE__);
	if (req)
		skcipher_request_free(req);
	return ret;
}
#endif

static void decrypt(char __user *buffer, size_t size, loff_t *offset)
{
}

/**
 * Handle a read by the user.
 */
static ssize_t vencrypt_read(struct file *fp, char __user *user_buffer,
			     size_t size, loff_t *offset)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s\n", __func__);

	return 0;
}

/**
 * Handle a write by the user.
 */
static ssize_t vencrypt_write(struct file *fp, const char *buffer, size_t size,
			      loff_t *offset)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s.%d fp %p data %p\n", __func__, __LINE__, fp,
	       vencrypt_data);

	vencrypt_data->output_size = 2048;
	vencrypt_data->output_data =
		kmalloc(vencrypt_data->output_size, GFP_KERNEL);

	if (encrypt /* && dev == pt */) {
		do_crypt(vencrypt_data, encrypt, key, buffer,
			 size /*, offset */);
	}

	kfree(vencrypt_data->output_data);

	return 0;
}

static int vencrypt_release(struct inode *node, struct file *fp)
{
	vencrypt_device_data_t *vencrypt_data =
		(vencrypt_device_data_t *)fp->private_data;
	printk("VENCRYPT: %s\n", __func__);

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
	int minor; // the minor device with the skcipher active

	// set up cipher for CT node
	if (encrypt) {
		minor = nodes[VE_MINOR_PT]
				.minor; // plaintext node will be encrypting
	} else {
		minor = nodes[VE_MINOR_CT]
				.minor; // cyphertext node will be decrypting
	}
	devs[minor].skcipher = crypto_alloc_skcipher("cbc-aes-neonbs", 0, 0);
	if (IS_ERR(devs[minor].skcipher)) {
		pr_info("could not allocate skcipher handle: error %ld\n",
			PTR_ERR(devs[minor].skcipher));
		return PTR_ERR(devs[minor].skcipher);
	}
	printk("VENCRYPT: %s encrypt=%u key=%s\n", __func__, encrypt, key);
	retval = alloc_chrdev_region(&device_number, 0, VE_MAX_DEVICES,
				     "vencrypt");
	if (retval) {
		pr_err("%s: Failed to allocate device number error:%d\n",
		       __func__, retval);
		if (devs[minor].skcipher) {
			crypto_free_skcipher(devs[minor].skcipher);
		}
		return retval;
	}

	major = MAJOR(device_number);
	vencrypt_class = class_create(THIS_MODULE, "vencrypt_class");

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

	if (retval && devs[minor].skcipher) {
		crypto_free_skcipher(devs[minor].skcipher);
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
	if (devs[nodes[VE_MINOR_CT].minor].skcipher) {
		crypto_free_skcipher(devs[nodes[VE_MINOR_CT].minor].skcipher);
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
