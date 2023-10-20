obj-m += vencrypt.o

vencrypt-objs+= vencrypt_main.o aes/aes.o
 
KDIR = /lib/modules/$(shell uname -r)/build
 
all:
	make -C $(KDIR) M=$(shell pwd) modules
 
clean:
	make -C $(KDIR) M=$(shell pwd) clean
