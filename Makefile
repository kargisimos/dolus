ROOTKIT :=  dolus

obj-m := $(ROOTKIT).o

$(ROOTKIT)-y    +=  src/Dolus.o

$(ROOTKIT)-y    +=  src/debug.o
$(ROOTKIT)-y    +=  src/privesc.o



CC = gcc -Wall
KDIR := /lib/modules/$(shell uname -r)/build
SRC_DIR := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(SRC_DIR) clean