savedcmd_/home/anass/myprojects/extra-backdoor/output/../khook/khook/x86/stub.o := gcc-13 -Wp,-MMD,/home/anass/myprojects/extra-backdoor/output/../khook/khook/x86/.stub.o.d -nostdinc -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/compiler-version.h -include ./include/linux/kconfig.h -I./ubuntu/include -D__KERNEL__ -fmacro-prefix-map=./= -D__ASSEMBLY__ -fno-PIE -m64 -DCC_USING_FENTRY -g -gdwarf-5  -DMODULE  -c -o /home/anass/myprojects/extra-backdoor/output/../khook/khook/x86/stub.o /home/anass/myprojects/extra-backdoor/../khook/khook/x86/stub.S 

source_/home/anass/myprojects/extra-backdoor/output/../khook/khook/x86/stub.o := /home/anass/myprojects/extra-backdoor/../khook/khook/x86/stub.S

deps_/home/anass/myprojects/extra-backdoor/output/../khook/khook/x86/stub.o := \
  include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \

/home/anass/myprojects/extra-backdoor/output/../khook/khook/x86/stub.o: $(deps_/home/anass/myprojects/extra-backdoor/output/../khook/khook/x86/stub.o)

$(deps_/home/anass/myprojects/extra-backdoor/output/../khook/khook/x86/stub.o):
