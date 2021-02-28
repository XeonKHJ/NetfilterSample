#include <linux/module.h>  
#include <linux/kernel.h>  
#include <linux/types.h>  
#include <linux/netdevice.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/in.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>  
#include <linux/udp.h>  

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("Kang Hongjia");
MODULE_DESCRIPTION("A NetFilter Demo");
MODULE_VERSION("1.0"); 

#define NIPQUAD(addr) \
 ((unsigned char *)&addr)[0], \
 ((unsigned char *)&addr)[1], \
 ((unsigned char *)&addr)[2], \
 ((unsigned char *)&addr)[3]

static unsigned int HookFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    __be32 srcIp, dstIp;

    struct sk_buff *sucketBuffer = skb;

    // if socket buffer is not null
    if(skb)
    {
        //获取IP数据包头部
        struct iphdr * ipHeader = ip_hdr(sucketBuffer);

        srcIp = ipHeader->saddr;
        dstIp = ipHeader->daddr;
        unsigned char destIp[4] = {192, 168, 137, 1};
        unsigned char localhostIp[4] = {127, 0, 0, 1};
        if((srcIp != *((__be32 *)localhostIp)) || dstIp != *((__be32 *)localhostIp))
        {
            printk("Packet from: %d.%d.%d.%d to %d.%d.%d.%d\n", NIPQUAD(srcIp), NIPQUAD(dstIp));
            printk("Dec packet addr: %d, %d", srcIp, dstIp);


            if(srcIp == *((__be32 *)destIp))
            {
                printk("Start modifying packet");
            }
            
        }
    }
    else
    {
        printk("No data come\n");
    }

    return NF_ACCEPT;
}

struct nf_hook_ops filter_ops = 
{
	/* User fills in from here down. */
	.hook = HookFunc,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING, //hook point. (filtering layer)
	/* Hooks are ordered in ascending priority. */
	.priority = NF_IP_PRI_FILTER
};

int NetfilterSample_Init(void)
{
    int result = nf_register_net_hook(&init_net, &filter_ops);
    
    if(!result)
    {
        printk("hook success.");
    }
    else
    {
        printk("hook error.");
    }

    printk("netfiltersample: module loaded\n");
    return 0;
}

void NetfilterSample_Exit(void)
{
    nf_unregister_net_hook(&init_net, &filter_ops);
    printk("netfiltersample: module exited\n");
}

module_init(NetfilterSample_Init);  
module_exit(NetfilterSample_Exit);   