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

static unsigned int HookFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    __be32 srcIp, destIp;
    if(skb)
    {
        
    }
}

nf_hook_ops

module_init(filter_GET_POST_init);  
module_exit(filter_GET_POST_exit);   