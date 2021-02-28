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

/// <summary>
/// 计算TCP/IP校验和
/// </summary>
/// <param name="bytes">要计算校验和的缓冲区指针，记得把校验和所在的位置置零再传进来。</param>
/// <param name="byteCounts">缓冲区大小（字节）</param>
/// <returns>校验和</returns>
unsigned short CalculateCheckSum(char* bytes, char* fakeHeader, int byteCounts, int fakeHeaderCounts, int marginBytes)
{
	unsigned int sum = 0;
	int paddings = byteCounts % marginBytes;

	int i = 0;
	for (i = 0; i < fakeHeaderCounts; i += 2)
	{
		unsigned int perSum = (unsigned int)(fakeHeader[i + 1] & 0xff) + (((unsigned int)((fakeHeader[i])) << 8) & 0xff00);
		sum += perSum;
	}

	for (i = 0; i < (byteCounts + paddings); i += 2)
	{
		unsigned int perSum = 0;

		if (i < byteCounts)
		{
			perSum += (((unsigned int)((bytes[i])) << 8) & 0xff00);
		}
		else
		{
			perSum += 0;
		}

		if (i + 1 < byteCounts)
		{
			perSum += (unsigned int)(bytes[i + 1] & 0xff);
		}
		else
		{
			perSum += 0;
		}

		sum += perSum;
	}

	while (sum > 0xffff)
	{
		unsigned int exceedPart = (sum & (~0xFFFF)) >> 16;
		unsigned int remainPart = sum & 0xffff;
		sum = remainPart + exceedPart;
	}

	return ~(sum & 0xFFFF);
}

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
        short checksum = ipHeader->check;
        unsigned char destIp[4] = {192, 168, 137, 1};
        unsigned char newIp[4] = {192, 168, 133, 1};
        unsigned char localhostIp[4] = {127, 0, 0, 1};
        if((srcIp != *((__be32 *)localhostIp)) || dstIp != *((__be32 *)localhostIp))
        {
            printk("Packet from: %d.%d.%d.%d to %d.%d.%d.%d\n", NIPQUAD(srcIp), NIPQUAD(dstIp));
            //printk("Dec packet addr: %d, %d", srcIp, dstIp);
            if(dstIp == *((__be32 *)destIp))
            {
                unsigned char * ipHeaderBuffer = (unsigned char*) ipHeader;
                printk("Start modifying packet");
                //printk("%d, %d, %d, %d", NIPQUAD(*ipHeaderBuffer));
                ipHeader->saddr = *((__be32 *)newIp);
                ipHeader->check = 0;
                short newCheckSum = CalculateCheckSum((char *)ipHeader, NULL, 20, 0, 2);
                char newCorrectCheckSum[2];
                newCorrectCheckSum[0] = ((char*)(&newCheckSum))[1];
                newCorrectCheckSum[1] = ((char*)(&newCheckSum))[0];
                ipHeader->check = *((short *)newCorrectCheckSum);
                
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
	.hooknum = NF_INET_POST_ROUTING, //hook point. (filtering layer)
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