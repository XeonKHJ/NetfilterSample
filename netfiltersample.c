#include <linux/module.h>  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/types.h>  
#include <linux/netdevice.h>  
#include <linux/skbuff.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/inet.h>  
#include <linux/in.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>  
#include <linux/udp.h>  
MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("XuShuzhan");
MODULE_DESCRIPTION("A NetFilter Demo");
MODULE_VERSION("1.0"); 

#define NIPQUAD(addr)  \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1],  \
  ((unsigned char *)&addr)[2],  \
  ((unsigned char *)&addr)[3]  

static unsigned int filter_GET_POST(void *p, struct sk_buff *skb, const struct nf_hook_state *s)
{  
 __be32 sip,dip;  
 if(skb){  
   char *data = NULL; //tcp data

   char *request_method;//http request method id request line

   struct sk_buff *sb = NULL;  
   struct tcphdr *tcph = NULL; 
   sb = skb;  
   struct iphdr *iph;  
   iph  = ip_hdr(sb);
   tcph = tcp_hdr(sb);     
   sip = iph->saddr;  //source ip address
   dip = iph->daddr;  //destination ip address

   //(64_bit pc) get tcp's data pointor 
   data = (unsigned long)tcph + (unsigned long)(tcph -> doff * 4);

   if(request_method = strstr(data,"GET")!=NULL){
  printk(">>GET>>>>GET>>>>>GET>>>>>>>>>GET>>>>>>>>>>>>>GET>>>>>>>>>>>> \n");
        printk("[GET]  Packet from: %d.%d.%d.%d to %d.%d.%d.%d ", NIPQUAD(sip), NIPQUAD(dip));
  printk("GET -> %s \n",data);

   }else if(request_method = strstr(data,"POST")!=NULL){
  printk(">>POST>>>>POST>>>>>POST>>>>>>>>>POST>>>>>>>>>>>>>POST>>>>>>>>>>>> \n");
  printk("[POST] Packet from: %d.%d.%d.%d to %d.%d.%d.%d", NIPQUAD(sip), NIPQUAD(dip));
  printk("POST -> %s \n",data);

   }
  }  
   return NF_ACCEPT;  
}  
 //regist a hook function 
 struct nf_hook_ops filter_GET_POST_ops = {  
   .list =  {NULL,NULL},  
   .hook = filter_GET_POST,  //hooked function
   .pf = NFPROTO_IPV4,  
   .hooknum = NF_INET_LOCAL_OUT, 
   .priority = NF_IP_PRI_FILTER+2  
 };  

static int __init filter_GET_POST_init(void) {  
  nf_register_hook(&filter_GET_POST_ops);  
  return 0;  
}  


static void __exit filter_GET_POST_exit(void) {  
  nf_unregister_hook(&filter_GET_POST_ops);  
}   
module_init(filter_GET_POST_init);  
module_exit(filter_GET_POST_exit);   