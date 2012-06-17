<<<<<<< HEAD
/* This is an insertable module that uses the firewall hooks mechanism
   on 2.2.16 to intercept a packet */
   /* gcc -O -c NetFWHook.c -I/usr/src/linux/include*/
   /* No one can then telnet,ftp,ping your machine */
   /*NetFWHook.c*/
   
   #define MODULE
   #define __KERNEL__

   #include<linux/config.h>
   #include<linux/module.h>
   #include<linux/version.h>
   #include<linux/netdevice.h>
   #include<net/protocol.h>
   #include<net/pkt_sched.h>
   #include<net/tcp.h>
   #include<net/ip.h>
   #include<linux/if_ether.h>
   #include<linux/ip.h>
   #include<linux/tcp.h>
   #include<linux/skbuff.h>
   #include<linux/icmp.h>
   #include<linux/kernel.h>
   #include<linux/mm.h>
   #include<linux/file.h>
   #include<linux/firewall.h>
   #include<asm/uaccess.h>

    //Function for forwarded packets
    static int fw_forward(struct firewall_ops *this,int pf,struct device *dev,void *phdr,void *arg,struct sk_buff **pskb)
    {
        struct iphdr *hdr = (struct iphdr *)(*pskb)->h.ipiph;
        printk("\n\tfw_forward)() called...");
        printk("\n\t\tThe source of this packet is:%s",in_ntoa(hdr->saddr));
        return FW_ACCEPT;
    }


   /*Function for incoming packets*/
    static int fw_input(struct firewall_ops *this,int pf,struct device *dev,void *phdr,void *arg,struct sk_buff **pskb)
    {
        struct iphdr *iph;
        iph = (struct iphdr*)(*pskb)->h.ipiph;
        printk("\n\tfw_input() called...");
        printk("\n\t\tThe source of this packet is:%s",in_ntoa(iph->saddr));
        return FW_ACCEPT;
    }


   /*Function for outgoing packets*/
    static int fw_output(struct firewall_ops *this,int pf,struct device *dev,void *phdr,void *arg,struct sk_buff **pskb)
    {
        struct iphdr *iph;
        iph = (struct iphdr*)(*pskb)->h.ipiph;
        printk("\n\tfw_output)() called...");
        printk("\n\tThis packet is destined for:%s",in_ntoa(iph->daddr));
        return FW_ACCEPT;
    }


   /*Filling the firewall_ops structure*/
    static struct firewall_ops myOps = {   NULL,
                                    fw_forward,
                                    fw_input,
                                    fw_output,
                                    PF_INE int fw_pf，/* Protocol family*/
                                    int fw_priority,    /* Priority of chosen firewalls */
                                    T,
                                    1
                                 };

   /*First function to be called at the time of loading of module*/
    int init_module(void)
    {
           /*registering the firewall_ops structure*/
        if(register_firewall(PF_INET,&myOps) < 0)
        {
            printk("\n\n\tERROR...firewall main aag lag gayee!!!");
            return -1;
        }
        else
        {
            printk("\n\n\tFirewall registered");
        }
        return 0;
    }



   /*Function that is called when the module is unloaded*/
    void cleanup_module(void)
    {
        /*Unregistering the firewall_ops structure*/
        if(unregister_firewall(PF_INET,&myOps)<0)

               {

                           printk("\n\n\tError....Firewall can't be
   unregistered");

               }

               else

               {

                           printk("\n\n\tFirewall unregistered");

               }


   }
=======
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops nfho;
static unsigned char *drop_ip = "\x7f\x00\x00\x01";

unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
       struct sk_buff *sb = *skb;
       struct iphdr     *iph ;
   
       iph = ip_hdr(sb);
       pr_info("Packet from %d.%d.%d.%d\n",NIPQUAD(iph->saddr));
       if ( iph->saddr == *(__be32 *) drop_ip)
       {
             pr_info("Dropped packet from ... %d.%d.%d.%d\n",*drop_ip, *(drop_ip+1), *(drop_ip+2), *(drop_ip+3) );
             return NF_DROP;
       }else {
           
             return NF_ACCEPT;
       }
}

int init_module()
{
       pr_info("i'm now in the kernel space!\n");
       nfho.hook      = hook_func;
       nfho.hooknum   = NF_IP_PRE_ROUTING;
       nfho.pf                = PF_INET;
       nfho.priority      = NF_IP_PRI_FIRST;
   
       nf_register_hook(&nfho);

       return 0;
}

void cleanup_module()
{
    nf_unregister_hook(&nfho);
    pr_info("module removed from kernel!\n");
}
>>>>>>> c09bc877709dcab62752e91d1ca3c6e8b6b1a88f
