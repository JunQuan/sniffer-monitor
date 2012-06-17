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
