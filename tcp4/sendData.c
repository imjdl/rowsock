#include <stdio.h>

#include <sys/socket.h>  // socket() 函数
#include <netinet/ip.h>  // 结构体ip 头部 和 IP_MAXPACKET
#include <netinet/tcp.h> // 结构体tcp 头部
#include <netdb.h>       // 结构体addrinfo getaddrinfo() 和 freeaddrinfo()
#include <net/if.h>      // 结构体 ifreq
#include <sys/ioctl.h>   // ioctl 函数
#include <bits/ioctls.h> // 定义了一些 ioctl 函数 的cmd参数
#include <stdlib.h>      //  strcpy()
#include <string.h>      // 字符串操作 memset()
#include <unistd.h>      // close()
#include <arpa/inet.h>   // inet_ntop()



#include <errno.h>       // perror errno

#define IP4_HDRLEN 20
#define TCP_HDRLEN 20


// 声明函数

int * allocate_intmem(int len);
char * allocate_strmem(int len);
uint8_t * allocate_ustrmem(int len);
uint16_t checksum (uint16_t *addr, int len);
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr);
int main(void){
    // 设置常量
    const int on = 1;

    // 定义一些变量
    int sd, status, *ip_flags, *tcp_flags, i;

    char  *target, *src_ip ,* dst_ip, *interface; // 目标域名或ip 源IP 目的IP 网卡接口

    struct ip iphdr;

    struct tcphdr tcphdr;

    uint8_t *packet; // 数据包指针

    struct addrinfo hints ,*res;

    struct sockaddr_in *ipv4, sin;

    struct ifreq ifr;

    void *tmp;

    // 分配内存空间
    packet = allocate_ustrmem(IP_MAXPACKET);
    interface = allocate_strmem(40);
    target = allocate_strmem(40);
    src_ip = allocate_strmem(INET_ADDRSTRLEN);
    dst_ip = allocate_strmem(INET_ADDRSTRLEN);
    ip_flags = allocate_intmem(4);
    tcp_flags = allocate_intmem(8);

    // 绑定到指定的网卡
    strcpy(interface,"wlan0");

    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        fprintf(stderr, "创建socket失败");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0){
        perror("ioctl error");
        exit(EXIT_FAILURE);
    }
    close(sd);
    // 设置目标ip和源ip getaddrinfo
    strcpy(src_ip, "10.100.44.42");
    strcpy(target, "10.100.44.48");

    memset(&hints, 0 , sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
    // 如果是域名的话 解析
    if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0){
        fprintf(stderr, "ERROR get addrinfo");
        exit(EXIT_FAILURE);
    }

    ipv4 = (struct sockaddr_in *)res->ai_addr;
    tmp = &(ipv4->sin_addr);
    if (inet_ntop(AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL){
        status = errno;
        fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    freeaddrinfo(res);

    // 构造 ip数据包 TCP数据包
    // ip头部是以32位字节为单位的
    iphdr.ip_hl = IP4_HDRLEN / sizeof(uint32_t);

    // 指定版本
    iphdr.ip_v = 4;

    // 指定服务
    iphdr.ip_tos = 0;

    // 指定长度
    iphdr.ip_len = htons(IP4_HDRLEN + TCP_HDRLEN);

    //  指定ID

    iphdr.ip_id = htons(0);

    // ?????
    ip_flags[0] = 0;
    ip_flags[1] = 0;
    ip_flags[2] = 0;
    ip_flags[3] = 0;
    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14) + (ip_flags[2] << 13) + ip_flags[0]);

    // 指定 ttl
    iphdr.ip_ttl = 255;

    // 指定协议
    iphdr.ip_p = IPPROTO_TCP;

    // 设置源ip
    if ((status = inet_pton(AF_INET, src_ip, &(iphdr.ip_src))) != 1){
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    // 设置目的ip
    if ((status = inet_pton(AF_INET, dst_ip, &(iphdr.ip_dst))) !=1 ){
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    // 设置校验和
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum((uint16_t *)&iphdr, IP4_HDRLEN);

    // tcp 首部
    // 源端口
    tcphdr.th_sport = htons(src_p);
    // 目的端口
    tcphdr.th_dport = htons(dst_p);
    // 序列号 32位
    tcphdr.th_seq = htonl(0);
    // 确认号 32位
    tcphdr.th_ack = htonl(0);

    //???
    // Reserved (4 bits): should be 0
    tcphdr.th_x2 = 0;
    //???
    // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr.th_off = TCP_HDRLEN / 4;

    // Flages 8位
    // FIN
    tcp_flags[0] = 0;

    // SYN
    tcp_flags[1] = 1;

    // RST
    tcp_flags[2] = 0;

    //PSH
    tcp_flags[3] = 0;

    //ACK
    tcp_flags[4] = 0;

    //URG
    tcp_flags[5] = 0;

    //ECE
    tcp_flags[6] = 0;

    //CWR
    tcp_flags[7] = 0;

    tcphdr.th_flags = 0;

    for (i =0; i<8; i++){
        tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Window size (16 bits)
    tcphdr.th_win = htons (65535);

    // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr.th_urp = htons (0);

    // TCP checksum (16 bits)
    tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr);

    // 将ip首部赋值给packet    》》》》packet 为数据包的首地址 《《《《
    memcpy(packet, &iphdr, IP4_HDRLEN* sizeof(uint8_t));
    // 将tcp首部赋值给packet
    memcpy((packet + IP4_HDRLEN),&tcphdr, TCP_HDRLEN * sizeof(uint8_t));

    // 内核会仅仅为我们准备到第二层的以太网帧头
    // 所以，我们需要给内核指定一个目标，来决定向哪里发送原始数据报，我们使用一个 sockaddr_in结构体来填充所需要的ip，并将次传递给sendto函数
    memset(&sin, 0 , sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    // 创建socket
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        fprintf(stderr, "socket创建失败");
        exit(EXIT_FAILURE);
    }
    // 设置标志，告诉操作系统，我们自己提供ip头部
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
        perror("setsocketopt 设置 IP_HDRINCL 失败");
        exit(EXIT_FAILURE);
    }
    // 绑定指定网卡接口
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0){
        perror("setsocketopt 绑定网卡设备失败");
        exit(EXIT_FAILURE);
    }

    // 发送数据包
    if (sendto(sd, packet, IP4_HDRLEN+TCP_HDRLEN, 0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0){
        perror("数据发送失败");
        exit(EXIT_FAILURE);
    }

    // 释放空间
    close(sd);
    free(packet);
    free(interface);
    free(target);
    free(src_ip);
    free(dst_ip);
    free(ip_flags);
    free(tcp_flags);
    return 0;
}

int *allocate_intmem(int len){
    void *tmp;
    if (len < 0){
        fprintf(stderr, "len 不能小于0 in allocate_intmem");
        exit(EXIT_FAILURE);
    }

    tmp = (int *)malloc(len * sizeof(int));
    if (tmp != NULL) {
        memset(tmp, 0, sizeof(tmp));
        return tmp;
    } else{
        fprintf(stderr, "内存分配失败 in allocate_intmem");
    }
}

char *allocate_strmem(int len){
    void *tmp;
    if (len < 0){
        fprintf(stderr, "len 不能小于0 in allocate_strmem");
        exit(EXIT_FAILURE);
    }
    tmp = (char *)malloc(len * sizeof(char));
    if (tmp != NULL) {
        memset(tmp, 0, sizeof(tmp));
        return tmp;
    } else{
        fprintf(stderr, "内存分配失败 in allocate_strmem");
        exit(EXIT_FAILURE);
    }
}

uint8_t * allocate_ustrmem(int len){
    void *tmp;
    if (len < 0){
        fprintf(stderr, "len 不能小于0 in allocate_ustrmem");
        exit(EXIT_FAILURE);
    }
    tmp = (uint8_t *)malloc(len * sizeof(uint8_t));
    if (tmp != NULL) {
        memset(tmp, 0, sizeof(tmp));
        return tmp;
    } else{
        fprintf(stderr, "内存分配失败 in allocate_strmem");
        exit(EXIT_FAILURE);
    }
}


// Checksum function
uint16_t
checksum (uint16_t *addr, int len)
{
    int nleft = len;
    int sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= sizeof (uint16_t);
    }

    if (nleft == 1) {
        *(uint8_t *) (&answer) = *(uint8_t *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr)
{
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;

    // ptr points to beginning of buffer buf
    ptr = &buf[0];

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
    ptr += sizeof (iphdr.ip_src.s_addr);
    chksumlen += sizeof (iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
    ptr += sizeof (iphdr.ip_dst.s_addr);
    chksumlen += sizeof (iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
    ptr += sizeof (iphdr.ip_p);
    chksumlen += sizeof (iphdr.ip_p);

    // Copy TCP length to buf (16 bits)
    svalue = htons (sizeof (tcphdr));
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    chksumlen += sizeof (svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
    ptr += sizeof (tcphdr.th_urp);
    chksumlen += sizeof (tcphdr.th_urp);

    return checksum ((uint16_t *) buf, chksumlen);
}