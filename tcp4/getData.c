//
// Created by root on 18-4-2.
// 接受数据
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <arpa/inet.h>


#include <errno.h>
#include <stdlib.h>

typedef struct iphdr IP_HEAD;
typedef struct tcphdr TCP_HEAD;

char * allocate_strmem(int len){
    void *tmp;
    if (len < 0){
        perror("len error in allocate_strmem\n");
        exit(EXIT_FAILURE);
    }
    tmp = (char *)malloc(sizeof(char) * len);
    if (tmp != NULL){
        memset(tmp, 0, sizeof(tmp));
        return tmp;
    }else{
        perror("ERROR:内存分配失败\n");
        exit(EXIT_FAILURE);
    }
}
int *allocate_intmem(int len){
    void * tmp;
    if (len < 0){
        perror("ERROR:len 错误在allocate_intmem");
        exit(EXIT_FAILURE);
    }
    tmp = (int *)malloc(sizeof(int) * len);
    if (tmp != NULL){
        memset(tmp, 0, sizeof(tmp));
        return tmp;
    } else{
        perror("allocate_intmem 内存分配失败\n");
        exit(EXIT_FAILURE);
    }
}
int getdata(int src_p);
int main(void){
    int src_p = 10086;
    getdata(src_p);
    return 0;
}
int getdata(int src_p){
    int sd, i;
    int targe_port = 80;
    char *interface;
    struct ifreq ifr;
    struct sockaddr_in target;
    char recvbuf[1024];
    char getdest[1024];

    interface = allocate_strmem(40);
    strcpy(interface, "wlan0");

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd < 0){
        perror("SOCKET 创建失败\n");
        exit(EXIT_FAILURE);
    }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),"%s",interface);
    if(ioctl(sd, SIOCGIFINDEX, &ifr) < 0){
        perror("ERROR:获取网卡接口失败\n");
        exit(EXIT_FAILURE);
    }
    close(sd);
    memset(&target, 0, sizeof(target));
    socklen_t target_len = sizeof(target);
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd < 0){
        perror("SOCKET 创建失败\n");
        exit(EXIT_FAILURE);
    }
    if(setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE,&ifr, sizeof(ifr)) < 0){
        perror("ERROR：绑定网卡失败\n");
        exit(EXIT_FAILURE);
    }
    for (;;){
        if(recvfrom(sd, recvbuf, sizeof(recvbuf),0,&target, &target_len) < 0 ){
            perror("ERROR:接收数据失败\n");
            continue;
        }
        IP_HEAD *ip = (IP_HEAD *)recvbuf;
        char *dest_ip = inet_ntop(AF_INET, &ip->saddr, getdest, sizeof(getdest));
        size_t iplen = (ip->ihl * 4);
        TCP_HEAD *tcp = (TCP_HEAD*)(recvbuf + iplen);
        if (tcp->th_flags == 18 && ntohs(tcp->th_dport) == src_p){
            printf("%s 存在 开放 %d端口\n", dest_ip, ntohs(tcp->th_sport));
        }
    }

    close(sd);
    return 0;
}