#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <linux/netlink.h>
#include <linux/connector.h>

#define MAX_PAYLOAD 64

#define GROUP 1

struct sockaddr_nl src_addr, dest_addr;
struct msghdr msg;
int sock_fd;

unsigned char *buf = NULL;
unsigned char *payload = NULL;

int main() {
    socklen_t addrlen;
    int status;
    int group = GROUP; 
    struct cn_msg *cnmsg;
    
    int i;
    
    sock_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    
    if (sock_fd == -1) {
        perror("socket()");
        return 1;
    }
    
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;       
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = group;
    
    status = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    
    if (status == -1) {
        close(sock_fd);
        perror("bind()");
        return 1;
    }
    
    memset(&dest_addr, 0, sizeof(dest_addr)); 
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = group;
    
    buf = (unsigned char *) malloc(MAX_PAYLOAD);
    
    if (!buf) {
    	perror("malloc()");
        return 1;
    }
    
    addrlen = sizeof(dest_addr);
    
    while(1) {
        
        memset(buf, 0, MAX_PAYLOAD);
        
        status = recvfrom(sock_fd, buf, MAX_PAYLOAD, 0, (struct sockaddr *)&dest_addr, &addrlen);
        
        if (status <= 0) {
            perror("recvfrom()");
            return 1;
        }
        
        payload = buf + sizeof(struct cn_msg) + sizeof(struct nlmsghdr);
        
        printf("payload received from kernel: %s\n", payload);
        
    }
    
    close(sock_fd);
    
    return 0;
}    
