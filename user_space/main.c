#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK   270
#endif
#define PANOP_PROTO   30
#define PANOP_GRP     21
#define BUFSZ         65536


static int open_sock(int* sk)
{
  struct sockaddr_nl addr = {0};
  int sock = 0;
  int res = 0;
  int grp = PANOP_GRP;

  if (0 > (sock = socket(AF_NETLINK, SOCK_RAW, PANOP_PROTO))) {
    fprintf(stderr, "Failed to create socket! %d\n", sock);
    return sock;
  }

  addr.nl_family = AF_NETLINK;
  addr.nl_pid = getpid();

  if(0 > (res = bind(sock, (struct sockaddr*)&addr, sizeof(addr)))) {
    fprintf(stderr, "Failed to bind! %d\n", res);
    goto cleanup;
  }

  if(0 > (res = setsockopt(sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                           &grp, sizeof(grp)))) {
    fprintf(stderr, "Setsockopt failed! %d\n", res);
    goto cleanup;
  }

  *sk = sock;

cleanup:
  if(0 > res)
    close(sock);

  return res;
}


static void read_event_data(int sock)
{
  struct sockaddr_nl addr = {0};
  struct msghdr      msg = {0};
  struct iovec       io = {0};
  char               buf[BUFSZ];
  int                rv = 0;

  io.iov_base = (void*)buf;
  io.iov_len = sizeof(buf);
  msg.msg_name = &addr;
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;

  if(0 > (rv = recvmsg(sock, &msg, 0))) {
    printf("Recv failed! %d\n", rv);
  } else {
    printf("Received: %s\n", NLMSG_DATA((struct nlmsghdr*)buf));
  }

}


int main(int argc, char** argv)
{
  int sock = 0;
  int rv = 0;
  if(0 > (rv = open_sock(&sock))) {
    return rv;
  }

  printf("> Up and running...\n");
  for(;;)
    read_event_data(sock);

  return 0;

}
