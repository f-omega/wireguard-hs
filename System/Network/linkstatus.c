#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

int wg_get_link_status(const char *ifname, int *flags) {
  struct ifreq ifr;
  int fd;

  /* Copy name */
  memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if ( fd < 0 )
    return -1;

  if ( ioctl(fd, SIOCGIFFLAGS, &ifr) < 0 )
    return -1;

  *flags = ifr.ifr_flags;

  close(fd);

  return 0;
}

