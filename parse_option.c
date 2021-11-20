#include "parse.h"

static void usage(void) {
  fprintf(stderr, "usage:./main [-d --daemon] [-p --port] [-s --sslport] [-l "
                  "--log] [-v --version] [-h --help]\n\n");
  exit(1);
}

static void version(void) {
  fprintf(stderr, "版本:1.0\n功能:web服务器的实现\n"
                  "提供GET,POST功能\n"
                  "实现SSL安全连接\n"
                  "提供目录访问和简单的访问控制\n\n"
                  "计算机网络大作业\n\n"
                  "SSL实现:基于OPENSSL库\n\n");
  exit(1);
}

#ifdef HTTPS
void parse_option(int argc, char **argv, char *d, char **portp, char **logp,
                  char **sslp, char *dossl)
#else
void parse_option(int argc, char **argv, char *d, char **portp, char **logp)
#endif
{
  int opt;
  static char port[16];
#ifdef HTTPS
  static char sslport[16];
#endif
  static char log[64];

  struct option longopts[] = {
      {"daemon", 0, NULL, 'd'},  {"port", 1, NULL, 'p'},
#ifdef HTTPS
      {"sslport", 1, NULL, 's'}, {"extent", 0, NULL, 'e'},
#endif
      {"log", 1, NULL, 'l'},     {"help", 0, NULL, 'h'},
      {"version", 0, NULL, 'v'}, {0, 0, 0, 0}};

#ifdef HTTPS
  while ((opt = getopt_long(argc, argv, ":dp:s:l:ehv", longopts, NULL)) != -1)
#else
  while ((opt = getopt_long(argc, argv, ":dp:l:hv", longopts, NULL)) != -1)
#endif
  {
    switch (opt) {
    case 'd':
      *d = 1;
      break;
    case 'p':
      strncpy(port, optarg, 15);
      *portp = port;
      break;
#ifdef HTTPS
    case 's':
      strncpy(sslport, optarg, 15);
      *sslp = sslport;
      break;
    case 'e':
      *dossl = 1;
      break;
#endif
    case 'l':
      strncpy(log, optarg, 63);
      *logp = log;
      break;
    case ':':
      fprintf(stderr, "-%c:option needs a value.\n", optopt);
      exit(1);
      break;
    case 'h':
      usage();
      break;
    case 'v':
      version();
      break;
    case '?':
      fprintf(stderr, "unknown option:%c\n", optopt);
      usage();
      break;
    }
  }
}

/* parse_option 测试
int main(int argc,char **argv)
{

        char d=0,*p=NULL;

        parse_option(argc,argv,&d,&p);
        if(d==1)
                printf("daemon\n");
        if(p!=NULL)
                printf("%s\n",p);

}
*/
