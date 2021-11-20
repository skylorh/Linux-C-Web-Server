#include "parse.h"
#include "wrap.h"

#define PID_FILE "pid.file"

static void doit(int fd);
static void writePid(int option);
static void get_requesthdrs(rio_t *rp);
static void post_requesthdrs(rio_t *rp, int *length);
static int parse_uri(char *uri, char *filename, char *cgiargs);
static void serve_static(int fd, char *filename, int filesize);
static void serve_dir(int fd, char *filename);
static void get_filetype(const char *filename, char *filetype);
static void get_dynamic(int fd, char *filename, char *cgiargs);
static void post_dynamic(int fd, char *filename, int contentLength, rio_t *rp);
static void clienterror(int fd, char *cause, char *errnum, char *shortmsg,
                        char *longmsg);

static void sigChldHandler(int signo);
/*ssl 设置*/
#ifdef HTTPS
static void ssl_init(void);
static void https_getlength(char *buf, int *length);
#endif

static int isShowdir = 1;
char *cwd;

#ifdef HTTPS
static SSL_CTX *ssl_ctx;
static SSL *ssl;
static char *certfile;
static int ishttps = 0;
static char httpspostdata[MAXLINE];
#endif

int main(int argc, char **argv) {
  int listenfd, connfd, port, clientlen;
  pid_t pid;
  struct sockaddr_in clientaddr;
  char isdaemon = 0, *portp = NULL, *logp = NULL, tmpcwd[MAXLINE];

#ifdef HTTPS
  int sslport;
  char dossl = 0, *sslportp = NULL;
#endif

  openlog(argv[0], LOG_NDELAY | LOG_PID, LOG_DAEMON);
  cwd = (char *)get_current_dir_name();
  strcpy(tmpcwd, cwd);
  strcat(tmpcwd, "/");
  /* 解析参数 */

#ifdef HTTPS
  parse_option(argc, argv, &isdaemon, &portp, &logp, &sslportp, &dossl);
  sslportp == NULL ? (sslport = atoi(Getconfig("https")))
                   : (sslport = atoi(sslportp));

  if (dossl == 1 || strcmp(Getconfig("dossl"), "yes") == 0)
    dossl = 1;
#else
  parse_option(argc, argv, &isdaemon, &portp, &logp);
#endif

  portp == NULL ? (port = atoi(Getconfig("http"))) : (port = atoi(portp));

  Signal(SIGCHLD, sigChldHandler);

  /* 日志初始化 */
  if (logp == NULL)
    logp = Getconfig("log");
  initlog(strcat(tmpcwd, logp));

  /* 目录展示判断 */
  if (strcmp(Getconfig("dir"), "no") == 0)
    isShowdir = 0;

  clientlen = sizeof(clientaddr);

  if (isdaemon == 1 || strcmp(Getconfig("daemon"), "yes") == 0)
    Daemon(1, 1);

  writePid(1);

/* HTTPS */
#ifdef HTTPS
  if (dossl) {
    if ((pid = Fork()) == 0) {
      listenfd = Open_listenfd(sslport);
      ssl_init();

      while (1) {
        connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
        if (access_ornot(inet_ntoa(clientaddr.sin_addr)) == 0) {
          clienterror(connfd, "maybe this web server not open to you!", "403",
                      "Forbidden", "Server couldn't read the file");
          continue;
        }

        if ((pid = Fork()) > 0) {
          Close(connfd);
          continue;
        } else if (pid == 0) {
          ishttps = 1;
          doit(connfd);
          exit(1);
        }
      }
    }
  }
#endif

  listenfd = Open_listenfd(port);
  while (1) {
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (access_ornot(inet_ntoa(clientaddr.sin_addr)) == 0) {
      clienterror(connfd, "maybe this web server not open to you!", "403",
                  "Forbidden", "Server couldn't read the file");
      continue;
    }

    if ((pid = Fork()) > 0) {
      Close(connfd);
      continue;
    } else if (pid == 0) {
      doit(connfd);
      exit(1);
    }
  }
}

/* 保护进程 */
static void sigChldHandler(int signo) {
  Waitpid(-1, NULL, WNOHANG);
  return;
}

/* ssl 初始化  */
#ifdef HTTPS
static void ssl_init(void) {
  static char crypto[] = "RC4-MD5";
  certfile = Getconfig("ca");

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  ssl_ctx = SSL_CTX_new(SSLv23_server_method());

  if (certfile[0] != '\0')
    if (SSL_CTX_use_certificate_file(ssl_ctx, certfile, SSL_FILETYPE_PEM) ==
            0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, certfile, SSL_FILETYPE_PEM) == 0 ||
        SSL_CTX_check_private_key(ssl_ctx) == 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  if (crypto != (char *)0) {

    if (SSL_CTX_set_cipher_list(ssl_ctx, crypto) == 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
  }
}
#endif

/*
 * 处理一个HTTP请求或响应事务
 */
static void doit(int fd) {
  int is_static, contentLength = 0, isGet = 1;
  struct stat sbuf;
  char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
  char filename[MAXLINE], cgiargs[MAXLINE], httpspostdata[MAXLINE];
  rio_t rio;

  memset(buf, 0, MAXLINE);

#ifdef HTTPS
  if (ishttps) {
    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) == 0) {
      ERR_print_errors_fp(stderr);
      exit(1);
    }
    SSL_read(ssl, buf, sizeof(buf));
  } else
#endif
  {
    /* 读取请求头 */
    Rio_readinitb(&rio, fd);
    Rio_readlineb(&rio, buf, MAXLINE);
  }

  sscanf(buf, "%s %s %s", method, uri, version);

  if (strcasecmp(method, "GET") != 0 && strcasecmp(method, "POST") != 0) {
    clienterror(fd, method, "501", "Not Implemented",
                "Server does not implement this method");
    return;
  }

  /* 从GET请求中解析URI */
  is_static = parse_uri(uri, filename, cgiargs);

  if (lstat(filename, &sbuf) < 0) {
    clienterror(fd, filename, "404", "Not found",
                "Server couldn't find this file");
    return;
  }

  if (S_ISDIR(sbuf.st_mode) && isShowdir)
    serve_dir(fd, filename);

  if (strcasecmp(method, "POST") == 0)
    isGet = 0;

  if (is_static) { /* 静态内容 */

#ifdef HTTPS
    if (!ishttps)
#endif
      get_requesthdrs(&rio); /* HTTPS已经通过SSL_read()读取了headers */

    if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
      clienterror(fd, filename, "403", "Forbidden",
                  "Server couldn't read the file");
      return;
    }
    serve_static(fd, filename, sbuf.st_size);
  } else { /* 动态内容 */
    if (!(S_ISREG(sbuf.st_mode)) || !(S_IXUSR & sbuf.st_mode)) {
      clienterror(fd, filename, "403", "Forbidden",
                  "Server couldn't run the CGI program");
      return;
    }

    if (isGet) {
#ifdef HTTPS
      if (!ishttps)
#endif
        get_requesthdrs(&rio); /* HTTPS已经通过SSL_read()读取了headers */
      get_dynamic(fd, filename, cgiargs);
    } else {
#ifdef HTTPS
      if (ishttps)
        https_getlength(buf, &contentLength);
      else
#endif
        post_requesthdrs(&rio, &contentLength);
      post_dynamic(fd, filename, contentLength, &rio);
    }
  }
}

#ifdef HTTPS
static void https_getlength(char *buf, int *length) {
  char *p, line[MAXLINE];
  char *tmpbuf = buf;
  int lengthfind = 0;

  while (*tmpbuf != '\0') {
    p = line;
    while (*tmpbuf != '\n' && *tmpbuf != '\0')
      *p++ = *tmpbuf++;
    *p = '\0';
    if (!lengthfind) {
      if (strncasecmp(line, "Content-Length:", 15) == 0) {
        p = &line[15];
        p += strspn(p, " \t");
        *length = atoi(p);
        lengthfind = 1;
      }
    }

    if (strncasecmp(line, "\r", 1) == 0) {
      strcpy(httpspostdata, ++tmpbuf);
      break;
    }
    ++tmpbuf;
  }
  return;
}
#endif

/*
 * 读取并解析HTTP请求头
 */
static void get_requesthdrs(rio_t *rp) {
  char buf[MAXLINE];

  Rio_readlineb(rp, buf, MAXLINE);
  writetime(); /* 在log文件中记录时间 */
  while (strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    writelog(buf);
  }
  return;
}

static void post_requesthdrs(rio_t *rp, int *length) {
  char buf[MAXLINE];
  char *p;

  Rio_readlineb(rp, buf, MAXLINE);
  writetime(); /* 在log文件中记录时间 */
  while (strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    if (strncasecmp(buf, "Content-Length:", 15) == 0) {
      p = &buf[15];
      p += strspn(p, " \t");
      *length = atol(p);
    }
    writelog(buf);
  }
  return;
}

static void serve_dir(int fd, char *filename) {
  DIR *dp;
  struct dirent *dirp;
  struct stat sbuf;
  struct passwd *filepasswd;
  int num = 1;
  char files[MAXLINE], buf[MAXLINE], name[MAXLINE], img[MAXLINE],
      modifyTime[MAXLINE], dir[MAXLINE];
  char *p;

  /*
   * 获取目录
   */
  p = strrchr(filename, '/');
  ++p;
  strcpy(dir, p);
  strcat(dir, "/");

  if ((dp = opendir(filename)) == NULL)
    syslog(LOG_ERR, "cannot open dir:%s", filename);

  sprintf(files, "<html><title>Dir Browser</title>");
  sprintf(files,
          "%s<style type="
          "text/css"
          "> a:link{text-decoration:none;} </style>",
          files);
  sprintf(files,
          "%s<body bgcolor="
          "ffffff"
          " font-family=Arial color=#fff font-size=14px>\r\n",
          files);

  while ((dirp = readdir(dp)) != NULL) {
    if (strcmp(dirp->d_name, ".") == 0 || strcmp(dirp->d_name, "..") == 0)
      continue;
    sprintf(name, "%s/%s", filename, dirp->d_name);
    Stat(name, &sbuf);
    filepasswd = getpwuid(sbuf.st_uid);

    if (S_ISDIR(sbuf.st_mode)) {
      sprintf(img, "<img src="
                   "dir.png"
                   " width="
                   "24px"
                   " height="
                   "24px"
                   ">");
    } else if (S_ISFIFO(sbuf.st_mode)) {
      sprintf(img, "<img src="
                   "fifo.png"
                   " width="
                   "24px"
                   " height="
                   "24px"
                   ">");
    } else if (S_ISLNK(sbuf.st_mode)) {
      sprintf(img, "<img src="
                   "link.png"
                   " width="
                   "24px"
                   " height="
                   "24px"
                   ">");
    } else if (S_ISSOCK(sbuf.st_mode)) {
      sprintf(img, "<img src="
                   "sock.png"
                   " width="
                   "24px"
                   " height="
                   "24px"
                   ">");
    } else
      sprintf(img, "<img src="
                   "file.png"
                   " width="
                   "24px"
                   " height="
                   "24px"
                   ">");

    sprintf(files,
            "%s<p><pre>%-2d %s "
            "<a href=%s%s"
            ">%-15s</a>%-10s%10d %24s</pre></p>\r\n",
            files, num++, img, dir, dirp->d_name, dirp->d_name,
            filepasswd->pw_name, (int)sbuf.st_size,
            timeModify(sbuf.st_mtime, modifyTime));
  }
  closedir(dp);
  sprintf(files, "%s</body></html>", files);

  /* 向客户端发送响应头 */
  sprintf(buf, "HTTP/1.0 200 OK\r\n");
  sprintf(buf, "%sServer: My Web Server\r\n", buf);
  sprintf(buf, "%sContent-length: %d\r\n", buf, strlen(files));
  sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, "text/html");

#ifdef HTTPS
  if (ishttps) {
    SSL_write(ssl, buf, strlen(buf));
    SSL_write(ssl, files, strlen(files));
  } else
#endif
  {
    Rio_writen(fd, buf, strlen(buf));
    Rio_writen(fd, files, strlen(files));
  }
  exit(0);
}

static void post_dynamic(int fd, char *filename, int contentLength, rio_t *rp) {
  char buf[MAXLINE], length[32], *emptylist[] = {NULL}, data[MAXLINE];
  int p[2];
#ifdef HTTPS
  int httpsp[2];
#endif

  sprintf(length, "%d", contentLength);
  memset(data, 0, MAXLINE);

  Pipe(p);

  /*       The post data is sended by client,we need to redirct the data to cgi
   * stdin. so, child read contentLength bytes data from fp,and write to p[1];
   *    parent should redirct p[0] to stdin. As a result, the cgi script can
   *    read the post data from the stdin.
   */

  /* HTTPS已经通过SSL_read()读取了包括post data在内的所有的数据 */
  if (Fork() == 0) { /* 子进程  */
    Close(p[0]);
#ifdef HTTPS
    if (ishttps) {
      Write(p[1], httpspostdata, contentLength);
    } else
#endif
    {
      Rio_readnb(rp, data, contentLength);
      Rio_writen(p[1], data, contentLength);
    }
    exit(0);
  }

  /* 向客户端发送响应头 */
  sprintf(buf, "HTTP/1.0 200 OK\r\n");
  sprintf(buf, "%sServer: My Web Server\r\n", buf);

#ifdef HTTPS
  if (ishttps)
    SSL_write(ssl, buf, strlen(buf));
  else
#endif
    Rio_writen(fd, buf, strlen(buf));

  Dup2(p[0], STDIN_FILENO); /* 重定向 p[0] 到 stdin */
  Close(p[0]);

  Close(p[1]);
  setenv("CONTENT-LENGTH", length, 1);
#ifdef HTTPS
  if (ishttps) /* HTTPS需要使用SSL_write */
  {
    Pipe(httpsp);

    if (Fork() == 0) {
      Dup2(httpsp[1], STDOUT_FILENO); /* 重定向 stdout 到 https[1] */
      Execve(filename, emptylist, environ);
    }
    Read(httpsp[0], data, MAXLINE);
    SSL_write(ssl, data, strlen(data));
  } else
#endif
  {
    Dup2(fd, STDOUT_FILENO); /* 重定向 stdout 到 client */
    Execve(filename, emptylist, environ);
  }
}

/*
 * 解析URI，如果是cgi调用则返回0，否则返回1。
 */
static int parse_uri(char *uri, char *filename, char *cgiargs) {
  char *ptr;
  char tmpcwd[MAXLINE];
  strcpy(tmpcwd, cwd);
  strcat(tmpcwd, "/");

  if (!strstr(uri, "cgi-bin")) {
    strcpy(cgiargs, "");
    strcpy(filename, strcat(tmpcwd, Getconfig("root")));
    strcat(filename, uri);
    if (uri[strlen(uri) - 1] == '/')
      strcat(filename, "home.html");
    return 1;
  } else {
    ptr = index(uri, '?');
    if (ptr) {
      strcpy(cgiargs, ptr + 1);
      *ptr = '\0';
    } else
      strcpy(cgiargs, "");
    strcpy(filename, cwd);
    strcat(filename, uri);
    return 0;
  }
}

/*
 * 复制一份文件返回给客户端
 */
static void serve_static(int fd, char *filename, int filesize) {
  int srcfd;
  char *srcp, filetype[MAXLINE], buf[MAXBUF];

  /* 发送响应头给客户端 */
  get_filetype(filename, filetype);
  sprintf(buf, "HTTP/1.0 200 OK\r\n");
  sprintf(buf, "%sServer: My Web Server\r\n", buf);
  sprintf(buf, "%sContent-length: %d\r\n", buf, filesize);
  sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);

  /* 发送响应体给客户端 */
  srcfd = Open(filename, O_RDONLY, 0);
  srcp = Mmap(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
  Close(srcfd);

#ifdef HTTPS
  if (ishttps) {
    SSL_write(ssl, buf, strlen(buf));
    SSL_write(ssl, srcp, filesize);
  } else
#endif
  {
    Rio_writen(fd, buf, strlen(buf));
    Rio_writen(fd, srcp, filesize);
  }
  Munmap(srcp, filesize);
}

/*
 * 区分文件类型
 */
static void get_filetype(const char *filename, char *filetype) {
  if (strstr(filename, ".html"))
    strcpy(filetype, "text/html");
  else if (strstr(filename, ".gif"))
    strcpy(filetype, "image/gif");
  else if (strstr(filename, ".jpg"))
    strcpy(filetype, "image/jpeg");
  else if (strstr(filename, ".png"))
    strcpy(filetype, "image/png");
  else
    strcpy(filetype, "text/plain");
}

/*
 * 运行cgi程序
 */
void get_dynamic(int fd, char *filename, char *cgiargs) {
  char buf[MAXLINE], *emptylist[] = {NULL}, httpsbuf[MAXLINE];
  int p[2];
  /* 返回HTTP响应的第一个部分 */
  sprintf(buf, "HTTP/1.0 200 OK\r\n");
  sprintf(buf, "%sServer: My Web Server\r\n", buf);

#ifdef HTTPS
  if (ishttps)
    SSL_write(ssl, buf, strlen(buf));
  else
#endif
    Rio_writen(fd, buf, strlen(buf));

#ifdef HTTPS
  if (ishttps) {
    Pipe(p);
    if (Fork() == 0) {
      Close(p[0]);
      setenv("QUERY_STRING", cgiargs, 1);
      Dup2(p[1], STDOUT_FILENO);            /* 重定向 stdout 到 p[1] */
      Execve(filename, emptylist, environ); /* 运行cgi程序 */
    }
    Close(p[1]);
    Read(p[0], httpsbuf, MAXLINE); /* 父进程从 p[0] 读 */
    SSL_write(ssl, httpsbuf, strlen(httpsbuf));
  } else
#endif
  {
    if (Fork() == 0) {
      /* 设置cgi参数 */
      setenv("QUERY_STRING", cgiargs, 1);
      Dup2(fd, STDOUT_FILENO);              /* 重定向 stdout 到 client */
      Execve(filename, emptylist, environ); /* 运行cgi程序 */
    }
  }
}

/*
 * 返回错误信息给客户端
 */
static void clienterror(int fd, char *cause, char *errnum, char *shortmsg,
                        char *longmsg) {
  char buf[MAXLINE], body[MAXBUF];

  /* HTTP response body */
  sprintf(body, "<html><title>Server Error</title>");
  sprintf(body,
          "%s<body bgcolor="
          "ffffff"
          ">\r\n",
          body);
  sprintf(body, "%s%s: %s\r\n", body, errnum, shortmsg);
  sprintf(body, "%s<p>%s: %s\r\n", body, longmsg, cause);
  sprintf(body, "%s<hr><em>My Web server</em>\r\n", body);

  /* 打印 HTTP response */
  sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
  sprintf(buf, "%sContent-type: text/html\r\n", buf);
  sprintf(buf, "%sContent-length: %d\r\n\r\n", buf, (int)strlen(body));

#ifdef HTTPS
  if (ishttps) {
    SSL_write(ssl, buf, strlen(buf));
    SSL_write(ssl, body, strlen(body));
  } else
#endif
  {
    Rio_writen(fd, buf, strlen(buf));
    Rio_writen(fd, body, strlen(body));
  }
}

/* 程序在执行的时候将pid写入文件，否则值为 -1  */
static void writePid(int option) {
  int pid;
  FILE *fp = Fopen(PID_FILE, "w+");
  if (option)
    pid = (int)getpid();
  else
    pid = -1;
  fprintf(fp, "%d", pid);
  Fclose(fp);
}
