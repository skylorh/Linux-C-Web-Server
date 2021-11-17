#include "../wrap.h"
#include <stdio.h>
#include <stdlib.h>

#define MAXLEN 10000
#define EXTRA 0
/* 4 for field name "data", 1 for "=" */
#define MAXINPUT MAXLEN + EXTRA + 2
/* 1 for added line break, 1 for trailing NUL */

void unencode(char *src, char *last, char *dest) {
  for (; src != last; src++, dest++)
    if (*src == '+')
      *dest = ' ';
    else if (*src == '%') {
      int code;
      if (sscanf(src + 1, "%2x", &code) != 1)
        code = '?';
      *dest = code;
      src += 2;
    } else
      *dest = *src;
  *dest = '\n';
  *++dest = '\0';
}

int main(void) {

  char *lenstr;
  char input[MAXINPUT], data[MAXINPUT];
  long len;

  char *c;
  char fname[50];
  memset(fname, '\0', sizeof(char));

  char fpath[50];
  memset(fpath, '\0', sizeof(char));

  printf("%s%c%c\n", "Content-Type:text/html;charset=iso-8859-1", 13, 10);
  printf("<TITLE>Response</TITLE>\n");
  lenstr = getenv("CONTENT-LENGTH");

  // extern char **environ;
  // int i;
  // for(i=0; environ[i]!=NULL; i++)
  // 	printf("<P>%s", environ[i]);

  if (lenstr == NULL || sscanf(lenstr, "%ld", &len) != 1 || len > MAXLEN)
    printf("<P>Error in invocation - wrong FORM probably.");
  else {
    FILE *f;

    fgets(input, len + 1, stdin);
    fgets(input, len + 1, stdin);
    c = strstr(input, "filename=");
    strcat(fpath, "./doc/dir/");
    strcat(fpath, c + 10);
    fpath[strlen(fpath) - 3] = '\0';

    strcat(fname, c + 10);
    fname[strlen(fname) - 3] = '\0';
    // printf("fname: %s!\n", fname);
    f = fopen(fpath, "a");

    fgets(input, len + 1, stdin);
    fgets(input, len + 1, stdin);
    while (fgets(input, len + 1, stdin) != NULL) {
      unencode(input + EXTRA, input + len, data);
      if ((c = strstr(data, "WebKitFormBoundary")) != NULL)
        break;
      if (f == NULL)
        printf("<P>Sorry, cannot store your data.");
      else {
        fputs(data, f);
      }
    }
    fclose(f);
    printf("<P>Upload %s success. Thank you!", fname);
  }
  return 0;
}