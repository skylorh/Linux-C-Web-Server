CC = gcc
CFLAGS = -O2 -Wall -I ..

all: getAuth  postAuth upload

getAuth: getAuth.c
	$(CC) $(CFLAGS) -o getAuth getAuth.c

postAuth: postAuth.c
	$(CC) $(CFLAGS) -o postAuth postAuth.c

upload: upload.c
	$(CC) $(CFLAGS)  upload.c -o upload

clean:
	rm -f getAuth postAuth upload *~
