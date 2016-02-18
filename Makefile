CC = gcc
CFLAGS = -g -Wall

all: deadline_test cyclicdeadline

deadline_test: deadline_test.o
	$(CC) $^ -o $@ -lpthread -lrt

cyclicdeadline: cyclicdeadline.o
	$(CC) $^ -o $@ -lpthread -lrt

