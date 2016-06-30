CC = gcc
CFLAGS = -g -Wall

ALL = deadline_test cyclicdeadline 
all: ${ALL}

deadline_test: deadline_test.o
	$(CC) $^ -o $@ -lpthread -lrt

cyclicdeadline: cyclicdeadline.o
	$(CC) $^ -o $@ -lpthread -lrt

clean:
	${RM} *.o ${ALL}
