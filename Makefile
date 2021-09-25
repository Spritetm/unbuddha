TARGET = unbuddha
OBJ = unbuddha.o crc.o
CFLAGS=-ggdb

$(TARGET): $(OBJ)
	$(CC) -o $@ $^

