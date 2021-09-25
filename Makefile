TARGET = unbuddha
OBJ = unbuddha.o
CFLAGS=-ggdb

$(TARGET): $(OBJ)
	$(CC) -o $@ $^

