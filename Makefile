TARGET = unbuddha
OBJ = unbuddha.o

$(TARGET): $(OBJ)
	$(CC) -o $@ $^

