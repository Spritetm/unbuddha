TARGET = unbuddha
OBJ = unbuddha.o crc.o
CFLAGS=-ggdb
LDFLAGS=-lcjson

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
