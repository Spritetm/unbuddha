TARGET = unjlfs2
OBJ = unpack_jlfs.o crc.o hexdump.o
CFLAGS=-ggdb
LDFLAGS=-lcjson

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
