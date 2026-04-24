CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -static
TARGET  = formation

all: $(TARGET)

$(TARGET): src/formation.c
	$(CC) $(CFLAGS) -o $(TARGET) src/formation.c

clean:
	rm -f $(TARGET)
