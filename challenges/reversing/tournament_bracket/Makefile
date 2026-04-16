BIN := dist/tournament
SRC := src/tournament.c

CC      ?= gcc
CFLAGS  ?= -O2 -s -fno-stack-protector -Wall -Wno-unused-result
LDFLAGS ?=

.PHONY: all clean test

all: $(BIN)

$(BIN): $(SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)
	strip -s $@ 2>/dev/null || true
	@echo "[+] built $(BIN) ($$(stat -c%s $(BIN)) bytes)"

test: $(BIN)
	@printf 'tiki_taka_baby\nroute_one_go\npenalty_shootout\n' | ./$(BIN)

clean:
	rm -f $(BIN)
