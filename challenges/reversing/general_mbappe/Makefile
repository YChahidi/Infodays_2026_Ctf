# GENERAL MBAPPE — InfoDays 2026 CTF build

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
STRIP   ?= strip

SRC    := src/cook.c
BIN    := dist/cook
ASM    := dist/recipe.asm
SPICE  := dist/spice.bin
WEBP_SRC := general_nbappe.webp
WEBP_OUT := dist/general_mbappe.webp
FLAG   := flag.txt

STATIC_DIR := ../../static-content/reversing-general-mbappe

.PHONY: all clean test dist regen stage

all: $(BIN) $(ASM) $(SPICE) $(WEBP_OUT) stage

$(BIN): $(SRC)
	mkdir -p dist
	$(CC) $(CFLAGS) -o $@ $<
	$(STRIP) --strip-unneeded $@

$(ASM) $(SPICE) $(FLAG): gen.py
	python3 gen.py

$(WEBP_OUT): $(WEBP_SRC) $(SPICE) stego.py
	mkdir -p dist
	python3 stego.py embed $(WEBP_SRC) $(SPICE) $(WEBP_OUT)

regen:
	python3 gen.py
	$(MAKE) -B all

test: all
	@echo "=== feeding the cook the kitchen pass ==="
	@PASS=$$(head -1 $(FLAG) | sed -E 's/^infodays\{SaamNoLimits_(.+)\}$$/\1/'); \
	 echo "kitchen pass: $$PASS"; \
	 printf '%s\n' "$$PASS" | ./$(BIN) $(ASM) $(SPICE)
	@echo "=== running solver (should NOT see spice.bin) ==="
	python3 solver/solve.py $(ASM) $(WEBP_OUT)

stage: $(BIN) $(ASM) $(WEBP_OUT)
	mkdir -p $(STATIC_DIR)
	cp $(BIN) $(STATIC_DIR)/cook
	cp $(ASM) $(STATIC_DIR)/recipe.asm
	cp $(WEBP_OUT) $(STATIC_DIR)/general_mbappe.webp
	chmod 755 $(STATIC_DIR)/cook
	@echo "Staged into $(STATIC_DIR)/ — cook + recipe.asm + general_mbappe.webp"
	@echo "NOTE: spice.bin is author-only, NEVER shipped to players."

clean:
	rm -rf dist
	rm -f $(STATIC_DIR)/cook $(STATIC_DIR)/recipe.asm $(STATIC_DIR)/general_mbappe.webp

dist: all
	@echo "Distributables staged in $(STATIC_DIR)/"
