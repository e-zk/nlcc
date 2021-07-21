CC = cc
BIN = nlcc
LDFLAGS = encrypt.c -lsodium

all: $(BIN)
$(BIN): nlcc.c encrypt.c crypto_aead.h
	$(CC) -o $(BIN) nlcc.c $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(BIN)
