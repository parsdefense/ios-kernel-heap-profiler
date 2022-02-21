SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC = $(shell xcrun --sdk $(SDK) --find clang)
CFLAGS = -g -arch arm64 -isysroot $(SDK)
CFLAGS += -Wno-deprecated-declarations -fno-stack-protector -D_FORTIFY_SOURCE=0 -O0

OUTPUT=kernel_hooks

all : kernel_hooks

kernel_hooks :
	$(CC) $(CFLAGS) $(LDFLAGS) kernel_hooks.c -o $(OUTPUT)
	ldid -Sent.xml ./$(OUTPUT)
	ssh -p2222 root@localhost rm -f /var/root/$(OUTPUT)
	scp -P2222 ./$(OUTPUT) root@localhost:

clean:
	rm -f $(OUTPUT)
	rm -rf *.dSYM
