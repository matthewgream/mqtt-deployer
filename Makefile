
##

CC      = gcc
# (no -Wwrite-strings: this program is exec-heavy and the execvp argv idiom
#  fights it; explicit casts on const args keep us honest instead.)
CFLAGS  = -Wall -Wextra -Wpedantic -Werror \
          -Wstrict-prototypes -Wold-style-definition \
          -Wshadow -Wpointer-arith -Wredundant-decls \
          -Wmissing-include-dirs -Wnull-dereference
LIBS    = -lmosquitto -lcjson -lcrypto

TARGET  = mqtt-deployer
MAIN    = mqtt-deployer.c

all: $(TARGET)

$(TARGET): $(MAIN)
	$(CC) $(CFLAGS) -o $(TARGET) $(MAIN) $(LIBS)

clean:
	rm -f $(TARGET) $(TARGET).armhf

format:
	clang-format -i $(MAIN)

## cross-build for the ARMv6 target. The fleet's cross-toolchain wrapper passes
## CROSS_CC_ARMHF; a plain `make armhf` uses Debian's gcc (v7 — won't run on a
## Pi Zero, so use the toolchain).
CROSS_CC_ARMHF ?= arm-linux-gnueabihf-gcc
$(TARGET).armhf: $(MAIN)
	$(CROSS_CC_ARMHF) $(CFLAGS) -o $(TARGET).armhf $(MAIN) $(LIBS)
armhf: $(TARGET).armhf

.PHONY: all clean format armhf
