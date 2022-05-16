CORES ?= 4

rust_lib:
	CORES=${CORES} cargo +nightly build --manifest-path ../chacha20/Cargo.toml --target riscv32imc-unknown-none-elf --no-default-features --release
	cd ../target/riscv32imc-unknown-none-elf/release && ar x libchacha20.a

# COMPILER FLAGS
APP_CFLAGS += -O1 -g3 -DNUM_CORES=${CORES}

APP = main
APP_SRCS	+= main.c 
# For some reason it does not compile with -O0
APP_LDFLAGS = ../target/riscv32imc-unknown-none-elf/release/*.o 

CONFIG_HYPERRAM = 1

include $(RULES_DIR)/pmsis_rules.mk
