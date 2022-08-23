CORES ?= 8
rust_lib:
	CORES=${CORES}  cargo +nightly build --manifest-path ../cipher-suite/Cargo.toml --target riscv32imc-unknown-none-elf --no-default-features --release
	cd ../target/riscv32imc-unknown-none-elf/release && ar x libcipher_suite.a

# COMPILER FLAGS
APP_CFLAGS += -O3 -g3 -DNUM_CORES=${CORES}

APP = main
APP_SRCS	+= main.c 
APP_LDFLAGS = ../target/riscv32imc-unknown-none-elf/release/*.o 

CONFIG_HYPERRAM = 1

include $(RULES_DIR)/pmsis_rules.mk
