# ---------------------------------------
#	Makefile for building the project
# ---------------------------------------

# Variables
CC := gcc
LD := gcc
RM := rm -rf

# target executable
TARGET_NAME   := cipher_test
TARGET_DIR    := bin
TARGET := $(TARGET_DIR)/$(TARGET_NAME)

# target variables
BUILD_DIR     := obj

# compiler flags
CFLAGS    := -g -Wall -Iinclude -O2
LDFLAGS   :=
CPPFLAGS  :=

# ---------------------------------------
#	Source and Object Files
# ---------------------------------------
SRCS :=

include src/build.mk

# main application source files
SRCS += test/main_app.c

OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))


# ---------------------------------------
#	target rules
# ---------------------------------------
all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "LD  ==> $@"
	@mkdir -p $(TARGET_DIR)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: %.c
	@echo "CC  ==> $@"
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

# clean
clean:
	@echo "Cleaning up..."
	$(RM) $(BUILD_DIR) $(TARGET_DIR)

# run
run: all
	@echo "Running the application..."
	@./$(TARGET)