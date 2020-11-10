PRODUCT := idsniff
BUILDDIR := ../build

HDRS := $(wildcard ./*.h)
SRCS := $(wildcard ./*.c)
BINARY := $(BUILDDIR)/$(PRODUCT)
OBJS := $(SRCS:./%.c=$(BUILDDIR)/%.o)

CC:=gcc

CFLAGS := -g -DDEBUG -Wall 
LDFLAGS := -lpcap -lpthread

.PHONY: all clean

all: $(BINARY)

clean: 
	rm -rf $(BUILDDIR)

$(BINARY): $(OBJS)
	echo $(OBJS)
	@echo linking $@
	$(maketargetdir)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILDDIR)/%.o : ./%.c
	@echo compiling $<
	$(maketargetdir)
	$(CC) $(CFLAGS) $(CINCLUDES) -c -o $@ $<

define maketargetdir
	-@mkdir -p $(dir $@) > /dev/null 2>&1
endef
