
DIR_OBJ         = ./.obj
IDIR            += ../include ./
IDIR            += ../private_include ./

CFLAGS		+= $(addprefix -I, $(IDIR))
CFLAGS		+= $(addprefix -D, $(DEFS))
CFLAGS		+=  -Werror

LIBA		:= ../../.obj/libgmalg.a
LIBS		:= pthread  dl

LDFLAGS		:= $(addprefix -L, $(LDIR))
LDFLAGS		+= $(addprefix -l, $(LIBS))
OBJS            = $(patsubst %.c,${DIR_OBJ}/%.o,$(notdir $(wildcard *.c)))

TODO		:= $(basename $(wildcard *.c))

.PHONY: all

all:  $(OBJS)
	$(foreach f, $(TODO), $(shell cd .obj; $(CC) $(LDFLAGS) $(f).o $(LIBA) -o $(f) -lpthread))

${DIR_OBJ}/%.o:%.c
	test -d $(DIR_OBJ) || mkdir -p $(DIR_OBJ)
	$(CC) $(CFLAGS) -c  $< -o $@

clean:
	$(RM) $(DIR_OBJ)/* *.o
