
IDIR            += ./include
IDIR            += ./private_include

CFLAGS          := $(addprefix -I, $(IDIR))
CFLAGS          += $(addprefix -L, $(LDIR))
CFLAGS          += $(addprefix -D, $(DEFS))
#CFLAGS          += -shared -fPIC -Werror -O3 -std=c99
CFLAGS          += -shared -fPIC -Werror -O3 -std=c89

export IDIR LDIR DEFS
