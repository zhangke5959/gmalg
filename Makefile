
include generic.mk

VERSION		:= 1.0
BASENAME	:= libgmalg
STATICLIB	:= $(BASENAME).a
SHAREDLIB	:= $(BASENAME).so


DIR_OBJ		= ./.obj
SOURCES		:= $(wildcard *.c)
OBJS		= $(patsubst %.c,${DIR_OBJ}/%.o,$(notdir ${SOURCES}))

export CC STRIP MAKE AR
.PHONY: all clean

all: $(OBJS)
	$(CC) $(CFLAGS) -o ${DIR_OBJ}/$(SHAREDLIB) $(OBJS)
	$(AR) -cr ${DIR_OBJ}/$(STATICLIB) $(OBJS)
	make -C utils

${DIR_OBJ}/%.o:%.c
	test -d $(DIR_OBJ) || mkdir -p $(DIR_OBJ)
	$(CC) $(CFLAGS) -c  $< -o $@

clean:
	$(RM) *.so.* ${DIR_OBJ}/* ${DIR_OBJ}/$(OBJS) ${DIR_OBJ}/$(SHAREDLIB) ${DIR_OBJ}/$(STATICLIB)
	make -C utils clean

mrproper: clean
	$(RM) tags *.tgz

tarball:
	@git archive --prefix=$(BASENAME)-$(GIT_VER)/ --format=tar HEAD \
		| gzip > $(BASENAME)-$(GIT_VER).tgz
