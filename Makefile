CC=gcc
LIBS=-lcrypto
OBJDIR=obj
EXECDIR=exec
CJSONDIR=cjson
CFLAGS=-I. -I./cjson/

OBJ=$(addprefix $(OBJDIR)/,pail_crypt.o pail_utils.o pail_homomorph.o pail_key.o cJSON.o)

OPAILEXEC=$(addprefix $(OBJDIR)/,opaillier.o)
KEYGENEXEC=$(addprefix $(OBJDIR)/,pail_keygen.o)

DEPS=opaillier.h pail_crypt.h pail_utils.h pail_homomorph.h pail_key.h
CJSONDEPS=$(addprefix $(CJSONDIR)/,cJSON.h)

$(OBJDIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJDIR)/%.o: $(CJSONDIR)/%.c $(CJSONDEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: pail_keygen opaillier

opaillier: $(OBJ) $(OPAILEXEC)
	$(CC) -o $(EXECDIR)/$@ $(OBJ) $(OPAILEXEC) $(LIBS)

pail_keygen:  $(KEYGENEXEC) $(OBJ)
	$(CC) -o $(EXECDIR)/$@ $(OBJ) $(KEYGENEXEC) $(LIBS)

#pail_encryptor: pail_encryptor.o

.PHONY: clean

clean:
	rm -f $(OBJDIR)/*.o $(EXECDIR)/opaillier $(EXECDIR)/pail_encryptor $(EXECDIR)/pail_decryptor $(EXECDIR)/pail_keygen
