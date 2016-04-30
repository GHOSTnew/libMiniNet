CC	= clang
RM	= rm -rf
CFLAGS	+= -fPIC -ansi -pedantic -Wall -Wextra -Werror -DOPENSSL
LDFLAGS	+= -lssl -lcrypto -shared

NAMEDYN	= libLibMiniNet.so
NAMESTA = libLibMiniNet.a

SRCS	= net.c 
OBJS	= $(addprefix src/, $(SRCS:.c=.o))

all: $(NAMEDYN) $(NAMESTA)

$(NAMEDYN): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(NAMESTA): $(OBJS)
	ar -rcs $@ $^

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAMEDYN)
	$(RM) $(NAMESTA)

re: fclean all

.PHONY: all re clean fclean
