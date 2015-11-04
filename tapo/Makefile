all: tcp_tool

TARGET=tcp_tool
PARSER_DIR=./parser
RULE_PARSER=rule_parser.c

CC=gcc
YACC=bison
LEX=flex
CFLAGS=-g -Wall
LD=gcc
LDFLAGS=
LIBS=-lpcap
CTAGS=ctags

HEADER=$(wildcard *.h)
SRC=$(wildcard *.c)
ifeq (,$(findstring $(RULE_PARSER), $(SRC)))
	SRC+= $(RULE_PARSER)
endif
OBJS=$(patsubst %.c, %.o, $(SRC))

$(RULE_PARSER): $(PARSER_DIR)/Makefile $(PARSER_DIR)/parser.y $(PARSER_DIR)/parser.lex $(PARSER_DIR)/rules.txt
	cd $(PARSER_DIR); make 

%.o: %.c $(HEADER)
	$(CC) $(CFLAGS) -c $< -o $@  

tcp_tool: $(OBJS)
	$(LD) $(LDFLAGS) $(LIBS) $(OBJS) -o $(TARGET)

tags: $(wildcard *.[hc]) 
	$(CTAGS) $(wildcard *.[hc])

clean:
	@rm -f *.o tcp_tool
