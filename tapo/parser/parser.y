%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

const char * src_name = "rule_parser";
FILE *cfile = NULL;
FILE *hfile = NULL;

int rule_num = 0;

char *enums = NULL;
char *text = NULL;
char *strings = NULL;
char *body = NULL;

char *print_string(const char *, ...);
void append_to_string(char **string, const char *str);
%}

// Symbols.
%union
{
	char *sval;
}

%token CONDITION TYPE DETAIL
%token ENUMERATION IDENTIFIER STRING
%token CALOP CMPOP LOGOP /* not */

%left GE LE EQ NE '>' '<'
%left '+' '-'
%left '*' '/'

%type<sval> CONDITION TYPE DETAIL ENUMERATION IDENTIFIER STRING CALOP CMPOP LOGOP
%type<sval> block condition cmpexpr expr

%%

program:
	/* empty */
	| program block
	;

block:
	CONDITION condition TYPE ENUMERATION DETAIL STRING 
	{ 
		char buff[2048];
		sprintf(buff, "\tif (%s)\n\t\treturn %s;\n", $2, $4);
		append_to_string(&body, buff);
		sprintf(buff, "%s, ", $4);
		append_to_string(&enums, buff);
		sprintf(buff, "\"%s\",\n\t", $4);
		append_to_string(&text, buff);
		sprintf(buff, "%s,\n\t", $6);
		append_to_string(&strings, buff);
		rule_num += 1;
	}
	;

condition:
	cmpexpr
	| condition LOGOP cmpexpr { $$ = print_string("(%s %s %s)", $1, $2, $3, NULL); }
	/* | not cmpexpr */
	;

cmpexpr:
	expr CMPOP expr { $$ = print_string("(%s %s %s)", $1, $2, $3, NULL); }
	;

expr:
	IDENTIFIER { $$ = $1; }
	| expr CALOP expr { $$ = print_string("(%s %s %s)", $1, $2, $3, NULL); }
	;

%%

void init()
{
	char name[1024];
	sprintf(name, "%s.c", src_name);
	cfile = fopen(name, "w");
	if (cfile == NULL) {
		fprintf(stderr, "could not open %s for writing rules.", name); 
		exit(1);
	}

	// init c source file
	fprintf(cfile, "#include \"%s.h\"\n", src_name);
	fprintf(cfile, "\n\n");

	sprintf(name, "%s.h", src_name);
	hfile = fopen(name, "w");
	if (hfile == NULL) {
		fprintf(stderr, "could not open %s for writing rules.", name); 
		exit(1);
	}

	// init header file
	fprintf(hfile, "#ifndef __RULE_PARSER_H__\n");
	fprintf(hfile, "#define __RULE_PARSER_H__\n\n");
	fprintf(hfile, "#include \"tcp_stall_state.h\"\n");
	fprintf(hfile, "extern const char *stall_details[];\n");
	fprintf(hfile, "extern const char *stall_text[];\n");
	fprintf(hfile, "extern enum stall_type parse_stall(struct tcp_stall_state *);\n");

	append_to_string(&enums, "enum stall_type {\n\t");
	append_to_string(&text, "const char *stall_text[] = {\n\t");
	append_to_string(&strings, "const char *stall_details[] = {\n\t");
	append_to_string(&body, "enum stall_type parse_stall(struct tcp_stall_state *tss)\n{\n");
}

char *print_string(const char *fmt, ...)
{
	va_list args;
	const char *arg;
	int len = strlen(fmt);

	va_start(args, fmt);
	while ((arg = va_arg(args, const char *)) != NULL) {
		len += (strlen(arg) + 1);
	}
	va_end(args);

	char *str = (char *)malloc(len);
	va_start(args, fmt);
	vsprintf(str, fmt, args);
	va_end(args);

	va_start(args, fmt);
	while ((arg = va_arg(args, char *)) != NULL) {
		free((void *)arg);
	}
	va_end(args);
	
	return str;
}

void append_to_string(char **string, const char *str)
{
	if (*string == NULL) {
		*string = (char *)malloc(strlen(str) + 1);
		*string[0] = '\0';
	}
	else {
		*string = (char *)realloc(*string, strlen(*string) + strlen(str) + 1);
	}

	strcat(*string, str);
}

void finish()
{
	append_to_string(&enums, "UNKNOWN_ISSUE\n};\n");
	append_to_string(&text, "\"UNKNOWN_ISSUE\"\n};\n\n");
	append_to_string(&strings, "\"unknown issue\"\n};\n\n");
	append_to_string(&body, "\n\treturn UNKNOWN_ISSUE;\n}\n");

	fprintf(cfile, strings);
	fprintf(cfile, text);
	fprintf(cfile, body);

	fprintf(hfile, enums);
	fprintf(hfile, "\n#endif\n");

	fclose(cfile);
	fclose(hfile);

	free(enums);
	free(strings);
	free(body);
}

int yyerror(char *s)
{
	fprintf(stderr, "yyerror: %s\n", s);
}

int main()
{
	init();
	yyparse();
	finish();

	return 0;
}
