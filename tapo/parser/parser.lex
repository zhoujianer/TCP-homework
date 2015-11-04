%{
#include "parser.tab.h"
%}

blanks [ \t\n]+
enumeration [_A-Z]+
variable [_a-zA-Z]+
number [0-9]+

/* not ! */
calop [\+\-\*\/\%]
cmpop ("<"|">"|"<="|">="|"==")
logop ("&&"|"||")

string L?\"(\\.|[^\\"])*\"

/* "statement"	return(STATEMENT); */

%%
{blanks} {}
"condition" return (CONDITION);
"type"	return(TYPE);
"detail" return(DETAIL);

{enumeration} {
	yylval.sval = malloc(strlen(yytext)+1);
	sprintf(yylval.sval,"%s",yytext); 
	return(ENUMERATION);
}

{variable} {
	yylval.sval = malloc(strlen(yytext)+strlen("tss->")+1);
	sprintf(yylval.sval, "%s%s", "tss->", yytext); 
	return(IDENTIFIER);
}

{number} {
	yylval.sval = malloc(strlen(yytext)+1);
	sprintf(yylval.sval,"%s",yytext); 
	return(IDENTIFIER);
}

{string} {
	yylval.sval = malloc(strlen(yytext)+1);
	sprintf(yylval.sval,"%s",yytext); 
	return(STRING);
}

{calop} {
	yylval.sval = malloc(strlen(yytext)+1);
	sprintf(yylval.sval,"%s",yytext); 
	return(CALOP);
}

{cmpop} {
	yylval.sval = malloc(strlen(yytext)+1);
	sprintf(yylval.sval,"%s",yytext); 
	return(CMPOP);
}

{logop} {
	yylval.sval = malloc(strlen(yytext)+1);
	sprintf(yylval.sval,"%s",yytext); 
	return(LOGOP);
}
