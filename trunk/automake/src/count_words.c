/**
Doxgen document here ..., including Brief, introduction about the four vars of fee_count, 
fie_count, etc. 
*/ 
#include <stdio.h>
extern int fee_count, fie_count, foe_count, fum_count; 
/**
this is the yylex function.
*/
extern int yylex( void ); 
/**
This is the main function.
*/
int main( int argc, char ** argv ) 
{ 
    yylex(); 
    printf( "%d %d %d %d\n", fee_count, fie_count, foe_count, fum_count ); 
    exit( 0 ); 
}
