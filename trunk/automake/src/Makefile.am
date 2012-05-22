AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS=countwords
bindir=/usr/local/bin/
countwords_SOURCES=count_words.c lexer.l
countwords_LDADD=-lfl

install:
	doxygen doxy.cfg
	cp ../doc/README /usr/local/share/doc/countwords
	cp countwords /usr/local/bin
uninstall:
	rm -r /usr/local/share/doc/countwords
	rm count_words.o countwords lexer.c lexer.o 
	rm /usr/local/bin/countwords
