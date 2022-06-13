
all: clean patch run 

.PHONY: run
run: patch
	./test.sh

.PHONY: patch
patch: test data.txt
	../postject.py --overwrite $< "foobar" data.txt

test: CFLAGS=-g
test: test.o

data.txt:
	@echo "hello world @ $$(date)" > $@


.PHONY: compile
clean: RM ?= rm
clean:
	$(RM) test *.o data.txt || true
