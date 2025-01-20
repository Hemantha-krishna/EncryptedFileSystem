JC = javac
JVM = java
JFLAGS = -g
SRCS = src/EFS.java src/Sample.java src/Editor.java src/Config.java src/PasswordIncorrectException.java src/Utility.java
TEST = src/EFS.java src/Sample.java src/Editor.java src/Config.java src/PasswordIncorrectException.java test/Utility.java test/Test.java

all: build

build: $(SRCS)
	@$(JC) $(JFLAGS) $(SRCS)

run: build
	@$(JVM) -cp src Editor

build-test: $(TEST)
	@$(JC) $(JFLAGS) $(TEST)

test: clean build-test
	@$(JVM) -cp src:test Test

clean:
	@rm -f src/*.class test/*.class
