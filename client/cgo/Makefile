SOURCEDIR=$(pwd)
SOURCES="verification.go"

NAME=coniks

UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
	LIB_NAME := lib$(NAME).dylib
else
	LIB_NAME := lib$(NAME).so
endif

BUILD_MODE=-buildmode=c-shared
CFLAGS=
LDFLAGS=-ldflags "-s -w"
.DEFAULT_GOAL: $(LIB_NAME)

$(LIB_NAME):
	go build ${LDFLAGS} ${BUILD_MODE} -o ${LIB_NAME} ${SOURCES}

.PHONY: clean
clean:
	if [ -f ${LIB_NAME} ] ; then rm ${LIB_NAME} ; fi
	if [ -f test ] ; then rm test ; fi
