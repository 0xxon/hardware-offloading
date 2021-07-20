THRIFTDIR = gen-cpp
LIBNAME = rte

CC=g++
CFLAGS += -Wall # Enable the 'all' set of warnings
CFLAGS += -Werror # Treat all warnings as error
CFLAGS += -Wshadow # Warn when shadowing variables
CFLAGS += -Wextra # Enable additional warnings
CFLAGS += -O2 # -D_FORTIFY_SOURCE=2 # Add canary code, i.e. detect buffer overflows
CFLAGS += -fstack-protector-all # Add canary code to detect stack smashing
CFLAGS += -std=c++11
CFLAGS += -I/usr/local/include/
LDFLAGS += -std=c++11
LDFLAGS += -L./$(THRIFTDIR) -L/usr/local/lib/
LDFLAGS += -Wl,-Bdynamic -lpthread -lrt -lthriftz -lthrift  -lz -l$(LIBNAME)

AR = ar
LIBFILE = $(THRIFTDIR)/lib$(LIBNAME).a
LIBSRC = $(wildcard $(THRIFTDIR)/*.cpp)
LIBOBJ = $(LIBSRC:.cpp=.o)

EXEC = controller
SRC= $(wildcard *.cc)
OBJ= $(SRC:.cc=.o)

all: $(THRIFTDIR) $(EXEC)

$(EXEC): $(OBJ) $(LIBFILE)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CC) -o $@ -c $< $(CFLAGS)

$(LIBFILE): $(LIBOBJ)
	$(AR) r $@ $(LIBOBJ)

$(THRIFTDIR)/%.o: $(THRIFTDIR)/%.cpp
	$(CC) -o $@ -c $<

clean:
	rm -f $(LIBOBJ) $(OBJ) $(LIBFILE) $(EXEC)
	rm -rf $(THRIFTDIR)

.PHONY: clean

