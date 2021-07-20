mkfile_path=$(abspath $(firstword $(MAKEFILE_LIST)))
mkfile_dir=$(dir $(mkfile_path))
current_dir=$(notdir $(patsubst %/,%,$(mkfile_dir)))

#####################################
grand_parent=$(notdir $(realpath $(mkfile_dir)../..))
parent=$(notdir $(realpath $(mkfile_dir)..))
name=$(current_dir)

#####################################
commondir =$(mkfile_dir:/=)
#commondir=$(realpath $(mkfile_dir)..)
contentdir=$(commondir)/../content/$(ARCH)/$(PLATFORM)
installdir=$(commondir)/../bin/$(ARCH)/$(PLATFORM)
installlibdir=$(commondir)/../lib/$(ARCH)/$(PLATFORM)
capidir=$(commondir)/arch-$(ARCH)/platform-$(PLATFORM)
testdir=$(commondir)/test/$(ARCH)/$(PLATFORM)
lib_area=$(commondir)/lib/$(ARCH)/$(PLATFORM)
bin_area=$(commondir)/bin/$(ARCH)/$(PLATFORM)
bld_area=$(realpath $(mkfile_dir))/build/$(ARCH)/$(PLATFORM)
pic_area=$(realpath $(mkfile_dir))/pic/$(ARCH)/$(PLATFORM)

#####################################
NAME    := $(name)
MAJOR   := $(VERSION)
MINOR   := $(BUILD)
LIBSO   := lib$(NAME).so
LIBSOM  := $(LIBSO).$(MAJOR)
LIBSOV  := $(LIBSO).$(VERSION_BUILD)
LIBA    := lib$(NAME).a

LIBS=  $(lib_area)/$(LIBA)
#LIBS+= $(lib_area)/$(LIBSO)
#LIBS+= $(lib_area)/$(LIBSOM)
#LIBS+= $(lib_area)/$(LIBSOV)

#####################################
BIN=$(bin_area)/$(NAME)
TEST=$(bin_area)/$(NAME)-tool
DUMP=$(bin_area)/$(NAME).dmp

#####################################
INSTALL-BINS-DEP=$(bin_area)/%
INSTALL-BINS-PAT=$(installdir)/%
INSTALL-BINS-SRC=$(wildcard $(bin_area)/*)
INSTALL-BINS=$(patsubst %, $(INSTALL-BINS-PAT),$(notdir $(INSTALL-BINS-SRC)))

INSTALL-LIBS-DEP=$(lib_area)/%
INSTALL-LIBS-PAT=$(installlibdir)/%
INSTALL-LIBS-SRC=$(wildcard $(lib_area)/*)
INSTALL-LIBS=$(patsubst %, $(INSTALL-LIBS-PAT),$(notdir $(INSTALL-LIBS-SRC)))

#####################################
DEPS=$(wildcard *.h) Makefile
_OBJS=

GOSRC=$(filter-out $(wildcard *test*), $(wildcard *.go))

CO_SRC=
_OBJS+= $(notdir $(CO_SRC:.c=.o))

C_SRC=$(wildcard *.c)
_OBJS+= $(C_SRC:.c=.o)

CC_SRC=$(wildcard *.cc)
_OBJS+= $(CC_SRC:.cc=.o)
CPP_SRC=$(wildcard *.cpp)
_OBJS+= $(CPP_SRC:.cpp=.o)

SRCS=$(CPP_SRC) $(C_SRC) $(CO_SRC)

_BIN_OBJS=$(filter-out test.o,$(_OBJS))
_LIB_OBJS=$(filter-out test.o,$(filter-out main.o,$(_OBJS)))
_TEST_OBJS=$(filter-out main.o,$(_OBJS))

BIN_OBJS=$(patsubst %,$(bld_area)/%,$(_BIN_OBJS))
LIB_OBJS=$(patsubst %,$(bld_area)/%,$(_LIB_OBJS))
LIB_PICS=$(patsubst %,$(pic_area)/%,$(_LIB_OBJS))
TEST_OBJS=$(patsubst %,$(bld_area)/%,$(_TEST_OBJS))

#####################################
CXXFLAGS+= -Wall
CPPFLAGS+= -std=c++11

SYS_LIB_PATH=/lib
ifeq ($(ARCH),arm64)
CPPFLAGS+= -march=armv8-a+crc -mtune=thunderx
SYS_LIB_PATH=/lib/aarch64-linux-gnu
else
CPPFLAGS+= -m64 -march=native -msse4.2 -msse4.1 -mssse3 -msse4 -msse2
endif

CFLAGS=	-I.		\
	-I$(capidir)	\
	-I$(commondir)

LDINC=-Wl,--as-needed
SO_LIBS=
STATIC_LIBS=
OTHER_LIBS=-lpthread -ldl

# Statically link re2 library, which should be located at
# ../../re2/build/lib
LDINC+= -L../../re2/build/lib
CFLAGS+= -I../../re2/build/include
OTHER_LIBS+= -Wl,-Bstatic -lre2 -Wl,-Bdynamic

# Custom DPDK include:
DPDK_HOME ?=dpdk
DPDK_INC=-I$(DPDK_HOME)/include/dpdk
DPDK_LDINC=-L$(DPDK_HOME)/lib
DPDK_SLIB=-Wl,--whole-archive -l:librte.a -Wl,--no-whole-archive

# Default DSDK include path:
# DPDK_HOME ?=/usr/local
# DPDK_INC=-I$(DPDK_HOME)/include/dpdk
# DPDK_LDINC=-L$(DPDK_HOME)/lib
# DPDK_SLIB=-Wl,--whole-archive -l:libdpdk.a -Wl,--no-whole-archive

CFLAGS+= ${DPDK_INC}
LDINC+= ${DPDK_LDINC}
STATIC_LIBS+= $(DPDK_SLIB)

SSL_LDINC=-L${SYS_LIB_PATH}
SSL_SLIB=-l:libssl.a -l:libcrypto.a
LDINC+= ${SSL_LDINC}
STATIC_LIBS+= ${SSL_SLIB}

#####################################
ifeq ($(BUILD_MODE),debug)
CFLAGS+= -O0 -g
LDFLAGS+= -g
else
CFLAGS+= -O3 -g
LDFLAGS+= -g
endif

#####################################
PREPROCESSOR_DEFINES=
PREPROCESSOR_DEFINES+= -DARCH_VALUE=$(ARCH_VALUE)
PREPROCESSOR_DEFINES+= -DPLATFORM_VALUE=$(PLATFORM_VALUE)
ifeq ($(BUILD_MODE),debug)
PREPROCESSOR_DEFINES+= -DDEBUG=1
endif
PREPROCESSOR_DEFINES+= -DRTE_ARCH_64 -DRTE_FORCE_INTRINSICS

#####################################
all: build

$(bld_area) $(pic_area) $(bin_area) $(lib_area) $(contentdir) $(installlibdir) $(installdir) $(manifestdir):
	- mkdir -p $@

create_build_area: $(bld_area)

$(bld_area)/%.o: %.c $(DEPS) | $(bld_area)
	$(CC) -c $< $(CFLAGS) $(PREPROCESSOR_DEFINES) -o $@ 

$(pic_area)/%.o: %.c $(DEPS) | $(pic_area)
	$(CC) -fPIC -c $< $(CFLAGS) $(PREPROCESSOR_DEFINES) -o $@ 

$(bld_area)/%.o: %.cc $(DEPS) | $(bld_area)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< $(CFLAGS) $(PREPROCESSOR_DEFINES) -o $@ 

$(pic_area)/%.o: %.cc $(DEPS) | $(pic_area)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< $(CFLAGS) $(PREPROCESSOR_DEFINES) -o $@ 

$(bld_area)/%.o: %.cpp $(DEPS) | $(bld_area)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< $(CFLAGS) $(PREPROCESSOR_DEFINES) -o $@ 

$(pic_area)/%.o: %.cpp $(DEPS) | $(pic_area)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< $(CFLAGS) $(PREPROCESSOR_DEFINES) -o $@ 

$(BIN): $(BIN_OBJS) | $(bin_area)
	$(CXX) $(CPPFLAGS) $^ $(LDINC) $(SO_LIBS) $(STATIC_LIBS) $(OTHER_LIBS) -o $@ 

$(lib_area)/$(LIBA) : $(LIB_OBJS) | $(lib_area)
	$(AR) rcs $@ $^

$(lib_area)/$(LIBSOV): $(LIB_PICS)
	$(CXX) $(CXXFLAGS) $(LDINC) -shared -Wl,-soname,$(LIBSOM) -o $@ $^

$(lib_area)/$(LIBSOM) $(lib_area)/$(LIBSO): $(lib_area)/$(LIBSOV)
	ln -fs $^ $@

build: $(SRC) $(GOSRC) $(LIBS) $(BIN)

$(INSTALL-BINS):$(INSTALL-BINS-PAT):$(INSTALL-BINS-DEP) | $(installdir)
	cp $^ $@

$(INSTALL-LIBS):$(INSTALL-LIBS-PAT):$(INSTALL-LIBS-DEP) | $(installlibdir)
	cp $^ $@

$(INS):$(INS-PAT):$(INS-DEP) $(MANIFEST_DEP) | $(manifestdir)
	manifix -D -i "$(MANIFEST_DEP)" -o $@ $<
	chmod 777 $@

install: $(INSTALL-BINS) $(INSTALL-LIBS)

clean:
	- rm -f $(DUMP)
	- rm -f $(TEST)
	- rm -f $(BIN)
	- rm -f $(INSTALL-BINS)
	- rm -f $(INSTALL-LIBS)
	- rm -f $(LIBS)
	- rm -rf $(bld_area)
	- rm -rf $(pic_area)
	- find * -type d -empty -delete

$(DUMP): $(BIN)
	- rm -f $@
	objdump -gfdS $< > $@

dump: $(DUMP)

$(TEST): $(TEST_OBJS) | all
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDINC) $(SO_LIBS) $(STATIC_LIBS) $(OTHER_LIBS)

tests: all $(TEST)
	$(TEST) ${TEST_CNT} ${TEST_CMD}

.PHONY: all clean build tests dump create_build_area install
