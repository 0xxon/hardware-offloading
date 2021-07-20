This repository contains prototype applications for offloading certain operations that are useful for network monitoring systems like, for example, [Zeek](https://zeek.org).

For a reference of the goals of this project, see the [following paper](https://www.icir.org/johanna/papers/sdnfvsec17codesign.pdf).

There are two separate implementations in this project, which are written for different hardware platforms.

The first, contained in the `sia` subdirectory is based on DPDK and was specifically developed to be used in a Myricom SIA card.

The relevant DPDK version that was used when writing this is 17.11; the documentation is available here: https://doc.dpdk.org/guides-17.11/.

The second, contained in the `p4` subdirectory is based on Netronome Agilio SmartNICs.

## Compiling the SIA applications

The source-code for our prototype to offload non-established connections is contained in the directory `sia/offload`. The source-code for our prototype for protocol detection is contained in the directory `sia/proto-matching`.

Both projects need some setup before they can be compiled:

### Setting up the SIA Development Environment from scratch

These applications must be compiled on the SIA, in the DSDK build environment provided by cSPI.

1. Follow the instructions from cSPI to set up the initial development
   environment on the SIA.

2. If it doesn't already exist, create a directory structure similar to the following:

```
repos
├── re2
└── offloading
```

The key is that `re2` and `offloading` must be in the same directory. Their parent directory is irrelevant. The easiest way to do this is to clone `re2` into the sia directory, after checking out this repository:

```
$ git clone http://github.com/0xxon/hardware-offloading
$ cd hardware-offloading/sia
$ git clone https://github.com/google/re2.git
```

Note: if the SIA is on a secure network without internet access, ou may first have to clone these
repositories on a local Internet-connected machine and then rsync them across to the SIA.

### Compile re2 on the SIA:

Just do 


```
$ cd re2 && make
```

Note: you may have to first install build-essentials on the SIA:

```
$ sudo apt update && sudo apt install build-essentials
```

### DPDK dependency

For our project, we need a custom build of DPDK. Ordinarily, the SIA development
workflow would consist of compiling against the bundled DPDK libraries from
cSPI. However, a modification was needed to the DPAA2 poll-mode driver in order
to support disabling hardware offloading of TCP checksums.

If your DPDK version is newer than 17.11 it is possible that these steps are no longer necessary.

If your DPDK version is not newer, extract the DPDK version used by the SIA in a directory and apply the [dpdk-dpaa.patch](dpdk-dpaa.patch) file contained in this repository:

```
patch -p1 < dpdk-dpaa.patch
```

After applying the patch, compile the custom dpdk:

```
$ make config T=arm64-dpaa2-linuxapp-gcc
$ make T=arm64-dpaa2-linuxapp-gcc
```

Note: at this stage, the build will fail. That is expected. Carry on.

```
$ git checkout devtool
$ make T=arm64-dpaa2-linuxapp-gcc
```

Now the build should succeed.

Now, take the original DPDK libraries shipped with the SIA NIC from the
Docker container and replace librte_pmd_dpaa2.a with the newly-compiled
custom one:

```
$ bldinteractive
$ mkdir /tmp/dpdk
$ cp -r /usr/local/lib /tmp/dpdk/lib
$ cp [PATH TO dpdk-ep FROM STEP 1]/build/lib/librte_pmd_dpaa2.a /tmp/dpdk/lib
```

If desired, you can also take the header files:

```
$ cp -r /usr/local/include/dpdk /tmp/dpdk/include
```

Note that it is OK to simply replace that one binary because the DPDK shipped
with the NIC is compiled from the same DPDK source tree that we used in step 1,
so they are binary-compatible.

Finally, create a unified `librte.a` library archive:

```
$ cd /tmp/dpdk/lib
$ echo "create librte.a" > librte.mri
$ for f in librte*.a; do echo "addlib $f" >> librte.mri; done
$ echo save >> librte.mri && echo end >> librte.mri
$ ar -M < librte.mri
```

And there you have it: a single librte.a, including our custom DPAA2 PMD.

### NIC Memory Config

To get the apps to run, we need to increase the number of hugepages available
on the NIC:

```
$ echo 14 | sudo tee /proc/sys/vm/nr_hugepages
$ grep -i huge /proc/meminfo
```

The output of the second command should be:

```
AnonHugePages:    516096 kB
ShmemHugePages:        0 kB
HugePages_Total:      14
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:    1048576 kB
```

### Compiling the offloading application

On the NIC, compile the app using make:

```
$ cd sia/offload
$ bldmake clean all
```

Run the app as follows:

```
$ sudo DPRC=dprc.2 ./bin/arm64/sia-lx2160/prototype -c 0xffff --master-lcore 0 -n 1
```

or simply by using the included `run.sh` script:

```
$ ./run.sh
```

### Compiling the proto-matching application

On the NIC, compile the app using make:

```
$ cd sia/proto-matching
$ bldmake clean all
```

Run the app as follows:

```
$ sudo DPRC=dprc.2 ./bin/arm64/sia-lx2160/prototype -c 0xffff --master-lcore 0 -n 1 --log-level=8 --log-level=".*,6" --log-level=prototype,6 --log-level=prototype.stats,8
```

or simply by using the included `run.sh` script:

```
$ ./run.sh
```


## Compiling the Netronome applications

The Netronome applications assume a specific file architecture:

* The SDK folder has to be located at `/opt/netromome/`. This can be changed in the `nic/Makefile` file of each application.

For each of the applications, you typically follow the similar steps for execution; there are slight differences for Pure P4 projects and hybrid projects (which contain additional low-level code).

### Compiling pure P4 projects

Execute the following commands:

```
$ make start_server      # start the RTE server
$ make                   # compile the P4 code
$ make design-reload     # Loads the firmware on the NIC
$ make config-reload     # Loads the config file user_config.json
```

### Compiling hybrid projects

Execute the following commands:

```
$ make start_server      # start the RTE server
$ make                   # compile the P4 and C sandbox code
$ make full-install      # Load the firmware on the NIC (3.5 min), start the controller
$ make install           # Equivalent to make full-install without loading the firmware
$ make stop              # Kill the controller process
```

### Projects

The following projects are in separate directories:

* `l2minifwd` is a simple P4 program just forwarding frames from one interface to another
* `pktCounter` adds a packet counter to the previous program
* `flowCounter` counts flows for a given set of rules

The next project is more complex, complete and involve a C sandbox and a controller running on the host

* `countReport` is the main project; it contains statistic advertisements for the traffic observed, syn offloading and splitting on the virtual interfaces. To compile the controller you need to put the `sdk6_rte.thrift` file from the Netronome sdk into the `p4/countReport/controller` directory.