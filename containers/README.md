# Testing locally using containers

You can run the tests executed in github actions in containers locally. This can
be handy to test some modification of the code or the CI pipeline.

First, we need to prepare the container image. This already runs setup and
mounts current working directory to the container:

```
$ podman build -v $PWD:/src -t opensc-build containers/opensc-build
```

Now, you can jump into the container with preinstalled dependencies to build
OpenSC:

```
$ podman run -v $PWD:/src -ti opensc-build
```
If you want to run the build manually, investigate some issues, you can start
with shell
```
$ podman run -v $PWD:/src -ti opensc-build /bin/bash
# .github/build.sh
```
To debug some issues with gdb, the container needs some more capabilities.
With the following configuration, I am able to run gdb to debug possible
issues:
```
$ podman run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v $PWD:/src -ti opensc-build /bin/bash
# .github/build.sh
# apt install -y libtool-bin gdb
# libtool --mode=execute gdb --args ./src/tools/pkcs11-tool --test-threads IN -L --module=/usr/lib/softhsm/libsofthsm2.so
```

Similarly for tests, you can build a container for example for CAC testing:
```
$ podman build -v $PWD:/src -t opensc-cac containers/opensc-test-cac
```
and then run the tests:
```
$ podman run -v $PWD:/src -ti opensc-cac
```

The javacard tests are very similar. This can be used to build a container for
PIV testing:
```
$ podman build -v $PWD:/src -t opensc-piv containers/opensc-test-piv
```
and then run the tests:
```
$ podman run -v $PWD:/src -ti opensc-piv
```
(if you are using Docker, you will need to replace "podman" with "docker" and
maybe change the generic Containerfile name to Dockerfile, but otherwise it
should work the same way)
