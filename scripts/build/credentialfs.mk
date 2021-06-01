# Copyright 2020 The arhat.dev Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# native
credentialfs:
	sh scripts/build/build.sh $@

# linux
credentialfs.linux.x86:
	sh scripts/build/build.sh $@

credentialfs.linux.amd64:
	sh scripts/build/build.sh $@

credentialfs.linux.armv5:
	sh scripts/build/build.sh $@

credentialfs.linux.armv6:
	sh scripts/build/build.sh $@

credentialfs.linux.armv7:
	sh scripts/build/build.sh $@

credentialfs.linux.arm64:
	sh scripts/build/build.sh $@

credentialfs.linux.mips:
	sh scripts/build/build.sh $@

credentialfs.linux.mipshf:
	sh scripts/build/build.sh $@

credentialfs.linux.mipsle:
	sh scripts/build/build.sh $@

credentialfs.linux.mipslehf:
	sh scripts/build/build.sh $@

credentialfs.linux.mips64:
	sh scripts/build/build.sh $@

credentialfs.linux.mips64hf:
	sh scripts/build/build.sh $@

credentialfs.linux.mips64le:
	sh scripts/build/build.sh $@

credentialfs.linux.mips64lehf:
	sh scripts/build/build.sh $@

credentialfs.linux.ppc64:
	sh scripts/build/build.sh $@

credentialfs.linux.ppc64le:
	sh scripts/build/build.sh $@

credentialfs.linux.s390x:
	sh scripts/build/build.sh $@

credentialfs.linux.riscv64:
	sh scripts/build/build.sh $@

credentialfs.linux.all: \
	credentialfs.linux.x86 \
	credentialfs.linux.amd64 \
	credentialfs.linux.armv5 \
	credentialfs.linux.armv6 \
	credentialfs.linux.armv7 \
	credentialfs.linux.arm64 \
	credentialfs.linux.mips \
	credentialfs.linux.mipshf \
	credentialfs.linux.mipsle \
	credentialfs.linux.mipslehf \
	credentialfs.linux.mips64 \
	credentialfs.linux.mips64hf \
	credentialfs.linux.mips64le \
	credentialfs.linux.mips64lehf \
	credentialfs.linux.ppc64 \
	credentialfs.linux.ppc64le \
	credentialfs.linux.s390x \
	credentialfs.linux.riscv64

credentialfs.darwin.amd64:
	sh scripts/build/build.sh $@

credentialfs.darwin.arm64:
	sh scripts/build/build.sh $@

credentialfs.darwin.all: \
	credentialfs.darwin.amd64

credentialfs.windows.x86:
	sh scripts/build/build.sh $@

credentialfs.windows.amd64:
	sh scripts/build/build.sh $@

credentialfs.windows.armv5:
	sh scripts/build/build.sh $@

credentialfs.windows.armv6:
	sh scripts/build/build.sh $@

credentialfs.windows.armv7:
	sh scripts/build/build.sh $@

# # currently no support for windows/arm64
# credentialfs.windows.arm64:
# 	sh scripts/build/build.sh $@

credentialfs.windows.all: \
	credentialfs.windows.amd64 \
	credentialfs.windows.armv7 \
	credentialfs.windows.x86 \
	credentialfs.windows.armv5 \
	credentialfs.windows.armv6

# # android build requires android sdk
# credentialfs.android.amd64:
# 	sh scripts/build/build.sh $@

# credentialfs.android.x86:
# 	sh scripts/build/build.sh $@

# credentialfs.android.armv5:
# 	sh scripts/build/build.sh $@

# credentialfs.android.armv6:
# 	sh scripts/build/build.sh $@

# credentialfs.android.armv7:
# 	sh scripts/build/build.sh $@

# credentialfs.android.arm64:
# 	sh scripts/build/build.sh $@

# credentialfs.android.all: \
# 	credentialfs.android.amd64 \
# 	credentialfs.android.arm64 \
# 	credentialfs.android.x86 \
# 	credentialfs.android.armv7 \
# 	credentialfs.android.armv5 \
# 	credentialfs.android.armv6

credentialfs.freebsd.amd64:
	sh scripts/build/build.sh $@

credentialfs.freebsd.x86:
	sh scripts/build/build.sh $@

credentialfs.freebsd.armv5:
	sh scripts/build/build.sh $@

credentialfs.freebsd.armv6:
	sh scripts/build/build.sh $@

credentialfs.freebsd.armv7:
	sh scripts/build/build.sh $@

credentialfs.freebsd.arm64:
	sh scripts/build/build.sh $@

credentialfs.freebsd.all: \
	credentialfs.freebsd.amd64 \
	credentialfs.freebsd.arm64 \
	credentialfs.freebsd.armv7 \
	credentialfs.freebsd.x86 \
	credentialfs.freebsd.armv5 \
	credentialfs.freebsd.armv6

credentialfs.netbsd.amd64:
	sh scripts/build/build.sh $@

credentialfs.netbsd.x86:
	sh scripts/build/build.sh $@

credentialfs.netbsd.armv5:
	sh scripts/build/build.sh $@

credentialfs.netbsd.armv6:
	sh scripts/build/build.sh $@

credentialfs.netbsd.armv7:
	sh scripts/build/build.sh $@

credentialfs.netbsd.arm64:
	sh scripts/build/build.sh $@

credentialfs.netbsd.all: \
	credentialfs.netbsd.amd64 \
	credentialfs.netbsd.arm64 \
	credentialfs.netbsd.armv7 \
	credentialfs.netbsd.x86 \
	credentialfs.netbsd.armv5 \
	credentialfs.netbsd.armv6

credentialfs.openbsd.amd64:
	sh scripts/build/build.sh $@

credentialfs.openbsd.x86:
	sh scripts/build/build.sh $@

credentialfs.openbsd.armv5:
	sh scripts/build/build.sh $@

credentialfs.openbsd.armv6:
	sh scripts/build/build.sh $@

credentialfs.openbsd.armv7:
	sh scripts/build/build.sh $@

credentialfs.openbsd.arm64:
	sh scripts/build/build.sh $@

credentialfs.openbsd.all: \
	credentialfs.openbsd.amd64 \
	credentialfs.openbsd.arm64 \
	credentialfs.openbsd.armv7 \
	credentialfs.openbsd.x86 \
	credentialfs.openbsd.armv5 \
	credentialfs.openbsd.armv6

credentialfs.plan9.amd64:
	sh scripts/build/build.sh $@

credentialfs.plan9.x86:
	sh scripts/build/build.sh $@

credentialfs.plan9.armv5:
	sh scripts/build/build.sh $@

credentialfs.plan9.armv6:
	sh scripts/build/build.sh $@

credentialfs.plan9.armv7:
	sh scripts/build/build.sh $@

credentialfs.plan9.all: \
	credentialfs.plan9.amd64 \
	credentialfs.plan9.armv7 \
	credentialfs.plan9.x86 \
	credentialfs.plan9.armv5 \
	credentialfs.plan9.armv6

credentialfs.solaris.amd64:
	sh scripts/build/build.sh $@

credentialfs.aix.ppc64:
	sh scripts/build/build.sh $@

credentialfs.dragonfly.amd64:
	sh scripts/build/build.sh $@
