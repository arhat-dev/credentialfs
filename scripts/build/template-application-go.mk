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
template-application-go:
	sh scripts/build/build.sh $@

# linux
template-application-go.linux.x86:
	sh scripts/build/build.sh $@

template-application-go.linux.amd64:
	sh scripts/build/build.sh $@

template-application-go.linux.armv5:
	sh scripts/build/build.sh $@

template-application-go.linux.armv6:
	sh scripts/build/build.sh $@

template-application-go.linux.armv7:
	sh scripts/build/build.sh $@

template-application-go.linux.arm64:
	sh scripts/build/build.sh $@

template-application-go.linux.mips:
	sh scripts/build/build.sh $@

template-application-go.linux.mipshf:
	sh scripts/build/build.sh $@

template-application-go.linux.mipsle:
	sh scripts/build/build.sh $@

template-application-go.linux.mipslehf:
	sh scripts/build/build.sh $@

template-application-go.linux.mips64:
	sh scripts/build/build.sh $@

template-application-go.linux.mips64hf:
	sh scripts/build/build.sh $@

template-application-go.linux.mips64le:
	sh scripts/build/build.sh $@

template-application-go.linux.mips64lehf:
	sh scripts/build/build.sh $@

template-application-go.linux.ppc64:
	sh scripts/build/build.sh $@

template-application-go.linux.ppc64le:
	sh scripts/build/build.sh $@

template-application-go.linux.s390x:
	sh scripts/build/build.sh $@

template-application-go.linux.riscv64:
	sh scripts/build/build.sh $@

template-application-go.linux.all: \
	template-application-go.linux.x86 \
	template-application-go.linux.amd64 \
	template-application-go.linux.armv5 \
	template-application-go.linux.armv6 \
	template-application-go.linux.armv7 \
	template-application-go.linux.arm64 \
	template-application-go.linux.mips \
	template-application-go.linux.mipshf \
	template-application-go.linux.mipsle \
	template-application-go.linux.mipslehf \
	template-application-go.linux.mips64 \
	template-application-go.linux.mips64hf \
	template-application-go.linux.mips64le \
	template-application-go.linux.mips64lehf \
	template-application-go.linux.ppc64 \
	template-application-go.linux.ppc64le \
	template-application-go.linux.s390x \
	template-application-go.linux.riscv64

template-application-go.darwin.amd64:
	sh scripts/build/build.sh $@

template-application-go.darwin.arm64:
	sh scripts/build/build.sh $@

template-application-go.darwin.all: \
	template-application-go.darwin.amd64

template-application-go.windows.x86:
	sh scripts/build/build.sh $@

template-application-go.windows.amd64:
	sh scripts/build/build.sh $@

template-application-go.windows.armv5:
	sh scripts/build/build.sh $@

template-application-go.windows.armv6:
	sh scripts/build/build.sh $@

template-application-go.windows.armv7:
	sh scripts/build/build.sh $@

# # currently no support for windows/arm64
# template-application-go.windows.arm64:
# 	sh scripts/build/build.sh $@

template-application-go.windows.all: \
	template-application-go.windows.amd64 \
	template-application-go.windows.armv7 \
	template-application-go.windows.x86 \
	template-application-go.windows.armv5 \
	template-application-go.windows.armv6

# # android build requires android sdk
# template-application-go.android.amd64:
# 	sh scripts/build/build.sh $@

# template-application-go.android.x86:
# 	sh scripts/build/build.sh $@

# template-application-go.android.armv5:
# 	sh scripts/build/build.sh $@

# template-application-go.android.armv6:
# 	sh scripts/build/build.sh $@

# template-application-go.android.armv7:
# 	sh scripts/build/build.sh $@

# template-application-go.android.arm64:
# 	sh scripts/build/build.sh $@

# template-application-go.android.all: \
# 	template-application-go.android.amd64 \
# 	template-application-go.android.arm64 \
# 	template-application-go.android.x86 \
# 	template-application-go.android.armv7 \
# 	template-application-go.android.armv5 \
# 	template-application-go.android.armv6

template-application-go.freebsd.amd64:
	sh scripts/build/build.sh $@

template-application-go.freebsd.x86:
	sh scripts/build/build.sh $@

template-application-go.freebsd.armv5:
	sh scripts/build/build.sh $@

template-application-go.freebsd.armv6:
	sh scripts/build/build.sh $@

template-application-go.freebsd.armv7:
	sh scripts/build/build.sh $@

template-application-go.freebsd.arm64:
	sh scripts/build/build.sh $@

template-application-go.freebsd.all: \
	template-application-go.freebsd.amd64 \
	template-application-go.freebsd.arm64 \
	template-application-go.freebsd.armv7 \
	template-application-go.freebsd.x86 \
	template-application-go.freebsd.armv5 \
	template-application-go.freebsd.armv6

template-application-go.netbsd.amd64:
	sh scripts/build/build.sh $@

template-application-go.netbsd.x86:
	sh scripts/build/build.sh $@

template-application-go.netbsd.armv5:
	sh scripts/build/build.sh $@

template-application-go.netbsd.armv6:
	sh scripts/build/build.sh $@

template-application-go.netbsd.armv7:
	sh scripts/build/build.sh $@

template-application-go.netbsd.arm64:
	sh scripts/build/build.sh $@

template-application-go.netbsd.all: \
	template-application-go.netbsd.amd64 \
	template-application-go.netbsd.arm64 \
	template-application-go.netbsd.armv7 \
	template-application-go.netbsd.x86 \
	template-application-go.netbsd.armv5 \
	template-application-go.netbsd.armv6

template-application-go.openbsd.amd64:
	sh scripts/build/build.sh $@

template-application-go.openbsd.x86:
	sh scripts/build/build.sh $@

template-application-go.openbsd.armv5:
	sh scripts/build/build.sh $@

template-application-go.openbsd.armv6:
	sh scripts/build/build.sh $@

template-application-go.openbsd.armv7:
	sh scripts/build/build.sh $@

template-application-go.openbsd.arm64:
	sh scripts/build/build.sh $@

template-application-go.openbsd.all: \
	template-application-go.openbsd.amd64 \
	template-application-go.openbsd.arm64 \
	template-application-go.openbsd.armv7 \
	template-application-go.openbsd.x86 \
	template-application-go.openbsd.armv5 \
	template-application-go.openbsd.armv6

template-application-go.plan9.amd64:
	sh scripts/build/build.sh $@

template-application-go.plan9.x86:
	sh scripts/build/build.sh $@

template-application-go.plan9.armv5:
	sh scripts/build/build.sh $@

template-application-go.plan9.armv6:
	sh scripts/build/build.sh $@

template-application-go.plan9.armv7:
	sh scripts/build/build.sh $@

template-application-go.plan9.all: \
	template-application-go.plan9.amd64 \
	template-application-go.plan9.armv7 \
	template-application-go.plan9.x86 \
	template-application-go.plan9.armv5 \
	template-application-go.plan9.armv6

template-application-go.solaris.amd64:
	sh scripts/build/build.sh $@

template-application-go.aix.ppc64:
	sh scripts/build/build.sh $@

template-application-go.dragonfly.amd64:
	sh scripts/build/build.sh $@
