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

# build
image.build.credentialfs.linux.x86:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.amd64:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.armv5:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.armv6:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.armv7:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.arm64:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.ppc64le:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.mips64le:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.s390x:
	sh scripts/image/build.sh $@

image.build.credentialfs.linux.all: \
	image.build.credentialfs.linux.amd64 \
	image.build.credentialfs.linux.arm64 \
	image.build.credentialfs.linux.armv7 \
	image.build.credentialfs.linux.armv6 \
	image.build.credentialfs.linux.armv5 \
	image.build.credentialfs.linux.x86 \
	image.build.credentialfs.linux.s390x \
	image.build.credentialfs.linux.ppc64le \
	image.build.credentialfs.linux.mips64le

image.build.credentialfs.windows.amd64:
	sh scripts/image/build.sh $@

image.build.credentialfs.windows.armv7:
	sh scripts/image/build.sh $@

image.build.credentialfs.windows.all: \
	image.build.credentialfs.windows.amd64 \
	image.build.credentialfs.windows.armv7

# push
image.push.credentialfs.linux.x86:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.amd64:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.armv5:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.armv6:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.armv7:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.arm64:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.ppc64le:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.mips64le:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.s390x:
	sh scripts/image/push.sh $@

image.push.credentialfs.linux.all: \
	image.push.credentialfs.linux.amd64 \
	image.push.credentialfs.linux.arm64 \
	image.push.credentialfs.linux.armv7 \
	image.push.credentialfs.linux.armv6 \
	image.push.credentialfs.linux.armv5 \
	image.push.credentialfs.linux.x86 \
	image.push.credentialfs.linux.s390x \
	image.push.credentialfs.linux.ppc64le \
	image.push.credentialfs.linux.mips64le

image.push.credentialfs.windows.amd64:
	sh scripts/image/push.sh $@

image.push.credentialfs.windows.armv7:
	sh scripts/image/push.sh $@

image.push.credentialfs.windows.all: \
	image.push.credentialfs.windows.amd64 \
	image.push.credentialfs.windows.armv7
