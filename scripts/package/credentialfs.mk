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

#
# linux
#
package.credentialfs.deb.amd64:
	sh scripts/package/package.sh $@

package.credentialfs.deb.armv6:
	sh scripts/package/package.sh $@

package.credentialfs.deb.armv7:
	sh scripts/package/package.sh $@

package.credentialfs.deb.arm64:
	sh scripts/package/package.sh $@

package.credentialfs.deb.all: \
	package.credentialfs.deb.amd64 \
	package.credentialfs.deb.armv6 \
	package.credentialfs.deb.armv7 \
	package.credentialfs.deb.arm64

package.credentialfs.rpm.amd64:
	sh scripts/package/package.sh $@

package.credentialfs.rpm.armv7:
	sh scripts/package/package.sh $@

package.credentialfs.rpm.arm64:
	sh scripts/package/package.sh $@

package.credentialfs.rpm.all: \
	package.credentialfs.rpm.amd64 \
	package.credentialfs.rpm.armv7 \
	package.credentialfs.rpm.arm64

package.credentialfs.linux.all: \
	package.credentialfs.deb.all \
	package.credentialfs.rpm.all

#
# windows
#

package.credentialfs.msi.amd64:
	sh scripts/package/package.sh $@

package.credentialfs.msi.arm64:
	sh scripts/package/package.sh $@

package.credentialfs.msi.all: \
	package.credentialfs.msi.amd64 \
	package.credentialfs.msi.arm64

package.credentialfs.windows.all: \
	package.credentialfs.msi.all

#
# darwin
#

package.credentialfs.pkg.amd64:
	sh scripts/package/package.sh $@

package.credentialfs.pkg.arm64:
	sh scripts/package/package.sh $@

package.credentialfs.pkg.all: \
	package.credentialfs.pkg.amd64 \
	package.credentialfs.pkg.arm64

package.credentialfs.darwin.all: \
	package.credentialfs.pkg.all
