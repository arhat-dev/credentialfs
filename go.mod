module arhat.dev/credentialfs

go 1.16

require (
	arhat.dev/bitwardenapi v0.0.0-20210605130951-03f16d731691
	arhat.dev/pkg v0.5.8
	github.com/deepmap/oapi-codegen v1.8.1
	github.com/denisbrodbeck/machineid v1.0.1
	github.com/hanwen/go-fuse/v2 v2.1.0
	github.com/keybase/go-keychain v0.0.0-20201121013009-976c83ec27a6
	github.com/klauspost/compress v1.13.0 // indirect
	github.com/mitchellh/go-ps v1.0.0
	github.com/mritd/touchid v0.0.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v5 v5.3.4
	go.uber.org/multierr v1.7.0
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/term v0.0.0-20210615171337-6886f2dfbf5b
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	nhooyr.io/websocket v1.8.7
)

replace (
	k8s.io/api => github.com/kubernetes/api v0.20.7
	k8s.io/apiextensions-apiserver => github.com/kubernetes/apiextensions-apiserver v0.20.7
	k8s.io/apimachinery => github.com/kubernetes/apimachinery v0.20.7
	k8s.io/apiserver => github.com/kubernetes/apiserver v0.20.7
	k8s.io/cli-runtime => github.com/kubernetes/cli-runtime v0.20.7
	k8s.io/client-go => github.com/kubernetes/client-go v0.20.7
	k8s.io/cloud-provider => github.com/kubernetes/cloud-provider v0.20.7
	k8s.io/cluster-bootstrap => github.com/kubernetes/cluster-bootstrap v0.20.7
	k8s.io/code-generator => github.com/kubernetes/code-generator v0.20.7
	k8s.io/component-base => github.com/kubernetes/component-base v0.20.7
	k8s.io/component-helpers => github.com/kubernetes/component-helpers v0.20.7
	k8s.io/controller-manager => github.com/kubernetes/controller-manager v0.20.7
	k8s.io/cri-api => github.com/kubernetes/cri-api v0.20.7
	k8s.io/csi-translation-lib => github.com/kubernetes/csi-translation-lib v0.20.7
	k8s.io/klog => github.com/kubernetes/klog v1.0.0
	k8s.io/klog/v2 => github.com/kubernetes/klog/v2 v2.9.0
	k8s.io/kube-aggregator => github.com/kubernetes/kube-aggregator v0.20.7
	k8s.io/kube-controller-manager => github.com/kubernetes/kube-controller-manager v0.20.7
	k8s.io/kube-proxy => github.com/kubernetes/kube-proxy v0.20.7
	k8s.io/kube-scheduler => github.com/kubernetes/kube-scheduler v0.20.7
	k8s.io/kubectl => github.com/kubernetes/kubectl v0.20.7
	k8s.io/kubelet => github.com/kubernetes/kubelet v0.20.7
	k8s.io/kubernetes => github.com/kubernetes/kubernetes v1.20.7
	k8s.io/legacy-cloud-providers => github.com/kubernetes/legacy-cloud-providers v0.20.7
	k8s.io/metrics => github.com/kubernetes/metrics v0.20.7
	k8s.io/mount-utils => github.com/kubernetes/mount-utils v0.20.7
	k8s.io/sample-apiserver => github.com/kubernetes/sample-apiserver v0.20.7
	k8s.io/utils => github.com/kubernetes/utils v0.0.0-20210527160623-6fdb442a123b
	vbom.ml/util => github.com/fvbommel/util v0.0.2
)
