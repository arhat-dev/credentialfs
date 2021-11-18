package envhelper

import "strings"

func EnvListToMap(envList []string) map[string]string {
	ret := make(map[string]string)

	for _, s := range envList {
		parts := strings.SplitN(s, "=", 2)
		switch len(parts) {
		case 1:
			ret[parts[0]] = ""
		case 2:
			ret[parts[0]] = parts[1]
		}
	}

	return ret
}
