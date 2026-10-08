package proxymanager

import "regexp"

var placeholder = regexp.MustCompile(`\{\{.*?\}\}`)
