package runner

import (
	"strings"
	"testing"

	"github.com/mubeng/mubeng/common"
)

func TestStickyRejectsAuth(t *testing.T) {
	opt := &common.Options{File: "/nonexistent", Sticky: true, Auth: "user:pass"}
	err := validate(opt)
	if err == nil || !strings.Contains(err.Error(), "sticky") {
		t.Fatalf("want sticky+auth error, got %v", err)
	}
}
