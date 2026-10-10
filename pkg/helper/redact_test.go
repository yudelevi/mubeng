package helper

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const testPassword = "s3cr3tPa55"

func TestRedactProxy(t *testing.T) {
	cases := map[string]string{
		"http://user-country-us-session-104237:" + testPassword + "@host:8080": "http://user-country-us-session-104237@host:8080",
		"socks5://user:" + testPassword + "@10.0.0.1:1080":                     "socks5://user@10.0.0.1:1080",
		"http://host:8080": "http://host:8080",
		"http://user:" + testPassword + "@host:8080/path?token=" + testPassword: "http://user@host:8080",
		"aws://AKIAEXAMPLE:" + testPassword + "/x/y@us-east-1":                  "aws://AKIAEXAMPLE@us-east-1",
		"http://user:" + testPassword + "@host:badport":                         InvalidProxyURL,
		"user:" + testPassword + "@host:8080":                                   InvalidProxyURL,
		"":                                                                      "",
	}
	for in, want := range cases {
		got := RedactProxy(in)
		if got != want {
			t.Errorf("RedactProxy(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(got, testPassword) {
			t.Errorf("RedactProxy(%q) leaked the password: %q", in, got)
		}
	}
}

func TestRedactProxyMetricLabel(t *testing.T) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_proxy_attempts_total"}, []string{"proxy"})
	a := "http://user-country-us-session-104237:" + testPassword + "@gw.example:8080"
	b := "http://user-country-us-session-999999:" + testPassword + "@gw.example:8080"
	counter.WithLabelValues(RedactProxy(a)).Inc()
	counter.WithLabelValues(RedactProxy(b)).Inc()

	if n := testutil.CollectAndCount(counter); n != 2 {
		t.Fatalf("got %d series, want 2 distinct per-username labels", n)
	}

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(counter)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if strings.Contains(label.GetValue(), testPassword) {
					t.Errorf("metric label %q leaked the password", label.GetValue())
				}
			}
		}
	}
}
