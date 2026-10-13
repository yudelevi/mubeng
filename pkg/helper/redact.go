package helper

import (
	"net/url"

	"github.com/mubeng/mubeng/pkg/helper/awsurl"
)

// InvalidProxyURL stands in for a proxy string that cannot be parsed, since
// echoing it back could expose whatever credentials it carries.
const InvalidProxyURL = "invalid-proxy-url"

// RedactProxy returns proxy as scheme://user@host:port with the password, path
// and query dropped. The username is kept so per-session proxies that differ
// only by username stay distinct in metric labels and logs.
func RedactProxy(proxy string) string {
	if awsurl.IsURL(proxy) {
		u, err := awsurl.Parse(proxy)
		if err != nil {
			return InvalidProxyURL
		}
		return "aws://" + u.AccessKeyID + "@" + u.Region
	}

	u, err := url.Parse(proxy)
	if err != nil || u.Opaque != "" {
		return InvalidProxyURL
	}

	redacted := url.URL{Scheme: u.Scheme, Host: u.Host}
	if u.User != nil {
		redacted.User = url.User(u.User.Username())
	}
	return redacted.String()
}
