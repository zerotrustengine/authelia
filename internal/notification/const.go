package notification

import "regexp"

const fileNotifierMode = 0600
const rfc5322DateTimeLayout = "Mon, 2 Jan 2006 15:04:05 -0700"

const (
	rfc2822NewLine       = "\r\n"
	rfc2822DoubleNewLine = rfc2822NewLine + rfc2822NewLine
	rfc2822MIMEHeader    = "MIME-Version: 1.0" + rfc2822DoubleNewLine
)

const (
	rfc4880HashSymbolSHA1   = "pgp-sha1"
	rfc4880HashSymbolSHA256 = "pgp-sha256"
	rfc4880HashSymbolSHA384 = "pgp-sha384"
	rfc4880HashSymbolSHA512 = "pgp-sha512"
)

var (
	reEOLWhitespace = regexp.MustCompile(`[ \t]+(\r\n|\n|\r|\f)`)
)
