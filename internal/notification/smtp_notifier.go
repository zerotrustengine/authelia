package notification

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/authelia/authelia/internal/configuration/schema"
	"github.com/authelia/authelia/internal/logging"
	"github.com/authelia/authelia/internal/utils"
)

// SMTPNotifier a notifier to send emails to SMTP servers.
type SMTPNotifier struct {
	username            string
	password            string
	sender              string
	identifier          string
	host                string
	port                int
	disableRequireTLS   bool
	address             string
	subject             string
	startupCheckAddress string
	client              *smtp.Client
	tlsConfig           *tls.Config
	signingPGPKeyring   openpgp.EntityList
	signingPGPAlgorithm string
}

// NewSMTPNotifier creates a SMTPNotifier using the notifier configuration.
func NewSMTPNotifier(configuration schema.SMTPNotifierConfiguration, certPool *x509.CertPool) *SMTPNotifier {
	notifier := &SMTPNotifier{
		username:            configuration.Username,
		password:            configuration.Password,
		sender:              configuration.Sender,
		identifier:          configuration.Identifier,
		host:                configuration.Host,
		port:                configuration.Port,
		disableRequireTLS:   configuration.DisableRequireTLS,
		address:             fmt.Sprintf("%s:%d", configuration.Host, configuration.Port),
		subject:             configuration.Subject,
		startupCheckAddress: configuration.StartupCheckAddress,
		tlsConfig:           utils.NewTLSConfig(configuration.TLS, tls.VersionTLS12, certPool),
	}

	if configuration.PGP != nil {
		switch configuration.PGP.Algorithm {
		case rfc4880HashSymbolSHA512, rfc4880HashSymbolSHA384, rfc4880HashSymbolSHA256, rfc4880HashSymbolSHA1:
			notifier.signingPGPAlgorithm = configuration.PGP.Algorithm
		default:
			notifier.signingPGPAlgorithm = rfc4880HashSymbolSHA256
		}

		var err error

		notifier.signingPGPKeyring, err = openpgp.ReadArmoredKeyRing(bytes.NewBufferString(configuration.PGP.Key))
		if err != nil {
			fmt.Printf("err loading pgp entitylist: %v\n", err)
		}

		printDebugInfo(notifier.signingPGPKeyring)
	}

	return notifier
}

func printDebugInfo(keyring openpgp.EntityList) {
	fmt.Println("printing key information")
	for _, entity := range keyring {
		fmt.Println("======================")

		fmt.Printf("fingerprint: %s\n", hex.EncodeToString(entity.PrivateKey.Fingerprint[:]))
		for key, identity := range entity.Identities {

			issuerKeyId := uint64(0)
			if identity.SelfSignature.IssuerKeyId != nil {
				issuerKeyId = *identity.SelfSignature.IssuerKeyId
			}

			isPrimaryKey := false
			if identity.SelfSignature.IsPrimaryId != nil {
				isPrimaryKey = *identity.SelfSignature.IsPrimaryId
			}

			fmt.Println("----------------------")
			fmt.Printf("key: %s, name: %s\n", key, identity.Name)
			fmt.Printf("user | id: %s, name: %s, email: %s, comment: %s\n", identity.UserId.Id, identity.UserId.Name, identity.UserId.Email, identity.UserId.Comment)
			fmt.Printf("self | hash: %s, hash suffix: %s, created: %v, sig lifetime: %v, key lifetime: %v, expired: %v, type: %v\n", identity.SelfSignature.Hash.String(), hex.EncodeToString(identity.SelfSignature.HashSuffix), identity.SelfSignature.CreationTime, identity.SelfSignature.SigLifetimeSecs, identity.SelfSignature.KeyLifetimeSecs, identity.SelfSignature.KeyExpired(time.Now()), identity.SelfSignature.SigType)
			fmt.Printf("self | algo: %v, issuer id: %d, compression: %d, hash %d, symetric: %v\n", identity.SelfSignature.PubKeyAlgo, issuerKeyId, identity.SelfSignature.PreferredCompression, identity.SelfSignature.PreferredCompression, identity.SelfSignature.PreferredSymmetric)
			fmt.Printf("self | primary: %v, sign: %v, certify: %v, encrypt storage: %v, encrypt communications: %v, mdc: %v, valid: %v\n", isPrimaryKey, identity.SelfSignature.FlagSign, identity.SelfSignature.FlagCertify, identity.SelfSignature.FlagEncryptStorage, identity.SelfSignature.FlagEncryptCommunications, identity.SelfSignature.MDC, identity.SelfSignature.FlagsValid)
			fmt.Printf("self | rsa signature: %v\n", identity.SelfSignature.RSASignature)
			if len(identity.Signatures) != 0 {
				fmt.Println("**********************\nother signatures:")
				for i, signature := range identity.Signatures {
					fmt.Printf("%d | hash: %s, hash suffix: %s, created: %v, sig lifetime: %v, key lifetime: %v, expired: %v, type: %v\n", i, signature.Hash.String(), hex.EncodeToString(signature.HashSuffix), signature.CreationTime, signature.SigLifetimeSecs, signature.KeyLifetimeSecs, signature.KeyExpired(time.Now()), signature.SigType)
					fmt.Printf("%d |  sign: %v, certify: %v, encrypt storage: %v, encrypt communications: %v, mdc: %v, valid: %v\n", i, signature.FlagSign, signature.FlagCertify, signature.FlagEncryptStorage, signature.FlagEncryptCommunications, signature.MDC, signature.FlagsValid)
				}
				fmt.Println("**********************")
			}
			fmt.Println("----------------------")
		}
		fmt.Println("======================")
	}
}

func writeDebugFile(header, signedContent string) {
	out := os.Getenv("TEST_SMTP_OUTPUT_FILE")
	if out != "" {
		outfile := fmt.Sprintf("%s_%s.txt", out, time.Now().Format(rfc5322DateTimeLayout))
		err := os.WriteFile(outfile, []byte(header+signedContent), 0600)

		if err != nil {
			fmt.Printf("err writing test file %s: %v\n", outfile, err)
		} else {
			fmt.Printf("test file written to %s\n", outfile)
		}
	}
}

// Do startTLS if available (some servers only provide the auth extension after, and encryption is preferred).
func (n *SMTPNotifier) startTLS() error {
	logger := logging.Logger()
	// Only start if not already encrypted
	if _, ok := n.client.TLSConnectionState(); ok {
		logger.Debugf("Notifier SMTP connection is already encrypted, skipping STARTTLS")
		return nil
	}

	switch ok, _ := n.client.Extension("STARTTLS"); ok {
	case true:
		logger.Debugf("Notifier SMTP server supports STARTTLS (disableVerifyCert: %t, ServerName: %s), attempting", n.tlsConfig.InsecureSkipVerify, n.tlsConfig.ServerName)

		if err := n.client.StartTLS(n.tlsConfig); err != nil {
			return err
		}

		logger.Debug("Notifier SMTP STARTTLS completed without error")
	default:
		switch n.disableRequireTLS {
		case true:
			logger.Warn("Notifier SMTP server does not support STARTTLS and SMTP configuration is set to disable the TLS requirement (only useful for unauthenticated emails over plain text)")
		default:
			return errors.New("Notifier SMTP server does not support TLS and it is required by default (see documentation if you want to disable this highly recommended requirement)")
		}
	}

	return nil
}

// Attempt Authentication.
func (n *SMTPNotifier) auth() error {
	logger := logging.Logger()
	// Attempt AUTH if password is specified only.
	if n.password != "" {
		_, ok := n.client.TLSConnectionState()
		if !ok {
			return errors.New("Notifier SMTP client does not support authentication over plain text and the connection is currently plain text")
		}

		// Check the server supports AUTH, and get the mechanisms.
		ok, m := n.client.Extension("AUTH")
		if ok {
			var auth smtp.Auth

			logger.Debugf("Notifier SMTP server supports authentication with the following mechanisms: %s", m)
			mechanisms := strings.Split(m, " ")

			// Adaptively select the AUTH mechanism to use based on what the server advertised.
			if utils.IsStringInSlice("PLAIN", mechanisms) {
				auth = smtp.PlainAuth("", n.username, n.password, n.host)

				logger.Debug("Notifier SMTP client attempting AUTH PLAIN with server")
			} else if utils.IsStringInSlice("LOGIN", mechanisms) {
				auth = newLoginAuth(n.username, n.password, n.host)

				logger.Debug("Notifier SMTP client attempting AUTH LOGIN with server")
			}

			// Throw error since AUTH extension is not supported.
			if auth == nil {
				return fmt.Errorf("notifier SMTP server does not advertise a AUTH mechanism that are supported by Authelia (PLAIN or LOGIN are supported, but server advertised %s mechanisms)", m)
			}

			// Authenticate.
			if err := n.client.Auth(auth); err != nil {
				return err
			}

			logger.Debug("Notifier SMTP client authenticated successfully with the server")

			return nil
		}

		return errors.New("Notifier SMTP server does not advertise the AUTH extension but config requires AUTH (password specified), either disable AUTH, or use an SMTP host that supports AUTH PLAIN or AUTH LOGIN")
	}

	logger.Debug("Notifier SMTP config has no password specified so authentication is being skipped")

	return nil
}

func (n *SMTPNotifier) compose(recipient, subject, body, htmlBody string) error {
	logger := logging.Logger()
	logger.Debugf("Notifier SMTP client attempting to send email body to %s", recipient)

	if !n.disableRequireTLS {
		_, ok := n.client.TLSConnectionState()
		if !ok {
			return errors.New("Notifier SMTP client can't send an email over plain text connection")
		}
	}

	wc, err := n.client.Data()
	if err != nil {
		logger.Debugf("Notifier SMTP client error while obtaining WriteCloser: %s", err)
		return err
	}

	boundary := utils.RandomString(30, utils.AlphaNumericCharacters)

	now := time.Now()

	header := "Date: " + now.Format(rfc5322DateTimeLayout) + crlf +
		"From: " + n.sender + crlf +
		"To: " + recipient + crlf +
		"Subject: " + subject + crlf

	signableContent := "--" + boundary + crlf +
		"Content-Type: text/plain; charset=\"utf-8\"" + crlf +
		"Content-Transfer-Encoding: quoted-printable" + crlf +
		"Content-Disposition: inline" + crlf +
		body + crlf

	if htmlBody != "" {
		signableContent += "--" + boundary + crlf +
			"Content-Type: text/html; charset=\"UTF-8\"" + crlf +
			"Content-Transfer-Encoding: quoted-printable" + crlf +
			htmlBody + crlf
	}

	signableContent += "--" + boundary + "--"

	signedContent, err := n.packAndSignContent(signableContent, boundary)
	if err != nil {
		logger.Debugf("Notifier SMTP client error while packing and signing email content: %v", err)
		return err
	}

	writeDebugFile(header, signedContent)

	_, err = fmt.Fprint(wc, header+signedContent)
	if err != nil {
		logger.Debugf("Notifier SMTP client error while sending email body over WriteCloser: %v", err)
		return err
	}

	err = wc.Close()
	if err != nil {
		logger.Debugf("Notifier SMTP client error while closing the WriteCloser: %s", err)
		return err
	}

	return nil
}

func (n *SMTPNotifier) packAndSignContent(content, contentBoundary string) (signedContent string, err error) {
	content = reEOLWhitespace.ReplaceAllString(content, "\r\n")
	content = reNonRFC2822Newlines.ReplaceAllString(content, "$1\r\n")
	contentTypeMultiPartAlternative := fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"", contentBoundary) + crlf

	var key *openpgp.Entity

	for _, entity := range n.signingPGPKeyring {
		if entity.PrivateKey.CanSign() {
			key = entity
			break
		}
	}

	if len(n.signingPGPKeyring) == 0 || key == nil {
		return contentTypeMultiPartAlternative + rfc2822MIMEHeader + content, nil
	}

	content = contentTypeMultiPartAlternative + crlf + content

	boundary := utils.RandomString(30, utils.AlphaNumericCharacters)

	var (
		config    *packet.Config
		signature strings.Builder
	)

	switch n.signingPGPAlgorithm {
	case rfc4880HashSymbolSHA512:
		config = &packet.Config{DefaultHash: crypto.SHA512}
	case rfc4880HashSymbolSHA384:
		config = &packet.Config{DefaultHash: crypto.SHA384}
	case rfc4880HashSymbolSHA256:
		config = &packet.Config{DefaultHash: crypto.SHA256}
	case rfc4880HashSymbolSHA1:
		config = &packet.Config{DefaultHash: crypto.SHA1}
	}

	err = openpgp.ArmoredDetachSignText(&signature, key, strings.NewReader(content), config)
	if err != nil {
		return rfc2822MIMEHeader + content, err
	}

	signedContent = fmt.Sprintf("Content-Type: multipart/signed; micalg=\"%s\"; protocol=\"application/pgp-signature\"; boundary=\"%s\"", n.signingPGPAlgorithm, boundary) + crlf +
		rfc2822MIMEHeader +
		"--" + boundary + crlf +
		content + doubleCRLF +
		"--" + boundary + crlf +
		"Content-Type: application/pgp-signature; name=\"signature.asc\"" + crlf +
		"Content-Disposition: attachment; filename=\"signature.asc\"" + crlf +
		"Content-Description: OpenPGP digital signature" + doubleCRLF +
		signature.String() + doubleCRLF +
		"--" + boundary + "--"

	return signedContent, nil
}

// Dial the SMTP server with the SMTPNotifier config.
func (n *SMTPNotifier) dial() error {
	logger := logging.Logger()
	logger.Debugf("Notifier SMTP client attempting connection to %s", n.address)

	if n.port == 465 {
		logger.Warnf("Notifier SMTP client configured to connect to a SMTPS server. It's highly recommended you use a non SMTPS port and STARTTLS instead of SMTPS, as the protocol is long deprecated.")

		conn, err := tls.Dial("tcp", n.address, n.tlsConfig)
		if err != nil {
			return err
		}

		client, err := smtp.NewClient(conn, n.host)
		if err != nil {
			return err
		}

		n.client = client
	} else {
		client, err := smtp.Dial(n.address)
		if err != nil {
			return err
		}

		n.client = client
	}

	logger.Debug("Notifier SMTP client connected successfully")

	return nil
}

// Closes the connection properly.
func (n *SMTPNotifier) cleanup() {
	logger := logging.Logger()

	err := n.client.Quit()
	if err != nil {
		logger.Warnf("Notifier SMTP client encountered error during cleanup: %s", err)
	}
}

// StartupCheck checks the server is functioning correctly and the configuration is correct.
func (n *SMTPNotifier) StartupCheck() (bool, error) {
	if err := n.dial(); err != nil {
		return false, err
	}

	defer n.cleanup()

	if err := n.client.Hello(n.identifier); err != nil {
		return false, err
	}

	if err := n.startTLS(); err != nil {
		return false, err
	}

	if err := n.auth(); err != nil {
		return false, err
	}

	if err := n.client.Mail(n.sender); err != nil {
		return false, err
	}

	if err := n.client.Rcpt(n.startupCheckAddress); err != nil {
		return false, err
	}

	if err := n.client.Reset(); err != nil {
		return false, err
	}

	return true, nil
}

// Send is used to send an email to a recipient.
func (n *SMTPNotifier) Send(recipient, title, body, htmlBody string) error {
	logger := logging.Logger()
	subject := strings.ReplaceAll(n.subject, "{title}", title)

	if err := n.dial(); err != nil {
		return err
	}

	// Always execute QUIT at the end once we're connected.
	defer n.cleanup()

	if err := n.client.Hello(n.identifier); err != nil {
		return err
	}

	// Start TLS and then Authenticate.
	if err := n.startTLS(); err != nil {
		return err
	}

	if err := n.auth(); err != nil {
		return err
	}

	// Set the sender and recipient first.
	if err := n.client.Mail(n.sender); err != nil {
		logger.Debugf("Notifier SMTP failed while sending MAIL FROM (using sender) with error: %s", err)
		return err
	}

	if err := n.client.Rcpt(recipient); err != nil {
		logger.Debugf("Notifier SMTP failed while sending RCPT TO (using recipient) with error: %s", err)
		return err
	}

	// Compose and send the email body to the server.
	if err := n.compose(recipient, subject, body, htmlBody); err != nil {
		return err
	}

	logger.Debug("Notifier SMTP client successfully sent email")

	return nil
}
