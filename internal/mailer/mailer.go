// Package mailer sends alert email over SMTP with mandatory TLS for auth.
package mailer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

const (
	ModeStartTLS = "starttls"
	ModeTLS      = "tls"
	ModeNone     = "none"
)

// Config is a complete SMTP configuration. Password is never logged or returned
// by the HTTP API.
type Config struct {
	Host       string
	Port       int
	Mode       string
	Username   string
	Password   string
	From       string
	Recipients []string
	Timeout    time.Duration
	Enabled    bool
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("SMTP host is required")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("SMTP port must be between 1 and 65535")
	}
	switch c.Mode {
	case ModeStartTLS, ModeTLS, ModeNone:
	default:
		return errors.New("SMTP mode must be starttls, tls, or none")
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return fmt.Errorf("invalid From address: %w", err)
	}
	if len(c.Recipients) == 0 {
		return errors.New("at least one recipient is required")
	}
	for _, recipient := range c.Recipients {
		if _, err := mail.ParseAddress(recipient); err != nil {
			return fmt.Errorf("invalid recipient %q: %w", recipient, err)
		}
	}
	if c.Mode == ModeNone && c.Username != "" {
		return errors.New("SMTP authentication requires TLS")
	}
	if c.Username != "" && c.Password == "" {
		return errors.New("SMTP password is required when a username is set")
	}
	return nil
}

// ParseRecipients accepts comma, semicolon, or newline separated addresses.
func ParseRecipients(value string) ([]string, error) {
	value = strings.ReplaceAll(value, ";", ",")
	value = strings.ReplaceAll(value, "\n", ",")
	value = strings.ReplaceAll(value, "\r", ",")
	parsed, err := mail.ParseAddressList(value)
	if err != nil {
		return nil, fmt.Errorf("invalid recipients: %w", err)
	}
	seen := make(map[string]bool)
	var recipients []string
	for _, address := range parsed {
		if seen[address.Address] {
			continue
		}
		seen[address.Address] = true
		recipients = append(recipients, address.Address)
	}
	if len(recipients) == 0 {
		return nil, errors.New("at least one recipient is required")
	}
	return recipients, nil
}

// Send delivers one plain-text email. Authentication is only attempted over a
// TLS connection; starttls requires the server to advertise STARTTLS.
func Send(cfg Config, to []string, subject, body string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	recipients := to
	if len(recipients) == 0 {
		recipients = cfg.Recipients
	}
	parsedTo := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		address, err := mail.ParseAddress(recipient)
		if err != nil {
			return fmt.Errorf("invalid recipient %q: %w", recipient, err)
		}
		parsedTo = append(parsedTo, address.Address)
	}
	if len(parsedTo) == 0 {
		return errors.New("at least one recipient is required")
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var client *smtp.Client
	switch cfg.Mode {
	case ModeTLS:
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig(cfg.Host))
		if err != nil {
			return fmt.Errorf("SMTP TLS connection: %w", err)
		}
		conn = tlsConn
		client, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTP handshake: %w", err)
		}
	case ModeStartTLS:
		plain, err := dialer.Dial("tcp", address)
		if err != nil {
			return fmt.Errorf("SMTP connection: %w", err)
		}
		conn = plain
		_ = conn.SetDeadline(time.Now().Add(timeout))
		client, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTP handshake: %w", err)
		}
		if err := client.StartTLS(tlsConfig(cfg.Host)); err != nil {
			_ = client.Close()
			return fmt.Errorf("SMTP STARTTLS: %w", err)
		}
	case ModeNone:
		plain, err := dialer.Dial("tcp", address)
		if err != nil {
			return fmt.Errorf("SMTP connection: %w", err)
		}
		conn = plain
		_ = conn.SetDeadline(time.Now().Add(timeout))
		client, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("SMTP handshake: %w", err)
		}
	default:
		return errors.New("unsupported SMTP mode")
	}
	defer client.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if cfg.Username != "" {
		if cfg.Mode != ModeTLS && cfg.Mode != ModeStartTLS {
			return errors.New("SMTP authentication requires TLS")
		}
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("SMTP authentication: %w", err)
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	for _, recipient := range parsedTo {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("SMTP RCPT TO: %w", err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	message := buildMessage(from, parsedTo, subject, body)
	if _, err := io.WriteString(writer, message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP QUIT: %w", err)
	}
	return nil
}

func tlsConfig(host string) *tls.Config {
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
}

func buildMessage(from *mail.Address, to []string, subject, body string) string {
	subject = strings.ReplaceAll(strings.ReplaceAll(subject, "\r", " "), "\n", " ")
	subject = mime.QEncoding.Encode("utf-8", subject)
	headers := []string{
		"From: " + from.String(),
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body
}
