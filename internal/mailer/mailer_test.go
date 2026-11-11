package mailer

import (
	"net/mail"
	"strings"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	valid := Config{Host: "smtp.example.com", Port: 587, Mode: ModeStartTLS, From: "hibp@example.com", Recipients: []string{"ops@example.com"}, Enabled: true}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalidAuth := valid
	invalidAuth.Mode = ModeNone
	invalidAuth.Username = "user"
	invalidAuth.Password = "secret"
	if err := invalidAuth.Validate(); err == nil {
		t.Fatal("expected plaintext auth rejection")
	}
	invalidRecipient := valid
	invalidRecipient.Recipients = []string{"not an address"}
	if err := invalidRecipient.Validate(); err == nil {
		t.Fatal("expected invalid recipient rejection")
	}
}

func TestParseRecipients(t *testing.T) {
	recipients, err := ParseRecipients("Ops Team <ops@example.com>, admin@example.com; ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 2 {
		t.Fatalf("expected two unique recipients, got %v", recipients)
	}
	if recipients[0] != "ops@example.com" || recipients[1] != "admin@example.com" {
		t.Fatalf("unexpected recipients: %v", recipients)
	}
}

func TestBuildMessageSanitizesSubject(t *testing.T) {
	from, _ := parseAddressForTest("hibp@example.com")
	message := buildMessage(from, []string{"ops@example.com"}, "alert\r\nBcc: evil@example.com", "body")
	if strings.Contains(message, "\r\nBcc:") {
		t.Fatal("header injection was not removed")
	}
	if !strings.Contains(message, "Subject: alert  Bcc: evil@example.com") {
		t.Fatalf("unexpected subject: %s", message)
	}
}

func TestBuildMessageEncodesNonASCIISubject(t *testing.T) {
	from, _ := parseAddressForTest("hibp@example.com")
	message := buildMessage(from, []string{"ops@example.com"}, "[HIBP] CPU – web01", "body")
	if strings.Contains(message, "CPU – web01") {
		t.Fatal("non-ASCII subject was not MIME encoded")
	}
	if !strings.Contains(message, "Subject: =?utf-8?") {
		t.Fatalf("unexpected encoded subject: %s", message)
	}
}

func parseAddressForTest(value string) (*mail.Address, error) {
	return mail.ParseAddress(value)
}
