package mail

import (
	"context"
	mailv1 "github.com/OfficialEvsty/protos/gen/go/mailer"
	"github.com/ilyakaznacheev/cleanenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log/slog"
	"os"
)

// MailTemplate is a working template for mail constructing
type MailTemplate struct {
	Verification VerificationMailTemplate `json:"verification"`
}

type VerificationMailTemplate struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	Html    string `json:"html"`
}

// MailClient for sending verification mails to user
type MailClient struct {
	conn     *grpc.ClientConn
	client   mailv1.MailServiceClient
	template *MailTemplate
	logger   *slog.Logger
}

// Initialize MailClient and provide connection
func NewMailClient(logger *slog.Logger) (*MailClient, error) {
	const op = "mail.NewMailClient"
	host := os.Getenv("MAIL_HOST")
	port := os.Getenv("MAIL_PORT")
	addr := host + ":" + port
	log := logger.With(slog.String("op", op), slog.String("address", addr))
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Error("Failed to create grpc connection", "error", err)
		return nil, err
	}
	log.Info("successfully created grpc connection to mail server")
	mailTemplate := MailTemplate{}
	templatePath := "mail/template.json"
	if err := cleanenv.ReadConfig(templatePath, &mailTemplate); err != nil {
		panic(err)
	}

	return &MailClient{conn: conn, client: mailv1.NewMailServiceClient(conn), template: &mailTemplate, logger: logger}, nil
}

// Close закрывает соединение
func (c *MailClient) Close() error {
	return c.conn.Close()
}

// SendVerificationMail sends verification mail to a user
func (c *MailClient) SendVerificationMail(ctx context.Context, emailTo string, callbackUrl string) error {
	mailRequest := mailv1.SendMailRequest{
		To:      emailTo,
		Subject: c.template.Verification.Subject,
		Text:    c.template.Verification.Text + " " + callbackUrl,
		Html:    c.template.Verification.Html,
	}

	_, err := c.client.SendMail(ctx, &mailRequest)
	if err != nil {
		c.logger.Error("Failed to send verification mail", "error", err)
		return err
	}
	c.logger.Debug("successfully sent verification mail")
	return nil
}
