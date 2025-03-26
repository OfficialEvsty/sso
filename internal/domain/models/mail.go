package models

// Mail is model using by MailClient
type Mail struct {
	MailTo   string
	Subject  string
	Body     string
	HtmlBody string
}
