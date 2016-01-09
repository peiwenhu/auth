package client

type Client struct {
	Id     string `json:"id"`
	Secret string `json:"secret"`
}

func NewClient(id string, secret string) *Client {
	return &Client{Id: id, Secret: secret}
}
