package bypassfast

import "context"

// Balance is the current prepaid USD balance.
type Balance struct {
	ErrorID      int          `json:"errorId"`
	Organization string       `json:"org_id"`
	Amount       float64      `json:"balance"`
	AmountCents  int64        `json:"balance_cents"`
	Currency     string       `json:"currency"`
	Response     ResponseMeta `json:"-"`
}

// Balance returns the current prepaid account balance.
func (c *Client) Balance(ctx context.Context) (*Balance, error) {
	result := new(Balance)
	meta, err := c.doJSON(ctx, "GET", "/balance", nil, result)
	if err != nil {
		return nil, err
	}
	result.Response = meta
	return result, nil
}
