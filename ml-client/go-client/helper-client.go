package goclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

type FlowPayload struct {
	Src         string  `json:"src"`
	Dst         string  `json:"dst"`
	SrcPort     int     `json:"src_port"`
	DstPort     int     `json:"dst_port"`
	Proto       string  `json:"proto"`
	PktCount    int     `json:"pkt_count"`
	TotalBytes  int     `json:"total_bytes"`
	Duration    float64 `json:"duration"`
	Bps         float64 `json:"bps"`
	AvgPktSize  float64 `json:"avg_pkt_size"`
	StdPktSize  float64 `json:"std_pkt_size"`
	MeanIAT     float64 `json:"mean_iat"`
	StdIAT      float64 `json:"std_iat"`
	BytesPerPkt float64 `json:"bytes_per_pkt"`
	Timestamp   string  `json:"ts,omitempty"`
}

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Retries    int
	Timeout    time.Duration
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
			},
		},
		Retries: 3,
		Timeout: 5 * time.Second,
	}
}

func (c *Client) SendFlow(f FlowPayload) error {
	url := fmt.Sprintf("%s/ingest", c.BaseURL)
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}

	var lastErr error
	for i := 0; i < c.Retries; i++ {
		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(data))
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		} else {
			lastErr = fmt.Errorf("ml service returned status %d", resp.StatusCode)
			time.Sleep(200 * time.Millisecond)
		}
	}
	return lastErr
}
