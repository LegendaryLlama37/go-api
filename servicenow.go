package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// ServiceNowClient is a client for interacting with ServiceNow
type ServiceNowClient struct {
	InstanceURL string
	Username    string
	Password    string
}

// NewServiceNowClient creates a new ServiceNow client
func NewServiceNowClient(instanceURL, username, password string) *ServiceNowClient {
	return &ServiceNowClient{
		InstanceURL: instanceURL,
		Username:    username,
		Password:    password,
	}
}

// SendEvent sends an event to the ServiceNow event table
func (client *ServiceNowClient) SendEvent(payload map[string]interface{}) error {
	url := fmt.Sprintf("%s/api/now/table/em_event", client.InstanceURL)
	
	// Marshal payload to JSON
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(client.Username, client.Password)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to send event: status code %d", resp.StatusCode)
	}

	return nil
}
