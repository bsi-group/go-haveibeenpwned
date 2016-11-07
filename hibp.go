package hibp

import (
	"net/http"
	"log"
	"time"
	"encoding/json"
	"fmt"
)

const API_URL = "https://haveibeenpwned.com/api/v2/%s"

type HibpClient struct {
}

// Parameters for the HTTP requests
type Parameters map[string]string

type Breaches []Breach

type Breach struct {
	Name      	string		`json:"Name"`
	Title       string   	`json:"Title"`
	Domain      string    	`json:"Domain"`
	BreachDate  string    	`json:"BreachDate"`
	AddedDate   time.Time 	`json:"AddedDate"`
	PwnCount    int       	`json:"PwnCount"`
	DataClasses []string  	`json:"DataClasses"`
	Description string    	`json:"Description"`
	IsVerified  bool      	`json:"IsVerified"`
	IsSensitive bool      	`json:"IsSensitive"`
	IsRetired   bool      	`json:"IsRetired"`
}

func (h *HibpClient) getApiJson(actionUrl string, parameters Parameters, result interface{}) (err error, resp string) {

	client := new(http.Client)

	req, err := http.NewRequest("GET", fmt.Sprintf(API_URL, actionUrl), nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Add("Accept", "application/vnd.haveibeenpwned.v2+json")
	req.Header.Add("User-Agent", "go-haveibeenpwned (HIBP golang API client library) - https://github.com/woanware/go-haveibeenpwned")

	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		return err, ""
	}
	defer res.Body.Close()

	dec := json.NewDecoder(res.Body)
	if err = dec.Decode(result); err != nil {
		return err, ""
	}

	return nil, ""
}

func (h *HibpClient) BreachesForAccount(email string, domain string, truncateResponse bool) (err error, resp string, breaches *Breaches) {

	breaches = &Breaches{}
	err, resp = h.getApiJson("breachedaccount/" + email, nil, breaches)
	if err != nil {
		return err, "", nil
	}

	return nil, "", breaches
}
