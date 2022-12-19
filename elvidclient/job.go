package elvidclient

import (
	"context"
	"encoding/json"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const tracerName = "go.opentelemetry.io/otel"

func newStarter(collector *optionsCollector, httpClient *http.Client, minimumResolvedSeconds int) starter {
	return &job{
		url:                    collector.tokenEndpoint,
		clientID:               collector.tokenClientID,
		clientSecret:           collector.tokenClientSecret,
		client:                 httpClient,
		minimumResolvedSeconds: minimumResolvedSeconds,
	}
}

type starter interface {
	start(ctx context.Context, output chan<- string)
}

type job struct {
	url                    string
	clientID               string
	clientSecret           string
	minimumResolvedSeconds int
	client                 *http.Client
}

func (j *job) start(ctx context.Context, output chan<- string) {
	tkn, err := j.get(ctx)
	if err != nil {
		panic(err)
	}

	output <- tkn.AccessToken

	for {
		<-time.After(secondsToWait(tkn.ExpiresIn, j.minimumResolvedSeconds))
		tkn, err = j.get(ctx)
		if err != nil {
			panic(err)
		}

		output <- tkn.AccessToken
	}
}

func (j *job) get(ctx context.Context) (token, error) {
	tracer := otel.GetTracerProvider().Tracer(tracerName)
	_, span := tracer.Start(ctx, "elvid.tokenJob.get", trace.WithAttributes(attribute.String("url", j.url)))
	defer span.End()

	var tkn token
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", j.clientID)
	data.Add("client_secret", j.clientSecret)
	encodedData := data.Encode()

	req, err := http.NewRequest("POST", j.url, strings.NewReader(encodedData))
	if err != nil {
		return tkn, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	resp, err := j.client.Do(req)
	if err != nil {
		return tkn, err
	}

	span.SetAttributes(attribute.Int("statusCode", resp.StatusCode))

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return tkn, err
	}

	err = json.Unmarshal(b, &tkn)
	if err != nil {
		return tkn, err
	}

	return tkn, nil
}

func secondsToWait(expiresIn, minimumResolvedSeconds int) time.Duration {
	res := expiresIn - 60
	if res < minimumResolvedSeconds {
		return time.Second * time.Duration(minimumResolvedSeconds)
	}

	return time.Duration(res) * time.Second
}
