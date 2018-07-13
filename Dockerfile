FROM golang:alpine
ADD . /go/src/github.com/dav009/survey
RUN go install github.com/dav009/survey
ADD home.html .
CMD ["/go/bin/survey"]
EXPOSE 8500
