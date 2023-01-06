package utils

import (
	log "github.com/sirupsen/logrus"
)

//nolint:gochecknoinits
func init() {
	log.SetFormatter(&log.TextFormatter{
		ForceColors:            true,
		FullTimestamp:          true,
		DisableLevelTruncation: true,
	})
	log.SetLevel(log.InfoLevel)
}
