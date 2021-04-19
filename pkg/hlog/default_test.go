// +build !integration

package hlog

import (
	"fmt"
	"testing"

	"github.com/ownmfa/hermes/pkg/test/random"
)

func TestDefault(t *testing.T) {
	logger := Default()
	t.Logf("logger: %#v", logger)

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can log %v", lTest), func(t *testing.T) {
			t.Parallel()

			logger.Debug("Debug")
			logger.Debugf("Debugf: %v", lTest)
			logger.Info("Info")
			logger.Infof("Infof: %v", lTest)
			logger.Error("Error")
			logger.Errorf("Errorf: %v", lTest)
			// Do not test Fatal* due to os.Exit.
		})
	}
}

func TestDefaultConsole(t *testing.T) {
	SetDefault(NewConsole())

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can log %v", lTest), func(t *testing.T) {
			t.Parallel()

			Debug("Debug")
			Debugf("Debugf: %v", lTest)
			Info("Info")
			Infof("Infof: %v", lTest)
			Error("Error")
			Errorf("Errorf: %v", lTest)
			// Do not test Fatal* due to os.Exit.
		})
	}
}

func TestDefaultJSON(t *testing.T) {
	SetDefault(NewJSON())

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can log %v", lTest), func(t *testing.T) {
			t.Parallel()

			Debug("Debug")
			Debugf("Debugf: %v", lTest)
			Info("Info")
			Infof("Infof: %v", lTest)
			Error("Error")
			Errorf("Errorf: %v", lTest)
			// Do not test Fatal* due to os.Exit.
		})
	}
}

func TestDefaultWithStr(t *testing.T) {
	t.Parallel()

	logger := WithStr(random.String(10), random.String(10))
	t.Logf("logger: %#v", logger)

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can log %v with string", lTest), func(t *testing.T) {
			t.Parallel()

			logger.Debug("Debug")
			logger.Debugf("Debugf: %v", lTest)
			logger.Info("Info")
			logger.Infof("Infof: %v", lTest)
			logger.Error("Error")
			logger.Errorf("Errorf: %v", lTest)
			// Do not test Fatal* due to os.Exit.
		})
	}
}

func TestDefaultWithFields(t *testing.T) {
	t.Parallel()

	fields := map[string]interface{}{
		random.String(10): random.String(10),
		random.String(10): random.Intn(99),
	}
	logger := WithFields(fields)
	t.Logf("logger: %#v", logger)

	for i := 0; i < 5; i++ {
		lTest := i

		t.Run(fmt.Sprintf("Can log %v with fields", lTest), func(t *testing.T) {
			t.Parallel()

			logger.Debug("Debug")
			logger.Debugf("Debugf: %v", lTest)
			logger.Info("Info")
			logger.Infof("Infof: %v", lTest)
			logger.Error("Error")
			logger.Errorf("Errorf: %v", lTest)
			// Do not test Fatal* due to os.Exit.
		})
	}
}
