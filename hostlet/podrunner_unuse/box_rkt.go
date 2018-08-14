package podrunner

import (
	"fmt"
	"time"
)

type BoxDriverRkt struct {
}

func (it *BoxDriverRkt) Name() string {
	return "rkt"
}

func (it *BoxDriverRkt) Run() {
	for {
		time.Sleep(2e9)

	}
}

func (it *BoxDriverRkt) ActionCommand(inst *BoxInstance) error {
	fmt.Println("rkt action command")
	return nil
}

func (it *BoxDriverRkt) StatsCollect(inst *BoxInstance, timo uint32) error {
	return nil
}
