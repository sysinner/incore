package nstatus

import (
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/inapi"
)

var (
	PodRepActives inapi.PodSets
	PodRepOpLogs  inapi.OpLogList
	BoxActives    napi.BoxInstanceSets
	PodQueue      inapi.PodSets // TODO
)
