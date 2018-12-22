package nstatus

import (
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/inapi"
)

var (
	PodRepActives inapi.PodRepItems
	PodRepOpLogs  inapi.OpLogList
	BoxActives    napi.BoxInstanceSets
	PodRepRemoves types.ArrayString
	PodRepStops   types.ArrayString
)
