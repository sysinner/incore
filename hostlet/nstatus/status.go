package nstatus

import (
	"github.com/lessos/lessgo/types"

	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/inapi"
)

var (
	PodRepActives inapi.PodRepItems
	PodRepRemoves types.ArrayString
	PodRepStops   types.ArrayString
)

var (
	BoxActives   napi.BoxInstanceSets
	PodRepOpLogs inapi.OpLogList
)
