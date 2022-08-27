package private_cloud

import (
	"github.com/sysinner/incore/inapi"
)

const (
	ZoneDriverName    = "private_cloud"
	ZoneDriverVersion = "0.1.0"
)

type zoneDriver struct {
}

func NewZoneDriver() (inapi.ZoneDriver, error) {
	return &zoneDriver{}, nil
}

func (zoneDriver) Name() string {
	return ZoneDriverName
}

func (zoneDriver) ConfigSpec() *inapi.ConfigSpec {
	return &inapi.ConfigSpec{
		Name:    ZoneDriverName,
		Version: ZoneDriverVersion,
		Fields: []*inapi.ConfigFieldSpec{
			{
				Name: "description",
				Type: inapi.ConfigFieldType_Text,
			},
		},
	}
}

func (zoneDriver) ConfigValid(spec *inapi.ConfigInstance) error {
	return nil
}

func (zoneDriver) HostList(cfg *inapi.ConfigInstance) ([]*inapi.ResHostCloudProvider, error) {
	return nil, nil
}

func (zoneDriver) HostAlloc(cfg *inapi.ConfigInstance, host *inapi.ResHost) error {
	return nil
}

func (zoneDriver) HostFree(cfg *inapi.ConfigInstance, host *inapi.ResHost) error {
	return nil
}
