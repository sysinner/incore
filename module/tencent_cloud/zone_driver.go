package tencent_cloud

import (
	"errors"
	"regexp"
	"strings"

	// "github.com/hooto/hlog4g/hlog"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"

	"github.com/sysinner/incore/inapi"
)

const (
	ZoneDriverName    = "tencent_cloud"
	ZoneDriverVersion = "0.1.0"
)

var (
	zoneNameRX  = regexp.MustCompile("^[a-z0-9]{1,4}-[a-z0-9]{1,30}-[0-9]{1,2}$")
	vpcNameRX   = regexp.MustCompile("^vpc-[a-zA-Z0-9]{1,30}$")
	osImageIdRX = regexp.MustCompile("^img-[a-zA-Z0-9]{1,30}$")
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
				Name:         "api_url",
				Type:         inapi.ConfigFieldType_String,
				DefaultValue: "cvm.tencentcloudapi.com",
			},
			{
				Name: "secret_id",
				Type: inapi.ConfigFieldType_String,
			},
			{
				Name: "secret_key",
				Type: inapi.ConfigFieldType_String,
			},
			{
				Name: "region_name",
				Type: inapi.ConfigFieldType_String,
			},
			{
				Name: "network-vpc-name",
				Type: inapi.ConfigFieldType_String,
			},
			{
				Name: "os-image-id",
				Type: inapi.ConfigFieldType_String,
			},
		},
	}
}

func (zoneDriver) ConfigValid(spec *inapi.ConfigInstance) error {
	for _, f := range spec.Fields {
		switch f.Name {
		case "region_name":
			if !zoneNameRX.MatchString(f.Value) {
				return errors.New("invalid region_name")
			}

		case "network-vpc-name":
			if !vpcNameRX.MatchString(f.Value) {
				return errors.New("invalid network-vpc-name")
			}

		case "os-image-id":
			if !osImageIdRX.MatchString(f.Value) {
				return errors.New("invalid os-image-id")
			}

		}
	}
	return nil
}

/**
{
    "Response": {
        "TotalCount": 1,
        "InstanceSet": [
            {
                "Placement": {
                    "Zone": "ap-beijing-5",
                    "ProjectId": 0
                },
                "InstanceId": "ins-myhzc8lp",
                "InstanceType": "SA2.SMALL2",
                "CPU": 1,
                "Memory": 2,
                "RestrictState": "NORMAL",
                "InstanceName": "bj3-1-sysinner",
                "InstanceChargeType": "PREPAID",
                "SystemDisk": {
                    "DiskType": "CLOUD_PREMIUM",
                    "DiskId": "disk-j17qy9oh",
                    "DiskSize": 50
                },
                "DataDisks": [
                    {
                        "DiskSize": 50,
                        "DiskType": "CLOUD_PREMIUM",
                        "DiskId": "disk-r9fs4y15",
                        "DeleteWithInstance": false
                    }
                ],
                "PrivateIpAddresses": [
                    "172.21.32.10"
                ],
                "PublicIpAddresses": [
                    "49.232.65.177"
                ],
                "InternetAccessible": {
                    "InternetChargeType": "BANDWIDTH_PREPAID",
                    "InternetMaxBandwidthOut": 3
                },
                "VirtualPrivateCloud": {
                    "VpcId": "vpc-60onv7zc",
                    "SubnetId": "subnet-99s4exch",
                    "AsVpcGateway": false
                },
                "ImageId": "img-l5eqiljn",
                "RenewFlag": "NOTIFY_AND_MANUAL_RENEW",
                "CreatedTime": "2021-07-31T06:49:47Z",
                "ExpiredTime": "2022-07-31T06:49:47Z",
                "OsName": "CentOS 8.4 64位",
                "SecurityGroupIds": [
                    "sg-p3vah01n"
                ],
                "LoginSettings": {
                    "KeyIds": [
                        "skey-b5aesnbp"
                    ]
                },
                "InstanceState": "RUNNING",
                "StopChargingMode": "NOT_APPLICABLE",
                "Uuid": "3355d9a7-3c13-4e58-8f60-6dca03904359",
                "LatestOperation": "ResetInstance",
                "LatestOperationState": "SUCCESS",
                "LatestOperationRequestId": "7bd973df-c1a2-48e3-bc60-94d440d4bc2d",
                "DisasterRecoverGroupId": "",
                "CamRoleName": "",
                "HpcClusterId": "",
                "IsolatedSource": "NOTISOLATED"
            }
        ],
        "RequestId": "d91f4365-5681-4a0d-ab4e-f8fcd010ebfa"
    }
}
*/

func (zoneDriver) HostList(cfg *inapi.ConfigInstance) ([]*inapi.ResHostCloudProvider, error) {

	if cfg == nil {
		return nil, errors.New("ConfigInstance empty")
	}

	var (
		secretId   = cfg.FieldValue("secret_id")
		secretKey  = cfg.FieldValue("secret_key")
		regionName = cfg.FieldValue("region_name")
	)

	if n := strings.LastIndexByte(regionName, '-'); n > 0 {
		regionName = regionName[:n]
	}

	credential := common.NewCredential(secretId, secretKey)

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = cfg.FieldValue("api_url")

	client, err := cvm.NewClient(credential, regionName, cpf)
	if err != nil {
		return nil, err
	}

	var (
		nodes   []*inapi.ResHostCloudProvider
		limit   = 100
		request = cvm.NewDescribeInstancesRequest()
	)

	request.Limit = common.Int64Ptr(int64(limit))

	for {

		rsp, err := client.DescribeInstances(request)
		if err != nil {
			return nil, err
		}

		if rsp.Response == nil {
			break
		}

		for _, v := range rsp.Response.InstanceSet {

			if len(v.PrivateIpAddresses) == 0 {
				continue
			}

			if v.Placement == nil || *v.Placement.Zone != cfg.FieldValue("region_name") {
				continue
			}

			/**
			nodeEntry := &inapi.ResHost{
				Meta: &inapi.ObjectMeta{
					Id: *v.InstanceId,
				},
				Spec: &inapi.ResHostSpec{
					Platform: &inapi.ResPlatform{
						Os:     *v.OsName,
						Kernel: "",
						Arch:   "",
					},
					Capacity: &inapi.ResHostResource{
						Mem: *v.Memory,
						Cpu: int32(*v.CPU),
					},
				},
				Operate: &inapi.ResHostOperate{},
				CloudProvider: &inapi.ResHostCloudProvider{
					InstanceId:   *v.InstanceId, //  *v.Uuid,
					InstanceName: *v.InstanceName,
					PrivateIp:    *v.PrivateIpAddresses[0],
					RawJson:      string(inapi.JsonEncode(v)),
				},
			}
			*/

			nodeEntry := &inapi.ResHostCloudProvider{
				InstanceId:   *v.InstanceId,
				InstanceName: *v.InstanceName,
				PrivateIp:    *v.PrivateIpAddresses[0],
				RawJson:      string(inapi.JsonEncode(v)),
			}

			nodes = append(nodes, nodeEntry)
		}

		if len(rsp.Response.InstanceSet) < limit ||
			len(nodes) >= int(*rsp.Response.TotalCount) {
			break
		}

		*request.Offset += int64(limit)
	}

	return nodes, nil
}

func (zoneDriver) HostAlloc(cfg *inapi.ConfigInstance, host *inapi.ResHost) error {
	return nil
}

func (zoneDriver) HostFree(cfg *inapi.ConfigInstance, host *inapi.ResHost) error {
	return nil
}
