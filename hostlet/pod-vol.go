package hostlet

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/encoding/json"
	ps_disk "github.com/shirou/gopsutil/disk"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/nstatus"
	"github.com/sysinner/incore/inapi"
)

type QuotaConfig struct {
	mu            sync.Mutex
	path          string
	sync_maps_sum string
	sync_ids_sum  string
	Items         []*QuotaProject `json:"items,omitempty"`
	Updated       int64           `json:"updated"`
}

type QuotaProject struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
	Soft int64  `json:"soft"`
	Hard int64  `json:"hard"`
	Used int64  `json:"used"`
}

func (it *QuotaConfig) Fetch(name string) *QuotaProject {
	it.mu.Lock()
	defer it.mu.Unlock()

	for _, v := range it.Items {
		if name == v.Name {
			return v
		}
	}

	return nil
}

func (it *QuotaConfig) FetchOrCreate(name string) *QuotaProject {

	it.mu.Lock()
	defer it.mu.Unlock()

	for _, v := range it.Items {
		if name == v.Name {
			return v
		}
	}

	bind_id := 0
	for i := 1; i < 1000; i++ {
		hit := false
		for _, v := range it.Items {
			if v.Id == i {
				hit = true
				break
			}
		}
		if !hit {
			bind_id = i
			break
		}
	}

	p := &QuotaProject{
		Id:   bind_id,
		Name: name,
	}

	it.Items = append(it.Items, p)

	return p
}

func (it *QuotaConfig) Remove(name string) {

	it.mu.Lock()
	defer it.mu.Unlock()

	for i, v := range it.Items {
		if name == v.Name {
			it.Items = append(it.Items[:i], it.Items[i+1:]...)
			return
		}
	}
}

func (it *QuotaConfig) Sync() error {
	it.Updated = time.Now().Unix()
	return json.EncodeToFile(it, it.path, "  ")
}

func (it *QuotaConfig) SyncVendor() error {

	//
	ids, maps := "", ""
	for _, v := range it.Items {
		if v.Id < 1 {
			continue
		}
		ids += fmt.Sprintf("%s:%d\n", v.Name, v.Id)
		maps += fmt.Sprintf("%d:%s\n", v.Id, filepath.Clean(config.Config.PodHomeDir+"/"+v.Name))
	}
	if maps == "" {
		return nil
	}

	var (
		ids_sum  = fmt.Sprintf("%x", sha1.Sum([]byte(ids)))
		maps_sum = fmt.Sprintf("%x", sha1.Sum([]byte(maps)))
	)

	if ids_sum != it.sync_ids_sum {
		if err := put_file("/etc/projid", ids); err != nil {
			return err
		}
		it.sync_ids_sum = ids_sum
	}

	if maps_sum != it.sync_maps_sum {
		if err := put_file("/etc/projects", maps); err != nil {
			return err
		}
		it.sync_maps_sum = maps_sum
	}

	return nil
}

func put_file(path, data string) error {

	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer fp.Close()

	fp.Seek(0, 0)
	fp.Truncate(0)

	_, err = fp.WriteString(data)
	return err
}

var (
	quotaInited     = false
	quotaReady      = false
	quotaCmd        = "xfs_quota"
	quotaMountpoint = ""
	regMultiSpace   = regexp.MustCompile("\\ \\ +")
	quotaConfig     QuotaConfig
	err             error
)

func QuotaKeeperInit() error {

	if quotaInited {
		return nil
	}

	defer func() {
		quotaInited = true
	}()

	_, err := exec.Command(quotaCmd, "-V").Output()
	if err != nil {
		return errors.New("command " + quotaCmd + " not found")
	}

	devs, _ := ps_disk.Partitions(false)

	sort.Slice(devs, func(i, j int) bool {
		if strings.Compare(devs[i].Mountpoint, devs[j].Mountpoint) > 0 {
			return true
		}
		return false
	})

	for _, d := range devs {
		if !strings.HasPrefix(config.Config.PodHomeDir, d.Mountpoint) {
			continue
		}
		if d.Fstype != "xfs" {
			return errors.New("invalid fstype (" + d.Fstype + ") to enable quota")
		}
		if !strings.Contains(d.Opts, "prjquota") {
			return errors.New("the option:prjquota required on mountpoint of " + d.Mountpoint)
		}
		quotaMountpoint = d.Mountpoint
		break
	}

	if quotaMountpoint == "" {
		return errors.New("no quota path found")
	}

	_, err = exec.Command(quotaCmd, "-x", "-c", "report", quotaMountpoint).Output()
	if err != nil {
		return err
	}

	//
	cfgpath := config.Prefix + "/etc/vol_quota.json"
	if err := json.DecodeFile(cfgpath, &quotaConfig); err != nil && !os.IsNotExist(err) {
		return err
	}
	quotaConfig.path = cfgpath

	quotaReady = true

	return nil
}

func podVolQuotaRefresh() error {

	if err := QuotaKeeperInit(); err != nil {
		return err
	}

	if !quotaReady {
		return nil
	}

	out, err := exec.Command(quotaCmd, "-x", "-c", "report", quotaMountpoint).Output()
	if err != nil {
		return err
	}

	lines := strings.Split(regMultiSpace.ReplaceAllString(string(out), " "), "\n")
	for _, v := range lines {

		vs := strings.Split(strings.TrimSpace(v), " ")
		if len(vs) < 5 {
			continue
		}

		if !inapi.NsZonePodOpRepKeyValid(vs[0]) {
			continue
		}

		proj := quotaConfig.FetchOrCreate(vs[0])

		if i64, err := strconv.ParseInt(vs[1], 10, 64); err == nil {
			proj.Used = i64 * 1024
		}

		if i64, err := strconv.ParseInt(vs[2], 10, 64); err == nil {
			proj.Soft = i64 * 1024
		}

		if i64, err := strconv.ParseInt(vs[3], 10, 64); err == nil {
			proj.Hard = i64 * 1024
		}
	}

	if err := quotaConfig.Sync(); err != nil {
		return err
	}

	nstatus.PodRepActives.Each(func(pod *inapi.Pod) {

		if pod.Spec == nil || pod.Operate.Replica == nil {
			return
		}

		if !inapi.OpActionAllow(pod.Operate.Action, inapi.OpActionStart) {
			return
		}

		spec_vol := pod.Spec.Volume("system")
		if spec_vol == nil {
			return
		}

		name := inapi.NsZonePodOpRepKey(pod.Meta.ID, pod.Operate.Replica.Id)

		proj := quotaConfig.FetchOrCreate(name)
		if proj.Id == 0 {
			return
		}

		if proj.Soft == spec_vol.SizeLimit {
			return
		}

		err := quotaConfig.SyncVendor()
		if err != nil {
			hlog.Printf("warn", "config init %s", err.Error())
			return
		}

		args := []string{
			"-x",
			"-c",
			fmt.Sprintf("\"project -s %s\"", name),
			quotaMountpoint,
		}

		_, err = exec.Command(quotaCmd, args...).Output()
		if err != nil {
			hlog.Printf("warn", "quota init %s", err.Error())
			return
		}

		//
		args = []string{
			"-x",
			"-c",
			fmt.Sprintf("limit -p bsoft=%d bhard=%d %s",
				spec_vol.SizeLimit, spec_vol.SizeLimit, name),
			quotaMountpoint,
		}

		if out, err := exec.Command(quotaCmd, args...).Output(); err != nil {
			hlog.Printf("warn", "quota limit %s, {{{%s}}}", err.Error(), string(out))
			fmt.Println(strings.Join(args, " "))
			return
		}
	})

	if err := quotaConfig.Sync(); err != nil {
		return err
	}

	for _, v := range quotaConfig.Items {

		if pod := nstatus.PodRepActives.Get(v.Name); pod != nil {
			continue
		}

		//
		args := []string{
			"-x",
			"-c",
			fmt.Sprintf("limit -p bsoft=0 bhard=0 %s", v.Name),
			quotaMountpoint,
		}

		_, err = exec.Command(quotaCmd, args...).Output()
		if err != nil {
			hlog.Printf("warn", "quota clean project %s, err %s", v.Name, err.Error())
			return err
		}

		quotaConfig.Remove(v.Name)
		if err := quotaConfig.Sync(); err != nil {
			return err
		}

		hlog.Printf("warn", "quota clean project %s, done", v.Name)
	}

	return nil
}
