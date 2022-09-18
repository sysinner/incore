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
	"github.com/lessos/lessgo/types"
	ps_disk "github.com/shirou/gopsutil/disk"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/hostlet/napi"
	"github.com/sysinner/incore/hostlet/nstatus"
	"github.com/sysinner/incore/inapi"
)

var (
	podBoxIdRe = regexp.MustCompile("^[a-f0-9]{12,20}.[a-f0-9]{4}$")
)

type QuotaConfig struct {
	mu            sync.Mutex
	path          string
	sync_maps_sum string
	sync_ids_sum  string
	Items         []*QuotaProject `json:"items,omitempty"`
	Updated       int64           `json:"updated"`
	IdOffset      int             `json:"id_offset"`
	MountPoints   []string        `json:"mount_points"`
}

type QuotaProject struct {
	Id   int    `json:"id"`
	Mnt  string `json:"mnt"`
	Name string `json:"name"`
	Soft int64  `json:"soft"`
	Hard int64  `json:"hard"`
	Used int64  `json:"used"`
}

func podBoxFoldMatch(boxdir string) (string, bool) {

	if n := strings.LastIndex(boxdir, "/"); n > 0 && (n+12) < len(boxdir) {
		name := boxdir[n+1:]
		if podBoxIdRe.MatchString(name) {
			return name, true
		}
	}

	return "", false
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

func (it *QuotaConfig) FetchById(id int) *QuotaProject {
	it.mu.Lock()
	defer it.mu.Unlock()

	for _, v := range it.Items {
		if id == v.Id {
			return v
		}
	}

	return nil
}

func (it *QuotaConfig) FetchOrCreate(mnt, name string) *QuotaProject {

	it.mu.Lock()
	defer it.mu.Unlock()

	if mnt == "" || mnt == "/" {
		mnt = "/opt" // TODO zone-master -> hostlet
	}

	for _, v := range it.Items {
		if name == v.Name {
			return v
		}
	}

	var (
		bind_id = 0
	)

	if it.IdOffset < 100 || it.IdOffset >= 100000 {
		it.IdOffset = 100
	}

	for i := it.IdOffset; i <= 110000; i++ {
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

	if bind_id == 0 {
		return nil
	}

	p := &QuotaProject{
		Id:   bind_id,
		Name: name,
		Mnt:  mnt,
	}

	it.Items = append(it.Items, p)

	it.IdOffset = bind_id + 1

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
	maps := ""
	for _, v := range it.Items {
		if v.Id < 1 {
			continue
		}

		if strings.HasPrefix(v.Mnt, "/data/") ||
			strings.HasPrefix(v.Mnt, "/opt") {
			maps += fmt.Sprintf("%d:%s\n", v.Id, filepath.Clean(v.Mnt+"/sysinner/pods/"+v.Name))
		} else {
			maps += fmt.Sprintf("%d:%s\n", v.Id, filepath.Clean(config.Config.Zone.PodHomeDir+"/"+v.Name))
		}
	}

	maps_sum := fmt.Sprintf("%x", sha1.Sum([]byte(maps)))
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
	quotaInited          = false
	quotaRefreshed int64 = 0
	quotaCmd             = "xfs_quota"
	regMultiSpace        = regexp.MustCompile("\\ \\ +")
	quotaConfig    QuotaConfig
	err            error
)

func quotaKeeperInit() error {

	if quotaInited {
		return nil
	}

	defer func() {
		quotaInited = true
	}()

	_, err := exec.Command(quotaCmd, "-V").CombinedOutput()
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

	mountPoints := []string{}
	for _, d := range devs {

		if !strings.HasPrefix(d.Mountpoint, "/data/") &&
			!strings.HasPrefix(d.Mountpoint, "/opt") &&
			!strings.HasPrefix(config.Config.Zone.PodHomeDir, d.Mountpoint) {
			continue
		}

		if strings.Contains(d.Mountpoint, "/opt/docker/") ||
			strings.Contains(d.Mountpoint, "/opt/pouch/") ||
			strings.Contains(d.Mountpoint, "devicemapper") {
			continue
		}

		if d.Fstype != "xfs" {
			hlog.Printf("warn", "invalid fstype (%s) to enable quota", d.Fstype)
			continue
		}

		/**
		if !strings.Contains(d.Opts, "prjquota") {
			hlog.Printf("warn", "the option:prjquota required on mountpoint %s", d.Mountpoint)
			continue
		}
		*/

		if _, err = exec.Command(quotaCmd, "-x", "-c", "report", d.Mountpoint).CombinedOutput(); err != nil {
			hlog.Printf("warn", "error to get report of prjquota on mountpoint of %s", d.Mountpoint)
			continue
		}

		mountPoints = append(mountPoints, d.Mountpoint)
	}

	if len(mountPoints) == 0 {
		return errors.New("no quota path found")
	}

	//
	cfgpath := config.Prefix + "/etc/hostlet_vol_quota.json"
	if err := json.DecodeFile(cfgpath, &quotaConfig); err != nil && !os.IsNotExist(err) {
		return err
	}
	quotaConfig.path = cfgpath
	quotaConfig.MountPoints = mountPoints

	quotaRefreshed = time.Now().Unix()

	return nil
}

func podVolQuotaRefresh() error {

	if err := quotaKeeperInit(); err != nil {
		hlog.Printf("warn", "hostlet/vol Failed to Enable Vol Quota : %s", err.Error())
		return nil
	}

	tn := time.Now().Unix()

	if quotaRefreshed < 1 || (tn-quotaRefreshed) < 10 {
		return nil
	}

	// args := []string{
	// 	"-xc",
	// 	"report",
	// 	quotaMountpoint,
	// }
	// out, err := exec.Command(quotaCmd, args...).CombinedOutput()
	// if err != nil {
	// 	return err
	// }

	// var (
	// 	lines       = strings.Split(regMultiSpace.ReplaceAllString(string(out), " "), "\n")
	// 	path_gots = types.ArrayUint32{}
	// 	device_ok   = false
	// )
	// for _, v := range lines {

	// 	vs := strings.Split(strings.TrimSpace(v), " ")
	// 	if len(vs) < 5 || len(vs[0]) < 2 {
	// 		continue
	// 	}

	// 	if vs[0][0] != '#' {
	// 		continue
	// 	}

	// 	if vs[0] == "#0" {
	// 		device_ok = true
	// 	}

	// 	id, err := strconv.ParseInt(vs[0][1:], 10, 32)
	// 	if err != nil || id < 100 {
	// 		continue
	// 	}

	// 	path_gots.Set(uint32(id))

	// 	proj := quotaConfig.FetchById(int(id))
	// 	if proj == nil {
	// 		continue
	// 	}

	// 	if i64, err := strconv.ParseInt(vs[1], 10, 64); err == nil {
	// 		proj.Used = i64 * 1024
	// 	}

	// 	if i64, err := strconv.ParseInt(vs[2], 10, 64); err == nil {
	// 		proj.Soft = i64 * 1024
	// 	}

	// 	if i64, err := strconv.ParseInt(vs[3], 10, 64); err == nil {
	// 		proj.Hard = i64 * 1024
	// 	}
	// }

	var (
		path_gots  = map[string]int{}
		quota_gots = types.ArrayUint32{}
		device_ok  = 0
	)

	for _, quotaMountpoint := range quotaConfig.MountPoints {

		args := []string{
			"-xc",
			"path",
			quotaMountpoint,
		}

		out, err := exec.Command(quotaCmd, args...).CombinedOutput()
		if err != nil {
			return err
		}

		lines := strings.Split(regMultiSpace.ReplaceAllString(string(out), " "), "\n")

		for _, v := range lines {

			vs := strings.Split(strings.TrimSpace(v), " ")
			if len(vs) < 4 || len(vs[0]) < 2 {
				continue
			}

			if vs[0] == "[000]" {
				device_ok += 1
				continue
			}

			if len(vs) != 5 || vs[3] != "(project" || len(vs[4]) < 2 {
				continue
			}

			id, err := strconv.ParseInt(vs[4][:len(vs[4])-1], 10, 32)
			if err != nil || id < 100 {
				continue
			}

			if name, ok := podBoxFoldMatch(vs[1]); ok {
				path_gots[name] = int(id)
			}
		}

		args = []string{
			"-xc",
			"df",
			quotaMountpoint,
		}
		out, _ = exec.Command(quotaCmd, args...).CombinedOutput()

		lines = strings.Split(regMultiSpace.ReplaceAllString(string(out), " "), "\n")
		for _, v := range lines {

			v = strings.TrimSpace(v)
			vs := strings.Split(v, " ")
			if len(vs) != 6 {
				if len(vs) > 2 && strings.Contains(v, "project quota flag not set") {
					if name, ok := podBoxFoldMatch(vs[len(vs)-1]); ok {
						if id, ok := path_gots[name]; ok && id >= 100 {
							if proj := quotaConfig.FetchById(int(id)); proj != nil {
								proj.Used = 0
								proj.Soft = 0
								proj.Hard = 0
								proj.Mnt = quotaMountpoint
								quota_gots.Set(uint32(id))
							}
						}
					}
				}
				continue
			}

			name, ok := podBoxFoldMatch(vs[5])
			if !ok {
				continue
			}

			id, ok := path_gots[name]
			if !ok || id < 100 {
				continue
			}

			proj := quotaConfig.FetchById(int(id))
			if proj == nil {
				continue
			}

			if i64, err := strconv.ParseInt(vs[2], 10, 64); err == nil {
				proj.Used = i64 * 1024
			}

			if i64, err := strconv.ParseInt(vs[1], 10, 64); err == nil {
				proj.Soft = i64 * 1024
			}

			proj.Hard = proj.Soft
			proj.Mnt = quotaMountpoint

			quota_gots.Set(uint32(id))
		}
	}

	// for p, id := range path_gots {
	// 	if !quota_gots.Has(uint32(id)) {
	// 		args := []string{
	// 			"-xc",
	// 			fmt.Sprintf("project -s %d", id),
	// 			quotaMountpoint,
	// 		}
	// 		exec.Command(quotaCmd, args...).CombinedOutput()
	// 		hlog.Printf("info", "project init %d:%s", id, p)
	// 	}
	// }

	// hlog.Printf("info", "get info %d  %d", len(quotaConfig.Items), len(path_gots))

	if device_ok > 0 {
		dels := []string{}
		for _, v := range quotaConfig.Items {
			if !quota_gots.Has(uint32(v.Id)) {
				dels = append(dels, v.Name)
			}
		}
		if len(dels) > 0 {

			for _, v := range dels {
				quotaConfig.Remove(v)
			}

			if err := quotaConfig.SyncVendor(); err != nil {
				return err
			}
		}
	}

	if err := quotaConfig.Sync(); err != nil {
		return err
	}

	// hlog.Printf("info", "get info %d, pods %d", len(quotaConfig.Items), len(nstatus.PodRepActives))

	nstatus.PodRepActives.Each(func(podRep *inapi.PodRep) {

		if podRep.Spec == nil || podRep.Replica.VolSysMnt == "" {
			return
		}

		if !inapi.OpActionAllow(podRep.Operate.Action, inapi.OpActionStart) {
			return
		}

		//
		path := napi.PodVolSysDir(podRep.Replica.VolSysMnt, podRep.Meta.ID, podRep.Replica.RepId)
		fp, err := os.Open(path)
		if err != nil {
			hlog.Printf("warn", "hostlet/vol check sysdir %s", err.Error())
			return
		}
		fp.Close()

		//
		name := inapi.NsZonePodOpRepKey(podRep.Meta.ID, podRep.Replica.RepId)
		proj := quotaConfig.FetchOrCreate(podRep.Replica.VolSysMnt, name)
		if proj == nil {
			hlog.Printf("error", "hostlet/vol failed to create quota/project : %s", name)
			return
		}

		volSys := int64(podRep.Replica.VolSys) * inapi.ByteGB
		if quota_gots.Has(uint32(proj.Id)) && proj.Soft == volSys {
			return
		}
		hlog.Printf("error", "hostlet/vol %v, %d, %d, %v", quota_gots.Has(uint32(proj.Id)), proj.Soft, volSys, quota_gots)

		err = quotaConfig.SyncVendor()
		if err != nil {
			hlog.Printf("info", "hostlet/vol config init %s", err.Error())
			return
		}

		args := []string{
			quotaCmd,
			"-x",
			"-c",
			fmt.Sprintf("\"project -s -p %s %d\"", path, proj.Id),
			proj.Mnt,
		}
		if out, err := exec.Command("bash", "-c", strings.Join(args, " ")+"\nexit 0\n").CombinedOutput(); err != nil {
			hlog.SlotPrint(60, "info", "hostlet/vol quota init err: %s, output %s", err.Error(), string(out))
			return
		} else {
			hlog.Printf("info", "hostlet/vol quota init : %s, output %s", strings.Join(args, " "), string(out))
		}

		//
		args = []string{
			quotaCmd,
			"-x",
			"-c",
			fmt.Sprintf("\"limit -p bsoft=%d bhard=%d %d\"", volSys, volSys, proj.Id),
			proj.Mnt,
		}
		if out, err := exec.Command("bash", "-c", strings.Join(args, " ")+"\nexit 0\n").CombinedOutput(); err != nil {
			hlog.SlotPrint(60, "info", "hostlet/vol quota limit %s, {{{%s}}}", err.Error(), string(out))
			return
		}
		hlog.Printf("info", "hostlet/vol quota limit : %s", strings.Join(args, " "))
	})

	if err := quotaConfig.Sync(); err != nil {
		return err
	}

	for _, v := range quotaConfig.Items {

		if v.Soft < 1 {
			continue
		}

		podRep := nstatus.PodRepActives.Get(v.Name)
		if podRep != nil && inapi.OpActionAllow(podRep.Operate.Action, inapi.OpActionStart) {
			continue
		}

		//
		args := []string{
			"-x",
			"-c",
			fmt.Sprintf("\"limit -p bsoft=0 bhard=0 %d\"", v.Id),
			v.Mnt,
		}

		_, err = exec.Command(quotaCmd, args...).CombinedOutput()
		if err != nil {
			hlog.Printf("warn", "hostlet/vol quota clean project %s, err %s", v.Name, err.Error())
			return err
		}

		//
		args = []string{
			"-xc",
			fmt.Sprintf("\"project -C %d\"", v.Id),
			v.Mnt,
		}
		_, err = exec.Command(quotaCmd, args...).CombinedOutput()
		if err != nil {
			hlog.Printf("warn", "hostlet/vol quota clean project %s, err %s", v.Name, err.Error())
			return err
		}

		hlog.Printf("info", "hostlet/vol quota clean project %s, done", v.Name)
	}

	quotaRefreshed = tn

	return nil
}
