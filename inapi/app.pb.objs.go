// Code generated by github.com/hooto/protobuf_slice
// source: app.proto
// DO NOT EDIT!

package inapi

import "sync"

var object_slice_mu_AppSpecDepend sync.RWMutex

func (it *AppSpecDepend) Equal(it2 *AppSpecDepend) bool {
	if it2 == nil ||
		it.Id != it2.Id ||
		it.Name != it2.Name ||
		it.Version != it2.Version ||
		it.Priority != it2.Priority ||
		!PbStringSliceEqual(it.Configs, it2.Configs) {
		return false
	}
	return true
}

func (it *AppSpecDepend) Sync(it2 *AppSpecDepend) bool {
	if it2 == nil {
		return false
	}
	if it.Equal(it2) {
		return false
	}
	*it = *it2
	return true
}

func AppSpecDependSliceGet(ls []*AppSpecDepend, arg_id string) *AppSpecDepend {
	object_slice_mu_AppSpecDepend.RLock()
	defer object_slice_mu_AppSpecDepend.RUnlock()

	for _, v := range ls {
		if v.Id == arg_id {
			return v
		}
	}
	return nil
}

func AppSpecDependSliceDel(ls []*AppSpecDepend, arg_id string) ([]*AppSpecDepend, bool) {
	object_slice_mu_AppSpecDepend.Lock()
	defer object_slice_mu_AppSpecDepend.Unlock()
	for i, v := range ls {
		if v.Id == arg_id {
			ls = append(ls[:i], ls[i+1:]...)
			return ls, true
		}
	}
	return ls, false
}

func AppSpecDependSliceEqual(ls, ls2 []*AppSpecDepend) bool {
	object_slice_mu_AppSpecDepend.RLock()
	defer object_slice_mu_AppSpecDepend.RUnlock()

	if len(ls) != len(ls2) {
		return false
	}
	hit := false
	for _, v := range ls {
		hit = false
		for _, v2 := range ls2 {
			if v.Id != v2.Id {
				continue
			}
			if !v.Equal(v2) {
				return false
			}
			hit = true
			break
		}
		if !hit {
			return false
		}
	}
	return true
}

func AppSpecDependSliceSync(ls []*AppSpecDepend, it2 *AppSpecDepend) ([]*AppSpecDepend, bool) {
	if it2 == nil {
		return ls, false
	}
	object_slice_mu_AppSpecDepend.Lock()
	defer object_slice_mu_AppSpecDepend.Unlock()

	hit := false
	changed := false
	for i, v := range ls {
		if v.Id != it2.Id {
			continue
		}
		if !v.Equal(it2) {
			ls[i], changed = it2, true
		}
		hit = true
		break
	}
	if !hit {
		ls = append(ls, it2)
		changed = true
	}
	return ls, changed
}

func AppSpecDependSliceSyncSlice(ls, ls2 []*AppSpecDepend) ([]*AppSpecDepend, bool) {
	if AppSpecDependSliceEqual(ls, ls2) {
		return ls, false
	}
	return ls2, true
}

var object_slice_mu_AppServiceReplica sync.RWMutex

func (it *AppServiceReplica) Equal(it2 *AppServiceReplica) bool {
	if it2 == nil ||
		it.Rep != it2.Rep ||
		it.Ip != it2.Ip ||
		it.Port != it2.Port {
		return false
	}
	return true
}

func (it *AppServiceReplica) Sync(it2 *AppServiceReplica) bool {
	if it2 == nil {
		return false
	}
	if it.Equal(it2) {
		return false
	}
	*it = *it2
	return true
}

func AppServiceReplicaSliceGet(ls []*AppServiceReplica, arg_rep uint32) *AppServiceReplica {
	object_slice_mu_AppServiceReplica.RLock()
	defer object_slice_mu_AppServiceReplica.RUnlock()

	for _, v := range ls {
		if v.Rep == arg_rep {
			return v
		}
	}
	return nil
}

func AppServiceReplicaSliceDel(ls []*AppServiceReplica, arg_rep uint32) ([]*AppServiceReplica, bool) {
	object_slice_mu_AppServiceReplica.Lock()
	defer object_slice_mu_AppServiceReplica.Unlock()
	for i, v := range ls {
		if v.Rep == arg_rep {
			ls = append(ls[:i], ls[i+1:]...)
			return ls, true
		}
	}
	return ls, false
}

func AppServiceReplicaSliceEqual(ls, ls2 []*AppServiceReplica) bool {
	object_slice_mu_AppServiceReplica.RLock()
	defer object_slice_mu_AppServiceReplica.RUnlock()

	if len(ls) != len(ls2) {
		return false
	}
	hit := false
	for _, v := range ls {
		hit = false
		for _, v2 := range ls2 {
			if v.Rep != v2.Rep {
				continue
			}
			if !v.Equal(v2) {
				return false
			}
			hit = true
			break
		}
		if !hit {
			return false
		}
	}
	return true
}

func AppServiceReplicaSliceSync(ls []*AppServiceReplica, it2 *AppServiceReplica) ([]*AppServiceReplica, bool) {
	if it2 == nil {
		return ls, false
	}
	object_slice_mu_AppServiceReplica.Lock()
	defer object_slice_mu_AppServiceReplica.Unlock()

	hit := false
	changed := false
	for i, v := range ls {
		if v.Rep != it2.Rep {
			continue
		}
		if !v.Equal(it2) {
			ls[i], changed = it2, true
		}
		hit = true
		break
	}
	if !hit {
		ls = append(ls, it2)
		changed = true
	}
	return ls, changed
}

func AppServiceReplicaSliceSyncSlice(ls, ls2 []*AppServiceReplica) ([]*AppServiceReplica, bool) {
	if AppServiceReplicaSliceEqual(ls, ls2) {
		return ls, false
	}
	return ls2, true
}

var object_slice_mu_AppServicePort sync.RWMutex

func (it *AppServicePort) Equal(it2 *AppServicePort) bool {
	if it2 == nil ||
		it.Port != it2.Port ||
		!AppServiceReplicaSliceEqual(it.Endpoints, it2.Endpoints) ||
		it.Name != it2.Name ||
		it.Spec != it2.Spec ||
		it.PodId != it2.PodId ||
		it.AppId != it2.AppId {
		return false
	}
	return true
}

func (it *AppServicePort) Sync(it2 *AppServicePort) bool {
	if it2 == nil {
		return false
	}
	if it.Equal(it2) {
		return false
	}
	*it = *it2
	return true
}

func AppServicePortSliceGet(ls []*AppServicePort, arg_port uint32, arg_podid string) *AppServicePort {
	object_slice_mu_AppServicePort.RLock()
	defer object_slice_mu_AppServicePort.RUnlock()

	for _, v := range ls {
		if v.Port == arg_port && v.PodId == arg_podid {
			return v
		}
	}
	return nil
}

func AppServicePortSliceDel(ls []*AppServicePort, arg_port uint32, arg_podid string) ([]*AppServicePort, bool) {
	object_slice_mu_AppServicePort.Lock()
	defer object_slice_mu_AppServicePort.Unlock()
	for i, v := range ls {
		if v.Port == arg_port && v.PodId == arg_podid {
			ls = append(ls[:i], ls[i+1:]...)
			return ls, true
		}
	}
	return ls, false
}

func AppServicePortSliceEqual(ls, ls2 []*AppServicePort) bool {
	object_slice_mu_AppServicePort.RLock()
	defer object_slice_mu_AppServicePort.RUnlock()

	if len(ls) != len(ls2) {
		return false
	}
	hit := false
	for _, v := range ls {
		hit = false
		for _, v2 := range ls2 {
			if v.Port != v2.Port || v.PodId != v2.PodId {
				continue
			}
			if !v.Equal(v2) {
				return false
			}
			hit = true
			break
		}
		if !hit {
			return false
		}
	}
	return true
}

func AppServicePortSliceSync(ls []*AppServicePort, it2 *AppServicePort) ([]*AppServicePort, bool) {
	if it2 == nil {
		return ls, false
	}
	object_slice_mu_AppServicePort.Lock()
	defer object_slice_mu_AppServicePort.Unlock()

	hit := false
	changed := false
	for i, v := range ls {
		if v.Port != it2.Port || v.PodId != it2.PodId {
			continue
		}
		if !v.Equal(it2) {
			ls[i], changed = it2, true
		}
		hit = true
		break
	}
	if !hit {
		ls = append(ls, it2)
		changed = true
	}
	return ls, changed
}

func AppServicePortSliceSyncSlice(ls, ls2 []*AppServicePort) ([]*AppServicePort, bool) {
	if AppServicePortSliceEqual(ls, ls2) {
		return ls, false
	}
	return ls2, true
}

var object_slice_mu_AppServicePortPodBind sync.RWMutex

func (it *AppServicePortPodBind) Equal(it2 *AppServicePortPodBind) bool {
	if it2 == nil ||
		it.Port != it2.Port ||
		it.PodId != it2.PodId ||
		!AppServiceReplicaSliceEqual(it.Endpoints, it2.Endpoints) {
		return false
	}
	return true
}

func (it *AppServicePortPodBind) Sync(it2 *AppServicePortPodBind) bool {
	if it2 == nil {
		return false
	}
	if it.Equal(it2) {
		return false
	}
	*it = *it2
	return true
}

func AppServicePortPodBindSliceGet(ls []*AppServicePortPodBind, arg_port uint32, arg_podid string) *AppServicePortPodBind {
	object_slice_mu_AppServicePortPodBind.RLock()
	defer object_slice_mu_AppServicePortPodBind.RUnlock()

	for _, v := range ls {
		if v.Port == arg_port && v.PodId == arg_podid {
			return v
		}
	}
	return nil
}

func AppServicePortPodBindSliceDel(ls []*AppServicePortPodBind, arg_port uint32, arg_podid string) ([]*AppServicePortPodBind, bool) {
	object_slice_mu_AppServicePortPodBind.Lock()
	defer object_slice_mu_AppServicePortPodBind.Unlock()
	for i, v := range ls {
		if v.Port == arg_port && v.PodId == arg_podid {
			ls = append(ls[:i], ls[i+1:]...)
			return ls, true
		}
	}
	return ls, false
}

func AppServicePortPodBindSliceEqual(ls, ls2 []*AppServicePortPodBind) bool {
	object_slice_mu_AppServicePortPodBind.RLock()
	defer object_slice_mu_AppServicePortPodBind.RUnlock()

	if len(ls) != len(ls2) {
		return false
	}
	hit := false
	for _, v := range ls {
		hit = false
		for _, v2 := range ls2 {
			if v.Port != v2.Port || v.PodId != v2.PodId {
				continue
			}
			if !v.Equal(v2) {
				return false
			}
			hit = true
			break
		}
		if !hit {
			return false
		}
	}
	return true
}

func AppServicePortPodBindSliceSync(ls []*AppServicePortPodBind, it2 *AppServicePortPodBind) ([]*AppServicePortPodBind, bool) {
	if it2 == nil {
		return ls, false
	}
	object_slice_mu_AppServicePortPodBind.Lock()
	defer object_slice_mu_AppServicePortPodBind.Unlock()

	hit := false
	changed := false
	for i, v := range ls {
		if v.Port != it2.Port || v.PodId != it2.PodId {
			continue
		}
		if !v.Equal(it2) {
			ls[i], changed = it2, true
		}
		hit = true
		break
	}
	if !hit {
		ls = append(ls, it2)
		changed = true
	}
	return ls, changed
}

func AppServicePortPodBindSliceSyncSlice(ls, ls2 []*AppServicePortPodBind) ([]*AppServicePortPodBind, bool) {
	if AppServicePortPodBindSliceEqual(ls, ls2) {
		return ls, false
	}
	return ls2, true
}

var object_slice_mu_AppServicePod sync.RWMutex

func (it *AppServicePod) Equal(it2 *AppServicePod) bool {
	if it2 == nil ||
		it.PodId != it2.PodId ||
		!AppServicePortSliceEqual(it.Ports, it2.Ports) {
		return false
	}
	return true
}

func (it *AppServicePod) Sync(it2 *AppServicePod) bool {
	if it2 == nil {
		return false
	}
	if it.Equal(it2) {
		return false
	}
	*it = *it2
	return true
}

func AppServicePodSliceGet(ls []*AppServicePod, arg_podid string) *AppServicePod {
	object_slice_mu_AppServicePod.RLock()
	defer object_slice_mu_AppServicePod.RUnlock()

	for _, v := range ls {
		if v.PodId == arg_podid {
			return v
		}
	}
	return nil
}

func AppServicePodSliceDel(ls []*AppServicePod, arg_podid string) ([]*AppServicePod, bool) {
	object_slice_mu_AppServicePod.Lock()
	defer object_slice_mu_AppServicePod.Unlock()
	for i, v := range ls {
		if v.PodId == arg_podid {
			ls = append(ls[:i], ls[i+1:]...)
			return ls, true
		}
	}
	return ls, false
}

func AppServicePodSliceEqual(ls, ls2 []*AppServicePod) bool {
	object_slice_mu_AppServicePod.RLock()
	defer object_slice_mu_AppServicePod.RUnlock()

	if len(ls) != len(ls2) {
		return false
	}
	hit := false
	for _, v := range ls {
		hit = false
		for _, v2 := range ls2 {
			if v.PodId != v2.PodId {
				continue
			}
			if !v.Equal(v2) {
				return false
			}
			hit = true
			break
		}
		if !hit {
			return false
		}
	}
	return true
}

func AppServicePodSliceSync(ls []*AppServicePod, it2 *AppServicePod) ([]*AppServicePod, bool) {
	if it2 == nil {
		return ls, false
	}
	object_slice_mu_AppServicePod.Lock()
	defer object_slice_mu_AppServicePod.Unlock()

	hit := false
	changed := false
	for i, v := range ls {
		if v.PodId != it2.PodId {
			continue
		}
		if !v.Equal(it2) {
			ls[i], changed = it2, true
		}
		hit = true
		break
	}
	if !hit {
		ls = append(ls, it2)
		changed = true
	}
	return ls, changed
}

func AppServicePodSliceSyncSlice(ls, ls2 []*AppServicePod) ([]*AppServicePod, bool) {
	if AppServicePodSliceEqual(ls, ls2) {
		return ls, false
	}
	return ls2, true
}
