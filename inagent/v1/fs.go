// Copyright 2015 Eryx <evorui аt gmаil dοt cοm>, All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hooto/httpsrv"
	"github.com/lessos/lessgo/types"
	"github.com/lessos/lessgo/utils"

	"github.com/sysinner/incore/config"
	"github.com/sysinner/incore/inapi"
)

type Fs struct {
	*httpsrv.Controller
}

func (c Fs) RenameAction() {

	var (
		rsp inapi.FsFile
		req inapi.FsFile
	)

	defer c.RenderJson(&rsp)

	if err := c.Request.JsonDecode(&req); err != nil {
		rsp.Error = &types.ErrorMeta{"400", "Bad Request"}
		return
	}

	path := filepath.Clean(req.Path)
	if !strings.HasPrefix(path, "/home/action") {
		rsp.Error = &types.ErrorMeta{"403", "Forbidden"}
		return
	}

	pathset := filepath.Clean(req.PathSet)
	if !strings.HasPrefix(pathset, "/home/action") {
		rsp.Error = &types.ErrorMeta{"403", "Forbidden"}
		return
	}

	pathfp := filepath.Clean(path)
	pathsetfp := filepath.Clean(pathset)

	dir := filepath.Dir(pathsetfp)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fsMakeDir(dir, config.User.Uid, config.User.Gid, 0750)
	}

	if err := os.Rename(pathfp, pathsetfp); err != nil {
		rsp.Error = &types.ErrorMeta{"500", err.Error()}
		return
	}

	rsp.Kind = "FsFile"
}

func (c Fs) DelAction() {

	var (
		rsp inapi.FsFile
		req inapi.FsFile
	)

	defer c.RenderJson(&rsp)

	if err := c.Request.JsonDecode(&req); err != nil {
		rsp.Error = &types.ErrorMeta{"400", "Bad Request"}
		return
	}

	//

	path := filepath.Clean(req.Path)
	if !strings.HasPrefix(path, "/home/action") {
		rsp.Error = &types.ErrorMeta{"403", "Forbidden"}
		return
	}

	pathfp := filepath.Clean(path)

	if err := os.Remove(pathfp); err != nil {
		rsp.Error = &types.ErrorMeta{"500", err.Error()}
		return
	}

	rsp.Kind = "FsFile"
}

func (c Fs) PutAction() {

	var (
		rsp inapi.FsFile
		req inapi.FsFile
		err error
	)

	defer c.RenderJson(&rsp)

	if err := c.Request.JsonDecode(&req); err != nil {
		rsp.Error = &types.ErrorMeta{"400", "Bad Request"}
		return
	}

	path := filepath.Clean(req.Path)
	if !strings.HasPrefix(path, "/home/action") {
		rsp.Error = &types.ErrorMeta{"403", "Forbidden"}
		return
	}

	if req.IsDir {
		fsMakeDir(path, config.User.Uid, config.User.Gid, 0750)
		rsp.Kind = "FsFile"
		return
	}

	var body []byte
	projfp := filepath.Clean(path)

	switch req.Encode {

	case "base64":
		dataurl := strings.SplitAfter(req.Body, ";base64,")
		if len(dataurl) != 2 {
			rsp.Error = &types.ErrorMeta{"400", "Bad Request"}
			return
		}

		body, err = base64.StdEncoding.DecodeString(dataurl[1])
		if err != nil {
			rsp.Error = &types.ErrorMeta{"400", err.Error()}
			return
		}

	case "text":
		body = []byte(req.Body)

	case "json":

		body, err = utils.JsonIndent(req.Body, "  ")
		if err != nil {
			rsp.Error = &types.ErrorMeta{"400", err.Error()}
			return
		}

	case "jm":

		var jsPrev, jsAppend map[string]interface{}

		err := utils.JsonDecode(req.Body, &jsAppend)
		if err != nil {
			rsp.Error = &types.ErrorMeta{"400", err.Error()}
			return
		}

		file := fsFileGetRead(projfp)
		if file.Error != nil {
			rsp.Error = file.Error
			return
		}

		err = utils.JsonDecode(file.Body, &jsPrev)
		if err != nil {
			rsp.Error = &types.ErrorMeta{"400", err.Error()}
			return
		}

		jsMerged := utils.JsonMerge(jsPrev, jsAppend)
		// fmt.Println(jsPrev, "\n\n", jsAppend, "\n\n", jsMerged)

		strMerged, _ := utils.JsonEncodeIndent(jsMerged, "  ")
		body = []byte(strMerged)

	default:
		rsp.Error = &types.ErrorMeta{"400", "Bad Request"}
		return
	}

	if err := fsFilePutWrite(projfp, body); err != nil {
		rsp.Error = &types.ErrorMeta{"500", err.Error()}
		return
	}

	rsp.Kind = "FsFile"
}

func fsFilePutWrite(path string, body []byte) error {

	defer func() {
		if r := recover(); r != nil {
			//
		}
	}()

	dir := filepath.Dir(path)

	if st, err := os.Stat(dir); os.IsNotExist(err) {

		fsMakeDir(dir, config.User.Uid, config.User.Gid, 0750)

	} else if !st.IsDir() {
		return errors.New("Can not create directory, File exists")
	}

	fp, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer fp.Close()

	fp.Seek(0, 0)
	fp.Truncate(int64(len(body))) // TODO
	if _, err = fp.Write(body); err != nil {
		return err
	}

	iUid, _ := strconv.Atoi(config.User.Uid)
	iGid, _ := strconv.Atoi(config.User.Gid)

	os.Chmod(path, 0644)
	os.Chown(path, iUid, iGid)

	return nil
}

func fsMakeDir(path, uuid, ugid string, mode os.FileMode) error {

	if _, err := os.Stat(path); err == nil {
		return nil
	}

	iUid, _ := strconv.Atoi(uuid)
	iGid, _ := strconv.Atoi(ugid)

	paths := strings.Split(strings.Trim(path, "/"), "/")

	path = ""

	for _, v := range paths {

		path += "/" + v

		if _, err := os.Stat(path); err == nil {
			continue
		}

		if err := os.Mkdir(path, mode); err != nil {
			return err
		}

		os.Chmod(path, mode)
		os.Chown(path, iUid, iGid)
	}

	return nil
}

func (c *Fs) ListAction() {

	var rsp inapi.FsFileList

	defer c.RenderJson(&rsp)

	//
	// path := filepath.Clean(req.Path)
	path := filepath.Clean(c.Params.Get("path"))
	if !strings.HasPrefix(path, "/home/action") {
		rsp.Error = &types.ErrorMeta{"403", "Forbidden"}
		return
	}

	projfp := filepath.Clean(path)

	rsp.Path = path
	rsp.Items = fsDirList(projfp, "", false)

	rsp.Kind = "FsFileList"
}

func fsDirList(path, ppath string, subdir bool) []inapi.FsFile {

	var ret []inapi.FsFile

	globpath := path
	if !strings.Contains(globpath, "*") {
		globpath += "/*"
	}

	rs, err := filepath.Glob(globpath)

	if err != nil {
		return ret
	}

	if len(ppath) > 0 {
		ppath += "/"
	}

	for _, v := range rs {

		var file inapi.FsFile
		// file.Path = v

		st, err := os.Stat(v)
		if os.IsNotExist(err) {
			continue
		}

		file.Name = ppath + st.Name()
		file.Size = st.Size()
		file.IsDir = st.IsDir()
		file.ModTime = st.ModTime().Format("2006-01-02T15:04:05Z07:00")

		if !st.IsDir() {
			file.Mime = fsFileMime(v)
		} else if subdir {
			subret := fsDirList(path+"/"+st.Name(), ppath+st.Name(), subdir)
			for _, v := range subret {
				ret = append(ret, v)
			}
		}

		ret = append(ret, file)
	}

	return ret
}

func fsFileMime(v string) string {

	// TODO
	//  ... add more extension types
	ctype := mime.TypeByExtension(filepath.Ext(v))

	if ctype == "" {
		fp, err := os.Open(v)
		if err == nil {

			defer fp.Close()

			if ctn, err := ioutil.ReadAll(fp); err == nil {
				ctype = http.DetectContentType(ctn)
			}
		}
	}

	ctypes := strings.Split(ctype, ";")
	if len(ctypes) > 0 {
		ctype = ctypes[0]
	}

	return ctype
}

func (c Fs) GetAction() {

	var rsp inapi.FsFile

	defer c.RenderJson(&rsp)

	path := filepath.Clean(c.Params.Get("path"))
	if !strings.HasPrefix(path, "/home/action") {
		rsp.Error = &types.ErrorMeta{"403", "Forbidden"}
		return
	}

	rsp = fsFileGetRead(path)
	if rsp.Error == nil {
		rsp.Kind = "FsFile"
	}
}

func fsFileGetRead(path string) inapi.FsFile {

	var file inapi.FsFile
	file.Path = path

	reg, _ := regexp.Compile("/+")
	path = "/" + strings.Trim(reg.ReplaceAllString(path, "/"), "/")

	st, err := os.Stat(path)
	if err != nil || os.IsNotExist(err) {
		file.Error = &types.ErrorMeta{"404", "File Not Found"}
		return file
	}
	file.Size = st.Size()

	if st.Size() > (2 * 1024 * 1024) {
		file.Error = &types.ErrorMeta{"413", "File size is too large"}
		return file
	}

	fp, err := os.Open(path)
	if err != nil {
		file.Error = &types.ErrorMeta{"500", "File Can Not Open"}
		return file
	}
	defer fp.Close()

	ctn, err := ioutil.ReadAll(fp)
	if err != nil {
		file.Error = &types.ErrorMeta{"500", "File Can Not Readable"}
		return file
	}
	file.Body = string(ctn)

	// TODO
	ctype := mime.TypeByExtension(filepath.Ext(path))
	if ctype == "" {
		ctype = http.DetectContentType(ctn)
	}
	ctypes := strings.Split(ctype, ";")
	if len(ctypes) > 0 {
		ctype = ctypes[0]
	}
	file.Mime = ctype

	return file
}
