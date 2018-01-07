package main

import "os/exec"
import "fmt"

func main() {

	name := "rsa"
	path := "local.key"

	out, err := exec.Command("sh", "-c", "ssh-keygen -t "+name+" -f "+path+" -N ''").Output()
	fmt.Println(err, string(out))
}
