/*
   Simple Netstat implementation.
   Get data from /proc/net/tcp and /proc/net/udp and
   and parse /proc/[0-9]/fd/[0-9].

   Author: Rafael Santos <rafael@sourcecode.net.br>
*/

package GOnetstat

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

const (
	PROC_TCP  = "/proc/net/tcp"
	PROC_UDP  = "/proc/net/udp"
	PROC_TCP6 = "/proc/net/tcp6"
	PROC_UDP6 = "/proc/net/udp6"
)

var STATE = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

type iNodes map[string]string

func buildNodes() iNodes {
	d, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	inodes := make(map[string]string)
	re := regexp.MustCompile("[0-9]+")

	for _, item := range d {
		if path, err := os.Readlink(item); err == nil {
			if inode := re.FindString(path); len(inode) > 0 {
				inodes[inode] = item
			}

		}
	}

	return inodes
}

func (inodes iNodes) getPid(inode string) string {
	if link, found := inodes[inode]; found {
		return strings.Split(link, "/")[2]
	}

	return ""
}

type Process struct {
	User        string
	Name        string
	Pid         string
	Exe         string
	State       string
	Ip          string
	Port        int64
	ForeignIp   string
	ForeignPort int64
}

func getData(t string) ([]string, error) {
	// Get data from tcp or udp file.
	var proc_t string

	if t == "tcp" {
		proc_t = PROC_TCP
	} else if t == "udp" {
		proc_t = PROC_UDP
	} else if t == "tcp6" {
		proc_t = PROC_TCP6
	} else if t == "udp6" {
		proc_t = PROC_UDP6
	} else {
		fmt.Printf("%s is a invalid type, tcp and udp only!\n", t)
		return nil, errors.Errorf("Unknown type: %v", t)
	}

	data, err := ioutil.ReadFile(proc_t)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 1 {
		// Return lines without Header line and blank line on the end
		return lines[1 : len(lines)-1], nil
	}
	return nil, errors.Errorf("Unsupport result line: %v", string(data))
}

func hexToDec(h string) (int64, error) {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	return d, err
}

func convertIp(ip string) string {
	// Convert the ipv4 to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string

	// Check ip size if greater than 8 is a ipv6 type
	if len(ip) > 8 {
		i := []string{ip[30:32],
			ip[28:30],
			ip[26:28],
			ip[24:26],
			ip[22:24],
			ip[20:22],
			ip[18:20],
			ip[16:18],
			ip[14:16],
			ip[12:14],
			ip[10:12],
			ip[8:10],
			ip[6:8],
			ip[4:6],
			ip[2:4],
			ip[0:2]}
		out = fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
			i[14], i[15], i[13], i[12],
			i[10], i[11], i[8], i[9],
			i[6], i[7], i[4], i[5],
			i[2], i[3], i[0], i[1])

	} else {
		a, _ := hexToDec(ip[6:8])
		b, _ := hexToDec(ip[4:6])
		c, _ := hexToDec(ip[2:4])
		d, _ := hexToDec(ip[0:2])
		i := []int64{a, b, c, d}

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
	}
	return out
}

func findPid(inode string) (string, error) {
	// Loop through all fd dirs of process on /proc to compare the inode and
	// get the pid.

	pid := "-"

	d, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	re := regexp.MustCompile(inode)
	for _, item := range d {
		path, _ := os.Readlink(item)
		out := re.FindString(path)
		if len(out) != 0 {
			pids := strings.Split(item, "/")
			if len(pids) > 2 {
				pid = pids[2]
				return pid, nil
			}
		}
	}
	return pid, errors.New("Not Found")
}

func getProcessExe(pid string) string {
	exe := fmt.Sprintf("/proc/%s/exe", pid)
	path, _ := os.Readlink(exe)
	return path
}

func getProcessName(exe string) string {
	n := strings.Split(exe, "/")
	var name string
	if len(n) > 1 {
		name = n[len(n)-1]
	} else {
		name = n[0]
	}
	return strings.Title(name)
}

func getUser(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return "Unknown"
	}
	return u.Username
}

func removeEmpty(array []string) []string {
	// remove empty data from line
	var new_array []string
	for _, i := range array {
		if i != "" {
			new_array = append(new_array, i)
		}
	}
	return new_array
}

func netstat(t string) ([]Process, error) {
	// Return a array of Process with Name, Ip, Port, State .. etc
	// Require Root acess to get information about some processes.

	var Processes []Process

	data, err := getData(t)
	if err != nil {
		return nil, err
	}
	inodes := buildNodes()

	for _, line := range data {

		// local ip and port
		line_array := removeEmpty(strings.Split(strings.TrimSpace(line), " "))
		ip_port := strings.Split(line_array[1], ":")
		var ip, fip, state, uid, pid, exe, name string
		var port, fport int64
		if len(ip_port) > 0 {
			ip = convertIp(ip_port[0])
		}
		if len(ip_port) > 1 {
			port, _ = hexToDec(ip_port[1])
		}

		// foreign ip and port
		if len(line_array) > 2 {
			fip_port := strings.Split(line_array[2], ":")

			if len(fip_port) > 0 {
				fip = convertIp(fip_port[0])
			}
			if len(fip_port) > 1 {
				fport, _ = hexToDec(fip_port[1])
			}
		}

		if len(line_array) > 3 {
			state = STATE[line_array[3]]
		}
		if len(line_array) > 7 {
			uid = getUser(line_array[7])
		}
		if len(line_array) > 9 {
			// pid, _ = findPid(line_array[9])
			pid = inodes.getPid(line_array[9])
		}
		exe = getProcessExe(pid)
		name = getProcessName(exe)

		p := Process{uid, name, pid, exe, state, ip, port, fip, fport}
		Processes = append(Processes, p)
	}

	return Processes, nil
}

func Tcp() ([]Process, error) {
	// Get a slice of Process type with TCP data
	return netstat("tcp")
}

func Udp() ([]Process, error) {
	// Get a slice of Process type with UDP data
	return netstat("udp")
}

func Tcp6() ([]Process, error) {
	// Get a slice of Process type with TCP6 data
	return netstat("tcp6")
}

func Udp6() ([]Process, error) {
	// Get a slice of Process type with UDP6 data
	return netstat("udp6")
}
