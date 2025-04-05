package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"

	firecracker "github.com/firecracker-microvm/firecracker-go-sdk"
	"github.com/firecracker-microvm/firecracker-go-sdk/client/models"
)

type FirecrackerVM struct {
	ID      string
	ctx     context.Context
	cancel  context.CancelFunc
	machine *firecracker.Machine
	image   string
}

var vms = make(map[string]*FirecrackerVM)

// last byte of next ip, e.g. 10.0.0.*x*
var nextIPByte byte = 3

type currentOptions struct {
	cpu int64
	mem int64
}

var curr currentOptions = currentOptions{
	cpu: 1,
	mem: 512,
}

type CreateRequest struct {
	RootDrivePath string `json:"root_image_path"`
	KernelPath    string `json:"kernel_path"`
	CloudInitPath string `json:"cloud_init_path"`
}

type CreateResponse struct {
	IpAddress string `json:"ip_address"`
	ID        string `json:"id"`
}

func main() {
	http.HandleFunc("/create", createRequestHandler)
	http.HandleFunc("/delete", deleteRequestHandler)
	//defer cleanup()

	var port = os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("listening on port " + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// cleans up the virtual machines instantiated by this service
func cleanup() {
	for _, vm := range vms {
		vm.cancel()
	}
}

func createRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	nextIPByte++
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("failed to read body: %s", err)
	}
	var createReq CreateRequest
	json.Unmarshal(body, &createReq)
	opts := getOptions(nextIPByte, createReq)
	runningVM, err := opts.createVMM(context.Background())
	if err != nil {
		// send error to user and log
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		log.Printf("Failed to create VM: %s", err)
		return
	}

	id := pseudo_uuid()
	resp := CreateResponse{
		IpAddress: opts.FcIP,
		ID:        id,
	}
	response, err := json.Marshal(&resp)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		log.Printf("Failed to marshal response: %s", err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(response)

	vms[id] = runningVM

	go func() {
		defer runningVM.cancel()
		runningVM.machine.Wait(runningVM.ctx)
	}()
}

// Handle delete request for a microvm
func deleteRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(id)
}

// pseudo_uuid generates a uuid, based on random bytes
//
// No parameters.
// Returns a string.
func pseudo_uuid() string {

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("failed to generate uuid, %s", err)
	}

	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type options struct {
	Id string `long:"id" description:"Jailer VMM id"`
	// maybe make this an int instead
	IpId            byte   `byte:"id" description:"an ip we use to generate an ip address"`
	FcBinary        string `long:"firecracker-binary" description:"Path to firecracker binary"`
	FcKernelCmdLine string `long:"kernel-opts" description:"Kernel commandline"`
	Request         CreateRequest
	FcSocketPath    string `long:"socket-path" short:"s" description:"path to use for firecracker socket"`
	TapMacAddr      string `long:"tap-mac-addr" description:"tap macaddress"`
	TapDev          string `long:"tap-dev" description:"tap device"`
	FcCPUCount      int64  `long:"ncpus" short:"c" description:"Number of CPUs"`
	FcMemSz         int64  `long:"memory" short:"m" description:"VM memory, in MiB"`
	FcIP            string `long:"fc-ip" description:"IP address of the VM"`
	TapIp           string `long:"tap-ip" description:"IP address of the tap device"`
	MaskShort       string `long:"mask-short" description:"Short form of the subnet mask of the VM"`
}

// getOptions returns options based on the given id and CreateRequest.
//
// id byte, req CreateRequest
// options
func getOptions(id byte, req CreateRequest) options {
	execPath, err := exec.LookPath("git")
	if err != nil {
		fmt.Println("Executable not found in the PATH, defaulting to current directory (./firecracker)")
		execPath = "./firecracker"
	}
	fc_ip := net.IPv4(172, 102, 0, id).String()
	gateway_ip := "172.102.0.1"
	docker_mask_long := "255.255.255.0"
	bootArgs := "ro console=ttyS0 noapic reboot=k panic=1 pci=off nomodules random.trust_cpu=on "
	bootArgs = bootArgs + fmt.Sprintf("ip=%s::%s:%s::eth0:off", fc_ip, gateway_ip, docker_mask_long)
	// get tap mac addr
	// The MAC is obtained by converting the four groups of the IP into hexadecimal, and using those as the last four hexa groups of the MAC.
	fc_mac := fmt.Sprintf("02:FC:%02x:%02x:%02x:%02x", 172, 102, 0, id)
	return options{
		FcBinary:        execPath,
		Request:         req,
		FcKernelCmdLine: bootArgs,
		FcSocketPath:    fmt.Sprintf("/tmp/firecracker-%d.sock", id),
		TapMacAddr:      fmt.Sprintf("02:FC:00:00:00:%02x", id),
		TapDev:          fmt.Sprintf("fc-tap-%d", id),
		FcIP:            fc_ip,
		FcCPUCount:      curr.cpu,
		FcMemSz:         curr.mem,
		TapIp:           gateway_ip,
		MaskShort:       "/30",
	}
}

// createVMM creates a Firecracker VM based on the provided options.
func (opts *options) createVMM(ctx context.Context) (*FirecrackerVM, error) {
	// Create a new context and cancellation function for the VM.
	vmmCtx, vmmCancel := context.WithCancel(ctx)

	// If a root drive path is specified, copy the image and update the root drive path.
	if opts.Request.RootDrivePath != "" {
		imagePath, err := copyImage(opts.Request.RootDrivePath)
		if err != nil {
			return nil, err
		}
		opts.Request.RootDrivePath = imagePath
	}

	// Get the Firecracker configuration.
	fcCfg, err := opts.getConfig()
	if err != nil {
		return nil, err
	}

	// Build the Firecracker VM command.
	cmd := firecracker.VMCommandBuilder{}.
		WithBin(opts.FcBinary).
		WithSocketPath(fcCfg.SocketPath).
		WithStdin(os.Stdin).
		WithStdout(os.Stdout).
		WithStderr(os.Stderr).
		Build(ctx)

	// Set up options for the Firecracker machine.
	machineOpts := []firecracker.Opt{
		firecracker.WithProcessRunner(cmd),
	}

	// Delete the existing tap device and create a new one.
	exec.Command("ip", "link", "del", opts.TapDev).Run()
	if err := exec.Command("ip", "tuntap", "add", "dev", opts.TapDev, "mode", "tap").Run(); err != nil {
		return nil, fmt.Errorf("failed creating ip link: %s", err)
	}
	// Set up sysctl configurations for the tap device.
	if err := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.proxy_arp=1", opts.TapDev)).Run(); err != nil {
		return nil, fmt.Errorf("failed doing first sysctl: %s", err)
	}
	if err := exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=1", opts.TapDev)).Run(); err != nil {
		return nil, fmt.Errorf("failed doing second sysctl: %s", err)
	}

	// Add an IP address to the tap device and bring it up.
	if err := exec.Command("ip", "addr", "add", fmt.Sprintf("%s%s", opts.TapIp, opts.MaskShort), "dev", opts.TapDev).Run(); err != nil {
		return nil, fmt.Errorf("failed creating ip link: %s", err)
	}
	if err := exec.Command("ip", "link", "set", opts.TapDev, "up").Run(); err != nil {
		return nil, fmt.Errorf("failed creating ip link: %s", err)
	}

	// Enable IP forwarding and set up iptables rules for NAT and forwarding.
	if err := exec.Command("sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward").Run(); err != nil {
		return nil, fmt.Errorf("failed setting up ip forwarding: %s", err)
	}
	if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE").Run(); err != nil {
		return nil, fmt.Errorf("failed setting up postrouting: %s", err)
	}
	if err := exec.Command("iptables", "-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run(); err != nil {
		return nil, fmt.Errorf("failed setting up iptables forwarding: %s", err)
	}
	if err := exec.Command("iptables", "-A", "FORWARD", "-i", opts.TapDev, "-o", "eth0", "-j", "ACCEPT").Run(); err != nil {
		return nil, fmt.Errorf("failed final iptables: %s", err)
	}

	// Create a new Firecracker machine and start it.
	m, err := firecracker.NewMachine(vmmCtx, *fcCfg, machineOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating machine: %s", err)
	}
	if err := m.Start(vmmCtx); err != nil {
		return nil, fmt.Errorf("failed to start machine: %v", err)
	}

	// Return the created Firecracker VM.
	return &FirecrackerVM{
		ctx:     vmmCtx,
		image:   opts.Request.RootDrivePath,
		cancel:  vmmCancel,
		machine: m,
	}, nil
}

// getConfig retrieves the configuration for firecracker.
//
// No parameters.
// Returns a *firecracker.Config and an error.
func (opts *options) getConfig() (*firecracker.Config, error) {
	drives := []models.Drive{
		models.Drive{
			DriveID:      firecracker.String("1"),
			PathOnHost:   &opts.Request.RootDrivePath,
			IsRootDevice: firecracker.Bool(true),
			IsReadOnly:   firecracker.Bool(false),
		},
	}
	if opts.Request.CloudInitPath != "" {
		isoPath, err := makeIso(opts.Request.CloudInitPath)
		if err != nil {
			return nil, fmt.Errorf("Failed to create iso: %s", err)
		}
		drives = append(drives, models.Drive{
			DriveID:      firecracker.String("2"),
			PathOnHost:   &isoPath,
			IsRootDevice: firecracker.Bool(false),
			IsReadOnly:   firecracker.Bool(true),
		})
	}

	return &firecracker.Config{
		VMID:            opts.Id,
		SocketPath:      opts.FcSocketPath,
		KernelImagePath: opts.Request.KernelPath,
		KernelArgs:      opts.FcKernelCmdLine,
		Drives:          drives,
		NetworkInterfaces: []firecracker.NetworkInterface{
			firecracker.NetworkInterface{
				CNIConfiguration: &firecracker.CNIConfiguration{
					NetworkName: "fcnet",
					IfName:      "cni-veth0",
				},
			},
		},
		MachineCfg: models.MachineConfiguration{
			VcpuCount:  firecracker.Int64(opts.FcCPUCount),
			MemSizeMib: firecracker.Int64(opts.FcMemSz),
			//CPUTemplate: models.CPUTemplate(opts.FcCPUTemplate),
		},
		//JailerCfg: jail,
		//VsockDevices:      vsocks,
		//LogFifo:           opts.FcLogFifo,
		//LogLevel:          opts.FcLogLevel,
		//MetricsFifo:       opts.FcMetricsFifo,
		//FifoLogWriter:     fifo,
	}, nil
}

// copyImage copies the image from source to a new destination.
//
// It takes a src string as a parameter and returns a string and an error.
func copyImage(src string) (string, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return "", err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer source.Close()

	destination, err := os.CreateTemp("images", "image")
	if err != nil {
		return "", err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return destination.Name(), err
}

// makeIso creates an ISO image using cloudInitPath.
//
// cloudInitPath string, returns string and error.
func makeIso(cloudInitPath string) (string, error) {
	image := "/tmp/cloud-init.iso"
	metaDataPath := "/tmp/my-meta-data.yml"
	err := os.WriteFile(metaDataPath, []byte("instance-id: i-litchi12345"), 0644)
	if err != nil {
		return "", fmt.Errorf("Failed to create metadata file: %s", err)
	}
	if err := exec.Command("cloud-localds", image, cloudInitPath, metaDataPath).Run(); err != nil {
		return "", fmt.Errorf("cloud-localds failed: %s", err)
	}
	return image, nil
}
