package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"time"

	sdk "github.com/CenturyLinkCloud/clc-sdk"
	api "github.com/CenturyLinkCloud/clc-sdk/api"
	group "github.com/CenturyLinkCloud/clc-sdk/group"
	server "github.com/CenturyLinkCloud/clc-sdk/server"
	"github.com/CenturyLinkCloud/clc-sdk/status"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

func main() {
	plugin.RegisterDriver(&Driver{})
}

// Driver for CLC
type Driver struct {
	*drivers.BaseDriver
	Username              string // CLC account + credentials
	Password              string
	Alias                 string
	SSHUsername           string
	SSHPassword           string
	DockerPort            int
	DockerSwarmMasterPort int
	ServerID              string // https://www.ctl.io/api-docs/v2/#servers-create-server
	Location              string
	Template              string
	CPU                   int
	MemoryGB              int
	ServerType            string
	GroupName             string
	NameTemplate          string
	Description           string
	Public                bool   // allocate public IP for docker ports
	PublicIP              string // calculated public IP
	AnityAffinityPolicy   string
	ConfigurationId       string
}

const (
	defaultSSHPort         = 22
	defaultSSHUser         = "root"
	defaultDockerPort      = 2376
	defaultSwarmMasterPort = 3376
	defaultLocation        = "WA1"
	defaultTemplate        = "ubuntu-14-64-template"
	defaultCPU             = 2
	defaultMemoryGB        = 2
	defaultServerType      = "standard"
	defaultGroupName       = "Default Group"
	defaultNameTemplate    = "DOCK"
	defaultDescription     = "docker-machine"
	defaultSSHKeyPackage   = "77abb844-579d-478d-3955-c69ab4a7ba1a" // uuid of ssh pubkey pkg
)

// GetCreateFlags registers the flags this d adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "CLC_USERNAME",
			Name:   "clc-account-username",
			Usage:  "REQUIRED: CLC account username",
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_PASSWORD",
			Name:   "clc-account-password",
			Usage:  "REQUIRED: CLC account password",
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_ALIAS",
			Name:   "clc-account-alias",
			Usage:  "REQUIRED: CLC account alias",
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_SSH_USER",
			Name:   "clc-ssh-user",
			Usage:  "ssh username (default:root)",
			Value:  defaultSSHUser,
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_SSH_PASSWORD",
			Name:   "clc-ssh-password",
			Usage:  "ssh password (default:<generated>)",
		},
		mcnflag.IntFlag{
			EnvVar: "CLC_SSH_PORT",
			Name:   "clc-ssh-port",
			Usage:  "ssh port (default:22)",
			Value:  defaultSSHPort,
		},
		mcnflag.IntFlag{
			EnvVar: "CLC_DOCKER_PORT",
			Name:   "clc-docker-port",
			Usage:  "docker port (default:2376)",
			Value:  defaultDockerPort,
		},
		mcnflag.IntFlag{
			EnvVar: "CLC_DOCKER_SWARM_MASTER_PORT",
			Name:   "clc-docker-swarm-master-port",
			Usage:  "swarm master port (default:3376)",
			Value:  defaultSwarmMasterPort,
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_SERVER_LOCATION",
			Name:   "clc-server-location",
			Usage:  "datacenter location (default:WA1)",
			Value:  defaultLocation,
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_SERVER_TEMPLATE",
			Name:   "clc-server-template",
			Usage:  "server template (default:ubuntu-14-64-template)",
			Value:  defaultTemplate,
		},
		mcnflag.IntFlag{
			EnvVar: "CLC_SERVER_CPU",
			Name:   "clc-server-cpu",
			Usage:  "server cpu cores (default:2)",
			Value:  defaultCPU,
		},
		mcnflag.IntFlag{
			EnvVar: "CLC_SERVER_MEM",
			Name:   "clc-server-mem",
			Usage:  "server memory in GB (default:2)",
			Value:  defaultMemoryGB,
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_SERVER_TYPE",
			Name:   "clc-server-type",
			Usage:  "server type (default:standard)",
			Value:  defaultServerType,
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_SERVER_GROUP",
			Name:   "clc-server-group",
			Usage:  "server group name (default:Default Group)",
			Value:  defaultGroupName,
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_SERVER_NAME",
			Name:   "clc-server-name",
			Usage:  "server name template (default:DOCK)",
			Value:  defaultNameTemplate,
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_SERVER_DESC",
			Name:   "clc-server-desc",
			Usage:  "server description (default:docker-machine)",
			Value:  defaultDescription,
		},
		mcnflag.BoolFlag{
			EnvVar: "CLC_SERVER_PRIVATE",
			Name:   "clc-server-private",
			Usage:  "disable public IP (default:publicly accessible)",
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_AA_POLICY",
			Name:   "clc-aa-policy",
			Usage:  "anti affinity policy name",
		},
		mcnflag.StringFlag{
			EnvVar: "CLC_CONFIGURATION_ID",
			Name:   "clc-configuration-id",
			Usage:  "baremetal configuration id",
		},
	}
}

// NewDriver instantiates a new driver with hostName into storePath
func NewDriver(hostName, storePath string) drivers.Driver {
	d := &Driver{
		DockerPort:            defaultDockerPort,
		DockerSwarmMasterPort: defaultSwarmMasterPort,
		Location:              defaultLocation,
		Template:              defaultTemplate,
		CPU:                   defaultCPU,
		MemoryGB:              defaultMemoryGB,
		ServerType:            defaultServerType,
		GroupName:             defaultGroupName,
		NameTemplate:          defaultNameTemplate,
		Description:           defaultDescription,
		BaseDriver: &drivers.BaseDriver{
			SSHPort:     defaultSSHPort,
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
	return d
}

// SetConfigFromFlags implements interface method for parsing cmdline args
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.Username = flags.String("clc-account-username")
	d.Password = flags.String("clc-account-password")
	d.Alias = flags.String("clc-account-alias")
	if d.Username == "" || d.Password == "" {
		return fmt.Errorf("Missing CLC Account credentials (see help)")
	}

	d.SSHPort = flags.Int("clc-ssh-port")
	if d.SSHPort == 0 {
		d.SSHPort = defaultSSHPort
	}
	d.SSHUser = flags.String("clc-ssh-user")
	if d.SSHUser == "" {
		d.SSHUser = defaultSSHUser
	}
	d.SSHPassword = flags.String("clc-ssh-password")
	if d.SSHPassword == "" {
		d.SSHPassword = generatePassword(12)
		log.Infof("SSH Password not provided. Generated: %v", d.SSHPassword)
	}
	d.DockerPort = flags.Int("clc-docker-port")
	d.DockerSwarmMasterPort = flags.Int("clc-docker-swarm-master-port")

	//d.SwarmMaster = flags.Bool("swarm-master")
	//d.SwarmHost = flags.String("swarm-host")
	//d.SwarmDiscovery = flags.String("swarm-discovery")
	d.SetSwarmConfigFromFlags(flags)

	d.Location = flags.String("clc-server-location")
	d.Template = flags.String("clc-server-template")
	d.CPU = flags.Int("clc-server-cpu")
	d.MemoryGB = flags.Int("clc-server-mem")
	d.GroupName = flags.String("clc-server-group")
	d.NameTemplate = flags.String("clc-server-name")
	d.Description = flags.String("clc-server-desc")
	d.Public = flags.Bool("clc-server-private") == false
	log.Warnf("public: %v", d.Public)

	d.ServerType = flags.String("clc-server-type")
	d.AnityAffinityPolicy = flags.String("clc-aa-policy")
	d.ConfigurationId = flags.String("clc-configuration-id")

	if d.AnityAffinityPolicy != "" && d.ServerType != "hyperscale" {
		log.Warnf("Anti affinity policy specified but the server type isn't 'hyperscale'")
	}
	if d.ConfigurationId == "" && d.ServerType == "baremetal" {
		return fmt.Errorf("Missing configuration id for baremetal server.")
	}
	if d.ConfigurationId != "" && d.ServerType != "baremetal" {
		log.Warnf("Configuration id specified but the server type isn't 'baremetal'")
	}

	return nil
}

var apiClient *sdk.Client

func (d *Driver) client() *sdk.Client {
	if apiClient == nil {
		config, _ := api.NewConfig(d.Username, d.Password)
		config.UserAgent = "docker-machine-driver"
		if d.Alias != "" {
			config.Alias = d.Alias
		}
		apiClient = sdk.New(config)
		err := apiClient.Authenticate()
		if err != nil {
			log.Errorf("Error authenticating %v", err)
		}
	}
	return apiClient
}

// GetIP returns an IP or hostname that this host is available at
// e.g. 1.2.3.4 or docker-host-d60b70a14d3a.cloudapp.net
func (d *Driver) GetIP() (string, error) {
	ip, err := d.detectIP()
	if err != nil {
		return "", err
	}
	return ip, nil
}

// GetSSHHostname aliases GetIP
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetSSHUsername returns a configurable ssh user
func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "root"
	}
	return d.SSHUser
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%v:%v", ip, d.DockerPort), nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "clc"
}

// Create a new machine (installs a generated pubkey and optionally allocates a public IP)
func (d *Driver) Create() error {
	m, err := dcGroups(d.client(), d.Location)
	if err != nil {
		return fmt.Errorf("Failed pulling groups in location %v - %v", d.Location, err)
	}

	gid, ok := m[d.GroupName]
	if !ok {
		return fmt.Errorf("Failed resolving group %v", d.GroupName)
	}
	log.Debugf("Spawning server into group: %v", gid)
	spec := server.Server{
		Name:           d.NameTemplate,
		Password:       d.SSHPassword,
		Description:    d.Description,
		GroupID:        gid,
		CPU:            d.CPU,
		MemoryGB:       d.MemoryGB,
		SourceServerID: d.Template,
		Type:           d.ServerType,
	}
	//spec.Additionaldisks = disks
	//spec.Customfields = fields

	log.Debugf("Spawning server with: %v", spec)
	resp, err := d.client().Server.Create(spec)
	if err != nil {
		return fmt.Errorf("Error creating server: %v", err)
	}

	ok, st := resp.GetStatusID()
	if !ok {
		return fmt.Errorf("Failed extracting status to poll on %v: %v", resp, err)
	}
	err = waitStatus(d.client(), st)
	if err != nil {
		return fmt.Errorf("Failed polling status: %v", err)
	}

	_, uuid := resp.Links.GetID("self")
	s, err := d.client().Server.Get(uuid)
	d.ServerID = s.ID
	log.Infof("Created server: %v", d.ServerID)

	// add ssh pubkey
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}
	path := fmt.Sprintf("%v.pub", d.GetSSHKeyPath())
	pubkey, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	pkg := server.Package{
		ID: defaultSSHKeyPackage,
		Params: map[string]string{
			"User":   d.SSHUser,
			"SshKey": string(pubkey),
		},
	}
	presp, err := d.client().Server.ExecutePackage(pkg, d.ServerID)
	if err != nil {
		return fmt.Errorf("Failed exec'ing pubkey package on %v - %v", d.ServerID, err)
	}
	ok, st = presp[0].GetStatusID()
	err = waitStatus(d.client(), st)
	if err != nil {
		return fmt.Errorf("Failed installing pubkey on %v - %v", d.ServerID, err)
	}
	log.Infof("SSH Pubkey installed from %v for user %v", path, d.SSHUser)

	// allocate IP and open ports
	if d.Public {
		internal, err := d.detectIP()
		pip := server.PublicIP{
			InternalIP: internal,
			Ports: []server.Port{
				server.Port{
					Protocol: "tcp",
					Port:     d.SSHPort,
				},
				server.Port{
					Protocol: "tcp",
					Port:     d.DockerPort,
				},
				server.Port{
					Protocol: "tcp",
					Port:     d.DockerSwarmMasterPort,
				},
			},
		}
		resp, err := d.client().Server.AddPublicIP(s.ID, pip)
		if err != nil {
			return fmt.Errorf("Failed adding public ip to %v - %v", s.ID, err)
		}
		err = waitStatus(d.client(), resp.ID)
		if err != nil {
			return fmt.Errorf("Failed while polling public ip %v - %v", s.ID, err)
		}

		// scan NICs for any public ip
		s, err = d.client().Server.Get(s.ID)
		ip, err := d.detectIP()
		if err != nil {
			return fmt.Errorf("Failed detecting public ip on %v - %v", d.ServerID, err)
		}
		d.PublicIP = ip
		log.Infof("Added public IP %v to %v", d.PublicIP, d.ServerID)
	}

	return nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	s, err := d.client().Server.Get(d.ServerID)
	if err != nil {
		log.Infof("Failed fetching server %v. (is it dead?) error: %v", d.ServerID, err)
		return state.None, nil
		//return state.Error, fmt.Errorf("Failed fetching server %v - %v", d.ServerID, err)
	}
	log.Debugf("server.status: %v powerstate: %v", s.Status, s.Details.Powerstate)
	if s.Status == "underConstruction" {
		return state.Starting, nil
	}
	if s.Status == "queuedForDelete" {
		return state.Stopped, nil
	}

	switch s.Details.Powerstate {
	case "started":
		return state.Running, nil
	case "stopped":
		return state.Stopped, nil
	case "paused":
		return state.Paused, nil
	}
	log.Warnf("server powerstate: %v not matched, returning state.None", s.Details.Powerstate)
	return state.None, nil
}

// PreCreateCheck allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	return nil
}

// Remove a host
func (d *Driver) Remove() error {
	st, err := d.GetState()
	if st == state.None {
		return nil
	} else if err != nil {
		return fmt.Errorf("Failed fetching state: %v", err)
	}
	return d.Kill()
}

// Start a host
func (d *Driver) Start() error {
	_, err := d.client().Server.PowerState(server.On, d.ServerID)
	if err != nil {
		return fmt.Errorf("Failed starting server: %v - %v", d.ServerID, err)
	}
	return nil
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	_, err := d.client().Server.PowerState(server.Off, d.ServerID)
	if err != nil {
		return fmt.Errorf("Failed stopping server: %v - %v", d.ServerID, err)
	}
	return nil
}

// Restart a host. This may just call Stop(); Start() if the provider does not
// have any special restart behaviour.
func (d *Driver) Restart() error {
	var err error
	err = d.Stop()
	if err != nil {
		return err
	}
	err = d.Start()
	if err != nil {
		return err
	}
	return nil
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	_, err := d.client().Server.Delete(d.ServerID)
	if err != nil {
		return fmt.Errorf("Failed killing server: %v - %v", d.ServerID, err)
	}
	return nil
}

func (d *Driver) detectIP() (string, error) {
	// scan NICs for any public ip
	s, err := d.client().Server.Get(d.ServerID)
	if err != nil {
		return "", fmt.Errorf("Failed fetching server while fetching IP: %v", err)
	}
	ip := ""
	for _, i := range s.Details.IPaddresses {
		if i.Public != "" {
			log.Debugf("Found public ip: %v", i.Public)
			ip = i.Public
		}
	}
	if ip == "" {
		log.Infof("Failed finding public IP on %v. scanning private NICs", d.ServerID)
		for _, i := range s.Details.IPaddresses {
			if i.Internal != "" {
				log.Debugf("Found private ip: %v", i.Internal)
				ip = i.Internal
			}
		}
	}
	return ip, nil
}

func waitStatus(client *sdk.Client, id string) error {
	// block until queue is processed and server is up
	poll := make(chan *status.Response, 1)
	err := client.Status.Poll(id, poll)
	if err != nil {
		return nil
	}
	status := <-poll
	log.Debugf("status %v", status)
	return nil
}

func dcGroups(apiClient *sdk.Client, dcname string) (map[string]string, error) {
	// FIXME: does not handle name collisions. passing group id oughta work though
	dc, _ := apiClient.DC.Get(dcname)
	_, id := dc.Links.GetID("group")
	m := map[string]string{}
	resp, _ := apiClient.Group.Get(id)
	m[resp.Name] = resp.ID // top
	for _, x := range resp.Groups {
		deepGroups(x, &m)
	}
	return m, nil
}

func deepGroups(g group.Groups, m *map[string]string) {
	(*m)[g.Name] = g.ID
	for _, sg := range g.Groups {
		deepGroups(sg, m)
	}
}

func generatePassword(strlen int) string {
	/* FIXME: ensure password conforms
	   A password must be at least 8 characters and contain at least 3 of the following:
	   uppercase letters
	   lowercase letters
	   numbers
	   symbols
	*/
	// adapted from http://siongui.github.io/2015/04/13/go-generate-random-string/
	rand.Seed(time.Now().UTC().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIFJKLMNOPQRSTUVWXYZ0123456789!@#$*&()_"
	result := make([]byte, strlen)
	for i := 0; i < strlen; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}
