
# Docker Machine driver for CenturyLinkCloud

```bash
docker-machine create -d clc machine0
```



## Installation

The easiest way to install ovh docker-machine driver is to:

```bash
go install github.com/CenturyLinkCloud/docker-machine-driver-clc
```

## Example Usage

inspect available options via --help


```bash
export CLC_USERNAME='<username>'
export CLC_PASSWORD='<password>'
export CLC_ALIAS='<alias>'

token=$(docker run swarm create)
docker-machine create -d clc --clc-server-group "my docker swarm" --swarm --swarm-discovery --swarm-token token://$token master
docker $(docker-machine config --swarm master) info
```


## Options

```bash
docker-machine create -d clc --help
```


| Option Name                                          | Description                                     | Default Value         | required |
|------------------------------------------------------|-------------------------------------------------|-----------------------+----------|
| ``--clc-account-username`` or ``$CLC_USERNAME``      | CLC account user                                | none                  | yes      |
| ``--clc-account-password`` or ``$CLC_PASSWORD``      | CLC account password                            | none                  | yes      |
| ``--clc-account-alias`` or ``$CLC_ALIAS``            | CLC account alias                               | none                  | yes      |
| ``--clc-server-private`` or ``CLC_SERVER_PRIVATE``   | allocates public ip (if disabled, VPN required) | false                 | no       |
| ``--clc-server-group`` or ``$CLC_SERVER_GROUP``      | server group (name or id) to spawn into         | Default Group         | no       |
| ``--clc-server-location`` or ``CLC_SERVER_LOCATION`` | datacenter                                      | WA1                   | no       |
| ``--clc-server-cpu`` or ``CLC_SERVER_CPU``           | cpu cores                                       | 2                     | no       |
| ``--clc-server-mem`` or ``CLC_SERVER_MEM``           | memory GB                                       | 2                     | no       |
| ``--clc-server-template`` or ``CLC_SERVER_TEMPLATE`` | OS image                                        | ubuntu-14-64-template | no       |
| ``--clc-ssh-user`` or ``CLC_SSH_USER``               | ssh user (specific to OS image)                 | root                  | no       |
| ``--clc-ssh-password`` or ``CLC_SSH_PASSWORD``       | ssh password                                    | <generated>           | no       |


Each environment variable may be overloaded by its option equivalent at runtime.

## Kernels

The default ubuntu image runs kernel 3.13.xx but advanced swarm/networking features require a newer kernel

Optionally `Docker-machine ssh` in and `apt-get install -qy linux-image-generic-lts-wily && reboot`

## Hacking

### Get the sources

```bash
go get github.com/CenturyLinkCloud/docker-machine-driver-clc
cd $GOPATH/src/github.com/CenturyLinkCloud/docker-machine-driver-clc
```

### Test the driver

To test the driver make sure your current build directory has the highest
priority in your ``$PATH`` so that docker-machine can find it.

```
export PATH=$GOPATH/src/github.com/CenturyLinkCloud/docker-machine-driver-clc:$PATH
```

## Related links

- **Docker Machine**: https://docs.docker.com/machine/
- **Contribute**: https://github.com/CenturyLinkCloud/docker-machine-driver-clc
- **Report bugs**: https://github.com/CenturyLinkCloud/docker-machine-driver-clc/issues

## License

Apache 2.0
