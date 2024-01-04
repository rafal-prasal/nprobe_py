# nprobe_py 0.0.1

License: http://www.apache.org/licenses/LICENSE-2.0

To some extent it is replacement to nprobe for ntop.org.

It takes NetFlow/IPFIX stream and makes it available as ZMQ for ntop.

Code found here is like "Cutting the grass with machete" and definitely could be prettier, but it simply gets the job done, so don't complain about it too much.

## Usage:
### Build images

    docker-compose build
    #or
    docker compose build

### Start 

    docker-compose up
    #or
    docker compose up

or in the backround

    docker-compose up -d
    #or
    docker compose up -d

## stop
    docker-compose stop
    #or
    docker compose stop

### Remove
    docker-compose rm
    or
    docker compose rm

### Access

#### ntop WebUI address

    http://{host}:3000

#### NetFlow/IPFIX collector

    udp://{host}:2055

### How to configure NetFlow/IPFIX stream
#### Mikrotik 7.X

\1 Go to Web ui

    http://{microtik}

\2 Navigate through menu

    WebFig -> IP -> Traffic Flow -> Targets -> Add New

\3 Set options

    Enabled: [x]
    Src. Address: {ip of Mikrotik}
    Dst. Address: {ip of host}
    port: 2055
    Version: IPFIX
    v9/IPFIX Template Refresh: 20
    v9/IPFIX Template Timeout: 1800

\4 Click OK

