# nprobe_py 0.0.1

License: http://www.apache.org/licenses/LICENSE-2.0

To some extent it is replacement to nprobe for ntop.org.

It takes NetFlow/IPFIX stream and makes it available as ZMQ for ntop.

Code found here is like "Cutting the grass with machete" and definitely could be prettier, but it simply gets the job done, so don't complain about it too much.

## Usage:
### build images
    doker-compose build

### start deployment
    docker-compose up

    #or in the backround

    docker-compose up -d

### stop
    docker-compose stop

