# update-ssh_known_hosts
Tool to merge ssh_known_hosts files and update them with ssh-keyscan results.


## Usage
```
usage: update_ssh_known_hosts.py [-h] [--verbose] [--hostlist HOSTLIST]
                                 [--inputfile INPUTFILE]
                                 outputfile

Merge and update host lists

positional arguments:
  outputfile            Output ssh_known_host files to write.

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -v         Give more output
  --hostlist HOSTLIST, -l HOSTLIST
                        List of hosts to scan and add.
  --inputfile INPUTFILE, -i INPUTFILE
                        Input ssh_known_host files to combine.
```

## Example
` update_ssh_known_hosts.py --inputfile /etc/ssh/ssh_known_hosts --inputfile new_stuff new_ssh_known_hosts`
