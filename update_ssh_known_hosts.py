#!/usr/bin/env python3
"Updater for ssh_known_hosts files"

from collections import defaultdict
import logging
import tempfile
import subprocess
import argparse
import sys


def parse_args():
    "Parse Arguments"
    parser = argparse.ArgumentParser(description='Merge and update host lists')

    parser.add_argument('--verbose',
                        '-v',
                        action='count',
                        help='Give more output',
                        default=0)
    parser.add_argument('--hostlist',
                        '-l',
                        help='List of hosts to scan and add.')
    parser.add_argument('--inputfile',
                        '-i',
                        action='append',
                        help='Input ssh_known_host files to combine.')
    parser.add_argument('outputfile',
                        help='Output ssh_known_host files to write.')

    args = parser.parse_args()
    return args


def run():
    "Main runner"
    logging.basicConfig(format='%(levelname)s:%(message)s')

    logging.getLogger().setLevel(logging.WARNING)
    args = parse_args()
    if args.verbose >= 1:
        logging.getLogger().setLevel(logging.DEBUG)

    inputs = []
    for inp in args.inputfile:
        try:
            with open(inp) as inpf:
                inputs.append(inpf.readlines())
        except OSError as err:
            print("Failed to read file, %s." % err)
            sys.exit(1)

    hosts = []
    if args.hostlist:
        try:
            with open(args.hostlist) as hostf:
                hosts = hostf.readlines()
        except OSError as err:
            print("Failed to read hostlist, %s." % err)
            sys.exit(1)

    fresh_scanned = scan_hosts(hosts)
    inputs.append(fresh_scanned)
    output = gen_output(inputs)
    try:
        with open(args.outputfile, 'w') as outf:
            outf.write(output)
    except OSError as err:
        print("Failed to write file, %s." % err)
        sys.exit(1)


def scan_hosts(hosts):
    "Scan hosts for ssh keys and return them."

    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.file.write(b"\n".join((h.encode() for h in hosts)))
        tmpf.file.flush()
        call = ['ssh-keyscan', '-T', '1', '-t', 'ed25519', '-f', tmpf.name]
        proc = subprocess.Popen(call,
                                stderr=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                bufsize=-1)
        logging.info("started ssh session")
        out, _ = proc.communicate()
        logging.info("communicated with hosts")
        return out.decode().splitlines()


def gen_output(inputs):
    """Merge inputs to generate a new ssh_known_hosts file.

    Later inputs overwrite earlier ones.
    """

    hashes = [_ssh_keyscan_to_hash(x) for x in inputs]
    newhash = hashes[0]
    for ahash in hashes[1:]:
        newhash.update(ahash)

    hosts = _combine_ssh_hosts(newhash)
    sorted_hosts = sorted(hosts)

    fcont = '\n'.join(
        [hname + ' ' + hosts[hname] for hname in sorted_hosts]
    )
    # ssh_known_hosts needs trailing newline
    # otherwise ssh-keygen will complain when reading it
    fcont += '\n'

    return fcont


def _ssh_keyscan_to_hash(indata):
    "Convert keyscan results to python dict of hostkeys"
    hosts = {}
    for line in indata:
        fields = line.split()
        if fields == []:
            continue
        if len(fields) < 3:
            logging.warning("encountered too short line: " + str(line))
            continue
        hnames = fields[0]
        keytype = fields[1]
        key = fields[2]
        for host in hnames.split(','):
            # prefer ed25519 over everything else
            if host in hosts and \
               keytype != 'ed25519' and \
               hosts[host].startswith('ed25519'):
                pass
            else:
                hosts[host] = keytype + ' ' + key
    return hosts


def _combine_ssh_hosts(hosts):
    """make the given dict host->sshkey shorter, by combinding hostnames
    with the same key"""
    # keymap: {'ed25519 key':['host1', 'host2']}
    keymap = defaultdict(list)
    for host, key in hosts.items():
        keymap[key].append(host)
    # shorthosts: { 'pcXX,abcpcXX,...':'ed25519 ...'}
    # sorted makes them more readable, set ensured there are no duplicates
    shorthosts = {','.join(sorted(set(hosts))): key for key, hosts in keymap.items()}
    return shorthosts


if __name__ == "__main__":
    run()
