import optparse
import nmap


def nmapScan(tgtHost, tgtPort):
    nScan = nmap.PortScanner()
    nScan.scan(tgtHost, tgtPort)
    state = nScan[tgtHost]['tcp'][int(tgtPort)]['state']
    print '[*] ' + tgtHost + ' tcp/' + tgtPort + ' ' + state


def Main():
    parser = optparse.OptionParser('usage %prog \n\t -H <target host> \n\t -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string',
                      help='specify target port(s), seperated by a comma, seperate ranges with a dash.')
    (options, args) = parser.parse_args()
    if options.tgtHost == None or options.tgtPort == None:
        print parser.usage
        exit(0)
    else:
        tgtHost = options.tgtHost
        if '-' in str(options.tgtPort):
            tgtPorts = options.tgtPort.split('-')
            tgtPorts = range(int(tgtPorts[0]), int(tgtPorts[1]))
        else:
            tgtPorts = str(options.tgtPort).split(',')
    print '[*] Scanning...'
    for tgtPort in tgtPorts:
        nmapScan(tgtHost, str(tgtPort))


if __name__ == '__main__':
    Main()
