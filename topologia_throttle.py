#!/usr/bin/python

''' 

    H3 -----> S1 
    H4 -----> S1  -----> S3 -----> S5 ------> H2
              |             -
              D1              -
                                -> S6
    H5 -----> S2  -----> S4 -----> S6 ------> Victim
    H6 -----> S2
              |
              D2

'''
from mininet.net import Containernet
from mininet.node import RemoteController, Docker, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Link


def topology():

    "Create a network with some docker containers acting as hosts."   
    net = Containernet(controller=RemoteController)

    info('*** Adding controller\n')
    net.addController('c0')

    info('*** Adding hosts\n')
    Victim = net.addHost( 'h1', mac='00:00:00:00:00:01')
    Host2 = net.addHost( 'h2', mac='00:00:00:00:00:02' )
    Host3 = net.addHost( 'h3', mac='00:00:00:00:00:03' )
    Host4 = net.addHost( 'h4', mac='00:00:00:00:00:04' )
    Host5 = net.addHost( 'h5', mac='00:00:00:00:00:05' )
    Host6 = net.addHost( 'h6', mac='00:00:00:00:00:06' )  

    #info('*** Adding docker containers\n')
    d1 = net.addDocker('d1', ip='10.0.0.251', mac='00:00:00:00:00:11', dimage="mit/filter:latest")
    d2 = net.addDocker('d2', ip='10.0.0.252', mac='00:00:00:00:00:12', dimage="mit/filter:latest")
    d5 = net.addDocker('d5', ip='10.0.0.253', mac='00:00:00:00:00:15', dimage="mit/filter:latest")

    info('*** Adding switch\n')
    Switch1 = net.addSwitch( 's1' )
    Switch2 = net.addSwitch( 's2' )
    Switch3 = net.addSwitch( 's3' )
    Switch4 = net.addSwitch( 's4' )
    Switch5 = net.addSwitch( 's5' )
    Switch6 = net.addSwitch( 's6' )
   

    info('*** Creating links\n')   
    net.addLink( Switch1, Switch3 )
    net.addLink( Switch3, Switch5 )
    net.addLink( Switch3, Switch6 )
    net.addLink( Switch5, Host2 )
    net.addLink( Switch6, Victim )
    net.addLink( Switch6, Switch4 )
    net.addLink( Switch4, Switch2)    
    
    net.addLink( Host3, Switch1 )
    net.addLink( Host4, Switch1 )
    net.addLink( Host5, Switch2 )
    net.addLink( Host6, Switch2 )

    net.addLink(Switch1 , d1 )
    net.addLink(Switch2 , d2 )
    net.addLink(Switch5 , d5 )

 
  
  
    #net.addLink(s1, s2, cls=TCLink, delay="100ms", bw=1, loss=10)
    # try to add a second interface to a docker container
    #net.addLink(d2, s3, params1={"ip": "11.0.0.254/8"})
    #net.addLink(d3, s3)

    info('*** Starting network\n')
    net.start()

    #net.ping([d1, d2])

    # our extended ping functionality
    #net.ping([d1], manualdestip="10.0.0.252")
    #net.ping([d2, d3], manualdestip="11.0.0.254")

    #info('*** Dynamically add a container at runtime\n')
    #d4 = net.addDocker('d4', dimage="ubuntu:trusty")
    # we have to specify a manual ip when we add a link at runtime
    #net.addLink(d4, s1, params1={"ip": "10.0.0.254/8"})
    # other options to do this
    #d4.defaultIntf().ifconfig("10.0.0.254 up")
    #d4.setIP("10.0.0.254")

    #net.ping([d1], manualdestip="10.0.0.254")

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()
