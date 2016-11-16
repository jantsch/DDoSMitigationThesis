# Copyright 2012-2013 James McCauley

"""
  RUN: sudo ~/pox/pox.py forwarding.controlador_throttle --gateways=1,2  --k=3  --victim=10.0.0.1 --limitervariation=30 info.packet_dump samples.pretty_log log.level --DEBUG

For each switch:
1) Keep a table that maps IP addresses to MAC addresses and switch ports.
   Stock this table using information from ARP and IP packets.
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  If the info in the table is old, just flood the query.
3) Flood all other ARPs.
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
from pox.openflow.discovery import Discovery
import pox.host_tracker
import networkx as nx
import pox.openflow.libopenflow_01 as of



from pox.lib.revent import *
from threading import Timer
from subprocess import call
import sys
import os
import subprocess
import time
import pipes







class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)
  

def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))



class l3_switch (EventMixin):
  def __init__ (self, gateways = [],k ="",victim ="",limitervariation= ""):
    # Mapeamento de IP para portas
    self.arpTable = {}

    # Instalacao de gateways - Tenho DPID.
    self.gateways = set(gateways)

    # Gateways e K saltos
    self.k = k
    self.victim = victim
    
    # Mapeamento
    self.G = nx.Graph()
    self.MappingHosts = {}
    self.SwitchesToApply = []
    
    self.Trigger = False
    
    # Configuracao do Rate-Limiting 
    self.Limiter = 15
    self.LimiterVariation = limitervariation
    self.oldLimiter =  self.Limiter

    # Inicializa funcao para disparar regra e habilitar filtro.
    t = Timer(15.0, self.CalculatePath)
    t.start()

    core.openflow_discovery.addListenerByName("LinkEvent", self._handle_LinkEvent)  # listen to openflow_discovery
    core.host_tracker.addListenerByName("HostEvent", self._handle_HostEvent)  # listen to host_tracker
    core.listen_to_dependencies(self)

  def UpdateRateLimit(self): 
        log.warning("Configurando taxas de limitacao")
        for x in self.SwitchesToApply:
            cmd = 'docker exec  mn.d'+ str(x) +' iptables -D FORWARD --dst '+  str(self.victim) +'  -m hashlimit --hashlimit '+ str(self.oldLimiter) +'/min --hashlimit-mode dstip --hashlimit-name hosts -j DROP '     
            os.system(cmd)           
            cmd = 'docker exec  mn.d'+ str(x) +' iptables -A FORWARD --dst '+  str(self.victim) +'  -m hashlimit --hashlimit '+ str(self.Limiter) +'/min --hashlimit-mode dstip --hashlimit-name hosts -j DROP '     
            os.system(cmd) 

        self.oldLimiter =  self.Limiter
        self.Limiter = self.Limiter + int(self.LimiterVariation)
        # do your stuff
        t = Timer(10,self.UpdateRateLimit).start()  



  def CalculatePath(self):
    # Recebo IP da Vitima, Acho Switch proximo, Calculo shortest para todos os nodos e pego os que sao igual a k.  Implemento o Rate-Limiting 
    # nesses roteadores.
    #print MappingHosts
    self.Trigger = True
    # Seleciona o switch -------CONCERTAR SE tiver HOST EM CAMINHOS MENORES TBM INSTALAR REGRAS.
    if self.victim in  self.MappingHosts: 
        switch_src =  self.MappingHosts[self.victim]
        for x in self.G :
          if x != switch_src:
             try:               
                  if int(self.k) -1== nx.shortest_path_length(self.G,switch_src,x):                     
                       self.SwitchesToApply.append(x)                      
             except:
                  print "no such Graph" 
    log.warning("Calculei Switches para instalacao de limitacao: %s " % ', '.join(map(str, self.SwitchesToApply)))
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for x in self.SwitchesToApply:
      c1 =  core.openflow.getConnection(x) 
      c1.send(msg)
    #  cmd = 'docker exec  mn.d'+ str(x) +' iptables -D FORWARD --dst '+  str(self.victim) +'  -m hashlimit --hashlimit '+ str(self.Limiter) +'/min --hashlimit-mode dstip --hashlimit-name hosts -j DROP '     
     # os.system(cmd)
     # cmd = 'docker exec  mn.d'+ str(x) +' iptables -A FORWARD --dst '+  str(self.victim) +'  -m hashlimit --hashlimit '+ str(self.Limiter) +'/min --hashlimit-mode dstip --hashlimit-name hosts -j DROP '     
     # os.system(cmd) 

    self.UpdateRateLimit()

    log.warning("Limpei Tabelas e Instalei Rate-Limiters")
    
    
  


  def _handle_openflow_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
      
    if not packet.parsed:
      log.warning("S: %d P: %d - Ignorando pacote mal-formado", dpid, inport)
      return

    # Switch nao esta na tabela. Aloca Espaco.
    if dpid not in self.arpTable:     
      self.arpTable[dpid] = {}

     #Ignora pacotes nivel 2 - LLDP 
    if packet.type == ethernet.LLDP_TYPE:    
      return     

    # Pacotes IPv4
    if isinstance(packet.next, ipv4):
        log.debug("S: %i P: %i - IP %s => %s", dpid,inport,packet.next.srcip,packet.next.dstip)         
    
        #self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)    
            
        dstaddr = packet.next.dstip

        if dstaddr == self.victim:
          if dpid in self.SwitchesToApply and (inport == 2 or inport == 3) :
               log.warning("Trafego sendo redirecionado para Limitacao")
               actions = []
               actions.append(of.ofp_action_dl_addr.set_dst("00:00:00:00:00:1"+str(dpid)))
               actions.append(of.ofp_action_output(port = 4))               
               match = of.ofp_match.from_packet(packet, inport)              
               msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                     #idle_timeout=FLOW_IDLE_TIMEOUT,
                                     buffer_id=event.ofp.buffer_id,
                                      actions=actions,
                                      match=match)
               event.connection.send(msg.pack()) 
          elif dstaddr in self.arpTable[dpid]:                        
               log.warning("Trafego sendo redirecionado para Destino")
               prt = self.arpTable[dpid][dstaddr].port
               mac = self.arpTable[dpid][dstaddr].mac
               actions = []
               actions.append(of.ofp_action_dl_addr.set_dst(mac))
               actions.append(of.ofp_action_output(port = prt))               
               match = of.ofp_match.from_packet(packet, inport)              
               msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                     #idle_timeout=FLOW_IDLE_TIMEOUT,
                                     buffer_id=event.ofp.buffer_id,
                                     actions=actions,
                                     match=match)
               event.connection.send(msg.pack()) 

                

          # Sei pra que porta vai mandar.
        elif dstaddr in self.arpTable[dpid]:             
                prt = self.arpTable[dpid][dstaddr].port
                mac = self.arpTable[dpid][dstaddr].mac
                if inport==4 and (dpid==1 or dpid ==2 or dpid ==5):
                    log.warning("Descartei")
                else:
                  if prt == inport:
                    log.warning("S: %i P: %i - Porta de entrada e a mesma de saida - %s" % (dpid, inport,str(dstaddr)))
                  else:
                    log.debug("S: %i P: %i - Instalando Flow para %s => %s out porta %i" % (dpid, inport, packet.next.srcip, dstaddr, prt))
                    actions = []
                    actions.append(of.ofp_action_dl_addr.set_dst(mac))
                    actions.append(of.ofp_action_output(port = prt))
                    match = of.ofp_match.from_packet(packet, inport)

                    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                          #idle_timeout=FLOW_IDLE_TIMEOUT,
                                          buffer_id=event.ofp.buffer_id,
                                          actions=actions,
                                          match=match)
                    event.connection.send(msg.pack())     
         
    # Pacotes ARP
    elif isinstance(packet.next, arp):
      a = packet.next
      log.debug("S: %i P: %i  - ARP %s %s => %s", dpid, inport, {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst)


      self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)


      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:  
            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.arpTable[dpid]:
                # Tem Resposta local

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   r.protosrc))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

      # Nao sabe ent'ao inunda
      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst))

      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)

  def _handle_LinkEvent(self,event):
        l = event.link
        sw1 = l.dpid1
        sw2 = l.dpid2
        pt1 = l.port1
        pt2 = l.port2
        self.G.add_node( sw1 )
        self.G.add_node( sw2 )
        if event.added:
            self.G.add_edge(sw1,sw2)
        if event.removed:
            try:
                self.G.remove_edge(sw1,sw2)
            except:
                print "remove edge error"
       # print 'link added is %s'%event.added
        #print 'link removed is %s' %event.removed
        #print 'switch1 %d' %l.dpid1
        #print 'port1 %d' %l.port1
        #print 'switch2 %d' %l.dpid2
        #print 'port2 %d' %l.port2
        #print self.G.edges()

  def _handle_HostEvent(self, event):
        """
        Listen to host_tracker events, fired up every time a host is up or down
        When this happens we need the topology. For now must issue a pingall from
        mininet cli. Later to fire own pings?
        To handle topology a thread is launched with arguments the host and the switch
        Args:
            event: HostEvent listening to core.host_tracker
        Returns: nada
        """   
        macaddr = event.entry.macaddr.toStr()
        s = pox.lib.util.dpid_to_str(event.entry.dpid)      
        if event.entry.ipAddrs != None and event.entry.ipAddrs !=[] :
           ipAddrs = event.entry.ipAddrs 
           ip = event.entry.ipAddrs.keys() 
           if len(ip) >0:
             self.MappingHosts[str(ip[0])] =  event.entry.dpid                 
             log.warning("HOST NO S: %d P: %d MAC %s %s", event.entry.dpid,  event.entry.port, macaddr,ipAddrs)
        else:
           log.warning("HOST NO S: %d P: %d MAC %s ", event.entry.dpid,  event.entry.port, macaddr)


      

        #self.host_alive.append(event.entry) 
        #print event.entry.ipAddrs.keys()
        # time.sleep(5)
        #htrt = threading.Thread(target=self.add_host_to_topology, args=(s, macaddr))
        #htrt.start()

def launch (gateways="" , k="", victim="",limitervariation=""):
  gateways = gateways.replace(","," ").split()  
  gateways = [int(x) for x in gateways]
  pox.openflow.discovery.launch()
  pox.host_tracker.launch()
 
  core.registerNew(l3_switch, gateways, k,victim, limitervariation)

