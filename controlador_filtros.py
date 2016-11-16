# Copyright 2012-2013 James McCauley

"""
  RUN : sudo ~/pox/pox.py forwarding.controlador_filtros --gateways=1,2  info.packet_dump samples.pretty_log log.level --DEBUG

A stupid L3 switch

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

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *
from threading import Timer
from subprocess import call
import sys
import os
import subprocess
import time
import pipes


TRIGGER = False

def ActivateFilters():
    # Muda encaminhamento quando pacotes chegarem nos gateways
    global TRIGGER 
    TRIGGER = True  

    # Apaga flowtable da conexao com dpid 1
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    c1 =  core.openflow.getConnection(1) 
    c1.send(msg)

    # Adiciona Regras - Possivel integracao com Algoritmo de Deteccao e Monitoramento    
    cmd = 'docker exec  mn.d1  iptables -A FORWARD -s 10.0.0.04/32 -j DROP'
    os.system(cmd)
    cmd = 'docker exec  mn.d1  iptables -A FORWARD -s 10.0.0.06/32 -j DROP'
    os.system(cmd)   
    cmd = 'docker exec  mn.d2  iptables -A FORWARD -s 10.0.0.04/32 -j DROP'
    os.system(cmd)   
    cmd = 'docker exec  mn.d2  iptables -A FORWARD -s 10.0.0.06/32 -j DROP'
    os.system(cmd) 

    log.warning("ATIVEI FILTROS E LIMPEI FLOW TABLE DO(S) GATEWAY(S)")


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
  def __init__ (self, gateways = []):
    # Mapeamento de IP para portas
    self.arpTable = {}

    # Instalacao de gateways - Tenho DPID.
    self.gateways = set(gateways)
    
    # Inicializa funcao para disparar regra e habilitar filtro.
    t = Timer(50.0, ActivateFilters)
    t.start()

    core.listen_to_dependencies(self)



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
      
      if inport!= 4:
        self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)


      log.debug("DPID: %d %s ------ Gate %s",dpid, TRIGGER, self.gateways)  
      # SE chegar tarefa no switch
      if dpid in self.gateways and TRIGGER == True:
          log.warning("Trafego chegando em S %d", dpid)

          # Portas externas do gateway -> 2 e 3
          if inport == 2 or inport == 3:
                  log.debug("Trafego chegando em S:%d P: %d", dpid, inport)
                  actions = []
                  if dpid == 1:
                    actions.append(of.ofp_action_dl_addr.set_dst("00:00:00:00:00:11"))
                  if dpid == 2:
                    actions.append(of.ofp_action_dl_addr.set_dst("00:00:00:00:00:12"))                    
                  actions.append(of.ofp_action_output(port = 4))
                  match = of.ofp_match.from_packet(packet, inport)
                  msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                        #idle_timeout=FLOW_IDLE_TIMEOUT,
                                        #hard_timeout=of.OFP_FLOW_PERMANENT,
                                        buffer_id=event.ofp.buffer_id,
                                        actions=actions,
                                        match=match)
                  event.connection.send(msg.pack())
          # Portas do filtro do gateway -> 4
          elif inport == 4:  
                  log.debug("Trafego chegando em S: %d P: %d",dpid,inport)    
                  prt = 1
                  mac = "00:00:00:00:00:02"
                  actions = []
                  actions.append(of.ofp_action_dl_addr.set_dst(mac))
                  actions.append(of.ofp_action_output(port = prt))
                  match = of.ofp_match.from_packet(packet, inport)
                  msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                        #idle_timeout=FLOW_IDLE_TIMEOUT,
                                        #hard_timeout=of.OFP_FLOW_PERMANENT,
                                        buffer_id=event.ofp.buffer_id,
                                        actions=actions,
                                        match=match)
                  event.connection.send(msg.pack())
          # Porta interna do Gateway -> 1 
          elif inport == 1:
                  dstaddr = packet.next.dstip
                  prt = self.arpTable[dpid][dstaddr].port
                  mac = self.arpTable[dpid][dstaddr].mac
                  log.debug("Trafego chegando em S:%d P: %d para ou %d ", dpid, inport, prt)
                  actions = []
                  actions.append(of.ofp_action_dl_addr.set_dst(mac))
                  actions.append(of.ofp_action_output(port = prt))
                  match = of.ofp_match.from_packet(packet, inport)
                  msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                        #idle_timeout=FLOW_IDLE_TIMEOUT,
                                        #hard_timeout=of.OFP_FLOW_PERMANENT,
                                        buffer_id=event.ofp.buffer_id,
                                        actions=actions,
                                        match=match)
                  event.connection.send(msg.pack())
      else: 
        
          dstaddr = packet.next.dstip
          # Sei pra que porta vai mandar.
          if dstaddr in self.arpTable[dpid]:
                prt = self.arpTable[dpid][dstaddr].port
                mac = self.arpTable[dpid][dstaddr].mac
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
                                        #hard_timeout=of.OFP_FLOW_PERMANENT,
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


def launch (gateways=""):
  gateways = gateways.replace(","," ").split()  
  gateways = [int(x) for x in gateways]
  core.registerNew(l3_switch, gateways)

