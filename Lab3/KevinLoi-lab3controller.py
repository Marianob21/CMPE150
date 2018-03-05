# Lab 3 Skeleton
#
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    # print "Example Code."

    ###################################################
    # Rules:
    #   Allow all ARP and TCP to pass, otherwise packet
    #   otherwise packet is dropped. Flow tables match
    #   the highest priority first where priority is
    #   established based on the order rules are placed
    #   on the table.
    ###################################################

    ###################################################
    # Psuedo code is used to help me understand what
    # I'm doing
    # Resources: http://intronetworks.cs.luc.edu/auxiliary_files/mininet/poxwiki.pdf
    # https://en.wikipedia.org/wiki/EtherType

    ###################################################
    # Making the table
    # Installing table entry
    msg = of.ofp_flow_mod()
    # match packet
    msg.match = of.ofp_match.from_packet(packet)
    # few entries of dump--flows from timeout
    msg.idle_timeout = 25 # 50
    msg.hard_timeout = 50 # 100
    ###################################################

    ###################################################
    # Making the RULES
    # check for any ipv4
    isIP = packet.find('ipv4')
    # if there is an ipv4
    if isIP is not None:
    # check for tcp
      isTCP = packet.find('tcp')
    # if tcp
      if isTCP is not None:
    # accept packet
        msg.data = packet_in
        msg.nw_proto = 6 # 6 = tcp
        # add action to send to specified port
        action = of.ofp_action_output(port = of.OFPP_FLOOD)
        msg.actions.append(action)
        self.connection.send(msg)
    #   else
      else:
    # no packets taken - packet dropped
        msg.data = packet_in
        self.connection.send(msg)
    # else
    else:
      msg.data = packet_in
    # check for ARP
      isARP = packet.find('arp')
    # if ARP
      if isARP is not None:
    # accept packet
        msg.data = packet_in
        msg.match.dl_type = 0x0806 # match ARP
        # add action to send to specified port
        action = of.ofp_action_output(port = of.OFPP_FLOOD)
        msg.actions.append(action)
        self.connection.send(msg)
    # else
      else:
    # drop packet
        msg.data = packet_in
        self.connection.send(msg)
    ###################################################

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
