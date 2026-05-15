#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys

if os.geteuid() != 0:
    print('[ERROR] Ejecutar con sudo.')
    sys.exit(1)

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

# Importar solo OVSKernelAP de mn_wifi para tener el AP SDN
from mn_wifi.node import OVSKernelAP

class PublicWifiTopo(Topo):

    def build(self):

        # AP / Switch SDN 
        ap1 = self.addSwitch(
            'ap1',
            cls=OVSKernelAP,
            ssid='RedWiFiPublica',
            mode='g',
            channel='6',
            failMode='standalone',
            protocols='OpenFlow13'
        )

        # Enrutador / Gateway 
        r1 = self.addHost(
            'r1',
            mac='00:00:00:00:00:FE',
            ip='10.0.0.1/24'
        )

        # Hosts — usuarios legítimos 
        h1 = self.addHost(
            'h1',
            mac='00:00:00:00:00:01',
            ip='10.0.0.11/24',
            defaultRoute='via 10.0.0.1'
        )
        h2 = self.addHost(
            'h2',
            mac='00:00:00:00:00:02',
            ip='10.0.0.12/24',
            defaultRoute='via 10.0.0.1'
        )
        h3 = self.addHost(
            'h3',
            mac='00:00:00:00:00:03',
            ip='10.0.0.13/24',
            defaultRoute='via 10.0.0.1'
        )

        # Host atacante 
        att = self.addHost(
            'att',
            mac='00:00:00:00:FF:FF',
            ip='10.0.0.99/24',
            defaultRoute='via 10.0.0.1'
        )

        # Enlaces
        # Backhaul: enrutador → AP
        self.addLink(r1,  ap1, bw=100, delay='2ms')
        # Clientes → AP (simulan conexión WiFi con distintos delay/bw)
        self.addLink(h1,  ap1, bw=54, delay='5ms')
        self.addLink(h2,  ap1, bw=54, delay='5ms')
        self.addLink(h3,  ap1, bw=30, delay='8ms')   # más lejos del AP
        self.addLink(att, ap1, bw=54, delay='5ms')

def run():
    setLogLevel('info')

    info('*** Iniciando Red WiFi Pública Simulada\n')

    topo = PublicWifiTopo()
    c0   = Controller('c0')

    net = Mininet(
        topo=topo,
        controller=c0,
        switch=OVSSwitch,
        link=TCLink
    )

    net.start()

    # Referencias a nodos 
    r1  = net.get('r1')
    h1  = net.get('h1')
    h2  = net.get('h2')
    h3  = net.get('h3')
    att = net.get('att')

    # Configuración post-arranque 
    info('\n*** Configurando nodos\n')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    att.cmd('sysctl -w net.ipv4.ip_forward=1')
    info('    [r1]  IP forwarding habilitado\n')
    info('    [att] IP forwarding habilitado (listo para MitM)\n')

    # Prueba de conectividad 
    info('\n*** Prueba de conectividad\n')
    net.ping([h1, h2, h3])

    CLI(net)

    info('*** Deteniendo red\n')
    net.stop()


if __name__ == '__main__':
    run()
