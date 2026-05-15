#!/usr/bin/env python3
import json
import os
import datetime
from collections import defaultdict
 
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp
from ryu.lib.packet import ether_types
 
RULES_FILE = os.path.join(os.path.dirname(__file__), 'security_rules.json')
LOG_FILE   = '/tmp/security_events.log'
 
# Tabla de confianza — MACs e IPs legítimas de la red
# Deben coincidir con los valores de public_wifi_topology.py
TRUSTED_HOSTS = {
    '00:00:00:00:00:fe': '10.0.0.1',   # r1 gateway
    '00:00:00:00:00:01': '10.0.0.11',  # h1
    '00:00:00:00:00:02': '10.0.0.12',  # h2
    '00:00:00:00:00:03': '10.0.0.13',  # h3
    '00:00:00:00:01:02': '10.0.1.11',  # sta2
    '00:00:00:00:01:03': '10.0.1.12',  # sta3
}
 
# Puertos sensibles bloqueados para hosts no autorizados
SENSITIVE_PORTS = [21, 23, 8080]
 
# Umbral de destinos únicos para sospechar distribución de malware
MALWARE_SPREAD_THRESHOLD = 3
 
# Cuántas veces debe repetirse una anomalía para escalar de nivel
CONFIRM_THRESHOLD = 2
 
# IDs de tablas OpenFlow
TABLE_MAIN       = 0   # Tabla principal — análisis inicial
TABLE_INSPECTION = 2   # Tabla de inspección profunda (nivel 2)
 
# Prioridades OpenFlow
PRIORITY_DEFAULT   = 1
PRIORITY_INSPECT   = 50
PRIORITY_BLOCK     = 100
PRIORITY_ISOLATE   = 200
 
LEVEL_NORMAL    = 0   # Sin anomalía → OUTPUT
LEVEL_SUSPECT   = 1   # Sospecha leve → CONTROLLER
LEVEL_HIGH      = 2   # Sospecha alta → GOTO_TABLE 2
LEVEL_CONFIRMED = 3   # Ataque confirmado → DROP / ISOLATE
 
LEVEL_LABELS = {
    LEVEL_NORMAL:    'NORMAL',
    LEVEL_SUSPECT:   'SOSPECHA_LEVE',
    LEVEL_HIGH:      'SOSPECHA_ALTA',
    LEVEL_CONFIRMED: 'ATAQUE_CONFIRMADO'
}
 
class SecurityRulesEngine(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
    def __init__(self, *args, **kwargs):
        super(SecurityRulesEngine, self).__init__(*args, **kwargs)
 
        # Tabla MAC → puerto del switch (aprendizaje dinámico)
        self.mac_to_port = defaultdict(dict)
 
        # Tabla ARP observada: IP → MAC
        self.arp_table = {}
 
        # IPs que cada MAC ha anunciado { mac: set(ips) }
        self.mac_ip_announcements = defaultdict(set)
 
        # Destinos únicos por host { mac: set(ips_destino) }
        self.connection_map = defaultdict(set)
 
        # Contador de anomalías por host { mac: { tipo: count } }
        self.anomaly_counter = defaultdict(lambda: defaultdict(int))
 
        # Nivel de sospecha actual por host { mac: nivel }
        self.suspicion_level = defaultdict(int)
 
        # Hosts ya aislados
        self.isolated_hosts = set()
 
        # Cargar reglas del JSON
        self.rules = self._load_rules()
 
        self.logger.info('=' * 55)
        self.logger.info('  Motor de Seguridad SDN — Tres niveles')
        self.logger.info(f'  Reglas cargadas : {len(self.rules)}')
        self.logger.info(f'  Log de eventos  : {LOG_FILE}')
        self.logger.info('  Tablas OpenFlow : TABLE_MAIN=0, TABLE_INSPECTION=2')
        self.logger.info('=' * 55)
 
    def _load_rules(self):
        try:
            with open(RULES_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.logger.info(f'Reglas cargadas desde {RULES_FILE}')
            return data.get('reglas', [])
        except FileNotFoundError:
            self.logger.error(f'No se encontró {RULES_FILE}')
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f'Error al leer JSON: {e}')
            return []
 
    def _get_rule(self, ataque):
        for regla in self.rules:
            if ataque.lower() in regla['ataque_cibernetico'].lower():
                return regla
        return None
 
    def _escalate(self, mac, tipo_anomalia):
        self.anomaly_counter[mac][tipo_anomalia] += 1
        total = sum(self.anomaly_counter[mac].values())
 
        nivel_anterior = self.suspicion_level[mac]
 
        if total >= CONFIRM_THRESHOLD * 2:
            self.suspicion_level[mac] = LEVEL_CONFIRMED
        elif total >= CONFIRM_THRESHOLD:
            self.suspicion_level[mac] = LEVEL_HIGH
        elif total == 1:
            self.suspicion_level[mac] = LEVEL_SUSPECT
 
        nivel_actual = self.suspicion_level[mac]
 
        if nivel_actual != nivel_anterior:
            self.logger.info(
                f'[ESCALADA] {mac} | '
                f'{LEVEL_LABELS[nivel_anterior]} → {LEVEL_LABELS[nivel_actual]}'
            )
 
        return nivel_actual
 
    def _reset_suspicion(self, mac):
        if mac in self.anomaly_counter:
            del self.anomaly_counter[mac]
        self.suspicion_level[mac] = LEVEL_NORMAL
        self.logger.info(f'[LIBERADO] {mac} — sospecha reiniciada a NORMAL')
 
    def _log_event(self, tipo_ataque, mac_atacante, ip_atacante,
                   victimas, accion, nivel, detalle, regla):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
 
        nivel_riesgo = regla.get('nivel_de_riesgo', 'DESCONOCIDO') if regla else 'DESCONOCIDO'
        factores     = [f['factor'] for f in regla.get('factores_asociados_a_la_vulnerabilidad', [])] if regla else []
        soluciones   = [s['solucion'] for s in regla.get('soluciones_comunmente_usadas', [])] if regla else []
 
        entrada = {
            'timestamp':            timestamp,
            'tipo_ataque':          tipo_ataque,
            'nivel_de_riesgo':      nivel_riesgo,
            'nivel_sospecha':       LEVEL_LABELS[nivel],
            'mac_atacante':         mac_atacante,
            'ip_atacante':          ip_atacante,
            'victimas':             victimas,
            'accion_tomada':        accion,
            'detalle':              detalle,
            'factores_asociados':   factores,
            'soluciones_aplicadas': soluciones
        }
 
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entrada, ensure_ascii=False) + '\n')
 
        self.logger.warning(
            f'[{tipo_ataque}] [{LEVEL_LABELS[nivel]}] {accion} | '
            f'Atacante: {mac_atacante} ({ip_atacante}) | '
            f'Víctimas: {victimas}'
        )
 
    def _add_flow(self, datapath, priority, match, actions,
                  table_id=TABLE_MAIN, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
 
        # Si hay acciones las empaquetamos — si no, es DROP
        if actions:
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions
            )]
        else:
            inst = []  # DROP — sin instrucciones
 
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            table_id=table_id,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)
 
    def _action_controller(self, datapath, mac_src, motivo):
        # NIVEL 1 — SOSPECHA LEVE
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
 
        match   = parser.OFPMatch(eth_src=mac_src)
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        # Timeout corto — si no se confirma el ataque, la regla expira
        self._add_flow(datapath, PRIORITY_INSPECT, match, actions,
                       idle_timeout=15, hard_timeout=30)
        self.logger.info(
            f'[CONTROLLER] Tráfico de {mac_src} enviado al controlador | {motivo}'
        )
 
    def _action_goto_table(self, datapath, mac_src, motivo):
        # NIVEL 2 — SOSPECHA ALTA
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
 
        match = parser.OFPMatch(eth_src=mac_src)
 
        # Instrucción GOTO_TABLE — no es una acción sino una instrucción
        inst = [parser.OFPInstructionGotoTable(table_id=TABLE_INSPECTION)]
 
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=PRIORITY_INSPECT,
            match=match,
            instructions=inst,
            table_id=TABLE_MAIN,
            idle_timeout=30,
            hard_timeout=60
        )
        datapath.send_msg(mod)
        self.logger.info(
            f'[GOTO_TABLE {TABLE_INSPECTION}] Tráfico de {mac_src} '
            f'enviado a inspección profunda | {motivo}'
        )
 
    def _action_drop(self, datapath, mac_src):
        # NIVEL 3 — ATAQUE CONFIRMADO (Spoofing / MitM)
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(eth_src=mac_src)
        # Acciones vacías = DROP en OpenFlow
        self._add_flow(datapath, PRIORITY_BLOCK, match, [],
                       idle_timeout=0, hard_timeout=0)
        self.logger.info(f'[DROP] Regla permanente instalada para {mac_src}')
 
    def _action_isolate(self, datapath, mac_src):
        # NIVEL 3 — ATAQUE CONFIRMADO (Malware)
        if mac_src in self.isolated_hosts:
            return
        parser = datapath.ofproto_parser
 
        # Bloquear salida
        match_out = parser.OFPMatch(eth_src=mac_src)
        self._add_flow(datapath, PRIORITY_ISOLATE, match_out, [],
                       idle_timeout=0, hard_timeout=0)
 
        # Bloquear entrada
        match_in = parser.OFPMatch(eth_dst=mac_src)
        self._add_flow(datapath, PRIORITY_ISOLATE, match_in, [],
                       idle_timeout=0, hard_timeout=0)
 
        self.isolated_hosts.add(mac_src)
        self.logger.info(f'[ISOLATE] Host aislado completamente: {mac_src}')
 
    def _action_block_port(self, datapath, mac_src, port):
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch(
            eth_src=mac_src, eth_type=0x0800,
            ip_proto=6, tcp_dst=port
        )
        self._add_flow(datapath, PRIORITY_BLOCK, match, [])
        self.logger.info(f'[DROP_PORT] Puerto {port} bloqueado para {mac_src}')
 
    def _setup_inspection_table(self, datapath):
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
 
        # Regla 1: bloquear puertos sensibles en inspección
        for port in SENSITIVE_PORTS:
            match = parser.OFPMatch(
                eth_type=0x0800, ip_proto=6, tcp_dst=port
            )
            self._add_flow(datapath, PRIORITY_BLOCK, match, [],
                           table_id=TABLE_INSPECTION,
                           idle_timeout=0, hard_timeout=0)
 
        # Regla 2: permitir HTTP (80) y HTTPS (443)
        for port in [80, 443]:
            match   = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self._add_flow(datapath, PRIORITY_INSPECT, match, actions,
                           table_id=TABLE_INSPECTION)
 
        # Regla 3: permitir ICMP (ping legítimo entre usuarios)
        match   = parser.OFPMatch(eth_type=0x0800, ip_proto=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self._add_flow(datapath, PRIORITY_INSPECT, match, actions,
                       table_id=TABLE_INSPECTION)
 
        # Regla 4 (table-miss de inspección): todo lo demás va al controlador
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, PRIORITY_DEFAULT, match, actions,
                       table_id=TABLE_INSPECTION)
 
        self.logger.info(f'Tabla de inspección (TABLE {TABLE_INSPECTION}) configurada')
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
 
        # Table-miss en tabla principal → enviar al controlador
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, PRIORITY_DEFAULT, match, actions,
                       table_id=TABLE_MAIN)
 
        # Configurar tabla de inspección profunda
        self._setup_inspection_table(datapath)
 
        self.logger.info(f'Switch {datapath.id} conectado y configurado')
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
 
        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
 
        if eth_pkt is None:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
 
        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst
        dpid    = datapath.id
 
        self.mac_to_port[dpid][src_mac] = in_port
 
        # Verificación desde tabla de inspección
        if self.suspicion_level[src_mac] == LEVEL_HIGH:
            if self._is_legitimate_traffic(pkt):
                self._reset_suspicion(src_mac)
                self._log_event(
                    tipo_ataque  = 'FALSO_POSITIVO',
                    mac_atacante = src_mac,
                    ip_atacante  = self._get_ip(pkt),
                    victimas     = [],
                    accion       = 'LIBERADO',
                    nivel        = LEVEL_NORMAL,
                    detalle      = (
                        f'Host {src_mac} verificado en tabla de inspección — '
                        f'tráfico legítimo confirmado, sospecha reiniciada'
                    ),
                    regla        = None
                )
 
        # Análisis de paquetes
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
 
        if arp_pkt:
            self._analyze_arp(datapath, src_mac, arp_pkt)
 
        if ip_pkt:
            self._analyze_ip(datapath, src_mac, ip_pkt, pkt)
 
        # Reenvío si no fue bloqueado 
        if src_mac not in self.isolated_hosts:
            self._forward_packet(datapath, msg, src_mac, dst_mac, in_port)
 
    def _analyze_arp(self, datapath, src_mac, arp_pkt):
        src_ip = arp_pkt.src_ip
 
        # Ignorar hosts de confianza con su IP correcta
        if src_mac in TRUSTED_HOSTS and TRUSTED_HOSTS[src_mac] == src_ip:
            return
 
        anomalia_detectada = False
        tipo_anomalia      = None
 
        # Spoofing: IP conocida con MAC diferente
        if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
            mac_registrada = self.arp_table[src_ip]
            anomalia_detectada = True
            tipo_anomalia      = 'ARP_SPOOFING'
            detalle = (
                f'IP {src_ip} registrada con {mac_registrada}, '
                f'ahora anunciada por {src_mac}'
            )
            regla = self._get_rule('Spoofing')
 
        # MitM: misma MAC anuncia múltiples IPs 
        self.mac_ip_announcements[src_mac].add(src_ip)
        if len(self.mac_ip_announcements[src_mac]) > 1 and not anomalia_detectada:
            ips = list(self.mac_ip_announcements[src_mac])
            anomalia_detectada = True
            tipo_anomalia      = 'MITM'
            detalle = (
                f'MAC {src_mac} anunció múltiples IPs: {ips} '
                f'— patrón de intercepción bidireccional'
            )
            regla = self._get_rule('MitM')
 
        if not anomalia_detectada:
            self.arp_table[src_ip] = src_mac
            return
 
        # Escalar nivel y aplicar acción 
        nivel = self._escalate(src_mac, tipo_anomalia)
 
        self._log_event(
            tipo_ataque  = tipo_anomalia,
            mac_atacante = src_mac,
            ip_atacante  = src_ip,
            victimas     = [src_ip],
            accion       = LEVEL_LABELS[nivel],
            nivel        = nivel,
            detalle      = detalle,
            regla        = regla
        )
 
        if nivel == LEVEL_SUSPECT:
            # Primera anomalía — enviar al controlador para verificar
            self._action_controller(
                datapath, src_mac,
                f'Primera inconsistencia ARP detectada ({tipo_anomalia})'
            )
 
        elif nivel == LEVEL_HIGH:
            # Segunda anomalía — inspección profunda
            self._action_goto_table(
                datapath, src_mac,
                f'Patrón repetido ({tipo_anomalia}) — enviando a TABLE_INSPECTION'
            )
 
        elif nivel == LEVEL_CONFIRMED:
            # Ataque confirmado — bloqueo definitivo
            self._action_drop(datapath, src_mac)
 
    def _analyze_ip(self, datapath, src_mac, ip_pkt, pkt):
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
 
        if src_mac in TRUSTED_HOSTS:
            return
 
        tcp_pkt = pkt.get_protocol(tcp.tcp)
 
        # Acceso a puertos sensibles (MitM) 
        if tcp_pkt and tcp_pkt.dst_port in SENSITIVE_PORTS:
            tipo_anomalia = 'MITM_PUERTO_SENSIBLE'
            nivel = self._escalate(src_mac, tipo_anomalia)
            regla = self._get_rule('MitM')
 
            self._log_event(
                tipo_ataque  = tipo_anomalia,
                mac_atacante = src_mac,
                ip_atacante  = src_ip,
                victimas     = [dst_ip],
                accion       = LEVEL_LABELS[nivel],
                nivel        = nivel,
                detalle      = (
                    f'Acceso al puerto sensible {tcp_pkt.dst_port} '
                    f'desde host no autorizado {src_mac}'
                ),
                regla        = regla
            )
 
            if nivel == LEVEL_SUSPECT:
                self._action_controller(
                    datapath, src_mac,
                    f'Primer acceso a puerto sensible {tcp_pkt.dst_port}'
                )
            elif nivel == LEVEL_HIGH:
                self._action_goto_table(
                    datapath, src_mac,
                    f'Acceso repetido a puertos sensibles'
                )
            elif nivel == LEVEL_CONFIRMED:
                self._action_block_port(datapath, src_mac, tcp_pkt.dst_port)
 
        # Distribución de Malware 
        self.connection_map[src_mac].add(dst_ip)
 
        if len(self.connection_map[src_mac]) >= MALWARE_SPREAD_THRESHOLD:
            tipo_anomalia = 'MALWARE_DISTRIBUTION'
            nivel = self._escalate(src_mac, tipo_anomalia)
            regla = self._get_rule('Malware')
            victimas = list(self.connection_map[src_mac])
 
            self._log_event(
                tipo_ataque  = tipo_anomalia,
                mac_atacante = src_mac,
                ip_atacante  = src_ip,
                victimas     = victimas,
                accion       = LEVEL_LABELS[nivel],
                nivel        = nivel,
                detalle      = (
                    f'Host {src_mac} conectado a {len(victimas)} '
                    f'destinos distintos: {victimas}'
                ),
                regla        = regla
            )
 
            if nivel == LEVEL_SUSPECT:
                self._action_controller(
                    datapath, src_mac,
                    f'Primeras conexiones múltiples detectadas ({len(victimas)} destinos)'
                )
            elif nivel == LEVEL_HIGH:
                self._action_goto_table(
                    datapath, src_mac,
                    f'Propagación creciente — {len(victimas)} destinos'
                )
            elif nivel == LEVEL_CONFIRMED:
                # Malware confirmado → aislamiento total (riesgo CRÍTICO)
                self._action_isolate(datapath, src_mac)
 
    def _is_legitimate_traffic(self, pkt):
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
 
        if ip_pkt is None:
            return False
 
        # ICMP (ping) es tráfico legítimo entre usuarios
        if ip_pkt.proto == 1:
            return True
 
        # HTTP y HTTPS son legítimos en una red pública
        if tcp_pkt and tcp_pkt.dst_port in [80, 443]:
            return True
 
        return False
 
    def _get_ip(self, pkt):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        return ip_pkt.src if ip_pkt else 'N/A'
 
    def _forward_packet(self, datapath, msg, src_mac, dst_mac, in_port):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        dpid    = datapath.id
 
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
 
        actions = [parser.OFPActionOutput(out_port)]
 
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst_mac, eth_src=src_mac
            )
            self._add_flow(datapath, PRIORITY_DEFAULT, match, actions)
 
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)