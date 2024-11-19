from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import socket
import struct

class DNSResolver(QMainWindow):
    def __init__(self, *args, **kwargs):
        super(DNSResolver, self).__init__(*args, **kwargs)

        # Set up the main window
        self.setWindowTitle("DNS Resolver")

        # Set up main layout with tab widget
        self.layout = QVBoxLayout()
        self.tab_widget = QTabWidget()

        # First tab: Main Query Input
        self.main_tab = QWidget()
        self.setup_main_tab()
        self.tab_widget.addTab(self.main_tab, "Query")

        # Second tab: Parsed DNS Response
        self.response_tab = QWidget()
        self.response_view = QTextEdit()
        self.response_view.setReadOnly(True)
        self.response_tab.setLayout(QVBoxLayout())
        self.response_tab.layout().addWidget(self.response_view)
        self.tab_widget.addTab(self.response_tab, "Response")

        # Third tab: Binary Response
        self.binary_tab = QWidget()
        self.binary_view = QTextEdit()
        self.binary_view.setReadOnly(True)
        self.binary_tab.setLayout(QVBoxLayout())
        self.binary_tab.layout().addWidget(self.binary_view)
        self.tab_widget.addTab(self.binary_tab, "Binary Response")

        # Fourth tab: Human-readable Detailed Response
        #self.decoded_tab = QWidget()
        #self.decoded_view = QTextEdit()
        #self.decoded_view.setReadOnly(True)
        #self.decoded_tab.setLayout(QVBoxLayout())
        #self.decoded_tab.layout().addWidget(self.decoded_view)
        #self.tab_widget.addTab(self.decoded_tab, "Decoded Response")

        # Add the tab widget to the main layout
        self.layout.addWidget(self.tab_widget)
        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

        self.resize(900, 600)

        # Show the main window
        self.show()

    def setup_main_tab(self):
        # Setup main tab layout
        layout = QVBoxLayout()

        # DNS server input (Line Edit or ComboBox for selection)
        self.dns_server_input = QLineEdit()
        self.dns_server_input.setPlaceholderText("Enter DNS server address")

        # Domain input and query type selection
        self.domain_bar = QTextEdit()
        self.domain_bar.setMaximumHeight(30)
        self.domain_bar.setPlaceholderText("Enter domain to resolve")
        self.query_type_combo = QComboBox()
        self.query_type_combo.addItems(["A", "MX", "NS", "CNAME", "TXT"])

        # Resolve button
        self.resolve_btn = QPushButton("Resolve")
        self.resolve_btn.setMinimumHeight(30)
        self.resolve_btn.clicked.connect(self.resolve_domain)

        # Arrange input widgets
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.domain_bar)
        input_layout.addWidget(self.dns_server_input)
        input_layout.addWidget(self.query_type_combo)
        input_layout.addWidget(self.resolve_btn)
        
        layout.addLayout(input_layout)
        self.main_tab.setLayout(layout)

    def parse_flags(self, flags):
        # Convertir los bytes de las flags (2 bytes) a un string en binario
        flags_bin = format(struct.unpack('>H', flags)[0], '016b')
        
        flag_details = []
        # Agregar la representación de las flags en hexadecimal
        flag_details.append(f"Flags: 0x{flags.hex()} Standard query response")
        
        # Dividir las flags en sus partes e interpretarlas
        # Bit 0: Query/Response
        flag_details.append(f"{'1' if flags_bin[0] == '1' else '0'}... .... .... .... = Response: Message is a {'response' if flags_bin[0] == '1' else 'query'}")
        # Bits 1-4: OPCODE (Operation Code)
        flag_details.append(f".{flags_bin[1:5]} .... .... .... = Opcode: {['Standard query', 'Inverse query', 'Server status request'][int(flags_bin[1:5], 2) if int(flags_bin[1:5], 2) < 3 else 0]} ({int(flags_bin[1:5], 2)})")
        # Bit 5: AA (Authoritative Answer) flag
        flag_details.append(f".... .{flags_bin[5]}.. .... .... = Authoritative: Server {'is' if flags_bin[5] == '1' else 'is not'} an authority for domain")
        # Bit 6: TC (Truncation) flag
        flag_details.append(f".... ..{flags_bin[6]}. .... .... = Truncated: Message is {'truncated' if flags_bin[6] == '1' else 'not truncated'}")
        # Bit 7: RD (Recursion Desired) flag
        flag_details.append(f".... ...{flags_bin[7]} .... .... = Recursion desired: Do query {'recursively' if flags_bin[7] == '1' else 'iteratively'}")
        # Bit 8: RA (Recursion Available) flag
        flag_details.append(f".... .... {flags_bin[8]}... .... = Recursion available: Server {'can' if flags_bin[8] == '1' else 'cannot'} do recursive queries")
        # Bit 9: Z (Reserved) flag
        flag_details.append(f".... .... .{flags_bin[9]}.. .... = Z: reserved (0)")
        # Bit 10: AD (Authenticated Data) flag
        flag_details.append(f".... .... ..{flags_bin[10]}. .... = Answer authenticated: Answer/authority portion was {'authenticated' if flags_bin[10] == '1' else 'not authenticated'} by the server")
        # Bit 11: CD (Checking Disabled) flag
        flag_details.append(f".... .... ...{flags_bin[11]} .... = Non-authenticated data: {'Acceptable' if flags_bin[11] == '1' else 'Unacceptable'}")
        # Bits 12-15: RCODE (Response Code)
        flag_details.append(f".... .... .... {format(int(flags_bin[12:], 2), '04x')} = Reply code: {['No error', 'Format error', 'Server failure', 'Name error', 'Not implemented', 'Refused'][int(flags_bin[12:], 2) if int(flags_bin[12:], 2) < 6 else 0]} ({int(flags_bin[12:], 2)})")
        
        return '\n'.join(flag_details)

    def parse_dns_response(self, response, query_type):
        try:
            # Guardar todas las partes de la respuesta en una lista
            detailed_response = []
            
            # Dividir el header (12 bytes) de la respuesta
            # Bytes 0-1: Transaction ID
            transaction_id = response[:2]
            # Bytes 2-3: Flags
            flags = response[2:4]
            # Bytes 4-5: Questions count
            qdcount = struct.unpack(">H", response[4:6])[0]
            # Bytes 6-7: Answer count
            ancount = struct.unpack(">H", response[6:8])[0]
            # Bytes 8-9: Authority record count
            nscount = struct.unpack(">H", response[8:10])[0]
            # Bytes 10-11: Additional record count
            arcount = struct.unpack(">H", response[10:12])[0]
            
            # Dividir y agregar las flags
            detailed_response.append(self.parse_flags(flags))
            # Agregar la cuenta de Questions, Answers, Authority records y Additional records
            detailed_response.append(f"Questions: {qdcount}")
            detailed_response.append(f"Answer RRs: {ancount}")
            detailed_response.append(f"Authority RRs: {nscount}")
            detailed_response.append(f"Additional RRs: {arcount}")
            
            # Dividr la sección de Queries
            detailed_response.append("Queries")
            offset = 12 # Comenzar después del header
            for _ in range(qdcount):
                # Parsear el nombre del query
                qname, offset = self.parse_name_with_offset(response, offset)
                # Obtener tipo de query y clase
                qtype = struct.unpack(">H", response[offset:offset+2])[0]
                qclass = struct.unpack(">H", response[offset+2:offset+4])[0]
                offset += 4
                
                # Agregar la información del query a la respuesta detallada
                detailed_response.append(f"    {qname}: type {self.get_type_name(qtype)}, class IN")
                detailed_response.append(f"        Name: {qname}")
                detailed_response.append(f"        [Name Length: {len(qname)}]")
                detailed_response.append(f"        [Label Count: {len(qname.split('.'))}]")
                detailed_response.append(f"        Type: {self.get_type_name(qtype)} ({qtype})")
                detailed_response.append(f"        Class: IN (0x{format(qclass, '04x')})")
            
            if ancount > 0:
                detailed_response.append("Answers:")
                for _ in range(ancount):
                    name, offset = self.parse_name_with_offset(response, offset)
                    record_info, offset = self.parse_record(response, offset, name)
                    detailed_response.append(f"    {record_info}")

            if nscount > 0:
                detailed_response.append("Authoritative nameservers:")
                for _ in range(nscount):
                    name, offset = self.parse_name_with_offset(response, offset)
                    record_info, offset = self.parse_record(response, offset, name)
                    detailed_response.append(f"    {record_info}")
            
            if arcount > 0:
                detailed_response.append("Additional records:")
                for _ in range(arcount):
                    name, offset = self.parse_name_with_offset(response, offset)
                    record_info, offset = self.parse_record(response, offset, name)
                    detailed_response.append(f"    {record_info}")
            
            return '\n'.join(detailed_response)
            
        except Exception as e:
            return f"Error parsing DNS response: {str(e)}"
        
    def parse_record(self, response, offset, name):
        # Obtener el tipo de registro desde la respuesta con el offset dado (2 bytes)
        record_type = struct.unpack(">H", response[offset:offset+2])[0]
        # Obtener la clase que usualmente es 1 IN (2 bytes)
        record_class = struct.unpack(">H", response[offset+2:offset+4])[0]
        # Obtener el TTL (4 bytes)
        ttl = struct.unpack(">I", response[offset+4:offset+8])[0]
        # Obtener la longitud de los datos (2 bytes)
        data_len = struct.unpack(">H", response[offset+8:offset+10])[0]
        # Mover el offset 10 bytes para llegar a los datos
        offset += 10

        # Manejar el registro A
        if record_type == 1: 
            ip = ".".join(str(x) for x in response[offset:offset+data_len])
            record_info = f"{name}: type A, class IN, addr {ip}"
        # Manejar resgitro NS
        elif record_type == 2:  
            ns_name, _ = self.parse_name_with_offset(response, offset)
            record_info = f"{name}: type NS, class IN, ns {ns_name}"
        # Manejar resgitro CNAME
        elif record_type == 5:  
            cname, _ = self.parse_name_with_offset(response, offset)
            record_info = f"{name}: type CNAME, class IN, cname {cname}"
        # Manejar el registro SOA
        elif record_type == 6:  
            current_offset = offset
            # Parse el nombre del servidor primario
            primary_ns, current_offset = self.parse_name_with_offset(response, current_offset)
            # Parse el responsible authority's mailbox
            resp_mailbox, current_offset = self.parse_name_with_offset(response, current_offset)
            # Parse los campos numericos (agregar 4 bytes a current_offset)
            serial = struct.unpack(">I", response[current_offset:current_offset+4])[0]
            current_offset += 4
            refresh = struct.unpack(">I", response[current_offset:current_offset+4])[0]
            current_offset += 4
            retry = struct.unpack(">I", response[current_offset:current_offset+4])[0]
            current_offset += 4
            expire = struct.unpack(">I", response[current_offset:current_offset+4])[0]
            current_offset += 4
            minimum = struct.unpack(">I", response[current_offset:current_offset+4])[0]
            
            # Mostrar el registro SOA de forma detallada
            record_info = f"{name}: type SOA, class IN, mname {primary_ns}\n"
            record_info += f"    Name: {name}\n"
            record_info += f"    Type: SOA (6) (Start Of a zone of Authority)\n"
            record_info += f"    Class: IN (0x0001)\n"
            record_info += f"    Time to live: {ttl} ({ttl} seconds)\n"
            record_info += f"    Data length: {data_len}\n"
            record_info += f"    Primary name server: {primary_ns}\n"
            record_info += f"    Responsible authority's mailbox: {resp_mailbox}\n"
            record_info += f"    Serial Number: {serial}\n"
            record_info += f"    Refresh Interval: {refresh} ({refresh//60} minutes)\n"
            record_info += f"    Retry Interval: {retry} ({retry//60} minutes)\n"
            record_info += f"    Expire limit: {expire} ({expire//60} minutes)\n"
            record_info += f"    Minimum TTL: {minimum} ({minimum//60} minute{'s' if minimum//60 != 1 else ''})"
        
        # Manejar el registro MX
        elif record_type == 15: 
            # Parse el numero de preferencia (2 bytes)
            preference = struct.unpack(">H", response[offset:offset+2])[0]
            # Parse el nombre del servidor de correo (MX)
            mx_name, _ = self.parse_name_with_offset(response, offset+2)
            record_info = f"{name}: type MX, class IN, preference {preference}, mx {mx_name}"

        # Manejar el registro TXT
        elif record_type == 16:  
            txt_strings = []
            current_offset = offset
            remaining_len = data_len
            
            # Leer los strings de texto mientras haya datos restantes
            while remaining_len > 0:
                txt_len = response[current_offset]
                current_offset += 1
                # Extraer el texto y decodificarlo como UTF-8
                txt_data = response[current_offset:current_offset + txt_len].decode('utf-8', errors='replace')
                txt_strings.append(txt_data)
                current_offset += txt_len
                remaining_len -= (txt_len + 1)
            
            # Unir los strings de texto en un solo string
            txt_content = ' '.join(txt_strings)
            record_info = f"{name}: type TXT, class IN, txt = \"{txt_content}\""
        else:
            record_info = f"{name}: type {self.get_type_name(record_type)}, class IN"
        
        offset += data_len
        return record_info, offset

    def get_type_name(self, type_code):
        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            15: "MX",
            16: "TXT",
        }
        return types.get(type_code, f"TYPE{type_code}")

    def parse_name_with_offset(self, response, offset):
        name_parts = []
        original_offset = offset
        
        while True:
            # Obtener la longitud de bytes del offset actual
            length = response[offset]
            # Si es 0 se llego al final del nombre de dominio
            if length == 0:
                offset += 1
                break

            # Buscar si hay compresion DNS
            # Ver si los 2 mas significativos estan encendidos (0xC0 = 11000000)
            # Esto significa que hay un puntero a otra parte del mensaje  
            if length & 0xC0 == 0xC0:
                # Extraer el valor del puntero (14 bits):
                # 1. Tomando 2 bytes empezando desde el offset actual
                # 2. Convertir a entero de 16b (">H")
                # 3. Agregando mascara a los primeros 2 bits (0x3FFF = 00111111 11111111)
                pointer = struct.unpack(">H", response[offset:offset+2])[0] & 0x3FFF
                # Dividir el nombre de forma recursiva donde se encuentra el puntero
                # Extender la lista con los resultados
                name_parts.extend(self.parse_name(response, pointer).split('.'))
                offset += 2 # Avanzar 2 bytes del puntero
                break
            
            # Si no hay compresion DNS, leer el nombre normalmente
            offset += 1 # Pasar al siguiente byte
            # Extraer el label y decodificar como ASCII
            name_parts.append(response[offset:offset+length].decode())
            offset += length # Pasar despues del label
            
        return '.'.join(name_parts), offset

    def get_type_name(self, type_code):
        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            15: "MX",
            16: "TXT",
        }
        return types.get(type_code, f"TYPE{type_code}")

    def resolve_domain(self):
        try:
            # Obtener el dominio del input
            domain = self.domain_bar.toPlainText().strip()
            # Obtener el tipo de resgistro DNS del combo box
            query_type = self.query_type_combo.currentText()
            if domain:
                # Obtener la respuesta en binario
                raw_response, binary_string = self.get_dns_response(domain, query_type)
                # Mostrar la respuesta decodificada detallada
                self.response_view.setPlainText(self.parse_dns_response(raw_response, query_type))
                # Mostrar la respuesta en binario
                self.binary_view.setPlainText(binary_string)
                # Mostrar la respuesta decodificada simple
                #self.decoded_view.setPlainText(self.parse_simple_response(raw_response, query_type))
            else:
                self.response_view.setPlainText("Please enter a valid domain.")
        except Exception as e:
            self.response_view.setPlainText(f"Error: {str(e)}")
            self.binary_view.setPlainText("")
            #self.decoded_view.setPlainText("")

    def get_dns_response(self, domain, query_type):
        # Definir el DNS a utilizar
        dns_server = self.dns_server_input.text() 
        # Crear la comunicacion por socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(5)  # Set timeout to 5 seconds

        # Construir el query DNS
        query = self.build_dns_query(domain, query_type)
        
        try:
            # Mandar el query por el puerto 53
            client_socket.sendto(query, (dns_server, 53))
            # Recibir la respuesta definiendo el tamaño de buffer a 512 bytes
            response, _ = client_socket.recvfrom(512)
            
            # Convertir el binario a uns string binario
            binary_string = ' '.join(format(byte, '08b') for byte in response)
            
            return response, binary_string
        finally:
            # Cerrar el socket
            client_socket.close()
    
    def build_dns_query(self, domain, query_type):
        query_type_codes = {
            "A": b'\x00\x01',
            "AAAA": b'\x00\x1c',
            "MX": b'\x00\x0f',
            "NS": b'\x00\x02',
            "CNAME": b'\x00\x05',
            "TXT": b'\x00\x10'
        }
        
        query_id = b'\x12\x34'  # Query ID
        flags = b'\x01\x00'  # Flags
        qdcount = b'\x00\x01'  # Number of questions
        ancount = b'\x00\x00'  # Number of answers
        nscount = b'\x00\x00'  # Number of authority records
        arcount = b'\x00\x00'  # Number of additional records

        # Construir el nombre del dominio dividiendolo en partes y codificandolo
        qname = b''.join([bytes([len(part)]) + part.encode() for part in domain.split('.')]) + b'\x00'
        #print(qname)
        # Tipo de query
        qtype = query_type_codes.get(query_type, b'\x00\x01')  # Default to A if not found
        qclass = b'\x00\x01'  # Class IN (Internet)
        # Construir el query completo
        return query_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass

    def parse_name(self, response, offset):
        # Lista para guardar el dominio
        name = []
        # Loop en al respuesta empezando desde el offset
        while response[offset] != 0: # Continuar hasta encontrar un byte nulo
            if response[offset] & 0xC0 == 0xC0:
                # Encontrar un puntero de compresion DNS (14 bits despues de 0xC0)
                ptr_offset = struct.unpack(">H", response[offset:offset+2])[0] & 0x3FFF
                # Dividir de forma recursiva el nombre
                name.append(self.parse_name(response, ptr_offset))
                # Moverse despues de 2 bytes del puntero
                offset += 2
                break
            # Si no hay compresion DNS, leer el label
            length = response[offset]
            # Moverse despues del label
            offset += 1
            # Extraer el label
            name.append(response[offset:offset+length].decode())
            # Moverse despues del label
            offset += length
        return ".".join(name)

if __name__ == "__main__":
    app = QApplication([])
    window = DNSResolver()
    window.show()
    app.exec_()
