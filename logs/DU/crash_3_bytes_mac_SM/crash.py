import socket
import sctp
import time
import random
import re
import json
import sys, json, threading, time, asn1tools, os, subprocess
import tempfile
from binascii import hexlify, unhexlify
import crc32c
from colorama import Fore, Style, init
import _sctp, os 
import select

# Initialize colorama
init(autoreset=True)

if _sctp.getconstant("IPPROTO_SCTP") != 132:
	raise(Exception("getconstant failed"))
MSG_EOF = _sctp.getconstant("MSG_EOF")

# Constants
IP_MITM = "192.168.71.129"
IP_XAPP = "192.168.71.185"
IP_RIC = "192.168.71.184"
PORT = 36422
# Load constraints from JSON file
constraints_file = "/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/constraints_output.json" 

with open(constraints_file, "r") as f:
    constraints = json.load(f)

asn1_files = {
    'E2SM-KPM': asn1tools.compile_files(['/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/asn1files/E2SM-COMMON-IEs.asn', '/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/asn1files/E2SM-KPM-v05.00.asn'], 'per'),
    'E2SM-RC': asn1tools.compile_files(['/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/asn1files/E2SM-COMMON-IEs.asn', '/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/asn1files/e2sm-rc-v3.00.asn'], 'per')
    }

target_keys = ['ricActionDefinition','ricEventTriggerDefinition','value']

definitions = [
    'E2SM-KPM-IndicationMessage',
    #'E2SM-KPM-IndicationHeader',
    #'E2SM-KPM-EventTriggerDefinition',
    'E2SM-KPM-ActionDefinition',
    'RICindicationHeader',
    'E2SM-RC-ControlMessage'
]

protocolIEs = {
    29: "RICrequestID",
    5: "RANfunctionID",
    15: "RICactionID",
    28: "RICindicationType",
    25: "RICindicationHeader",
    26: "RICindicationMessage",
    30: "RICeventTriggerDefinition",
    19: "RICaction-ToBeSetup-List"
}

class JsonFuzzer:
    def __init__(self):
        pass
    
class SCTPMITMProxy:
    def __init__(self, mitm_ip=IP_MITM, xapp_ip=IP_XAPP, ric_ip=IP_RIC, port=PORT):
        self.mitm = mitm_ip
        self.xapp = xapp_ip
        self.ric_ip = ric_ip
        self.port = port
        self.server = None
        self.conn_from_xapp = None
        self.ric_client = None
        self.captures_folder = "/media/p3rplex/data3/Backup_ubuntu22/oran-orchestration/captures_bridge"
             
        # Ensure the captures_bridge folder exists
        if not os.path.exists(self.captures_folder):
            os.makedirs(self.captures_folder)
            print(Fore.GREEN + f"[+] Created folder: {self.captures_folder}")
            
    def start(self):
        try:
            # RIC connection is stable
            self.ric_client = sctp.sctpsocket_tcp(socket.AF_INET)
            self.ric_client.bind((self.mitm, 0))  
            self.ric_client.connect((self.ric_ip, self.port))
            print(Fore.GREEN + f"[+] Connected to RIC at {self.ric_ip}:{self.port}")

            # Set up SCTP server to accept xApp connections
            self.server = sctp.sctpsocket_tcp(socket.AF_INET)
            self.server.bind((self.mitm, self.port))
            self.server.listen(1)
            print(Fore.YELLOW + f"[*] Listening for xApp on {self.mitm}:{self.port}...")

            # Loop to accept new xApp connections
            while True:
                print(Fore.YELLOW + "[*] Waiting for new xApp connection...")
                self.conn_from_xapp, addr = self.server.accept()
                print(Fore.GREEN + f"[+] Accepted xApp connection from {addr}")

                # Handle the traffic in its own function
                try:
                    self.proxy_traffic()
                except Exception as e:
                    print(Fore.RED + f"[-] Proxy error: {e}")
                    import traceback
                    traceback.print_exc()

                # Clean up and wait for new xApp connection
                self.cleanup_xapp()

        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] KeyboardInterrupt: Shutting down proxy.")
        except Exception as e:
            print(Fore.RED + f"[-] Unhandled error in start(): {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.close_all()
                
    def cleanup_xapp(self):
        try:
            if self.conn_from_xapp:
                print(Fore.YELLOW + "[*] Cleaning up xApp connection.")
                self.conn_from_xapp.close()
                self.conn_from_xapp = None
        except Exception as e:
            print(Fore.RED + f"[-] Error during xApp cleanup: {e}")

    def close_all(self):
        try:
            if self.conn_from_xapp:
                self.conn_from_xapp.close()
            if self.ric_client:
                self.ric_client.close()
            if self.server:
                self.server.close()
            print(Fore.CYAN + "[*] Closed all sockets. Goodbye!")
        except Exception as e:
            print(Fore.RED + f"[-] Error closing sockets: {e}")

    def map_procedure_code(self, procedure_code):
        """Map ProcedureCode (as per O-RAN ASN.1 specification) to message types."""
        procedure_mapping = {
            0x01: "E2setup",
            0x02: "ErrorIndication",
            0x03: "Reset",
            0x04: "RICcontrol",
            0x05: "RICindication",
            0x06: "RICserviceQuery",
            0x07: "RICserviceUpdate",
            0x08: "RICsubscription",
            0x09: "RICsubscriptionDelete",
            0x0A: "E2nodeConfigurationUpdate",
            0x0B: "E2connectionUpdate",
            0x0C: "RICsubscriptionDeleteRequired",
            0x0D: "E2removal",
            0x0E: "E42setup",
            0x0F: "E42RICsubscription",
            0x10: "E42RICsubscriptionDelete",
            0x11: "E42RICcontrol",
            0x12: "E42updateE2node",
            # Add other procedure codes if necessary
        }
        return procedure_mapping.get(procedure_code, "UnknownProcedureCode")

    def guess_message_type(self, msg):
        """Try to identify the message type from SCTP payload using ProcedureCode and ASN.1 structure."""
        try:
            #print(msg)
            if len(msg) < 4:
                print(msg)

                return #"Unknown or Incomplete"
            
            msg_type = msg[0]
            
            # Second byte is typically the ProcedureCode or message type identifier
            procedure_code = msg[1]
            print(f"[*] ProcedureCode: {hex(procedure_code)}")            
            # Determine the message type from ProcedureCode using the map
            message_type = self.map_procedure_code(procedure_code)
            
            # Try to identify more details based on the first byte (msg_type)
            if msg_type == 0:
                return f"InitiatingMessage - {message_type}"
            elif msg_type == 1:
                return f"SuccessfulOutcome - {message_type}"
            elif msg_type == 2:
                return f"UnsuccessfulOutcome - {message_type}"
            else:
                return f"Unknown ({msg_type}) - {message_type}"

        except Exception as e:
            print(Fore.RED + f"Error guessing message type: {e}")
            return "Error guessing message type"
            
    def proxy_traffic(self):
        """Main proxy loop to intercept, fuzz, and forward traffic with robustness."""
        sockets = [self.conn_from_xapp, self.ric_client]
        while True:
            try:
                rlist, _, _ = select.select(sockets, [], [], 10.0)
                if not rlist:
                    print(Fore.YELLOW + "[!] Timeout waiting for packets. Continuing...")
                    continue

                for sock in rlist:
                    if sock == self.conn_from_xapp:
                        start_time = time.time()
                        fromaddr, flags, msg, notif = self.conn_from_xapp.sctp_recv(65535)
                        print(Fore.GREEN + f"[TX] [xApp --> RIC]")
                        # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Received message from xApp:")
                        print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Length: {len(msg)} bytes")
                        # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Flags: {flags}")
                        # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"From Address: {fromaddr}")
                        # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Notification: {notif}")
                        #print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Hex: {hexlify(msg)}")
                        message_type = self.guess_message_type(msg)
                        print(Fore.LIGHTYELLOW_EX + f"[DEBUG] Message Type: {message_type}")
                        modified_msg = self.process_message(msg, direction="to_ric")
                        if not modified_msg:
                            return
                        else:
                            self.ric_client.sctp_send(modified_msg, ppid=socket.htonl(0))
                            end_time = time.time()
                            conversion_time = (end_time - start_time) * 1000  # milliseconds
                            print(Fore.LIGHTCYAN_EX + f"[DEBUG] Overhead: {conversion_time:.2f} ms")

                        print(Fore.YELLOW + "-" * 50)
                    elif sock == self.ric_client:
                        start_time = time.time()
                        fromaddr2, flags2, msg2, notif2 = self.ric_client.sctp_recv(65535)
                        print(Fore.LIGHTBLUE_EX + "[RX] [xApp <-- RIC]")
                        # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Received message from RIC: {hexlify(msg2)}")
                        print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Length: {len(msg2)} bytes")
                        # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Flags: {flags}")
                        # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"From Address: {fromaddr2}")
                        # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Notification: {notif2}")
                        #print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Hex: {hexlify(msg2)}")
                        
                        response_type = self.guess_message_type(msg2)
                        print(Fore.LIGHTYELLOW_EX + f"[DEBUG] Response Type: {response_type}")
                        response = self.process_message(msg2, direction="to_xapp")
                        if not response:
                            return
                        else:
                            self.conn_from_xapp.sctp_send(response, ppid=socket.htonl(0))
                            end_time = time.time()
                            conversion_time = (end_time - start_time) * 1000  # milliseconds
                            print(Fore.LIGHTCYAN_EX + f"[DEBUG] Overhead: {conversion_time:.2f} ms")

                        print(Fore.YELLOW + "-" * 50)

            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] KeyboardInterrupt detected. Exiting cleanly.")
                break
            except Exception as e:
                print(Fore.RED + f"[-] Exception in proxy_traffic loop: {e}")
                import traceback
                traceback.print_exc()
                print(Fore.YELLOW + "[*] Attempting to reset connection...\n")
                time.sleep(2)
                self.close_connections()
                self.start()
                break
        
    def close_connections(self):
        try:
            if self.conn_from_xapp:
                self.conn_from_xapp.close()
            if self.ric_client:
                self.ric_client.close()
            if self.server:
                self.server.close()
        except Exception as e:
            print(Fore.RED + f"[-] Error during connection cleanup: {e}")
            
    def process_message(self, msg, direction="to_ric"):
        """Process the SCTP message, potentially applying fuzzing"""
        try:
            # Convert message to hex for processing
            msg_hex = hexlify(msg).decode()
            #print(f"Before modification ({len(msg)} bytes):")
            #print(f"Hex: {msg_hex[:100]}..." if len(msg_hex) > 100 else f"Hex: {msg_hex}")
            #print(Fore.YELLOW + f"[*] Processing message: {msg_hex}")
            # Only fuzz messages in the to_ric direction
            if direction == "to_ric":
                # Extract the hex data that needs fuzzing
                modified_hex = self.process_and_convert(msg_hex)
                if modified_hex and modified_hex.strip():
                    
                    modified_msg = unhexlify(modified_hex)
                    print(Fore.GREEN + f"[+] Modified message ({len(modified_msg)} bytes)")
                    return modified_msg
                else:
                    #print(Fore.RED + "[-] Skipping modification: produced empty hex string")
                    return msg
            
            # If no modification or in to_xapp direction, return original
            return msg
            
        except Exception as e:
            print(Fore.RED + f"[-] Error processing message: {e}")
            import traceback
            traceback.print_exc()
            return msg  # Return original on error
    
    def is_hex_string(self, value):
        """Check if the string contains only hexadecimal characters."""
        return isinstance(value, str) and re.fullmatch(r'[0-9A-Fa-f]+', value) is not None


    def find_raw_hex(self, json_message, constraints, seen_hex=None):
        """ Recursively find raw hex strings, decode them, mutate fields, and replace in place. """
        if seen_hex is None:
            seen_hex = set()

        if isinstance(json_message, dict):
            for key, value in list(json_message.items()):
                if key in target_keys and self.is_hex_string(value) and value not in seen_hex:
                    seen_hex.add(value)

                    for asn1_name, asn1_compiled in asn1_files.items():
                        for definition in definitions:
                            try:
                                decoded_json = asn1_compiled.decode(definition, unhexlify(value))
                                if decoded_json:
                                    #print(decoded_json)
                                    # Mutate the field and ensure JSON updates
                                    modified_json = self.mutate_field(decoded_json, constraints, "measName")
                                    #print(Fore.CYAN + "[AFTER MUTATION]" + Style.RESET_ALL)
                                    #print(modified_json) 
                                    # Re-encode back to hex
                                    #encoded_json = asn1_compiled.encode(definition, decoded_json)
                                    
                                    encoded_json = asn1_compiled.encode(definition, modified_json)
                                    encoded_hex = hexlify(encoded_json).decode()
                                    
                                    #print("" + Fore.GREEN + f"[+] Re-encoded hex:\n{encoded_hex}")

                                    # Replace hex in the JSON message
                                    json_message[key] = encoded_hex
                                    #print("Mutated JSON", json_message)
                                    return json_message  # Stop after first mutation
                                else: 
                                    continue 
                            except Exception:
                                continue

                # Recursively process nested structures
                json_message[key] = self.find_raw_hex(value, constraints, seen_hex)
                
        elif isinstance(json_message, list):
            for i, item in enumerate(json_message):
                json_message[i] = self.find_raw_hex(item, constraints, seen_hex)
        return json_message
    

    def hex_to_json(self, hex_data):
        """Convert hex data to JSON using the reader tool, ignore empty/incomplete messages."""
        if not hex_data or not str(hex_data).strip():
            # Skip empty or whitespace-only hex input
            return None

        try:
            reader_command = ['/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/reader', '-hex', str(hex_data)]
            reader_output = subprocess.check_output(reader_command).decode('utf-8').strip()

            if not reader_output:
                # Empty output from reader, ignore silently
                return None

            try:
                json_data = json.loads(reader_output)
                return json_data if json_data else None

            except json.JSONDecodeError as e:
                # Ignore known incomplete or garbage messages
                print(Fore.YELLOW + f"[!] Ignored invalid JSON: {e}")
                return None

        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[!] Reader command failed: {e}")
            return None

        except Exception as e:
            print(Fore.RED + f"[!] Unexpected error: {e}")
            return None

    def json_to_hex(self, json_data):
        """Convert JSON data back to hex using the reader_json tool."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                json.dump(json_data, temp_file)
                temp_file_path = temp_file.name
                #print(Fore.YELLOW + f"[*] JSON written to temporary file: {dir(temp_file_path)}")
            try:
                reader_json_command = ['/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/reader_json', '-json', temp_file_path]
                hex_output = subprocess.check_output(reader_json_command).decode('utf-8').strip()
                return hex_output
            finally:
                import os
                os.unlink(temp_file_path)
        
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"reader_json command failed: {e}")
            return None
        except Exception as e:
            print(Fore.RED + f"Error converting JSON to hex: {e}")
            return None
        
##### working but slow!!###
    # def get_random_value(self, constraints, field_name):
    #     """Find a field in constraints JSON and return a random value within min/max."""
    #     stack = [constraints]
    #     seen = False
    #     while stack:
    #         current = stack.pop()
    #         for key, value in current.items():
    #             if key == field_name and isinstance(value, dict) and "min" in value and "max" in value:
    #                 return random.randint(value["min"], value["max"])
    #             elif isinstance(value, dict) and "root_members" in value:
    #                 stack.append(value["root_members"])
    #     return None
    
    def get_random_value(self, constraints, field_name):
        """Find the first matching field in constraints and return a single random value."""
        stack = [constraints]
        seen = False

        while stack:
            current = stack.pop()

            if isinstance(current, dict):
                for key, value in current.items():
                    if key == field_name and isinstance(value, dict) and "min" in value and "max" in value and not seen:
                        seen = True
                        return random.randint(value["min"], value["max"])
                    elif isinstance(value, dict):
                        stack.append(value)
                    elif isinstance(value, list):
                        stack.extend(value)

            elif isinstance(current, list):
                stack.extend(current)

        return None

    def mutate_field(self, json_data, constraints, field_name):
        """Iteratively modify the specified field in the JSON using a consistent random value."""
        random_value = self.get_random_value(constraints, field_name)
        #print(f"[DEBUG] Random value chosen for {field_name}: {random_value}")

        stack = [json_data]

        while stack:
            current = stack.pop()

            if isinstance(current, dict):
                for key in list(current.keys()):
                    value = current[key]
                    if key == field_name and isinstance(value, (int, float)):
                        print(Fore.RED + f"[+] Mutating {field_name}: {value} -> {random_value}")
                        current[key] = random_value
                    elif isinstance(value, (dict, list, tuple)):
                        stack.append(value)

            elif isinstance(current, list):
                for item in current:
                    if isinstance(item, (dict, list, tuple)):
                        stack.append(item)

            elif isinstance(current, tuple):
                for item in list(current):
                    if isinstance(item, (dict, list, tuple)):
                        stack.append(item)

        return json_data
 
    
### RECURSIVE FUNCTION ####
    # def mutate_field(self, json_data, constraints, field_name):
    #     """ Recursively modify the specified field in the JSON. """
        
    #     # Get a random value for the field
    #     random_value = self.get_random_value(constraints, field_name)
    #     print(random_value)
    #     if isinstance(json_data, dict):
    #         for k, v in json_data.items():
    #             if k == field_name and isinstance(v, (int, float)):  # Ensure it's a numeric value
    #                 print(Fore.RED + f"[+] Mutating {field_name}: {v} -> {random_value}")
    #                 json_data[k] = random_value  # Modify in place
    #             elif isinstance(v, (dict, list, tuple)):  # Recursively check inside lists, dicts, and tuples
    #                 json_data[k] = self.mutate_field(v, constraints, field_name)

    #     elif isinstance(json_data, list):  # If it's a list, iterate over each item
    #         for i, item in enumerate(json_data):
    #             json_data[i] = self.mutate_field(item, constraints, field_name)

    #     elif isinstance(json_data, tuple):  # If it's a tuple, convert to list, mutate, and convert back
    #         json_data = list(json_data)
    #         for i, item in enumerate(json_data):
    #             json_data[i] = self.mutate_field(item, constraints, field_name)
    #         return tuple(json_data)
    #     #print(Fore.YELLOW + f"[+] Final mutated JSON:\n{json_data}")
    #     return json_data

    
    def process_and_convert(self, hex_data):
        global constraints
        """Convert hex data to JSON, mutate fields, and re-encode."""
        
        if hex_data.startswith("200e00") or hex_data.startswith("2e000091") \
            or hex_data.startswith("000e0081e7") or hex_data is None:
            #print(Fore.YELLOW + "Skipping decoding for packet with specified prefix.")
            return
        print(Fore.GREEN + f"Original message encoded:\n{hex_data}")
        json_data = self.hex_to_json(hex_data)
        
        if json_data:
            print(Fore.GREEN + "Converted to JSON:")
            print(json.dumps(json_data, indent=2))

            # Apply mutation
            modified_json = self.find_raw_hex(json_data, constraints)
            print(Fore.YELLOW + "Mutated Message:")
            print(json.dumps(modified_json, indent=2))
            
            new_hex = self.json_to_hex(modified_json)
            print(Fore.GREEN + f"[+] Encoded again:\n{new_hex}")
            return new_hex


    def _create_new_session_file(self):
        """Create a new session file with a unique name."""
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        self.session_file = os.path.join(self.captures_folder, f"session_{timestamp}.pcap")
        self.pcap_writer = PcapWriter(self.session_file, append=False, sync=True)
        print(Fore.GREEN + f"[+] New session started. Writing packets to: {self.session_file}")

    def _split_and_save(self):
        """Close the current session file, generate the state machine, and start a new session."""
        if self.pcap_writer:
            self.pcap_writer.close()
            print(Fore.GREEN + f"[+] Closed session file: {self.session_file}")
        
        # Generate the state machine for the closed session
        self._generate_state_machine()
        
        # Generate the diff between the current and previous session
        if self.previous_session_file:
            self._generate_diff(self.session_file, self.previous_session_file,)
        
        # Update the previous session file
        self.previous_session_file = self.session_file
        
        # Start a new session
        self._create_new_session_file()
        
        self.timer = threading.Timer(20.0, self._split_and_save) # res
        self.timer.start()

    def _generate_state_machine(self):
        """
        Generate a state machine from the session's PCAP file using the wdmapper command.
        """
        if not self.session_file:
            print(Fore.RED + "[-] No session file found. Cannot generate state machine.")
            return

        # Construct the wdmapper command
        wdmapper_gen_state_m = [
            "./bin/wdmapper",
            "--udp-dst-port=36421,38412,9999,38472,38412,36422",
            "-i", self.session_file,
            "-c", "./configs/5gnr_gnb_config.json",
            "-o", "wdmapper_tmp.svg"
        ]

        print(Fore.YELLOW + f"[*] Generating state machine for session: {self.session_file}")
        print(Fore.CYAN + f"[*] Command: {' '.join(wdmapper_gen_state_m)}")

        try:
            print(Fore.YELLOW + "[*] Running wdmapper command...")
            
            # Run the wdmapper command
            result = subprocess.run(
                wdmapper_gen_state_m,
                capture_output=True,
                text=True,
                cwd="./vakt-ble-defender/PortableSetup/wdissector",
                check=True  # Raises CalledProcessError if return code != 0
            )

            print(Fore.GREEN + "[+] State machine generated successfully.")
            if result.stdout.strip():
                print(f"[*] Output:\n{result.stdout}")

        except FileNotFoundError:
            print(Fore.RED + "[-] Error: wdmapper command not found. Check if the executable exists and has the correct path.")

        except PermissionError:
            print(Fore.RED + "[-] Permission denied. Try running with 'chmod +x wdmapper' or using sudo.")

        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] wdmapper failed with return code {e.returncode}.")
            if e.stderr:
                print(Fore.LIGHTRED_EX + f"[*] Error Output:\n{e.stderr}")

        except Exception as e:
            print(Fore.RED + f"[-] Unexpected error: {str(e)}")

    def _generate_diff(self, current_file,previous_file):

        if not previous_file or not current_file:
            print(Fore.RED + "[-] Missing previous or current session file. Cannot generate diff.")
            return

        # Construct the wdmapper command for diffing
        wdmapper_gen_diff = [
            "./bin/wdmapper",
            "-d", '../../../captures/true_baseline.pcapng',
            "-i", current_file,
            "-c", "./configs/5gnr_gnb_config.json",
            "-o", "wdmapperdiff.svg"
            #"-o", os.path.join(self.diff_folders, f"diff_{os.path.basename(current_file)}.json")
        ]
        print(current_file)
        print(Fore.YELLOW + f"[*] Generating diff between {previous_file} and {current_file}")
        print(Fore.CYAN + f"[*] Command: {' '.join(wdmapper_gen_diff)}")

        try:
            print(Fore.YELLOW + "[*] Running wdmapper diff command with baseline State Machine...")
            
            # Run the wdmapper command
            result = subprocess.run(
                wdmapper_gen_diff,
                capture_output=True,
                text=True,
                cwd="./vakt-ble-defender/PortableSetup/wdissector",
                check=True  # Raises CalledProcessError if return code != 0
            )

            print(Fore.GREEN + "[+] Diff generated successfully.")
            if result.stdout.strip():
                print(f"[*] Output:\n{result.stdout}")

        except FileNotFoundError:
            print(Fore.RED + "[-] Error: wdmapper command not found. Check if the executable exists and has the correct path.")

        except PermissionError:
            print(Fore.RED + "[-] Permission denied. Try running with 'chmod +x wdmapper' or using sudo.")

        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] wdmapper failed with return code {e.returncode}.")
            if e.stderr:
                print(Fore.LIGHTRED_EX + f"[*] Error Output:\n{e.stderr}")

        except Exception as e:
            print(Fore.RED + f"[-] Unexpected error: {str(e)}")

        

def main():
    print(Fore.CYAN + "=" * 50)
    print(Fore.CYAN + "            SCTP MITM Proxy - Starting   ")
    print(Fore.CYAN + "=" * 50)
    
    # Initialize the fuzzer
    fuzzer = SCTPMITMProxy()
    
    # Start the MITM
    fuzzer.start()

if __name__ == "__main__":
    main()