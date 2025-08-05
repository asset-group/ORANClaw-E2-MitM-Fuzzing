
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
import string
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
constraints_file = "/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/constraints_output_test.json" 

with open(constraints_file, "r") as f:
    constraints = json.load(f)

asn1_files = {
    'E2SM-KPM': asn1tools.compile_files(['/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/asn1files/E2SM-COMMON-IEs.asn', '/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/asn1files/E2SM-KPM-v05.00.asn'], 'per'),
    'E2SM-RC': asn1tools.compile_files(['/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/asn1files/E2SM-COMMON-IEs.asn', '/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/asn1files/e2sm-rc-v3.00.asn'], 'per')
    #'E2SM-CTRL1': asn1tools.compile_files(['./asn1files/E2SM-COMMON-IEs.asn', './asn1files/e2sm-rc-v3.00.asn'], 'per'),
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
    1: "Cause",
    2: "CriticalityDiagnostics",
    3: "GlobalE2node-ID",
    4: "GlobalRIC-ID",
    5: "RANfunctionID",
    6: "RANfunctionID-Item",
    7: "RANfunctionIEcause-Item",
    8: "RANfunction-Item",
    9: "RANfunctionsAccepted",
    10: "RANfunctionsAdded",
    11: "RANfunctionsDeleted",
    12: "RANfunctionsModified",
    13: "RANfunctionsRejected",
    14: "RICaction-Admitted-Item",
    15: "RICactionID",
    16: "RICaction-NotAdmitted-Item",
    17: "RICactions-Admitted",
    18: "RICactions-NotAdmitted",
    19: "RICaction-ToBeSetup-Item",
    20: "RICcallProcessID",
    21: "RICcontrolAckRequest",
    22: "RICcontrolHeader",
    23: "RICcontrolMessage",
    24: "RICcontrolStatus",
    25: "RICindicationHeader",
    26: "RICindicationMessage",
    27: "RICindicationSN",
    28: "RICindicationType",
    29: "RICrequestID",
    30: "RICsubscriptionDetails",
    31: "TimeToWait",
    32: "RICcontrolOutcome",
    33: "E2nodeComponentConfigUpdate",
    34: "E2nodeComponentConfigUpdate-Item",
    35: "E2nodeComponentConfigUpdateAck",
    36: "E2nodeComponentConfigUpdateAck-Item",
    39: "E2connectionSetup",
    40: "E2connectionSetupFailed",
    41: "E2connectionSetupFailed-Item",
    42: "E2connectionFailed-Item",
    43: "E2connectionUpdate-Item",
    44: "E2connectionUpdateAdd",
    45: "E2connectionUpdateModify",
    46: "E2connectionUpdateRemove",
    47: "E2connectionUpdateRemove-Item",
    48: "TNLinformation",
    49: "TransactionID",
    50: "E2nodeComponentConfigAddition",
    51: "E2nodeComponentConfigAddition-Item",
    52: "E2nodeComponentConfigAdditionAck",
    53: "E2nodeComponentConfigAdditionAck-Item",
    54: "E2nodeComponentConfigRemoval",
    55: "E2nodeComponentConfigRemoval-Item",
    56: "E2nodeComponentConfigRemovalAck",
    57: "E2nodeComponentConfigRemovalAck-Item",
    58: "E2nodeTNLassociationRemoval",
    59: "E2nodeTNLassociationRemoval-Item",
    60: "RICsubscriptionToBeRemoved",
    61: "RICsubscription-withCause-Item",
    62: "RICsubscriptionStartTime",
    63: "RICsubscriptionEndTime",
    64: "RICeventTriggerDefinitionToBeModified",
    65: "RICactionsToBeRemovedForModification-List",
    66: "RICaction-ToBeRemovedForModification-Item",
    67: "RICactionsToBeModifiedForModification-List",
    68: "RICaction-ToBeModifiedForModification-Item",
    69: "RICactionsToBeAddedForModification-List",
    70: "RICaction-ToBeAddedForModification-Item",
    71: "RICactionsRemovedForModification-List",
    72: "RICaction-RemovedForModification-Item",
    73: "RICactionsFailedToBeRemovedForModification-List",
    74: "RICaction-FailedToBeRemovedForModification-Item",
    75: "RICactionsModifiedForModification-List",
    76: "RICaction-ModifiedForModification-Item",
    77: "RICactionsFailedToBeModifiedForModification-List",
    78: "RICaction-FailedToBeModifiedForModification-Item",
    79: "RICactionsAddedForModification-List",
    80: "RICaction-AddedForModification-Item",
    81: "RICactionsFailedToBeAddedForModification-List",
    82: "RICaction-FailedToBeAddedForModification-Item",
    83: "RICactionsRequiredToBeModified-List",
    84: "RICaction-RequiredToBeModified-Item",
    85: "RICactionsRequiredToBeRemoved-List",
    86: "RICaction-RequiredToBeRemoved-Item",
    87: "RICactionsConfirmedForModification-List",
    88: "RICaction-ConfirmedForModification-Item",
    89: "RICactionsRefusedToBeModified-List",
    90: "RICaction-RefusedToBeModified-Item",
    91: "RICactionsConfirmedForRemoval-List",
    92: "RICaction-ConfirmedForRemoval-Item",
    93: "RICactionsRefusedToBeRemoved-List",
    94: "RICaction-RefusedToBeRemoved-Item",
    95: "RICqueryHeader",
    96: "RICqueryDefinition",
    97: "RICqueryOutcome",
    98: "XAPP-ID",
    99: "E2nodesConnected",
    100: "NODEfunctionID-Item"
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
        self.fuzz_success_rate = {}  # Track fuzzing success rate by message type
        
        # Fuzzing statistics
        self.messages_processed = 0
        self.messages_fuzzed = 0
        self.fuzzing_start_time = time.time()
        
        # Fuzzing configuration
        self.fuzz_enabled = True
        self.fuzz_probability = 0.7  # 70% chance to fuzz each message
        self.max_mutations = 1  # Maximum mutations per message
        
        
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
            self.print_statistics()
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


    def print_statistics(self):
        """Print fuzzing statistics."""
        runtime = time.time() - self.fuzzing_start_time
        hours, remainder = divmod(runtime, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        print(Fore.CYAN + "=" * 50)
        print(Fore.CYAN + "            FUZZING STATISTICS            ")
        print(Fore.CYAN + "=" * 50)
        print(f"Runtime: {int(hours)}h {int(minutes)}m {int(seconds)}s")
        print(f"Total messages processed: {self.messages_processed}")

        if self.messages_processed > 0:
            fuzz_percentage = (self.messages_fuzzed / self.messages_processed) * 100
        else:
            fuzz_percentage = 0.0

        print(f"Messages fuzzed: {self.messages_fuzzed} ({fuzz_percentage:.2f}%)")
        
        # Print success rate by message type
        if hasattr(self, 'fuzz_success_rate') and self.fuzz_success_rate:
            print("\nFuzzing success rate by message type:")
            for msg_type, rate in self.fuzz_success_rate.items():
                print(f"  {msg_type}: {rate*100:.2f}%")
        
        print(Fore.CYAN + "=" * 50)
        
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
            #print(msg[2])
            
            print(f"[*] ProcedureCode: {hex(procedure_code)}")            
            # Determine the message type from ProcedureCode using the map
            message_type = self.map_procedure_code(procedure_code)
            
            # Try to identify more details based on the first byte (msg_type)
            return f"{message_type}"

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
                        try:
                            start_time = time.time()
                            fromaddr, flags, msg, notif = self.conn_from_xapp.sctp_recv(65535)
    #                     # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Received message from xApp:")
    #                     print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Length: {len(msg)} bytes")
    #                     # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Flags: {flags}")
    #                     # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"From Address: {fromaddr}")
    #                     # print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Notification: {notif}")
    #                     #print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Hex: {hexlify(msg)}")
                            if msg == b'':
                                continue
                            
                            print(Fore.GREEN + f"[TX] [xApp --> RIC]")
                            print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Length: {len(msg)} bytes")
                            
                            self.messages_processed += 1
                            
                            message_type = self.guess_message_type(msg)
                            print(Fore.LIGHTYELLOW_EX + f"[DEBUG] Message Type: {message_type}")
                            modified_msg = self.process_message(msg, direction="to_ric")
                            
                            if modified_msg != msg and modified_msg is not None:
                                self.messages_fuzzed += 1
                            
                            if not modified_msg:
                                return
                            else:
                                try:
                                    self.ric_client.sctp_send(modified_msg, ppid=socket.htonl(0))
                                    end_time = time.time()
                                    conversion_time = (end_time - start_time) * 1000  # milliseconds
                                    print(Fore.LIGHTCYAN_EX + f"[DEBUG] Overhead: {conversion_time:.2f} ms")
                                except BrokenPipeError:
                                    print(Fore.RED + f"[!] Connection to RIC lost during send. Reconnecting...")
                                    raise  # Re-raise to trigger the outer exception handler for reconnection
                        except Exception as e:
                            print(Fore.RED + f"[-] Error during xApp->RIC forwarding: {e}")
                            raise  # Re-raise to trigger reconnection

                        print(Fore.YELLOW + "-" * 50)
                    elif sock == self.ric_client:
                        try:
                            start_time = time.time()
                            fromaddr2, flags2, msg2, notif2 = self.ric_client.sctp_recv(65535)
                            print(Fore.LIGHTBLUE_EX + "[RX] [xApp <-- RIC]")
                            print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Length: {len(msg2)} bytes")
                            
                            self.messages_processed += 1
                            
                            response_type = self.guess_message_type(msg2)
                            print(Fore.LIGHTYELLOW_EX + f"[DEBUG] Response Type: {response_type}")
                            response = self.process_message(msg2, direction="to_xapp")
                            if not response:
                                return
                            else:
                                try:
                                    self.conn_from_xapp.sctp_send(response, ppid=socket.htonl(0))
                                    end_time = time.time()
                                    conversion_time = (end_time - start_time) * 1000  # milliseconds
                                    print(Fore.LIGHTCYAN_EX + f"[DEBUG] Overhead: {conversion_time:.2f} ms")
                                except BrokenPipeError:
                                    print(Fore.RED + f"[!] Connection to xApp lost during send. Need to wait for new connection.")
                                    return  # Exit proxy_traffic to wait for new xApp connection
                        except Exception as e:
                            print(Fore.RED + f"[-] Error during RIC->xApp forwarding: {e}")
                            raise  # Re-raise to trigger reconnection

                        print(Fore.YELLOW + "-" * 50)

            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] KeyboardInterrupt detected. Exiting cleanly.")
                break
            except BrokenPipeError as e:
                print(Fore.RED + f"[-] Connection broken: {e}")
                print(Fore.YELLOW + "[*] Attempting to reset connection...\n")
                time.sleep(2)
                self.close_connections()
                self.start()
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
        if seen_hex is None:
            seen_hex = set()

        if isinstance(json_message, dict):
            for key, value in list(json_message.items()):
                if key in target_keys and self.is_hex_string(value) and value not in seen_hex:
                    seen_hex.add(value)
                    if len(value)<= 8:
                        #print(Fore.YELLOW + f"[!] Skipping short hex value: {value}")
                        continue
                    #print(len(value))
                    for asn1_name, asn1_compiled in asn1_files.items():
                        for definition in definitions:
                            try:
                                decoded_json = asn1_compiled.decode(definition, unhexlify(value))
                                if decoded_json:
                                    #print(decoded_json)
                                    print("Decoded definition:", definition)

                                    # Mutate and check if mutation occurred
                                    modified_json, mutated = self.mutate_field(decoded_json,
                                                                               constraints, 
                                                                               "measName")

                                    if mutated or modified_json:
                                        encoded_json = asn1_compiled.encode(definition, modified_json)
                                        encoded_hex = hexlify(encoded_json).decode()
                                        #print("Mutated",encoded_json)
                                        #print(Fore.GREEN + f"[+] Re-encoded hex:\n{encoded_hex}")
                                        json_message[key] = encoded_hex
                                        return json_message
                                    else:
                                        print(Fore.YELLOW + "[!] No mutation occurred. Retaining original hex.")
                                    #print("Mutated JSON:", json.dumps(modified_json, indent=2))
                                    return json_message  # Stop after first match

                            except Exception:
                                continue

                # Recursively process
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


    def get_random_value(self, constraints, field_name):
        """Find all matching fields in constraints and return a randomly selected value."""
        matching_values = []
        stack = [constraints]
        
        while stack:
            current = stack.pop()

            if isinstance(current, dict):
                for key, value in current.items():
                    if key == field_name:
                        if isinstance(value, dict):
                            # Handle specific types based on constraints
                            if "min" in value and "max" in value:
                                if value["min"] is not None and value["max"] is not None:
                                    matching_values.append(("integer", value["min"], value["max"]))
                            if "alphabet" in value:
                                alphabet = value.get("alphabet", string.ascii_letters + string.digits + " ")
                                min_len = value.get("min", 1)
                                max_len = value.get("max", len(alphabet))
                                matching_values.append(("string", alphabet, min_len, max_len))
                            if value.get("type_name") == "BITSTRING":
                                length = value.get("min", 8)
                                matching_values.append(("bitstring", length))
                            if value.get("type_name") == "OCTETSTRING":
                                length = value.get("min", 1)
                                matching_values.append(("octetstring", length))
                            if value.get("type_name") == "ENUMERATED":
                                enum_values = value.get("enumerations", [])
                                if enum_values:
                                    matching_values.append(("enum", enum_values))
                            if "root_members" in value:
                                stack.append(value["root_members"])

                        # Handle CHOICE type
                        if value.get("type_name") == "CHOICE":
                            choice_values = value.get("choices", [])
                            if choice_values:
                                matching_values.append(("choice", choice_values))

                    elif isinstance(value, dict):
                        stack.append(value)
                    elif isinstance(value, list):
                        stack.extend(value)

            elif isinstance(current, list):
                stack.extend(current)

        # If we found matching values, randomly select one and generate a value
        if matching_values:
            # Use random.choice to select from all possible matches
            value_type = random.choice(matching_values)
            #print(Fore.LIGHTCYAN_EX + f"[DEBUG] Random value type selected: {value_type}")
            if value_type[0] == "integer":
                return random.randint(value_type[1], value_type[2])
            elif value_type[0] == "string":
                alphabet, min_len, max_len = value_type[1], value_type[2], value_type[3]
                length = random.randint(min_len, max_len)
                return ''.join(random.choice(alphabet) for _ in range(length))
            elif value_type[0] == "bitstring":
                length = value_type[1]
                return ''.join(random.choice('01') for _ in range(length))
            elif value_type[0] == "octetstring":
                length = value_type[1]
                return bytes([random.randint(0, 255) for _ in range(length)])
            elif value_type[0] == "enum":
                enum_values = value_type[1]
                return random.choice(enum_values)
            elif value_type[0] == "choice":
                choice_values = value_type[1]
                return random.choice(choice_values)
        
        return None
    
    # def mutate_field(self, json_data, constraints, field_name):
    #     mutated = False  # <-- Track whether a mutation happened
        
    #     def field_exists(data, field_name):
    #         if not isinstance(data, (dict, list, tuple)) or isinstance(data, str):
    #             return False
    #         if isinstance(data, dict):
    #             # Direct match in keys
    #             if field_name in data:
    #                 return True
    #             # Check all values
    #             for value in data.values():
    #                 if field_exists(value, field_name):
    #                     return True
    #         # For lists and tuples
    #         elif isinstance(data, (list, tuple)):
    #             # Special case: field_name is the first element in a tuple
    #             if len(data) > 0 and data[0] == field_name:
    #                 return True
    #             # Check all elements
    #             for item in data:
    #                 if field_exists(item, field_name):
    #                     return True
    #         return False

    #     if not field_exists(json_data, field_name):
    #         print(Fore.YELLOW + f"[!] Field '{field_name}' not found. Skipping mutation.")
    #         return json_data, mutated

    #     random_value = self.get_random_value(constraints, field_name)
    #     print(Fore.LIGHTCYAN_EX + f"[DEBUG] Random value chosen for {field_name}: {random_value}")

    #     stack = [json_data]
    #     while stack:
    #         current = stack.pop()
    #         if isinstance(current, dict):
    #             for key, value in current.items():
    #                 if key == field_name and isinstance(value, (int, float, str)):
    #                     print(Fore.RED + f"[+] Mutating {field_name}: {value} -> {random_value}")
    #                     current[key] = random_value
    #                     mutated = True
    #                 elif isinstance(value, (dict, list, tuple)):
    #                     stack.append(value)
    #         elif isinstance(current, (list, tuple)):
    #             for i in range(len(current)):
    #                 item = current[i]
    #                 if isinstance(item, tuple) and len(item) >= 2 and item[0] == field_name:
    #                     print(Fore.RED + f"[+] Mutating {field_name} tuple: {item[1]} -> {random_value}")
    #                     current[i] = (field_name, random_value)
    #                     mutated = True
    #                 elif isinstance(item, (dict, list, tuple)):
    #                     stack.append(item)

    #     return json_data, mutated
    
    def mutate_field(self, json_data, constraints, field_name):
        mutated = False
        
        # Get a random value for the field
        random_value = self.get_random_value(constraints, field_name)
        #print(Fore.LIGHTCYAN_EX + f"[DEBUG] Random value chosen for {field_name}: {random_value}")
        
        if random_value is None:
            print(Fore.YELLOW + f"[!] No valid random value generated for {field_name}. Skipping mutation.")
            return json_data, mutated
        
        # Using a stack to implement a non-recursive approach
        stack = [([], json_data)]  # Each item is (path, data)
        
        while stack:
            path, current = stack.pop()
            
            # Handle dictionaries
            if isinstance(current, dict):
                for key, value in list(current.items()):
                    if key == field_name:
                        print(Fore.RED + f"[+] Mutating {field_name}: {value} -> {random_value}")
                        current[key] = random_value
                        mutated = True
                        return json_data, mutated
                    elif isinstance(value, (dict, list, tuple)) and not isinstance(value, str):
                        stack.append((path + [key], value))
            
            # Handle lists
            elif isinstance(current, list):
                for i, item in enumerate(current):
                    if isinstance(item, (dict, list, tuple)) and not isinstance(item, str):
                        stack.append((path + [i], item))
            
            # Handle tuples - special case for measType format
            elif isinstance(current, tuple):
                # Check for the specific structure we're looking for: ('measName', 'value')
                if len(current) >= 2 and current[0] == field_name:
                    parent = json_data
                    for step in path[:-1]:  # Navigate to parent
                        parent = parent[step]
                    
                    # Create new tuple with mutated value
                    new_tuple = (field_name, random_value)
                    
                    # Replace the tuple in the parent
                    if isinstance(parent, dict):
                        parent[path[-1]] = new_tuple
                    elif isinstance(parent, list):
                        parent[path[-1]] = new_tuple
                    
                    print(Fore.RED + f"[+] Mutating {field_name} tuple: {current[1]} -> {random_value}")
                    mutated = True
                    return json_data, mutated
                
                # For other tuples, add their contents to the stack if they're complex types
                else:
                    for i, item in enumerate(current):
                        if isinstance(item, (dict, list, tuple)) and not isinstance(item, str):
                            # We need to handle immutable tuples carefully
                            stack.append((path + [i], item))
        
        return json_data, mutated


    def process_and_convert(self, hex_data):
        global constraints
        """Convert hex data to JSON, mutate fields, and re-encode."""
        
        if hex_data.startswith("200e00") or hex_data.startswith("2e000091") \
            or hex_data.startswith("000e0081e7") or hex_data is None:
            #print(Fore.YELLOW + "Skipping decoding for packet with specified prefix.")
            return
        print(Fore.GREEN + f"Before decoding:\n{hex_data}")
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
    