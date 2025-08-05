import socket
import time
import random
import re
import sys, json, threading, time, asn1tools, os, subprocess
import tempfile
from binascii import hexlify, unhexlify
from colorama import Fore, Style, init
import _sctp, os, sctp
import select, string
from scapy.utils import PcapWriter
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
constraints_file = "./asn1/constraints_w_types.json" 

with open(constraints_file, "r") as f:
    constraints = json.load(f)

asn1_files = {
    'E2SM-KPM': asn1tools.compile_files(['./asn1/asn1files/E2SM-COMMON-IEs.asn', './asn1/asn1files/E2SM-KPM-v05.00.asn'], 'per'),
    'E2SM-RC': asn1tools.compile_files(['./asn1/asn1files/E2SM-COMMON-IEs.asn', './asn1/asn1files/e2sm-rc-v3.00.asn'], 'per')
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
    1: "Cause", 2: "CriticalityDiagnostics", 3: "GlobalE2node-ID", 4: "GlobalRIC-ID",
    5: "RANfunctionID", 6: "RANfunctionID-Item", 7: "RANfunctionIEcause-Item",
    8: "RANfunction-Item", 9: "RANfunctionsAccepted", 10: "RANfunctionsAdded",
    11: "RANfunctionsDeleted", 12: "RANfunctionsModified", 13: "RANfunctionsRejected",
    14: "RICaction-Admitted-Item", 15: "RICactionID", 16: "RICaction-NotAdmitted-Item",
    17: "RICactions-Admitted", 18: "RICactions-NotAdmitted", 19: "RICaction-ToBeSetup-Item",
    20: "RICcallProcessID", 21: "RICcontrolAckRequest", 22: "RICcontrolHeader",
    23: "RICcontrolMessage", 24: "RICcontrolStatus", 25: "RICindicationHeader",
    26: "RICindicationMessage", 27: "RICindicationSN", 28: "RICindicationType",
    29: "RICrequestID", 30: "RICsubscriptionDetails", 31: "TimeToWait",
    32: "RICcontrolOutcome", 33: "E2nodeComponentConfigUpdate",
    34: "E2nodeComponentConfigUpdate-Item", 35: "E2nodeComponentConfigUpdateAck",
    36: "E2nodeComponentConfigUpdateAck-Item", 39: "E2connectionSetup",
    40: "E2connectionSetupFailed", 41: "E2connectionSetupFailed-Item",
    42: "E2connectionFailed-Item", 43: "E2connectionUpdate-Item",
    44: "E2connectionUpdateAdd", 45: "E2connectionUpdateModify",
    46: "E2connectionUpdateRemove", 47: "E2connectionUpdateRemove-Item",
    48: "TNLinformation", 49: "TransactionID", 50: "E2nodeComponentConfigAddition",
    51: "E2nodeComponentConfigAddition-Item", 52: "E2nodeComponentConfigAdditionAck",
    53: "E2nodeComponentConfigAdditionAck-Item", 54: "E2nodeComponentConfigRemoval",
    55: "E2nodeComponentConfigRemoval-Item", 56: "E2nodeComponentConfigRemovalAck",
    57: "E2nodeComponentConfigRemovalAck-Item", 58: "E2nodeTNLassociationRemoval",
    59: "E2nodeTNLassociationRemoval-Item", 60: "RICsubscriptionToBeRemoved",
    61: "RICsubscription-withCause-Item", 62: "RICsubscriptionStartTime",
    63: "RICsubscriptionEndTime", 64: "RICeventTriggerDefinitionToBeModified",
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
    95: "RICqueryHeader", 96: "RICqueryDefinition", 97: "RICqueryOutcome",
    98: "XAPP-ID", 99: "E2nodesConnected", 100: "NODEfunctionID-Item"
}

class JsonFuzzer:
    def __init__(self, constraints, protocol_ie_map):
        self.constraints = constraints
        self.protocol_ie_map = protocol_ie_map
        self.asn1_files = asn1_files  # Using from global scope
        self.definitions = definitions  # Using from global scope
        self.target_keys = target_keys  # Using from global scope
        self.fuzz_history = {}
        self.fuzz_success_rate = {}
        
    def map_procedure_code(self, procedure_code):
        procedure_mapping = {
            0x01: "E2setup", 0x02: "ErrorIndication", 0x03: "Reset",
            0x04: "RICcontrol", 0x05: "RICindication", 0x06: "RICserviceQuery",
            0x07: "RICserviceUpdate", 0x08: "RICsubscription", 
            0x09: "RICsubscriptionDelete", 0x0A: "E2nodeConfigurationUpdate",
            0x0B: "E2connectionUpdate", 0x0C: "RICsubscriptionDeleteRequired",
            0x0D: "E2removal", 0x0E: "E42setup", 0x0F: "E42RICsubscription",
            0x10: "E42RICsubscriptionDelete", 0x11: "E42RICcontrol", 
            0x12: "E42updateE2node"
        }
        return procedure_mapping.get(procedure_code, "UnknownProcedureCode")

    def guess_message_type(self, msg):
        try:
            if len(msg) < 4:
                return None
            
            procedure_code = msg[1]
            print(f"[*] ProcedureCode: {hex(procedure_code)}")            
            return self.map_procedure_code(procedure_code)
        except Exception as e:
            print(Fore.RED + f"Error guessing message type: {e}")
            return "Error guessing message type"
    
    def hex_to_json(self, hex_data):
        if not hex_data or not str(hex_data).strip():
            return None

        try:
            reader_output = subprocess.check_output(['./asn1/reader', '-hex', str(hex_data)]).decode('utf-8').strip()
            if not reader_output:
                return None
            return json.loads(reader_output)
        except (subprocess.CalledProcessError, json.JSONDecodeError, Exception) as e:
            print(Fore.RED + f"[!] Error in hex_to_json: {e}")
            return None

    def json_to_hex(self, json_data):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                json.dump(json_data, temp_file)
                temp_file_path = temp_file.name
            
            hex_output = subprocess.check_output(['./asn1/reader_json', '-json', temp_file_path]).decode('utf-8').strip()
            os.unlink(temp_file_path)
            return hex_output
        except Exception as e:
            print(Fore.RED + f"Error converting JSON to hex: {e}")
            return None

    def get_random_value(self, constraints, field_name):
        """Generate a random value based on field constraints"""
        # Handle the case where field_name is a dictionary 
        if isinstance(field_name, dict):
            # Use the field constraints directly
            return self._generate_value_from_constraint(field_name)
        
        # Search for constraints by name
        if isinstance(field_name, str):
            # First, try direct lookup
            if field_name in constraints:
                return self._generate_value_from_constraint(constraints[field_name])
            
            # Try without case sensitivity
            field_name_lower = field_name.lower()
            for name, value in constraints.items():
                if name.lower() == field_name_lower:
                    return self._generate_value_from_constraint(value)
            
            # Extract simple name from path and try to find a match
            simple_name = field_name.split('.')[-1] if '.' in field_name else field_name
            simple_name_lower = simple_name.lower()
            
            for name, value in constraints.items():
                if name.lower() == simple_name_lower:
                    return self._generate_value_from_constraint(value)
                
                # Also check for partial matches in nested structures
                if isinstance(value, dict):
                    # Check type_name
                    if 'type_name' in value and value['type_name'].lower() == simple_name_lower:
                        return self._generate_value_from_constraint(value)
                    
                    # Check in root_name_to_index and root_data_to_value
                    if 'root_name_to_index' in value:
                        for key in value['root_name_to_index'].keys():
                            if key.lower() == simple_name_lower:
                                return self._generate_value_from_constraint(value)
                    
                    if 'root_data_to_value' in value:
                        for key in value['root_data_to_value'].keys():
                            if key.lower() == simple_name_lower:
                                return self._generate_value_from_constraint(value)

    def _generate_value_from_constraint(self, constraint):
        """Generate a random value based on a specific constraint"""
        if not constraint or not isinstance(constraint, dict):
            return None
            
        # Handle INTEGER constraints
        if "min" in constraint and "max" in constraint:
            min_val = constraint.get("min")
            max_val = constraint.get("max")
            if isinstance(min_val, int) and isinstance(max_val, int):
                return random.randint(min_val, max_val)
        
        # Handle ENUMERATED type with root_data_to_value
        if "root_data_to_value" in constraint:
            choices = list(constraint["root_data_to_value"].keys())
            if choices:
                return random.choice(choices)
        
        # Handle nested_type ENUMERATED
        if "nested_type" in constraint and constraint["nested_type"] == "ENUMERATED":
            if "root_data_to_value" in constraint:
                choices = list(constraint["root_data_to_value"].keys())
                if choices:
                    return random.choice(choices)
        
        # Handle CHOICE type
        if "type_name" in constraint and "root_name_to_index" in constraint:
            choices = list(constraint["root_name_to_index"].keys())
            if choices:
                return random.choice(choices)
        
        # Handle string with alphabet constraint
        if "alphabet" in constraint:
            alphabet = constraint["alphabet"]
            min_len = constraint.get("min", 1)
            max_len = constraint.get("max", min_len)  # Default to min if max not specified
            length = random.randint(min_len, max_len)
            return ''.join(random.choice(alphabet) for _ in range(length))
            
        # Handle OCTETSTRING
        if "nested_type" in constraint and constraint["nested_type"] == "OCTETSTRING":
            min_len = constraint.get("min", 1)
            max_len = constraint.get("max", min_len)
            length = random.randint(min_len, max_len)
            return ''.join(random.choice('0123456789ABCDEF') for _ in range(length*2))
            
        # Handle BITSTRING
        if "nested_type" in constraint and constraint["nested_type"] == "BITSTRING":
            bits = constraint.get("number_of_bits")
            if bits:
                return ''.join(random.choice('01') for _ in range(int(bits)))
        
        # If no appropriate constraint is found, return None
        return None

    def field_exists(self, data, field_name):
        if not isinstance(data, (dict, list, tuple)) or isinstance(data, str):
            return False
            
        if isinstance(data, dict):
            if field_name in data:
                return True
            for value in data.values():
                if self.field_exists(value, field_name):
                    return True
        elif isinstance(data, (list, tuple)):
            if len(data) > 0 and data[0] == field_name:
                return True
            for item in data:
                if self.field_exists(item, field_name):
                    return True
        return False

    def get_all_fields(self, data, prefix="", result=None):
        if result is None:
            result = []
            
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{prefix}.{key}" if prefix else key
                result.append(current_path)
                if isinstance(value, (dict, list, tuple)) and not isinstance(value, str):
                    self.get_all_fields(value, current_path, result)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{prefix}[{i}]"
                if isinstance(item, tuple) and len(item) >= 2:
                    result.append(item[0])
                if isinstance(item, (dict, list, tuple)) and not isinstance(item, str):
                    self.get_all_fields(item, current_path, result)
                    
        return result

    def collect_all_constraint_fields(self, constraints):
        all_fields = set()
        stack = [constraints]
        
        while stack:
            current = stack.pop()
            
            if isinstance(current, dict):
                all_fields.update(current.keys())
                for value in current.values():
                    if isinstance(value, dict):
                        stack.append(value)
                    elif isinstance(value, list):
                        stack.extend(value)
            elif isinstance(current, list):
                stack.extend(current)
            

    def apply_mutation_to_asn1(self, asn1_content, field_name, new_value):
        """Apply a mutation to a field in an ASN.1 structure"""
        if isinstance(asn1_content, dict):
            if field_name in asn1_content:
                asn1_content[field_name] = new_value
                return asn1_content
            
            for key, value in asn1_content.items():
                if isinstance(value, (dict, list, tuple)) and not isinstance(value, (str, bytes)):
                    asn1_content[key] = self.apply_mutation_to_asn1(value, field_name, new_value)
        
        elif isinstance(asn1_content, (list, tuple)) and not isinstance(asn1_content, (str, bytes)):
            # Handle ASN.1 choice tuples (name, value)
            if len(asn1_content) == 2 and isinstance(asn1_content[0], str):
                if asn1_content[0] == field_name:
                    return (field_name, new_value)
                elif isinstance(asn1_content[1], (dict, list, tuple)) and not isinstance(asn1_content[1], (str, bytes)):
                    return (asn1_content[0], self.apply_mutation_to_asn1(asn1_content[1], field_name, new_value))
            else:
                result = []
                for item in asn1_content:
                    if isinstance(item, (dict, list, tuple)) and not isinstance(item, (str, bytes)):
                        result.append(self.apply_mutation_to_asn1(item, field_name, new_value))
                    else:
                        result.append(item)
                
                if isinstance(asn1_content, tuple):
                    return tuple(result)
                return result
        
        return asn1_content

    def fuzz_raw_hex(self, json_data):
        """
        Function that intelligently fuzzes ASN.1 encoded hex data within the JSON object.
        It first extracts all hex fields, decodes them, mutates specific fields, and re-encodes.
        """
        asn1_fields = self.extract_asn1_content(json_data)
        print(Fore.CYAN + f"[*] Found {len(asn1_fields)} potential ASN.1 encoded fields.")
        print(Fore.CYAN + f"[*] ASN.1 fields: {asn1_fields}")
        
        if not asn1_fields:
            print(Fore.YELLOW + "[!] No potential ASN.1 encoded fields found.")
            return json_data, []
            
        import copy
        modified_json = copy.deepcopy(json_data)
        mutations = []
        
        for field in asn1_fields:
            # Skip very short hex strings as they're likely not complex ASN.1 structures
            if len(field["hex"]) <= 18:
                continue
                
            # Try to decode the hex string as ASN.1
            decoded = self.decode_asn1_content(field["hex"])
            if not decoded:
                continue
                
            print(Fore.GREEN + f"[+] Successfully decoded {field['path']} as {decoded['definition']}")
            print(Fore.GREEN + f"[+] ASN.1 decoded: {decoded}")
            
            # Extract the actual decoded content
            asn1_content = decoded["decoded"]
            
            # Get all available fields from the decoded content
            available_fields = []
            self.extract_available_fields(asn1_content, available_fields)
            print(Fore.CYAN + f"[DEBUG] Available fields in {decoded['definition']}: {available_fields}")
            
            if not available_fields:
                continue
                
            # Select 1-2 fields randomly from the available fields
            #num_fields_to_mutate = random.sample(1,(min(2, len(available_fields))))
            #fields_to_mutate = random.sample(available_fields, num_fields_to_mutate)
            
            num_fields_to_mutate = min(1, len(available_fields))
            fields_to_mutate = random.sample(available_fields, num_fields_to_mutate)

            print(Fore.CYAN + f"[DEBUG] ASN.1 targeting fields: {fields_to_mutate}")
    
            mutated_fields = []
            for target_field in fields_to_mutate:
                # Get constraints for the selected field if available
                field_constraints = self.get_field_constraints(target_field)
                print(Fore.CYAN + f"[DEBUG] Constraints for {target_field}: {field_constraints}")
                
                if field_constraints:
                    # Generate a value based on constraints
                    random_value = self.get_random_value(constraints, field_constraints)
                    
                    print(Fore.CYAN + f"[DEBUG] Generated new value for {target_field}: {random_value}")
                else:
                    # Generate a reasonable default value based on field type inference
                    random_value = self.generate_default_value(target_field, asn1_content)
                
                if random_value is not None:
                    # Apply the mutation to the ASN.1 content
                    asn1_content = self.apply_mutation_to_asn1(asn1_content, target_field, random_value)
                    print(Fore.GREEN + f"[+] Mutated field '{target_field}' to {random_value} in {decoded['definition']}")
                    print(Fore.CYAN + f"[DEBUG] ASN.1 content after mutation: {asn1_content}")
                    mutated_fields.append(target_field)
            
            if mutated_fields:
                try:
                    # Re-encode the modified ASN.1 content
                    encoded = decoded["asn1_spec"].encode(decoded["definition"], asn1_content)
                    encoded_hex = hexlify(encoded).decode()
                    
                    # Update the field in the JSON object with the new hex
                    self.update_field_in_json(modified_json, field["path"], encoded_hex)
                    print(Fore.GREEN + f"[+] Successfully re-encoded and updated {field['path']}")
                    
                    mutations.append({
                        "path": field["path"],
                        "definition": decoded["definition"],
                        "fields": mutated_fields
                    })
                    
                except Exception as e:
                    print(Fore.RED + f"[!] Error re-encoding ASN.1: {e}")
        
        return modified_json, mutations

    def apply_field_importance_weights(self, fields):
        """Apply weights to fields based on their importance for fuzzing"""
        # Start with the original fields
        weighted_fields = fields.copy()
        
        # Add important fields multiple times to increase their selection probability
        high_importance_keywords = ["id", "type", "action", "value", "criticality", "ricRequestorID", "ricInstanceID", "procedureCode"]
        
        for field in fields:
            field_name = field["name"].lower()
            for keyword in high_importance_keywords:
                if keyword in field_name:
                    # Add duplicates to increase selection probability
                    weighted_fields.append(field)
                    
                    # For especially important fields, add even more copies
                    if keyword in ["id", "value", "procedureCode"]:
                        weighted_fields.append(field)
        
        return weighted_fields


    def fuzz_top_level_json(self, json_data, message_type=None, max_mutations=2):
        """
        Function that intelligently fuzzes fields in the top-level JSON object.
        It selects fields that actually exist in the JSON and then applies mutations
        based on available constraints.
        """
        import copy
        mutated_json = copy.deepcopy(json_data)
        
        # Extract all available fields from the JSON object
        all_json_fields = []
        self.extract_json_fields(mutated_json, all_json_fields)
        
        if not all_json_fields:
            print(Fore.YELLOW + "[!] No fields found in JSON to mutate.")
            return mutated_json, []
            
        # Filter out fields that are complex structures or hex strings
        # Focus on simple values like integers, strings, and enums
        mutable_fields = []
        for field in all_json_fields:
            field_value = self.get_field_value(mutated_json, field["path"])
            #print(Fore.CYAN + f"[DEBUG] Field {field['name']} has value: {field_value}")
            if isinstance(field_value, (int, str, bool)):
                mutable_fields.append(field)
        
        if not mutable_fields:
            print(Fore.YELLOW + "[!] No mutable simple fields found in JSON.")
            return mutated_json, []
        
        # Choose a limited number of fields to mutate
        num_fields = min(max_mutations, len(mutable_fields))
        # Give higher probability to important fields
        weighted_fields = self.apply_field_importance_weights(mutable_fields)
        fields_to_mutate = random.sample(weighted_fields, num_fields)
        
        print(Fore.CYAN + f"[DEBUG] Selected JSON fields to mutate: {[f['name'] for f in fields_to_mutate]}")
        
        mutations = []
        
        for field in fields_to_mutate:
            field_name = field["name"]
            field_path = field["path"]
            original_value = self.get_field_value(mutated_json, field_path)
            
            # Get constraints for this field if available
            field_constraints = self.get_field_constraints(field_name)
            
            # Generate a value based on field name, not the constraints dict
            new_value = self.get_random_value(self.constraints, field_name)
            print(Fore.CYAN + f"[DEBUG] Generated new value for {field_name}: {new_value}")
            
            if new_value is not None:
                # Apply the mutation to the JSON
                self.set_field_value(mutated_json, field_path, new_value)
                print(Fore.RED + f"[+] Mutated {field_path}: {original_value} -> {new_value}")
                
                mutations.append({
                    "path": field_path,
                    "name": field_name,
                    "old_value": original_value,
                    "new_value": new_value
                })
        
        if mutations:
            print(Fore.GREEN + f"[*] Successfully mutated {len(mutations)} JSON fields")
        else:
            print(Fore.BLUE + "[*] No mutations applied to JSON fields.")
        
        if message_type:
            if message_type not in self.fuzz_history:
                self.fuzz_history[message_type] = []
            
            self.fuzz_history[message_type].append({
                "time": time.time(),
                "mutations": mutations,
                "success": bool(mutations)
            })
            
            all_attempts = len(self.fuzz_history[message_type])
            successful = sum(1 for entry in self.fuzz_history[message_type] if entry["success"])
            self.fuzz_success_rate[message_type] = successful / all_attempts if all_attempts > 0 else 0
        
        return mutated_json, mutations


    def extract_available_fields(self, data, result=None, current_path=""):
        """Extract all available fields from an ASN.1 decoded structure with improved handling"""
        if result is None:
            result = []
        
        # Handle special case for ASN.1 choice tuples (name, value)
        if isinstance(data, tuple) and len(data) == 2 and isinstance(data[0], str):
            choice_name = data[0]
            choice_value = data[1]
            result.append(choice_name)
            
            # Add the nested choice type if applicable
            if isinstance(choice_value, (dict, list, tuple)) and not isinstance(choice_value, (str, bytes)):
                self.extract_available_fields(choice_value, result, f"{current_path}.{choice_name}")
            return result
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{current_path}.{key}" if current_path else key
                result.append(key)
                if isinstance(value, (dict, list, tuple)) and not isinstance(value, (str, bytes)):
                    self.extract_available_fields(value, result, new_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{current_path}[{i}]"
                if isinstance(item, (dict, list, tuple)) and not isinstance(item, (str, bytes)):
                    self.extract_available_fields(item, result, new_path)
                elif isinstance(item, str) and item not in result:
                    # For list of field names
                    result.append(item)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_result = []
        for field in result:
            if field not in seen:
                seen.add(field)
                unique_result.append(field)
        
        return unique_result

    def extract_json_fields(self, data, result=None, current_path=""):
        """Extract all fields from a JSON structure with their paths"""
        if result is None:
            result = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{current_path}.{key}" if current_path else key
                #print(f"[DEBUG] Extracting field: {new_path} of type {type(value).__name__}")
                result.append({"name": key, "path": new_path, "type": type(value).__name__})
                if isinstance(value, (dict, list)):
                    self.extract_json_fields(value, result, new_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{current_path}[{i}]"
                if isinstance(item, dict):
                    self.extract_json_fields(item, result, new_path)
        
        return result

    def get_field_value(self, data, path):
        """Get a field value from a JSON structure using its path"""
        parts = path.split('.')
        current = data
        
        for part in parts:
            if '[' in part and ']' in part:
                # Handle array index
                array_name = part.split('[')[0]
                index = int(part.split('[')[1].split(']')[0])
                current = current[array_name][index]
            else:
                current = current[part]
        
        return current

    def set_field_value(self, data, path, value):
        """Set a field value in a JSON structure using its path"""
        parts = path.split('.')
        current = data
        
        for i, part in enumerate(parts[:-1]):
            if '[' in part and ']' in part:
                # Handle array index
                array_name = part.split('[')[0]
                index = int(part.split('[')[1].split(']')[0])
                print(f"[DEBUG] Setting field: {array_name} at index {index}")

                current = current[array_name][index]
                print(f"[DEBUG] Current context after setting array: {current}")
            else:
                current = current[part]
        
        last_part = parts[-1]
        if '[' in last_part and ']' in last_part:
            # Handle array index
            array_name = last_part.split('[')[0]
            index = int(last_part.split('[')[1].split(']')[0])
            current[array_name][index] = value
        else:
            current[last_part] = value

    def update_field_in_json(self, data, path, new_value):
        """Update a field in a JSON structure using its path"""
        self.set_field_value(data, path, new_value)

    def get_field_constraints(self, field_name):
        """Get constraints for a field from the global constraints dictionary"""
        matching_constraints = {}
        
        def search_constraints(constraints, current_result=None):
            if current_result is None:
                current_result = {}
                
            if isinstance(constraints, dict):
                if field_name in constraints:
                    # Check if the value is a dictionary before updating
                    if isinstance(constraints[field_name], dict):
                        current_result.update(constraints[field_name])
                    else:
                        # If it's not a dictionary, store it as a special value
                        current_result["_value"] = constraints[field_name]
                
                for key, value in constraints.items():
                    if isinstance(value, (dict, list)):
                        search_constraints(value, current_result)
            elif isinstance(constraints, list):
                for item in constraints:
                    if isinstance(item, (dict, list)):
                        search_constraints(item, current_result)
            
            return current_result
        
        return search_constraints(self.constraints)
    

    def extract_asn1_content(self, json_data):
        results = []
        
        def search_hex_fields(data, path=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    if key in self.target_keys and isinstance(value, str) and re.fullmatch(r'[0-9A-Fa-f]+', value):
                        results.append({
                            "path": f"{path}.{key}" if path else key,
                            "hex": value
                        })
                    elif isinstance(value, (dict, list)):
                        search_hex_fields(value, f"{path}.{key}" if path else key)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    search_hex_fields(item, f"{path}[{i}]")
                    
        search_hex_fields(json_data)
        return results
    
    def decode_asn1_content(self, hex_string, definition=None):
        for asn1_name, asn1_compiled in self.asn1_files.items():
            defs_to_try = [definition] if definition else self.definitions
            
            for definition in defs_to_try:
                try:
                    decoded = asn1_compiled.decode(definition, unhexlify(hex_string))
                    return {
                        "asn1_spec": asn1_name,
                        "definition": definition,
                        "decoded": decoded
                    }
                except Exception:
                    continue
        return None


    def process_message(self, msg, direction="to_ric"):
        """Main method to process and fuzz a message"""
        try:
            msg_hex = hexlify(msg).decode()
             
            if msg_hex.startswith("200e00") or msg_hex.startswith("2e000091") \
                or msg_hex.startswith("000e0081e7") or msg_hex is None:
                #print(Fore.YELLOW + "Skipping decoding for packet with specified prefix.")
                return msg
            if direction == "to_ric":
                message_type = self.guess_message_type(msg)
                print(Fore.CYAN + f"[*] Processing {message_type} message ({len(msg)} bytes)")
                print(Fore.GREEN + f"Before decoding:\n{msg_hex}")
                
                json_data = self.hex_to_json(msg_hex)
                
                if not json_data:
                    print(Fore.YELLOW + "[!] Failed to convert message to JSON. Skipping fuzzing.")
                    return msg
                print(Fore.GREEN + "Converted to JSON:")
                print(json.dumps(json_data, indent=2)) 
                
                # Decide which fuzzing approach to use (with higher probability for ASN.1 fuzzing)
                fuzz_strategy = random.choices(
                    ["asn1", "json", "both"], 
                    weights=[0.5, 0.4, 0.1], 
                    k=1
                )[0]
                
                print(Fore.CYAN + f"[*] Selected fuzzing strategy: {fuzz_strategy}")
                
                if fuzz_strategy in ["asn1", "both"]:
                    # Fuzz ASN.1 encoded data
                    fuzzed_json, asn1_mutations = self.fuzz_raw_hex(json_data)
                    if not asn1_mutations and fuzz_strategy == "both":
                        # If ASN.1 fuzzing didn't produce mutations but we want both, try JSON fuzzing
                        fuzzed_json, json_mutations = self.fuzz_top_level_json(fuzzed_json, message_type)
                        mutations = asn1_mutations + json_mutations
                    else:
                        mutations = asn1_mutations
                else:
                    # Fuzz JSON fields directly
                    fuzzed_json, mutations = self.fuzz_top_level_json(json_data, message_type)
                
                if mutations:
                    modified_hex = self.json_to_hex(fuzzed_json)
                    if modified_hex and modified_hex.strip():
                        modified_msg = unhexlify(modified_hex)
                        print(Fore.GREEN + f"[+] Successfully fuzzed message ({len(modified_msg)} bytes)")
                        print(Fore.GREEN + f"[+] Encoded again:\n{modified_hex}")
                        return modified_msg
                    else:
                        print(Fore.RED + "[-] Failed to convert fuzzed JSON back to hex. Using original message.")
                else:
                    print(Fore.BLUE + "[*] No mutations applied to this message.")
            
            return msg
            
        except Exception as e:
            print(Fore.RED + f"[-] Error processing message: {e}")
            import traceback
            traceback.print_exc()
            return msg



    
class SCTPMITMProxy:
    
    def __init__(self, mitm_ip=IP_MITM, xapp_ip=IP_XAPP, ric_ip=IP_RIC, port=PORT):
        self.mitm = mitm_ip
        self.xapp = xapp_ip
        self.ric_ip = ric_ip
        self.port = port
        self.server = None
        self.conn_from_xapp = None
        self.ric_client = None
        self.captures_folder = "/media/p3rplex/data5/Backup_ubuntu22/oran-orchestration/asn1/captures_bridge"
        self.pcap_writer = None
        self.session_file = None
        self.previous_session_file = None  # Track the previous session file
        self.timer = None  # Timer for splitting files

            
        # Initialize the enhanced fuzzer
        self.fuzzer = JsonFuzzer(constraints, protocolIEs)
        
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
                self._create_new_session_file()
        
                # Start the timer for splitting files
                self.timer = threading.Timer(20.0, self._split_and_save)
                self.timer.start()

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
                print(Fore.CYAN + f"[*] Fuzzing enabled: {self.fuzz_enabled} (Probability: {self.fuzz_probability*100}%)")

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

    

    def proxy_traffic(self):
        fuzzer = JsonFuzzer(constraints, protocolIEs)
        """Main proxy loop to intercept, fuzz, and forward traffic with robustness."""
        sockets = [self.conn_from_xapp, self.ric_client]
        while True:
            try:
                rlist, _, _ = select.select(sockets, [], [], 10.0)
                if not rlist:
                    print(Fore.YELLOW + "[!] Timeout waiting for packets. Continuing...")
                    continue
                
                # Start the timer for splitting files
                self.timer = threading.Timer(20.0, self._split_and_save)
                self.timer.start()

                for sock in rlist:
                    if sock == self.conn_from_xapp:
                        try:
                            start_time = time.time()
                            fromaddr, flags, msg, notif = self.conn_from_xapp.sctp_recv(65535)
                            print(Fore.GREEN + f"[TX] [xApp --> RIC]")
                            print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Length: {len(msg)} bytes")
                            
                            self.messages_processed += 1
                            
                            message_type = fuzzer.guess_message_type(msg)
                            print(Fore.LIGHTYELLOW_EX + f"[DEBUG] Message Type: {message_type}")
                            modified_msg = fuzzer.process_message(msg, direction="to_ric")
                            
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
                            
                            response_type = fuzzer.guess_message_type(msg2)
                            print(Fore.LIGHTYELLOW_EX + f"[DEBUG] Response Type: {response_type}")
                            response = fuzzer.process_message(msg2, direction="to_xapp")
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
        if hasattr(self.fuzzer, 'fuzz_success_rate') and self.fuzzer.fuzz_success_rate:
            print("\nFuzzing success rate by message type:")
            for msg_type, rate in self.fuzzer.fuzz_success_rate.items():
                print(f"  {msg_type}: {rate*100:.2f}%")
        
        print(Fore.CYAN + "=" * 50)

    def cleanup_xapp(self):
        """Clean up xApp connection."""
        try:
            if self.conn_from_xapp:
                print(Fore.YELLOW + "[*] Cleaning up xApp connection.")
                self.conn_from_xapp.close()
                self.conn_from_xapp = None
        except Exception as e:
            print(Fore.RED + f"[-] Error during xApp cleanup: {e}")
            
    def _create_new_session_file(self):
        """Create a new session file with a unique name."""
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        self.session_file = os.path.join(self.captures_folder, f"session_{timestamp}.pcapng")
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
       
        self._generate_diff(self.session_file)

        
        # Start a new session
        #self._create_new_session_file()
        
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

    def _generate_diff(self, current_file):

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
        print(Fore.YELLOW + f"[*] Generating diff between {current_file} and true_baseline.pcapng")
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
    
    