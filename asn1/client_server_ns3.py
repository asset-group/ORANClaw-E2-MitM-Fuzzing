from contextlib import contextmanager
import socket
import time
import random
import re
import sys, json, threading, time, asn1tools, os, subprocess
import tempfile
from binascii import hexlify, unhexlify
from colorama import Fore, Style, init
import _sctp, os, sctp, signal
import select, string
from scapy.utils import PcapWriter, PcapNgWriter
# Initialize colorama
init(autoreset=True)

if _sctp.getconstant("IPPROTO_SCTP") != 132:
    raise(Exception("getconstant failed"))
MSG_EOF = _sctp.getconstant("MSG_EOF")

# Constants
IP_MITM = "192.168.1.205"
IP_XAPP = "127.0.0.1"
IP_RIC = "127.0.0.1"

PORT = 36422
# Load constraints from JSON file
constraints_file = "./constraints_w_types_ns3.json" 

with open(constraints_file, "r") as f:
    constraints = json.load(f)

asn1_files = {
    'E2SM-KPM': asn1tools.compile_files(['./asn1files/E2SM-COMMON-IEs.asn', './asn1files/E2SM-KPM-v05.00.asn'], 'per'),
    'E2SM-RC': asn1tools.compile_files(['./asn1files/E2SM-COMMON-IEs.asn', './asn1files/e2sm-rc-v3.00.asn'], 'per')
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

@contextmanager
def redirect_stdout_to_file(filepath):
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    log_file = None
    try:
        log_file = open(filepath, 'a', encoding='utf-8')
        sys.stdout = log_file
        sys.stderr = log_file 
        print(f"--- Session log started: {filepath} ---")
        yield
    finally:
        if log_file:
            original_stdout.write(f"--- Session log ended: {filepath} ---\n")
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            log_file.close()


class GeneticFuzzerOptimizer:
    def __init__(self, population_size=6,
                 mutation_rate=0.3): # 0.3 Balanced search and stability

        self.POPULATION_SIZE = population_size
        self.MUTATION_RATE = mutation_rate
        self.population = [self._random_individual() for _ in range(self.POPULATION_SIZE)]
        self.fitness_scores = [0] * self.POPULATION_SIZE

    def _random_individual(self):
        weights = [random.random() for _ in range(3)] # random weights for 3 fields
        total = sum(weights)
        return [w / total for w in weights]  # Normalize to sum to 1

    def _fitness(self, cost):
        # Fitness is the cost directly (higher is better)
        return cost

    def _crossover(self, parent1, parent2):
        child = [(a + b) / 2 for a, b in zip(parent1, parent2)]
        total = sum(child)
        return [w / total for w in child]  # Normalize

    def _mutate(self, individual):
        idx = random.randint(0, 2)
        change = random.uniform(-0.2, 0.2)
        individual[idx] = max(0.01, individual[idx] + change)
        total = sum(individual)
        return [w / total for w in individual]

    def update(self, cost):
        # Assign fitness based on most recent cost
        self.fitness_scores = [self._fitness(cost) for _ in self.population]

        # Select top 2 individuals
        top = sorted(zip(self.population, self.fitness_scores), key=lambda x: x[1], reverse=True)[:2]
        best1, best2 = top[0][0], top[1][0]

        new_population = [best1, best2]

        # Generate new offspring
        while len(new_population) < self.POPULATION_SIZE:
            child = self._crossover(best1, best2)
            if random.random() < self.MUTATION_RATE:
                child = self._mutate(child)
            new_population.append(child)

        self.population = new_population

    def get_best_weights(self):
        best = self.population[0]
        return [round(w, 2) for w in best]
        #return self.population[0],2

class JsonFuzzer:
    def __init__(self, constraints, protocol_ie_map):
        self.constraints = constraints
        self.protocol_ie_map = protocol_ie_map
        self.asn1_files = asn1_files  # Using from global scope
        self.definitions = definitions  # Using from global scope
        self.target_keys = target_keys  # Using from global scope
        self.fuzz_history = {}
        self.fuzz_success_rate = {}
        self.fuzzing_enabled = True
        self.randomize_weights = True


    def map_procedure_code(self, procedure_code):

        #############  OAI  ############
        # procedure_mapping = {
        #     0x01: "E2setup", 0x02: "ErrorIndication", 0x03: "Reset",
        #     0x04: "RICcontrol", 0x05: "RICindication", 0x06: "RICserviceQuery",
        #     0x07: "RICserviceUpdate", 0x08: "RICsubscription", 
        #     0x09: "RICsubscriptionDelete", 0x0A: "E2nodeConfigurationUpdate",
        #     0x0B: "E2connectionUpdate", 0x0C: "RICsubscriptionDeleteRequired",
        #     0x0D: "E2removal", 0x0E: "E42setup", 0x0F: "E42RICsubscription",
        #     0x10: "E42RICsubscriptionDelete", 0x11: "E42RICcontrol", 
        #     0x12: "E42updateE2node"
        # }

        ############ NS3 #############
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
            0x0C: "E42setup",
            0x0D: "E42RICsubscription",
            0x0E: "E42RICsubscriptionDelete",
            0x0F: "E42RICcontrol"
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
            reader_output = subprocess.check_output(['./reader', '-hex', str(hex_data)]).decode('utf-8').strip()
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
            
            hex_output = subprocess.check_output(['./reader_json', '-json', temp_file_path]).decode('utf-8').strip()
            os.unlink(temp_file_path)
            return hex_output
        except Exception as e:
            print(Fore.RED + f"Error converting JSON to hex: {e}")
            return None

    def get_random_value(self, constraints, field_name):
        """Generate a random value based on field constraints"""
        # Handle the case where field_name is a dictionary 
        if isinstance(field_name, dict):
            #print(Fore.YELLOW + "[!] Received field_name as a dictionary, using its keys directly.")
            # Use the field constraints directly
            return self._generate_value_from_constraint(field_name)
        
        # Search for constraints by name
        if isinstance(field_name, str):
            # First, try direct lookup
            if field_name in constraints:
                #print(Fore.CYAN + f"[*] Found constraints for field: {field_name}")
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
                        #print(Fore.CYAN + f"[*] Found type_name match for {simple_name_lower} in constraints")
                        return self._generate_value_from_constraint(value)
                    
                    # Check in root_name_to_index and root_data_to_value
                    if 'root_name_to_index' in value:
                        for key in value['root_name_to_index'].keys():
                            if key.lower() == simple_name_lower:
                                #print(Fore.CYAN + f"[*] Found root_name_to_index match for {simple_name_lower} in constraints")
                                return self._generate_value_from_constraint(value)
                    
                    if 'root_data_to_value' in value:
                        for key in value['root_data_to_value'].keys():
                            if key.lower() == simple_name_lower:
                                #print(Fore.CYAN + f"[*] Found root_data_to_value match for {simple_name_lower} in constraints")
                                return self._generate_value_from_constraint(value)
                            
        
    def _generate_value_from_constraint(self, constraint):
        """Generate a random value based on a specific constraint"""
        #print("Received constraint:", constraint)

        # Handle list/sequence types (like LabelInfoList)
        if "asn1_type" in constraint and constraint["asn1_type"] in ["SEQUENCE OF", "SEQUENCE"]:
            min_val = constraint.get("min", 1)
            max_val = constraint.get("max", 3)
            
            # Generate a list with random length between min and max
            list_length = random.randint(int(min_val), int(max_val))
            result_list = []
            
            # If there are element constraints, use them to generate list items
            if "element_type" in constraint:
                element_constraint = constraint["element_type"]
                for _ in range(list_length):
                    element_value = self._generate_value_from_constraint(element_constraint)
                    if element_value is not None:
                        result_list.append(element_value)
            else:
                # Fallback: create simple dictionary entries for SEQUENCE OF
                for i in range(list_length):
                    result_list.append({"measLabel": {"noLabel": "true"}})
            
            #print(f"Generated {constraint['asn1_type']} with {len(result_list)} elements")
            return result_list

        # Handle ENUMERATED type with root_data_to_value
        if "root_data_to_value" in constraint:
            choices = list(constraint["root_data_to_value"].keys())
            #print("Enumerated constraint with root_data_to_value:", choices)
            if choices:
                result = random.choice(choices)
                #print("Chosen enumerated value:", result)
                return result

        # Handle nested_type ENUMERATED
        if "nested_type" in constraint and constraint["nested_type"] == "ENUMERATED":
            #print("Nested ENUMERATED constraint detected.")
            if "root_data_to_value" in constraint:
                choices = list(constraint["root_data_to_value"].keys())
                #print("Nested enumerated choices:", choices)
                if choices:
                    result = random.choice(choices)
                    #print("Chosen nested enumerated value:", result)
                    return result

        # Handle CHOICE type - FIXED VERSION
        if "type_name" in constraint and "root_name_to_index" in constraint:
            choices = list(constraint["root_name_to_index"].keys())
            #print("CHOICE type detected:", choices)
            if choices:
                chosen_field = random.choice(choices)
                #print("Chosen CHOICE value:", chosen_field)
                
                # Get the constraint for the chosen field and generate its value
                if "root_index_to_member" in constraint:
                    chosen_index = constraint["root_name_to_index"][chosen_field]
                    if str(chosen_index) in constraint["root_index_to_member"]:
                        member_info = constraint["root_index_to_member"][str(chosen_index)]
                        if "constraints" in member_info:
                            member_constraint = member_info["constraints"]
                            #print(f"Generating value for CHOICE field '{chosen_field}' with constraint:", member_constraint)
                            generated_value = self._generate_value_from_constraint(member_constraint)
                            if generated_value is not None:
                                return (chosen_field, generated_value)
                
                # Fallback: return None if value generation failed
                #print(f"Warning: Could not generate value for CHOICE field '{chosen_field}'")
                return None

        # Handle string types with alphabet constraint - FIXED TO HANDLE MeasurementTypeName
        if "alphabet" in constraint:
            alphabet = constraint["alphabet"]
            min_val = constraint.get("min")
            max_val = constraint.get("max")
            
            if min_val is not None and max_val is not None:
                length = random.randint(int(min_val), int(max_val))
            elif min_val is not None:
                length = int(min_val)
            elif max_val is not None:
                length = int(max_val)
            else:
                #print("Alphabet constraint: No length constraints found, using default length of 10")
                length = 10
                
            result = ''.join(random.choice(alphabet) for _ in range(length))
            #print(f"Alphabet constraint: alphabet={alphabet}, length={length}")
            #print("Generated string:", result)
            return result

        # Handle PrintableString - INCLUDING MeasurementTypeName
        if "asn1_type" in constraint and constraint["asn1_type"] in ["PrintableString", "MeasurementTypeName", ""]:
            alphabet = constraint.get("alphabet")
            min_val = constraint.get("min")
            max_val = constraint.get("max")
            
            if alphabet is None:
                print(f"{constraint['asn1_type']}: No alphabet constraint found")
                return None
                
            if min_val is not None and max_val is not None:
                length = random.randint(int(min_val), int(max_val))
            elif min_val is not None:
                length = int(min_val)
            elif max_val is not None:
                length = int(max_val)
            else:
                print(f"{constraint['asn1_type']}: No length constraints found, using default length of 10")
                length = 10
                
            result = ''.join(random.choice(alphabet) for _ in range(length))
            print(f"{constraint['asn1_type']}: alphabet={alphabet}, length={length}")
            #print("Generated string:", result)
            return result

        # Handle BIT STRING - Only use constraints, no hardcoded conversion
        if "asn1_type" in constraint and constraint["asn1_type"] == "BIT STRING":
            #print("BIT STRING: Cannot generate value without explicit byte format in constraints")
            return None

        # Handle OCTET STRING - Fixed to return bytes
        if "asn1_type" in constraint and constraint["asn1_type"] == "OCTET STRING":
            min_val = constraint.get("min")
            max_val = constraint.get("max")
            
            if min_val is not None and max_val is not None:
                length = random.randint(int(min_val), int(max_val))
            elif min_val is not None:
                length = int(min_val)
            elif max_val is not None:
                length = int(max_val)
            else:
                #print("OCTET STRING: No size constraints found, using default length of 16")
                length = 16
                
            # Generate random bytes
            result = bytes(random.randint(0, 255) for _ in range(length))
            #print(f"OCTET STRING: length={length}, result={result}")
            return result

        # Handle BOOLEAN
        if "asn1_type" in constraint and constraint["asn1_type"] == "BOOLEAN":
            boolean_values = constraint.get("boolean_values")
            if boolean_values is not None:
                result = random.choice(boolean_values)
                #print(f"BOOLEAN: result={result}")
                return result
            else:
                #print("BOOLEAN: No boolean_values constraint found, using default True/False")
                return random.choice([True, False])

        # Handle INTEGER - MOVED BEFORE min/max check to avoid conflict
        if "asn1_type" in constraint and constraint["asn1_type"] in ["INTEGER"]:# "MeasurementTypeID", "GNB-DU-ID","gNB-CU-UP-ID" ]:
            min_val = constraint.get("min")
            max_val = constraint.get("max")
            
            if min_val is not None and max_val is not None:
                result = random.randint(int(min_val), int(max_val))
                print(f"{constraint['asn1_type']}: min={min_val}, max={max_val}, result={result}")
                return result
            else:
                #print(f"{constraint['asn1_type']}: No min/max constraints found, using default range 1-100")
                return random.randint(1, 100)

        # Handle min/max constraints for non-string types (now only for cases not handled above)
        if "min" in constraint and "max" in constraint and "alphabet" not in constraint:
            min_val = constraint.get("min")
            max_val = constraint.get("max")
            if isinstance(min_val, int) and isinstance(max_val, int):
                result = random.randint(min_val, max_val)
                #print(f"Generic min/max constraint: min={min_val}, max={max_val}, result={result}")
                return result

        # Handle legacy OCTETSTRING
        if "nested_type" in constraint and constraint["nested_type"] == "OCTETSTRING":
            min_val = constraint.get("min")
            max_val = constraint.get("max")
            
            if min_val is not None and max_val is not None:
                length = random.randint(int(min_val), int(max_val))
            elif min_val is not None:
                length = int(min_val)
            elif max_val is not None:
                length = int(max_val)
            else:
                #print("Legacy OCTETSTRING: No size constraints found, using default length of 16")
                length = 16
                
            result = bytes(random.randint(0, 255) for _ in range(length))
            #print(f"Legacy OCTETSTRING: length={length}, result={result}")
            return result

        # Handle legacy BITSTRING - Only use constraints, no hardcoded conversion
        if "nested_type" in constraint and constraint["nested_type"] == "BITSTRING":
            # print("Legacy BITSTRING: Cannot generate value without explicit byte format in constraints")
            return None

        # If no appropriate constraint is found, return None
        print("No applicable constraint handler found. Returning None.")
        return None


    def apply_mutation_to_asn1(self, asn1_content, field_name, new_value):
        """Apply a mutation to a field in an ASN.1 structure"""
        print(f"[DEBUG] Applying mutation: {field_name} -> {new_value}")
        # print(f"[DEBUG] ASN.1 content var: {asn1_content}")

        def recursive_search_and_replace(data, target_field, replacement_value):
            """Recursively search for target_field and replace its value"""
            if isinstance(data, dict):
                # Check if target field exists at this level
                if target_field in data:
                    old_value = data[target_field]
                    #print(f"[DEBUG] Found field {target_field} at this level, old value: {old_value}")

                    # FIXED TYPE CHECKING: Only check types for non-ID fields
                    # ID fields can change type (e.g., from dict to int when changing protocol IE types)
                    if target_field != "id":
                        # If the old value is a list but new value isn't, skip this mutation
                        if isinstance(old_value, list) and not isinstance(replacement_value, list):
                            #print(f"[DEBUG] Skipping mutation: {target_field} expects list but got {type(replacement_value)}")
                            return False
                        
                        # If the old value is a dict but new value isn't, skip this mutation  
                        if isinstance(old_value, dict) and not isinstance(replacement_value, dict):
                            #print(f"[DEBUG] Skipping mutation: {target_field} expects dict but got {type(replacement_value)}")
                            return False

                    # Handle bytes objects by converting to hex
                    if isinstance(replacement_value, bytes):
                        replacement_value = replacement_value.hex()
                    
                    # Handle malformed nested dictionaries
                    if isinstance(replacement_value, dict) and "value" in replacement_value:
                        inner_value = replacement_value["value"]
                        if isinstance(inner_value, str) and inner_value.startswith('"') and inner_value.endswith('"'):
                            replacement_value = inner_value[1:-1]
                        else:
                            replacement_value = inner_value
                    
                    data[target_field] = replacement_value
                    #print(f"[DEBUG] Successfully updated {target_field} to {replacement_value}")
                    return True
                
                # Recursively search in nested structures
                for key, value in data.items():
                    if isinstance(value, (dict, list, tuple)) and not isinstance(value, (str, bytes)):
                        if recursive_search_and_replace(value, target_field, replacement_value):
                            return True
            
            elif isinstance(data, (list, tuple)) and not isinstance(data, (str, bytes)):
                # Handle ASN.1 choice tuples (name, value)
                if isinstance(data, tuple) and len(data) == 2 and isinstance(data[0], str):
                    choice_name, choice_value = data
                    
                    # If we're targeting this specific choice name itself
                    if choice_name == target_field:
                        if isinstance(replacement_value, str):
                            # Replace the choice name
                            data = (replacement_value, choice_value if isinstance(choice_value, (dict, list, tuple)) else {})
                            #print(f"[DEBUG] Updated CHOICE name from {choice_name} to {replacement_value}")
                            return True
                        else:
                            # Replace the choice value
                            data = (choice_name, replacement_value)
                            #print(f"[DEBUG] Updated CHOICE value for {choice_name}")
                            return True
                    
                    # Search within the choice value
                    elif isinstance(choice_value, (dict, list, tuple)) and not isinstance(choice_value, (str, bytes)):
                        if recursive_search_and_replace(choice_value, target_field, replacement_value):
                            return True
                else:
                    # Generic list or tuple of items
                    for i, item in enumerate(data):
                        if isinstance(item, (dict, list, tuple)) and not isinstance(item, (str, bytes)):
                            if recursive_search_and_replace(item, target_field, replacement_value):
                                return True
            
            return False
        
        # Perform the recursive search and replacement
        recursive_search_and_replace(asn1_content, field_name, new_value)
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
            #print(Fore.YELLOW + "[!] No potential ASN.1 encoded fields found.")
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
                
            #print(Fore.GREEN + f"[+] Successfully decoded {field['path']} as {decoded['definition']}")
            #print(Fore.GREEN + f"[+] ASN.1 decoded: {decoded}")
            
            # Extract the actual decoded content
            asn1_content = decoded["decoded"]
            
            # Get all available fields from the decoded content
            available_fields = []
            self.extract_available_fields(asn1_content, available_fields)
            #print(Fore.CYAN + f"[DEBUG] Available fields in {decoded['definition']}: {available_fields}")
            
            if not available_fields:
                continue
                
            # Select 1 field randomly from the available fields
            num_fields_to_mutate = min(1, len(available_fields))
            fields_to_mutate = random.sample(available_fields, num_fields_to_mutate)

            print(Fore.CYAN + f"[DEBUG] ASN.1 targeting fields: {fields_to_mutate}")

            mutated_fields = []
            for target_field in fields_to_mutate:
                # Get constraints for the selected field if available
                field_constraints = self.get_field_constraints(target_field)
                #print(Fore.CYAN + f"[DEBUG] Constraints for {target_field}: {field_constraints}")
                
                random_value = None
                if field_constraints:
                    # Generate a value based on constraints
                    random_value = self.get_random_value(self.constraints, field_constraints)
                    print(Fore.CYAN + f"[DEBUG] Generated new value for {target_field}: {random_value}")

                if random_value is not None:
                    # Apply the mutation to the ASN.1 content
                    asn1_content = self.apply_mutation_to_asn1(asn1_content, target_field, random_value)
                    print(Fore.GREEN + f"[+] Mutated field '{target_field}' to {random_value} in {decoded['definition']}")
                    print(Fore.CYAN + f"[DEBUG] ASN.1 content after mutation: {asn1_content}")
                    mutated_fields.append(target_field)
                    print(Fore.CYAN + f"[DEBUG] Mutated fields: {mutated_fields}")
            
            if mutated_fields:
                try:
                    # Re-encode the modified ASN.1 content using the compiled object
                    # decoded["asn1_spec"] is now the actual compiled ASN.1 object
                    encoded = decoded["asn1_spec"].encode(decoded["definition"], asn1_content)
                    encoded_hex = hexlify(encoded).decode()
                    
                    # Update the field in the JSON object with the new hex
                    self.update_field_in_json(modified_json, field["path"], encoded_hex)
                    #print(Fore.GREEN + f"[+] Successfully re-encoded and updated {field['path']}")
                    
                    mutations.append({
                        "path": field["path"],
                        "definition": decoded["definition"],
                        "asn1_name": decoded.get("asn1_name", "unknown"),  # Use the name if available
                        "fields": mutated_fields
                    })
                    
                except Exception as e:
                    print(Fore.RED + f"[!] Error re-encoding ASN.1: {e}")
                    print(Fore.RED + f"[!] Error details: {type(e).__name__}: {str(e)}")
                    # Optional: print more debug info
                    import traceback
                    print(Fore.RED + f"[!] Traceback: {traceback.format_exc()}")
        
        return modified_json, mutations

    def apply_field_importance_weights(self, fields):
        """Apply weights to fields based on their importance for fuzzing"""
        # Start with the original fields
        weighted_fields = fields.copy()
        
        # Add important fields multiple times to increase their selection probability
        high_importance_keywords = ["type", "action", "value",
                                    "criticality", "ricRequestorID",
                                    "ricInstanceID", "gNB",
                                    "gNB-CU-UP-ID", "gNB-DU-ID"]
        
        for field in fields:
            field_name = field["name"].lower()
            for keyword in high_importance_keywords:
                if keyword in field_name:
                    # Add duplicates to increase selection probability
                    weighted_fields.append(field)
                    
                    # For especially important fields, add even more copies
                    if keyword in high_importance_keywords:
                        weighted_fields.append(field)
        
        return weighted_fields

    def fuzz_top_level_json(self, json_data, message_type=None, max_mutations=1):
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
            #print(Fore.YELLOW + "[!] No fields found in JSON to mutate.")
            return mutated_json, []
            
        # Filter out fields that are complex structures or hex strings
        # Focus on simple values like integers, strings, and enums
        mutable_fields = []
        for field in all_json_fields:
            field_value = self.get_field_value(mutated_json, field["path"])
            #print(Fore.CYAN + f"[DEBUG] Field {field['name']} has value: {field_value}")
            if isinstance(field_value, (int, str, bool)) and field["name"] != "procedureCode":  # <-- ADD THIS CONDITION
                mutable_fields.append(field)
        
        if not mutable_fields:
            #print(Fore.YELLOW + "[!] No mutable simple fields found in JSON.")
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
        
        #if mutations:
        #    print(Fore.GREEN + f"[*] Successfully mutated {len(mutations)} JSON fields")
        #else:
        #    print(Fore.BLUE + "[*] No mutations applied to JSON fields.")
        
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
                result.append(key)  # Add the field name itself
                if isinstance(value, (dict, list, tuple)) and not isinstance(value, (str, bytes)):
                    self.extract_available_fields(value, result, new_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{current_path}[{i}]"
                if isinstance(item, (dict, list, tuple)) and not isinstance(item, (str, bytes)):
                    self.extract_available_fields(item, result, new_path)
                elif isinstance(item, str) and item not in result:
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
                #print(Fore.CYAN + f"[DEBUG] Found field: {new_path} (Type: {type(value).__name__})")
                # Add value and mutation info to the result
                field_info = {
                    "name": key, 
                    "path": new_path, 
                    "type": type(value).__name__,
                    "value": value,
                }
                result.append(field_info)
                
                if isinstance(value, (dict, list)):
                    self.extract_json_fields(value, result, new_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{current_path}[{i}]"
                
                # Also capture list items with their info
                field_info = {
                    "name": f"[{i}]",
                    "path": new_path,
                    "type": type(item).__name__,
                    "value": item,
                }
                result.append(field_info)
                
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
        
        # Navigate to the parent of the target field
        for i, part in enumerate(parts[:-1]):
            if '[' in part and ']' in part:
                # Handle array index
                array_name = part.split('[')[0]
                index = int(part.split('[')[1].split(']')[0])
                if array_name in current and isinstance(current[array_name], list):
                    if index < len(current[array_name]):
                        current = current[array_name][index]
                    else:
                        print(f"[DEBUG] Array index {index} out of bounds for {array_name}")
                        return
                else:
                    print(f"[DEBUG] Array {array_name} not found or not a list")
                    return
            else:
                if part in current:
                    current = current[part]
                else:
                    print(f"[DEBUG] Field {part} not found in current context")
                    return
        
        # Set the value for the final field
        last_part = parts[-1]
        if '[' in last_part and ']' in last_part:
            # Handle array index for the final part
            array_name = last_part.split('[')[0]
            index = int(last_part.split('[')[1].split(']')[0])
            if array_name in current and isinstance(current[array_name], list):
                if index < len(current[array_name]):
                    current[array_name][index] = value
                else:
                    print(f"[DEBUG] Array index {index} out of bounds for {array_name}")
            else:
                print(f"[DEBUG] Array {array_name} not found or not a list")
        else:
            if last_part in current:
                current[last_part] = value
            else:
                print(f"[DEBUG] Field {last_part} not found for setting value")

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
            #print(Fore.CYAN + f"[*] Attempting to decode ASN.1 content for {asn1_name} with hex: {hex_string}")
            defs_to_try = [definition] if definition else self.definitions
            
            for definition in defs_to_try:
                try:
                    decoded = asn1_compiled.decode(definition, unhexlify(hex_string))
                    return {
                        "asn1_spec": asn1_compiled,
                        "asn1_name": asn1_name,
                        "definition": definition,
                        "decoded": decoded
                    }
                except Exception:
                    continue
        return None


    def process_message(self, msg, direction="to_ric"):
        """Main method to process and fuzz a message"""
        try:
            self.fuzzing_enabled = True
            if not self.fuzzing_enabled:
                #print(Fore.BLUE + "[*] Fuzzing disabled.")
                return msg
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
                    #print(Fore.YELLOW + "[!] Failed to convert message to JSON. Skipping fuzzing.")
                    return msg
                print(Fore.GREEN + "Converted to JSON:")
                print(json.dumps(json_data, indent=2)) 
                
                # Decide which fuzzing approach to use
                #if hasattr(self, 'randomize_weights') and self.randomize_weights:
                #    raw_weights = [random.random() for _ in range(3)]
                #    weights = [w/sum(raw_weights) for w in raw_weights]
    
                #    print(Fore.RED + f"[*] Randomized weights for fuzzing strategies: {[round(w, 2) for w in weights]}")
                
                if hasattr(self, "strategy_optimizer"):
                    weights = self.strategy_optimizer.get_best_weights()

                #else:
                #weights = [0.6, 0.3, 0.1]
                #print(Fore.RED + f"[*] Using default weights for fuzzing strategies: {weights}")
                    
                fuzz_strategy = random.choices(["asn1", "json", "both"], weights=weights, k=1)[0]
                        
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
            #import traceback
            #traceback.print_exc()
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
        
        self.strategy_optimizer = GeneticFuzzerOptimizer()
        
        base_dir = os.path.dirname(os.path.abspath(__file__))
        # Define paths relative to script location
        self.captures_folder = os.path.join(base_dir,"captures_bridge")
        self.state_machines_folder = os.path.join(base_dir,"state_machines")
        self.state_machines_diff_folder = os.path.join(base_dir,"state_machines_diff")
        self.transitions_file = os.path.join(base_dir, "..", "vakt-ble-defender", "PortableSetup", "wdissector", "transitions.json")
        self.fuzzing_logs = os.path.join(base_dir, "fuzzing_logs")
        self.timestamp = None
        self.pcap_writer = None
        self.interface = "lo"
        self.session_file = None
        self.tshark_process = None
        self.cost_history = []
        
        self.timer = None  # Timer for splitting files
        #self.tshark_filter = "not tcp and not arp and not pfcp and sctp.chunk_type != 5 and sctp.chunk_type != 4"
        self.tshark_filter = "not tcp and not arp and not udp port 8805"
            
        # Initialize the enhanced fuzzer
        self.fuzzer = JsonFuzzer(constraints, protocolIEs)
        self.fuzzer.strategy_optimizer = self.strategy_optimizer
        # Fuzzing statistics
        self.messages_processed = 0
        self.messages_fuzzed = 0
        self.fuzzing_start_time = time.time()
        
        # Fuzzing configuration
        self.fuzz_enabled = True
        self.fuzz_probability = 0.2  # 70% chance to fuzz each message
        self.max_mutations = 1  # Maximum mutations per message
        
        #Duplication 
        self.duplication_probability = 0.3  # 30% chance to duplicate
        self.max_duplicates = 5
        self.duplication_enabled = False

        # Ensure the captures_bridge folder exists
        if not os.path.exists(self.captures_folder):
            os.makedirs(self.captures_folder)
            print(Fore.GREEN + f"[+] Created capture files folder: {self.captures_folder}")
        if not os.path.exists(self.state_machines_folder):
            os.makedirs(self.state_machines_folder)
            print(Fore.GREEN + f"[+] Created state machines folder: {self.state_machines_folder}")
        if not os.path.exists(self.state_machines_diff_folder):
            os.makedirs(self.state_machines_diff_folder)
            print(Fore.GREEN + f"[+] Created state machines diff folder: {self.state_machines_diff_folder}")
        
        if not os.path.exists(self.fuzzing_logs):
            os.makedirs(self.fuzzing_logs)
            print(Fore.GREEN + f"[+] Created state machines diff folder: {self.state_machines_diff_folder}")
        
        
    def start(self):
            try:
                self._start_tshark_capture()
                print(Fore.LIGHTMAGENTA_EX + f"[Genetic Algorithm] Enabled\nCurrent strategy weights: {self.strategy_optimizer.get_best_weights()}")

                # RIC connection is stable
# Connect to RIC with retry if disconnected
                while True:
                    try:
                        self.ric_client = sctp.sctpsocket_tcp(socket.AF_INET)
                        #self.ric_client.setsockopt(socket.AF_INET, socket.SO_REUSEADDR, 1)
                        #self.ric_client.bind((self.mitm, 0))  
                        self.ric_client.connect((self.ric_ip, self.port))
                        print(Fore.GREEN + f"[+] Connected to RIC at {self.ric_ip}:{self.port}")
                        break
                    except Exception as e:
                        print(Fore.RED + f"[!] Failed to connect to RIC: {e}. Retrying in 3 seconds...")
                        time.sleep(2)

                # Set up SCTP server to accept xApp connections
                self.server = sctp.sctpsocket_tcp(socket.AF_INET)
                #self.server.setsockopt(socket.AF_INET, socket.SO_REUSEADDR, 1)
                self.server.bind((self.mitm, self.port))
                self.server.listen(1)
                print(Fore.YELLOW + f"[*] Listening for xApp on {self.mitm}:{self.port}...")
                print(Fore.CYAN + f"[*] Fuzzing enabled: {self.fuzz_enabled} (Probability: {self.fuzz_probability*100}%)")

                # Loop to accept new xApp connections
                while True:
                    print(Fore.YELLOW + "[*] Waiting for new xApp connection...")
                    self.conn_from_xapp, addr = self.server.accept()
                    print(Fore.GREEN + f"[+] Accepted xApp connection from {addr}")
                    
                    try:
                    # Handle the traffic in its own function
                        self.proxy_traffic()
                    except Exception as e:
                        print(Fore.RED + f"[-] Proxy error: {e}")
                        #import traceback
                        #traceback.print_exc()
                    time.sleep(2)
                    # Clean up and wait for new xApp connection
                    self.cleanup_xapp()

            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] KeyboardInterrupt: Shutting down proxy.")
                try:
                    if self.tshark_process and self.tshark_process.pid:
                        os.killpg(os.getpgid(self.tshark_process.pid), signal.SIGTERM)
                        subprocess.run(['pkill', '-9', 'tshark'])
                        self.tshark_process = None

                except Exception as e:
                    print(Fore.YELLOW + f"[!] Error terminating tshark: {e}")

                self.print_statistics()
            except Exception as e:
                print(Fore.RED + f"[-] Unhandled error in start(): {e}")
                #import traceback
                #traceback.print_exc()
            finally:
                self.close_all()
                sys.exit(0)


    def cleanup_xapp(self):
        try:
            if self.conn_from_xapp:
                print(Fore.YELLOW + "[*] Cleaning up xApp connection.")
                
                # Stop current capture before generating state machine
                self._stop_tshark_capture()
                # Only generate state machine and diff if we actually captured data
                if self.session_file and os.path.exists(self.session_file):
                    # Check if the file has actual content (not just empty)
                    if os.path.getsize(self.session_file) > 0:
                        print(Fore.CYAN + f"[*] Session ended. Analyzing captured data...")
                        time.sleep(1)
                        # Generate the state machine for this session
                        self._generate_state_machine()
                        
                        # Generate the diff between current session and baseline
                        self._generate_diff(self.session_file)
                        
                        # Calculate and display cost
                        cost_result = self.calculate_fuzzing_cost(
                            max_mutations=self.max_mutations,
                            timestamp=self.timestamp,
                        )
                        self.cost_history.append(cost_result)
                        
                        ## ENABLE GENETIC OPTIMIZER
                        self.strategy_optimizer.update(cost_result["total_cost"])

                        print(f"[COST] Session cost: {cost_result['total_cost']:.2f}")
                        print(f"[COST] State changes: {cost_result['state_changes']}")
                        print(f"[COST] Transitions: {cost_result['total_transitions']}")
                        print(Fore.GREEN + f"[+] Session ID: {self.timestamp}")
                                                ## ENABLE GENETIC OPTIMIZER
                        #print(Fore.CYAN + f"[*] Updating strategy optimizer with cost: {cost_result['total_cost']:.2f}")
                        self.strategy_optimizer.update(cost_result["total_cost"])
                        print(Fore.CYAN + f"[*] Current best weights: {self.strategy_optimizer.get_best_weights()}")
                        print(Fore.MAGENTA + "=" * 50)
                    else:
                        print(Fore.YELLOW + "[*] Session file is empty, skipping analysis")
                else:
                    print(Fore.YELLOW + "[*] No session file found, skipping analysis")
                    #         try:
                try:
                    if self.conn_from_xapp:
                        print(Fore.YELLOW + "[*] Cleaning up xApp connection.")
                        self.conn_from_xapp.close()
                        self.conn_from_xapp = None
                        # Stop current capture and start new one for next session
                        self._stop_tshark_capture()
                        self._start_tshark_capture()
                except Exception as e:
                    print(Fore.RED + f"[-] Error during xApp cleanup: {e}")
                    
                # Cancel any existing timer since session is complete
                if self.timer:
                    self.timer.cancel()
                    self.timer = None
                
                print(Fore.GREEN + "[+] xApp session cleanup completed")
                
        except Exception as e:
            print(Fore.RED + f"[-] Error during xApp cleanup: {e}")
            # Ensure connection is closed even if other operations fail
            try:
                if self.conn_from_xapp:
                    self.conn_from_xapp.close()
                    self.conn_from_xapp = None
            except:
                pass

    def close_all(self):
        try:
            self._stop_tshark_capture()
            #self._split_and_save()
            if self.conn_from_xapp:
                self.conn_from_xapp.close()
            if self.ric_client:
                self.ric_client.close()
            if self.server:
                self.server.close()
            print(Fore.CYAN + "[*] Closed all sockets. Goodbye!")
        except Exception as e:
            print(Fore.RED + f"[-] Error closing sockets: {e}")

    
    def _start_tshark_capture(self):
        
        self.timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        self.session_file = os.path.join(self.captures_folder, f"session_{self.timestamp}.pcapng")
        tshark_cmd = [
            "tshark",
            "-i", self.interface,
            "-f", self.tshark_filter,  # Display filter
            "-w", self.session_file,
            "-F", "pcapng"
        ]
        
        try:
            self.tshark_process = subprocess.Popen(
                tshark_cmd,
                stdout=subprocess.PIPE,
                #stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group for clean shutdown
            )
            #print(Fore.GREEN + f"[+] Tshark process started with PID: {self.tshark_process.pid}")
            #stderr_output = self.tshark_process.stderr.read().decode()
            #print(Fore.YELLOW + f"[!] Tshark stderr output: {stderr_output}")
            #if stderr_output:
            #    print(Fore.RED + f"[!] Tshark stderr: {stderr_output}")
            print(Fore.GREEN + f"[+] Started tshark capture")
            #print(Fore.CYAN + f"[*] Command: {' '.join(tshark_cmd)}")
        except Exception as e:
            print(Fore.RED + f"[-] Failed to start tshark: {e}")
            self.tshark_process = None


    def _stop_tshark_capture(self):
        
        if self.tshark_process:
            try:
                # Send SIGTERM to the process group to cleanly stop tshark
                os.killpg(os.getpgid(self.tshark_process.pid), signal.SIGTERM)
                self.tshark_process.wait(timeout=5)
                print(Fore.GREEN + f"[+] Stopped tshark capture")
                
                # Generate diff for the completed session
                #if self.session_file and os.path.exists(self.session_file):
                #    self._generate_diff(self.session_file)
                    
            except subprocess.TimeoutExpired:
                print(Fore.YELLOW + "[!] Tshark didn't stop gracefully, forcing kill...")
                os.killpg(os.getpgid(self.tshark_process.pid), signal.SIGKILL)
                self.tshark_process.wait()  # Wait for the process to actually terminate
            except Exception as e:
                print(Fore.RED + f"[-] Error stopping tshark: {e}")
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] KeyboardInterrupt detected while stopping tshark.")
                os.killpg(os.getpgid(self.tshark_process.pid), signal.SIGTERM)
                self.tshark_process.wait()
            finally:
                self.tshark_process = None

    def duplicate_packet(self, msg, fromaddr, flags, notif, duplication_count):
        try:
            # Send original packet first
            self.ric_client.sctp_send(msg, ppid=socket.htonl(0))
            print(Fore.GREEN + f"[+] Sent original packet (Length: {len(msg)} bytes)")
            #print(Fore.LIGHTCYAN_EX + f"[DEBUG] Duplicated: {hexlify(msg)} bytes")
            # Configure duplication parameters
            duplicate_delay = getattr(self, 'duplicate_delay', 0.001)  # 1ms default delay
            max_failures = getattr(self, 'max_duplicate_failures', 3)
            
            print(Fore.MAGENTA + f"[FUZZ] Flooding with {duplication_count} duplicates (delay: {duplicate_delay*1000:.1f}ms)")
            
            failures = 0
            successful_duplicates = 0
            
            for i in range(duplication_count):
                try:
                    # Send duplicate using same SCTP socket to maintain association state
                    self.ric_client.sctp_send(msg, ppid=socket.htonl(0))
                    successful_duplicates += 1
                    print(Fore.YELLOW + f"[+] Duplicate #{i+1}/{duplication_count} sent")
                    # Add small delay between duplicates to avoid overwhelming receiver
                    if duplicate_delay > 0:
                        time.sleep(duplicate_delay)
                        
                except (BrokenPipeError, ConnectionResetError) as e:
                    print(Fore.RED + f"[-] Connection error on duplicate #{i+1}: {e}")
                    failures += 1
                    if failures >= max_failures:
                        print(Fore.RED + f"[-] Too many connection failures ({failures}), stopping duplication")
                        break
                    # Re-raise connection errors to trigger reconnection
                    raise
                        
                except Exception as e:
                    print(Fore.RED + f"[-] Error sending duplicate #{i+1}: {e}")
                    failures += 1
                    if failures >= max_failures:
                        print(Fore.RED + f"[-] Too many failures ({failures}), stopping duplication")
                        break
            
            print(Fore.CYAN + f"[*] Duplication complete: {successful_duplicates}/{duplication_count} successful")
            
            # Update statistics if they exist
            if hasattr(self, 'duplicate_stats'):
                self.duplicate_stats['sent'] += successful_duplicates
                self.duplicate_stats['failed'] += failures
            
        except Exception as e:
            print(Fore.RED + f"[-] Error during packet duplication: {e}")
            raise
    

    def proxy_traffic(self):
        """Main proxy loop to intercept, fuzz, and forward traffic with robustness."""
        self.duplication = True 
        while True:
            try:
                # Filter out None or closed sockets
                sockets = []
                if self.conn_from_xapp and self.conn_from_xapp.fileno() != -1:
                    sockets.append(self.conn_from_xapp)
                if self.ric_client and self.ric_client.fileno() != -1:
                    sockets.append(self.ric_client)
                
                # If no valid sockets, break out of the loop
                if not sockets:
                    print(Fore.YELLOW + "[!] No valid sockets available, ending proxy session")
                    break
                    
                rlist, _, _ = select.select(sockets, [], [], 10.0)
                if not rlist:
                    print(Fore.YELLOW + "[!] Timeout waiting for packets. Continuing...")
                    return

                for sock in rlist:
                    if sock == self.conn_from_xapp:
                        try:
                            # Start the timer for splitting files
                            if self.timer:
                                self.timer.cancel()
                            start_time = time.time()
                            fromaddr, flags, msg, notif = self.conn_from_xapp.sctp_recv(65535)
                            # print("From Address:",fromaddr)
                            # print("Flags:", flags)
                            # print("Message:", msg)
                            # print("Notification:", notif)

                            print(Fore.GREEN + f"[TX] [xApp --> RIC]")
                            print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Length: {len(msg)} bytes")
                            
                            self.messages_processed += 1
                            
                            message_type = self.fuzzer.guess_message_type(msg)
                            print(Fore.LIGHTYELLOW_EX + f"[DEBUG] Message Type: {message_type}")
                            modified_msg = self.fuzzer.process_message(msg, direction="to_ric")
                            
                            if modified_msg != msg and modified_msg is not None:
                                self.messages_fuzzed += 1
                            
                            if not modified_msg:
                                return
                            else:
                                try:
                                    # Check if duplication should be applied
                                    if self.duplication_enabled and random.random() < self.duplication_probability:
                                        # Generate random number of duplicates
                                        duplication_count = random.randint(1, self.max_duplicates)
                                        print(Fore.MAGENTA + f"[FUZZ] Applying duplication attack - {duplication_count} duplicates")
                                        
                                        # Call duplicate_packet with the SCTP parameters
                                        self.duplicate_packet(modified_msg, fromaddr, flags, notif, duplication_count)
                                    else:
                                        # Send normally without duplication
                                        self.ric_client.sctp_send(modified_msg, ppid=socket.htonl(0))
                                        #print(Fore.GREEN + f"[+] Sent packet normally")
                                    
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
                            try:
                                fromaddr2, flags2, msg2, notif2 = self.ric_client.sctp_recv(65535)
                            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                                print(Fore.RED + f"[!] RIC connection lost: {e}")
                                print(Fore.YELLOW + "[*] RIC disconnected, attempting to reconnect...")
                                raise  # Re-raise to trigger RIC reconnection
                            print(Fore.LIGHTBLUE_EX + "[RX] [xApp <-- RIC]")
                            print(Fore.LIGHTCYAN_EX + f"[DEBUG]" + Fore.RESET + f"Length: {len(msg2)} bytes")
                            
                            self.messages_processed += 1
                            
                            response_type = self.fuzzer.guess_message_type(msg2)
                            print(Fore.LIGHTYELLOW_EX + f"[DEBUG] Response Type: {response_type}")
                            response = self.fuzzer.process_message(msg2, direction="to_xapp")
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
                        except (ConnectionResetError, BrokenPipeError, OSError) as e:
                            print(Fore.RED + f"[-] RIC connection lost during forwarding: {e}")
                            print(Fore.YELLOW + "[*] Attempting to reconnect to RIC...")
                            raise  # Re-raise to trigger RIC reconnection
                        except Exception as e:
                            print(Fore.RED + f"[-] Error during RIC->xApp forwarding: {e}")
                            raise  # Re-raise to trigger reconnection

                        print(Fore.YELLOW + "-" * 50)

            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] KeyboardInterrupt: Shutting down proxy.")
                try:
                    if self.tshark_process and self.tshark_process.pid:
                        os.killpg(os.getpgid(self.tshark_process.pid), signal.SIGTERM)
                    subprocess.run(['pkill', '-9', 'tshark'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    print(Fore.YELLOW + f"[!] Error shutting down tshark: {e}")
                finally:
                    #if self.timer:
                    #    self.timer.cancel()
                    self.close_all()
                    sys.exit(0)  # clean exit
            except BrokenPipeError as e:
                print(Fore.RED + f"[-] Connection broken: {e}")
                print(Fore.YELLOW + "[*] Attempting to reconnect to RIC...\n")
                try:
                    if self.ric_client:
                        self.ric_client.close()
                except Exception:
                    pass

                # Retry RIC reconnection in-place
                while True:
                    try:
                        self.ric_client = sctp.sctpsocket_tcp(socket.AF_INET)
                        #self.ric_client.setsockopt(socket.AF_INET, socket.SO_REUSEADDR, 1)
                        #self.ric_client.bind((self.mitm, 0))
                        self.ric_client.connect((self.ric_ip, self.port))
                        print(Fore.GREEN + f"[+] Reconnected to RIC at {self.ric_ip}:{self.port}")
                        break
                    except Exception as e:
                        print(Fore.RED + f"[!] Reconnection to RIC failed: {e}. Retrying in 3 seconds...")
                        time.sleep(2)
                continue  # restart main loop
            
            except Exception as e:
                print(Fore.RED + f"[-] Exception in proxy_traffic loop: {e}")
                #import traceback
                #traceback.print_exc()
                print(Fore.YELLOW + "[*] Attempting to reconnect to RIC...\n")
                try:
                    if self.ric_client:
                        self.ric_client.close()
                except Exception:
                    pass

                # Retry RIC reconnection in-place
                while True:
                    try:
                        self.ric_client = sctp.sctpsocket_tcp(socket.AF_INET)
                        #self.ric_client.setsockopt(socket.AF_INET, socket.SO_REUSEADDR, 1)
                        #self.ric_client.bind((self.mitm, 0))
                        self.ric_client.connect((self.ric_ip, self.port))
                        print(Fore.GREEN + f"[+] Reconnected to RIC at {self.ric_ip}:{self.port}")
                        break
                    except Exception as e:
                        print(Fore.RED + f"[!] Reconnection to RIC failed: {e}. Retrying in 3 seconds...")
                        time.sleep(2)
                continue  # restart ma
            
    def close_connections(self):
        for sock in [self.conn_from_xapp, self.ric_client, self.server]:
            try:
                if sock:
                    sock.close()
            except Exception as e:
                print(Fore.YELLOW + f"[!] Failed to close socket: {e}")
        self.conn_from_xapp = None
        self.ric_client = None

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
        #if hasattr(self.fuzzer, 'fuzz_success_rate') and self.fuzzer.fuzz_success_rate:
        #    print("\nFuzzing success rate by message type:")
        #    for msg_type, rate in self.fuzzer.fuzz_success_rate.items():
        #        print(f"  {msg_type}: {rate*100:.2f}%")
        
        print(Fore.CYAN + "=" * 50)
        
    def _split_and_save(self):
        """Close the current session file, generate the state machine, and start a new session."""
        if self.pcap_writer:
            self.pcap_writer.close()
            print(Fore.GREEN + f"[+] Closed session file: {self.session_file}")
        
        # Stop current tshark process and start a new one
        current_session = self.session_file
        self._stop_tshark_capture()
        time.sleep(0.5)  # pause due to asyncrhonous killing of tshark
        
        # Generate the state machine for the closed session
        self._generate_state_machine()
        
        # Generate the diff between the current and previous session
        self._generate_diff(current_session)
            
        #self._start_tshark_capture()
        
        # Restart the timer for the next split
        if self.timer:
            self.timer.cancel()
        #self.timer = threading.Timer(10.0, self._split_and_save)
        #self.timer.start()

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
            "-o", (os.path.join(self.state_machines_folder, f"wdmapper_tmp_{self.timestamp}.svg"))
            
        ]

        print(Fore.YELLOW + f"[*] Generating state machine")
        #print(Fore.CYAN + f"[*] Command: {' '.join(wdmapper_gen_state_m)}")

        try:
            #print(Fore.YELLOW + "[*] Running wdmapper command...")
            
            # Run the wdmapper command
            result = subprocess.run(
                wdmapper_gen_state_m,
                capture_output=True,
                text=True,
                cwd="../vakt-ble-defender/PortableSetup/wdissector",
                check=True  # Raises CalledProcessError if return code != 0
            )
            print(Fore.GREEN + "[+] State machine generated successfully.")
            #if result.stdout.strip():
            #    print(f"[*] Output:\n{result.stdout}")

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
        wdissector_dir = "../vakt-ble-defender/PortableSetup/wdissector"
        transitions_source = os.path.join(wdissector_dir, "transitions.json")
        transitions_backup = os.path.join(wdissector_dir, f"transitions_{self.timestamp}.json")
        
        # Copy transitions.json BEFORE running wdmapper to preserve current state
        try:
            if os.path.exists(transitions_source):
                import shutil
                shutil.copy2(transitions_source, transitions_backup)
                #print(Fore.GREEN + f"[+] Backed up transitions.json to: transitions_{self.timestamp}.json")
            else:
                print(Fore.YELLOW + f"[!] transitions.json not found at {transitions_source}")
        except Exception as e:
            print(Fore.RED + f"[-] Error backing up transitions.json: {e}")

        # Construct the wdmapper command for diffing
        wdmapper_gen_diff = [
            "./bin/wdmapper",
            "--udp-dst-port=36421,38412,9999,38472,38412,36422",
            "-d", current_file,
            "-i", '../../../captures/Baseline_kpm_rc_ns3.pcapng',
            "-c", "./configs/5gnr_gnb_config.json",
            "-o", (os.path.join(self.state_machines_diff_folder,f"wdmapper_diff_{self.timestamp}.svg"))
        ]
        
        print(Fore.YELLOW + f"[*] Generating diff between current session and baseline Model")

        try:
            print(Fore.YELLOW + "[*] Running wdmapper diff command with baseline State Machine...")
            
            # Run the wdmapper command
            result = subprocess.run(
                wdmapper_gen_diff,
                capture_output=True,
                text=True,
                cwd=wdissector_dir,
                check=True  # Raises CalledProcessError if return code != 0
            )

            print(Fore.GREEN + "[+] Diff generated successfully.")
            
            # Store the path to the backed up transitions file for this session
            #self.current_session_transitions = transitions_backup
            self.current_session_transitions = os.path.abspath(transitions_backup)
            print(Fore.GREEN + f"[+] Session transitions file: {self.current_session_transitions}")

            
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

        subprocess.run(['pkill', '-9', 'tshark'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


    def calculate_fuzzing_cost(self, target_fields=None, max_mutations=1, 
                               alpha=0, beta=40, mu=0.1, t=20, timestamp=None):
        """
        Calculate the cost/reward function for fuzzing based on state machine exploration.
        
        Parameters:
        - target_fields: List of mutated field names (can be None)
        - max_mutations: Number of mutations applied
        - alpha: Weight for state discovery (higher = prioritize new states more)
        - beta: Weight for transitions (lower = less emphasis on transitions)
        - mu: Weight for mutation complexity
        - t: Normalization constant for transitions
        
        Returns:
        - cost: Dict representing the fuzzing effectiveness score (higher = better)
        """

        try:
            diff_file = os.path.join("../vakt-ble-defender/PortableSetup/wdissector", f"wdmapper_diff_{self.timestamp}.diff.json")
            #transitions_file = self.transitions_file
            transitions_file = os.path.join("../vakt-ble-defender/PortableSetup/wdissector", f"transitions_{self.timestamp}.json")

            # Initialize default values
            added_states = 0
            removed_states = 0
            total_transitions = 0
            
            # Try to load diff data
            try:
                with open(diff_file, 'r') as f:
                    diff_data = json.load(f)
                  
                print(Fore.MAGENTA + "=" * 50)
                print(Fore.MAGENTA + "            Cost Function Summary            ")
                print(Fore.MAGENTA + "=" * 50)
                # Calculate absolute state changes (|Added| + |Removed|)
                added_states = len(diff_data.get("Added", []))
                print(f"[DEBUG] Added states: {added_states}")
                removed_states = len(diff_data.get("Removed", []))
                print(f"[DEBUG] Removed states: {removed_states}")
            except FileNotFoundError:
                print(f"[WARNING] Diff file not found: {diff_file}, using default values")
                diff_data = {"Added": [], "Removed": []}
            except Exception as e:
                print(f"[WARNING] Error reading diff file: {e}, using default values")
                diff_data = {"Added": [], "Removed": []}
            
            # Try to load transitions data
            try:
                with open(transitions_file, 'r') as f:
                    transitions_data = json.load(f)
                total_transitions = transitions_data.get("total_transitions", 0)
                #print(f"[DEBUG] Total transitions extracted: {total_transitions}")
            except FileNotFoundError:
                print(f"[WARNING] Transitions file not found: {transitions_file}, using default values")
                transitions_data = {"total_transitions": 0}
            except Exception as e:
                print(f"[WARNING] Error reading transitions file: {e}, using default values")
                transitions_data = {"total_transitions": 0}
            
            state_change = abs(added_states) + abs(removed_states)
            print(f"[DEBUG] State changes: {state_change}")
            # Calculate mutation factor
            num_mutated_fields = len(target_fields) if target_fields else max_mutations
            print(f"[DEBUG] Number of mutated fields: {num_mutated_fields}")

            # Apply the cost function: cost = alpha * |state_changes| + beta * (transitions/t) + mu * mutations
            state_reward = alpha * state_change
            transition_reward = beta * (total_transitions / t)
            mutation_penalty = mu * num_mutated_fields
            
            total_cost = state_reward + transition_reward + mutation_penalty
            
            return {
                "total_cost": total_cost,
                "state_reward": state_reward,
                "transition_reward": transition_reward,
                "mutation_penalty": mutation_penalty,
                "state_changes": state_change,
                "added_states": added_states,
                "removed_states": removed_states,
                "total_transitions": total_transitions,
                "mutated_fields": num_mutated_fields
            }
            
        except Exception as e:
            print(f"[ERROR] Error calculating cost: {e}")
            return {
                "total_cost": 0.0,
                "state_reward": 0.0,
                "transition_reward": 0.0,
                "mutation_penalty": 0.0,
                "state_changes": 0,
                "added_states": 0,
                "removed_states": 0,
                "total_transitions": 0,
                "mutated_fields": 0
            }

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
    
