from contextlib import contextmanager
import socket
import time
import random
import re
import sys, json, threading, time, asn1tools, os, subprocess
import tempfile
from binascii import hexlify, unhexlify
from colorama import Fore, Style, init
import _sctp, os, sctp, signal, math
import select, string, copy
from scapy.utils import PcapWriter, PcapNgWriter
# Initialize colorama
init(autoreset=True)

if _sctp.getconstant("IPPROTO_SCTP") != 132:
    raise(Exception("getconstant failed"))
MSG_EOF = _sctp.getconstant("MSG_EOF")


IP_MITM = "192.168.1.195"    # Host bridge for RIC network
IP_GNB = "192.168.1.211"    # gNB container IP
# IP_GNB = "10.0.4.5"
# #IP_GNB ="10.0.2.1"
IP_E2TERM = "10.0.2.10" # E2Term container IP
# IP_E2TERM = "10.0.4.5"
E2_SCTP_PORT = 36422  

# Load constraints from JSON file
constraints_file = "./constraints_w_types.json" 

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
                mutation_rate=0.3):  # Increased from 0.3
        self.POPULATION_SIZE = population_size
        self.MUTATION_RATE = mutation_rate
        self.population = [self._random_individual() for _ in range(self.POPULATION_SIZE)]
        self.fitness_scores = [0] * self.POPULATION_SIZE

    def _random_individual(self):
        weights = [random.random() for _ in range(3)]
        total = sum(weights)
        return [w / total for w in weights]

    def _fitness(self, cost):
        return cost

    def _crossover(self, parent1, parent2):
        child = [(a + b) / 2 for a, b in zip(parent1, parent2)]
        total = sum(child)
        return [w / total for w in child]

    def _mutate(self, individual):
        # CRITICAL: Create a copy to avoid modifying original
        mutated = individual.copy()
        idx = random.randint(0, 2)
        change = random.uniform(-0.2, 0.2)
        mutated[idx] = max(0.01, mutated[idx] + change)
        total = sum(mutated)
        return [w / total for w in mutated]

    def update(self, cost):
        for i, c in enumerate(cost):
            self.fitness_scores[i] = self._fitness(c)
        
        # Select top 2 individuals
        top = sorted(zip(self.population, self.fitness_scores), 
                    key=lambda x: x[1], reverse=True)[:2]
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


class HardcodedMutations:
    
    def __init__(self):
        self.mutation_strategies = {
            "field_deletion": self.delete_critical_fields,
            "field_duplication": self.duplicate_fields,
            "invalid_ie_values": self.insert_invalid_ie_values,
            "boundary_values": self.insert_boundary_values,
            "type_confusion": self.type_confusion_mutation,
            "sequence_manipulation": self.manipulate_sequences,
            "id_manipulation": self.manipulate_ids,
            "size_manipulation": self.manipulate_sizes,
        }
    
    def apply_random_mutation(self, json_data, message_type):
        """Apply a random hardcoded mutation strategy"""
        strategy_name = random.choice(list(self.mutation_strategies.keys()))
        mutation_func = self.mutation_strategies[strategy_name]
        
        mutated_data, description = mutation_func(json_data, message_type)
        
        return mutated_data, strategy_name, description
    
    # ============= FIELD DELETION MUTATIONS =============
    def delete_critical_fields(self, json_data, message_type):
        """Delete critical mandatory fields to test error handling"""
        mutated = copy.deepcopy(json_data)
        deleted_fields = []
        
        # Target fields based on message type
        if message_type == "RICindication":
            targets = [
                ("protocolIEs.value.RICrequestID", ["ricRequestorID", "ricInstanceID"]),
                ("protocolIEs.value", ["RANfunctionID"]),
                ("protocolIEs.value", ["RICactionID"]),
                ("protocolIEs.value", ["RICindicationSN"]),
                ("protocolIEs.value", ["RICindicationType"]),
            ]
        elif message_type == "RICsubscription":
            targets = [
                ("protocolIEs.value.RICrequestID", ["ricRequestorID"]),
                ("protocolIEs.value", ["RANfunctionID"]),
                ("protocolIEs.value.RICsubscriptionDetails.ricAction-ToBeSetup-List", None),
            ]
        elif message_type == "E2setup":
            targets = [
                ("protocolIEs.value", ["GlobalE2node-ID"]),
                ("protocolIEs.value", ["RANfunctionsAdded"]),
            ]
        else:
            # Generic targets for any message
            targets = [
                ("protocolIEs.value.RICrequestID", ["ricRequestorID", "ricInstanceID"]),
                ("protocolIEs.value", ["RANfunctionID"]),
            ]
        
        # Select and delete 1-2 targets
        num_deletions = random.randint(1, min(2, len(targets)))
        selected_targets = random.sample(targets, num_deletions)
        
        for path, fields in selected_targets:
            if fields:
                # Delete specific fields
                for field in fields:
                    if self._delete_field_by_path(mutated, path, field):
                        deleted_fields.append(f"{path}.{field}")
            else:
                # Delete entire structure
                if self._delete_field_by_path(mutated, path):
                    deleted_fields.append(path)
        
        description = f"Deleted fields: {', '.join(deleted_fields)}"
        return mutated, description
    
    # ============= FIELD DUPLICATION MUTATIONS =============
    def duplicate_fields(self, json_data, message_type):
        """Duplicate fields/IEs to test parser robustness"""
        mutated = copy.deepcopy(json_data)
        duplicated = []
        
        # Find protocolIEs list
        if "protocolIEs" in mutated:
            protocol_ies = mutated["protocolIEs"]
            
            if isinstance(protocol_ies, list) and len(protocol_ies) > 0:
                # Select random IE to duplicate
                ie_to_duplicate = random.choice(protocol_ies)
                
                # Create 2-5 duplicates
                num_duplicates = random.randint(2, 5)
                
                for _ in range(num_duplicates):
                    duplicate = copy.deepcopy(ie_to_duplicate)
                    protocol_ies.append(duplicate)
                
                ie_id = ie_to_duplicate.get("id", "unknown")
                duplicated.append(f"IE-{ie_id} x{num_duplicates}")
                description = f"Duplicated {', '.join(duplicated)}"
                return mutated, description
        
        return mutated, "No fields duplicated"
    
    # ============= INVALID IE VALUE MUTATIONS =============
    def insert_invalid_ie_values(self, json_data, message_type):
        """Insert invalid values in Information Elements"""
        mutated = copy.deepcopy(json_data)
        mutations = []
        
        # Invalid RIC Request ID (out of valid range)
        if self._set_nested_value(mutated, "protocolIEs.value.RICrequestID.ricRequestorID", 65536):
            mutations.append("ricRequestorID=65536 (>max)")
        
        if self._set_nested_value(mutated, "protocolIEs.value.RICrequestID.ricInstanceID", 4294967295):
            mutations.append("ricInstanceID=4294967295 (max uint32)")
        
        # Invalid RANfunctionID
        if self._set_nested_value(mutated, "protocolIEs.value.RANfunctionID", 4096):
            mutations.append("RANfunctionID=4096 (>max 4095)")
        
        # Invalid RICactionID  
        if self._set_nested_value(mutated, "protocolIEs.value.RICactionID", 65535):
            mutations.append("RICactionID=65535 (max uint16)")
        
        # Invalid Criticality (valid: 0=reject, 1=ignore, 2=notify)
        if self._set_nested_value(mutated, "protocolIEs.criticality", 255):
            mutations.append("criticality=255 (invalid)")
        
        description = f"Invalid values: {', '.join(mutations)}"
        return mutated, description
    
    # ============= BOUNDARY VALUE MUTATIONS =============
    def insert_boundary_values(self, json_data, message_type):
        """Insert boundary/edge case values"""
        mutated = copy.deepcopy(json_data)
        mutations = []
        
        boundary_values = {
            "ricRequestorID": [0, 65535, -1, 32768],
            "ricInstanceID": [0, 4294967295, -1, 2147483647],
            "RANfunctionID": [0, 4095, 4096, 65535],
            "RICactionID": [0, 255, 256, 65535],
            "RICindicationSN": [0, 65535, -1],
        }
        
        # Apply 2-3 boundary value mutations
        fields = list(boundary_values.keys())
        random.shuffle(fields)
        
        for field in fields[:random.randint(2, 3)]:
            value = random.choice(boundary_values[field])
            if self._set_nested_value(mutated, f"protocolIEs.value.{field}", value):
                mutations.append(f"{field}={value}")
        
        description = f"Boundary values: {', '.join(mutations)}"
        return mutated, description
    
    # ============= TYPE CONFUSION MUTATIONS =============
    def type_confusion_mutation(self, json_data, message_type):
        """Replace field types to cause type confusion"""
        mutated = copy.deepcopy(json_data)
        mutations = []
        
        type_confusions = [
            # Replace integer with string
            ("protocolIEs.value.RANfunctionID", "not_a_number"),
            ("protocolIEs.value.RICactionID", "invalid"),
            
            # Replace string with integer
            ("protocolIEs.value.ricEventTriggerDefinition", 123456),
            ("protocolIEs.value.ricActionDefinition", 999999),
            
            # Replace dict with list
            ("protocolIEs.value.RICrequestID", [1, 2, 3]),
            
            # Replace list with dict
            ("protocolIEs", {"invalid": "structure"}),
            
            # Replace value with null
            ("protocolIEs.value.RICindicationHeader", None),
            ("protocolIEs.value.RICindicationMessage", None),
        ]
        
        # Apply 1-2 type confusions
        selected = random.sample(type_confusions, min(2, len(type_confusions)))
        
        for path, value in selected:
            if self._set_nested_value(mutated, path, value):
                mutations.append(f"{path}={type(value).__name__}")
        
        description = f"Type confusions: {', '.join(mutations)}"
        return mutated, description
    
    # ============= SEQUENCE MANIPULATION =============
    def manipulate_sequences(self, json_data, message_type):
        """Manipulate SEQUENCE OF structures"""
        mutated = copy.deepcopy(json_data)
        mutations = []
        
        # Find and manipulate lists
        if "protocolIEs" in mutated and isinstance(mutated["protocolIEs"], list):
            original_length = len(mutated["protocolIEs"])
            
            manipulation = random.choice([
                "empty",      # Empty the list
                "oversized",  # Add many duplicate entries
                "reorder",    # Shuffle order
                "remove_random" # Remove random entries
            ])
            
            if manipulation == "empty":
                mutated["protocolIEs"] = []
                mutations.append(f"emptied protocolIEs (was {original_length})")
                
            elif manipulation == "oversized":
                # Duplicate entries to create oversized list
                if len(mutated["protocolIEs"]) > 0:
                    duplicates = random.randint(50, 100)
                    for _ in range(duplicates):
                        mutated["protocolIEs"].append(
                            copy.deepcopy(random.choice(mutated["protocolIEs"]))
                        )
                    mutations.append(f"oversized protocolIEs to {len(mutated['protocolIEs'])} items")
                    
            elif manipulation == "reorder":
                random.shuffle(mutated["protocolIEs"])
                mutations.append("shuffled protocolIEs order")
                
            elif manipulation == "remove_random":
                if len(mutated["protocolIEs"]) > 2:
                    num_remove = random.randint(1, len(mutated["protocolIEs"]) - 1)
                    for _ in range(num_remove):
                        mutated["protocolIEs"].pop(random.randint(0, len(mutated["protocolIEs"]) - 1))
                    mutations.append(f"removed {num_remove} random IEs")
        
        description = f"Sequence manipulation: {', '.join(mutations)}"
        return mutated, description
    
    # ============= ID MANIPULATION =============
    def manipulate_ids(self, json_data, message_type):
        """Manipulate various ID fields"""
        mutated = copy.deepcopy(json_data)
        mutations = []
        
        id_mutations = [
            # Swap IDs between different IEs
            ("swap_ric_ids", lambda: self._swap_ric_request_ids(mutated)),
            
            # Set all IDs to same value
            ("unify_ids", lambda: self._unify_all_ids(mutated)),
            
            # Increment all IDs by large number
            ("increment_ids", lambda: self._increment_all_ids(mutated, 10000)),
            
            # Set negative IDs
            ("negative_ids", lambda: self._set_negative_ids(mutated)),
        ]
        
        selected = random.choice(id_mutations)
        mutation_name, mutation_func = selected
        
        if mutation_func():
            mutations.append(mutation_name)
        
        description = f"ID manipulation: {', '.join(mutations)}"
        return mutated, description
    
    # ============= SIZE MANIPULATION =============
    def manipulate_sizes(self, json_data, message_type):
        """Manipulate size/length fields"""
        mutated = copy.deepcopy(json_data)
        mutations = []
        
        # Manipulate hex string sizes (ricEventTriggerDefinition, ricActionDefinition, etc.)
        hex_fields = [
            "ricEventTriggerDefinition",
            "ricActionDefinition", 
            "RICindicationHeader",
            "RICindicationMessage",
            "ricControlMessage",
            "ricControlHeader"
        ]
        
        for field in hex_fields:
            value = self._get_nested_value(mutated, f"protocolIEs.value.{field}")
            if value and isinstance(value, str):
                manipulation = random.choice(["truncate", "extend", "zero"])
                
                if manipulation == "truncate" and len(value) > 4:
                    # Truncate to quarter size
                    new_value = value[:len(value)//4]
                    self._set_nested_value(mutated, f"protocolIEs.value.{field}", new_value)
                    mutations.append(f"{field} truncated to {len(new_value)} chars")
                    
                elif manipulation == "extend":
                    # Extend with random hex
                    extension = ''.join(random.choice('0123456789ABCDEF') for _ in range(1000))
                    new_value = value + extension
                    self._set_nested_value(mutated, f"protocolIEs.value.{field}", new_value)
                    mutations.append(f"{field} extended by 1000 chars")
                    
                elif manipulation == "zero":
                    # Replace with zeros
                    new_value = '00' * (len(value) // 2)
                    self._set_nested_value(mutated, f"protocolIEs.value.{field}", new_value)
                    mutations.append(f"{field} zeroed")
                
                break  # Only mutate one field
        
        description = f"Size manipulation: {', '.join(mutations)}"
        return mutated, description
    
    # ============= HELPER METHODS =============
    def _delete_field_by_path(self, data, path, field=None):
        """Delete a field at the given path"""
        parts = path.split('.')
        current = data
        
        try:
            # Navigate to parent
            for part in parts[:-1]:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                elif isinstance(current, list):
                    # Handle list notation like protocolIEs[0]
                    if '[' in part:
                        idx = int(part.split('[')[1].split(']')[0])
                        current = current[idx]
                    else:
                        return False
                else:
                    return False
            
            # Delete the target
            last_part = parts[-1]
            
            if field:
                # Delete specific field within the structure
                if isinstance(current, dict) and last_part in current:
                    target = current[last_part]
                    if isinstance(target, dict) and field in target:
                        del target[field]
                        return True
                    elif isinstance(target, list):
                        # Search in list items
                        for item in target:
                            if isinstance(item, dict) and field in item:
                                del item[field]
                                return True
            else:
                # Delete entire structure
                if isinstance(current, dict) and last_part in current:
                    del current[last_part]
                    return True
            
            return False
            
        except Exception as e:
            return False
    
    def _set_nested_value(self, data, path, value):
        """Set a value at nested path"""
        parts = path.split('.')
        current = data
        
        try:
            # Navigate to target
            for i, part in enumerate(parts[:-1]):
                if isinstance(current, dict):
                    if part in current:
                        current = current[part]
                    else:
                        return False
                elif isinstance(current, list):
                    # Search for matching structure in list
                    found = False
                    for item in current:
                        if isinstance(item, dict) and "value" in item:
                            current = item["value"]
                            found = True
                            break
                    if not found:
                        return False
            
            # Set value
            last_part = parts[-1]
            if isinstance(current, dict):
                current[last_part] = value
                return True
            elif isinstance(current, list):
                for item in current:
                    if isinstance(item, dict) and last_part in item:
                        item[last_part] = value
                        return True
            
            return False
            
        except Exception:
            return False
    
    def _get_nested_value(self, data, path):
        """Get value at nested path"""
        parts = path.split('.')
        current = data
        
        try:
            for part in parts:
                if isinstance(current, dict):
                    if part in current:
                        current = current[part]
                    else:
                        return None
                elif isinstance(current, list):
                    for item in current:
                        if isinstance(item, dict) and "value" in item:
                            current = item["value"]
                            break
                else:
                    return None
            
            return current
            
        except Exception:
            return None
    
    def _swap_ric_request_ids(self, data):
        """Swap ricRequestorID and ricInstanceID values"""
        try:
            if "protocolIEs" in data:
                for ie in data["protocolIEs"]:
                    if isinstance(ie, dict) and "value" in ie:
                        value = ie["value"]
                        if "RICrequestID" in value:
                            ric_req = value["RICrequestID"]
                            if "ricRequestorID" in ric_req and "ricInstanceID" in ric_req:
                                # Swap values
                                temp = ric_req["ricRequestorID"]
                                ric_req["ricRequestorID"] = ric_req["ricInstanceID"]
                                ric_req["ricInstanceID"] = temp
                                return True
            return False
        except Exception:
            return False
    
    def _unify_all_ids(self, data):
        """Set all ID fields to same value"""
        try:
            unified_value = 42
            modified = False
            
            if "protocolIEs" in data:
                for ie in data["protocolIEs"]:
                    if isinstance(ie, dict) and "value" in ie:
                        value = ie["value"]
                        
                        if "RICrequestID" in value:
                            ric_req = value["RICrequestID"]
                            if "ricRequestorID" in ric_req:
                                ric_req["ricRequestorID"] = unified_value
                                modified = True
                            if "ricInstanceID" in ric_req:
                                ric_req["ricInstanceID"] = unified_value
                                modified = True
                        
                        if "RANfunctionID" in value:
                            value["RANfunctionID"] = unified_value
                            modified = True
                        
                        if "RICactionID" in value:
                            value["RICactionID"] = unified_value
                            modified = True
            
            return modified
        except Exception:
            return False
    
    def _increment_all_ids(self, data, increment):
        """Increment all ID fields by a value"""
        try:
            modified = False
            
            if "protocolIEs" in data:
                for ie in data["protocolIEs"]:
                    if isinstance(ie, dict) and "value" in ie:
                        value = ie["value"]
                        
                        if "RICrequestID" in value:
                            ric_req = value["RICrequestID"]
                            if "ricRequestorID" in ric_req and isinstance(ric_req["ricRequestorID"], int):
                                ric_req["ricRequestorID"] += increment
                                modified = True
                            if "ricInstanceID" in ric_req and isinstance(ric_req["ricInstanceID"], int):
                                ric_req["ricInstanceID"] += increment
                                modified = True
                        
                        if "RANfunctionID" in value and isinstance(value["RANfunctionID"], int):
                            value["RANfunctionID"] += increment
                            modified = True
                        
                        if "RICactionID" in value and isinstance(value["RICactionID"], int):
                            value["RICactionID"] += increment
                            modified = True
            
            return modified
        except Exception:
            return False
    
    def _set_negative_ids(self, data):
        """Set ID fields to negative values"""
        try:
            modified = False
            
            if "protocolIEs" in data:
                for ie in data["protocolIEs"]:
                    if isinstance(ie, dict) and "value" in ie:
                        value = ie["value"]
                        
                        if "RICrequestID" in value:
                            ric_req = value["RICrequestID"]
                            if "ricRequestorID" in ric_req:
                                ric_req["ricRequestorID"] = -1
                                modified = True
                            if "ricInstanceID" in ric_req:
                                ric_req["ricInstanceID"] = -999
                                modified = True
                        
                        if "RANfunctionID" in value:
                            value["RANfunctionID"] = -100
                            modified = True
            
            return modified
        except Exception:
            return False

class JsonFuzzer:

    _subprocess_lock = threading.Lock()

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

        self.fuzzer_lock = threading.Lock()

        self.hardcoded_mutations = HardcodedMutations()
        self.use_hardcoded_mutations = False  # Toggle this to enable/disable
        self.hardcoded_probability = 0.7  # 70% chance to use hardcoded mutations


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

        with JsonFuzzer._subprocess_lock:
            try:
                reader_output = subprocess.check_output(
                    ['./reader', '-hex', str(hex_data)]
                ).decode('utf-8').strip()
                
                if not reader_output:
                    return None
                    
                return json.loads(reader_output)
                
            except (subprocess.CalledProcessError, json.JSONDecodeError, Exception) as e:
                print(Fore.RED + f"[!] Error in hex_to_json: {e}")
                return None
    
    # def hex_to_json(self, hex_data):
    #     if not hex_data or not str(hex_data).strip():
    #         return None

    #     try:
    #         reader_output = subprocess.check_output(['./reader', '-hex', str(hex_data)]).decode('utf-8').strip()
    #         if not reader_output:
    #             return None
    #         return json.loads(reader_output)
    #     except (subprocess.CalledProcessError, json.JSONDecodeError, Exception) as e:
    #         print(Fore.RED + f"[!] Error in hex_to_json: {e}")
    #         return None

    def json_to_hex(self, json_data):
        with JsonFuzzer._subprocess_lock:
            temp_file_path = None
            try:
                thread_id = threading.current_thread().ident
                
                with tempfile.NamedTemporaryFile(
                    mode='w', 
                    suffix=f'_{thread_id}.json',
                    delete=False
                ) as temp_file:
                    json.dump(json_data, temp_file)
                    temp_file_path = temp_file.name
                
                hex_output = subprocess.check_output(
                    ['./reader_json', '-json', temp_file_path]
                ).decode('utf-8').strip()
                
                os.unlink(temp_file_path)
                return hex_output
                
            except Exception as e:
                print(Fore.RED + f"Error converting JSON to hex: {e}")
                if temp_file_path and os.path.exists(temp_file_path):
                    try:
                        os.unlink(temp_file_path)
                    except:
                        pass
                return None
        
    # def json_to_hex(self, json_data):
    #     try:
    #         with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
    #             json.dump(json_data, temp_file)
    #             temp_file_path = temp_file.name
            
    #         hex_output = subprocess.check_output(['./reader_json', '-json', temp_file_path]).decode('utf-8').strip()
    #         os.unlink(temp_file_path)
    #         return hex_output
    #     except Exception as e:
    #         print(Fore.RED + f"Error converting JSON to hex: {e}")
    #         return None
    
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

            min_val = constraint.get("min")
            max_val = constraint.get("max")
            
            if min_val is not None and max_val is not None:
                length = random.randint(int(min_val), int(max_val))
            elif min_val is not None:
                length = int(min_val)
            elif max_val is not None:
                length = int(max_val)
            else:
                # Default to 8 bits if nothing specified
                length = 8

            # Generate random bits
            bits = [random.randint(0, 1) for _ in range(length)]

            # Convert to bit string and pad to byte boundary
            padded_length = math.ceil(length / 8) * 8
            bit_str = ''.join(str(b) for b in bits).ljust(padded_length, '0')

            # Pack into bytes
            packed_int = int(bit_str, 2)
            packed_bytes = packed_int.to_bytes(padded_length // 8, byteorder='big')
            return packed_bytes
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
        # print(f"[DEBUG] Applying mutation: {field_name} -> {new_value}")
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
        #print(Fore.CYAN + f"[*] Found {len(asn1_fields)} potential ASN.1 encoded fields.")
        #print(Fore.CYAN + f"[*] ASN.1 fields: {asn1_fields}")
        
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

            #print(Fore.CYAN + f"[DEBUG] ASN.1 targeting fields: {fields_to_mutate}")

            mutated_fields = []
            for target_field in fields_to_mutate:
                # Get constraints for the selected field if available
                field_constraints = self.get_field_constraints(target_field)
                #print(Fore.CYAN + f"[DEBUG] Constraints for {target_field}: {field_constraints}")
                
                random_value = None
                if field_constraints:
                    # Generate a value based on constraints
                    random_value = self.get_random_value(self.constraints, field_constraints)
                    #print(Fore.CYAN + f"[DEBUG] Generated new value for {target_field}: {random_value}")

                if random_value is not None:
                    # Apply the mutation to the ASN.1 content
                    asn1_content = self.apply_mutation_to_asn1(asn1_content, target_field, random_value)
                    print(Fore.GREEN + f"[+] Mutated field '{target_field}' to {random_value} in {decoded['definition']}")
                    #print(Fore.CYAN + f"[DEBUG] ASN.1 content after mutation: {asn1_content}")
                    mutated_fields.append(target_field)
                    #print(Fore.CYAN + f"[DEBUG] Mutated fields: {mutated_fields}")
            
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
                    #print(Fore.RED + f"[!] Traceback: {traceback.format_exc()}")
        
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
        
        #print(Fore.CYAN + f"[DEBUG] Selected JSON fields to mutate: {[f['name'] for f in fields_to_mutate]}")
        
        mutations = []
        
        for field in fields_to_mutate:
            field_name = field["name"]
            field_path = field["path"]
            original_value = self.get_field_value(mutated_json, field_path)
            
            # Get constraints for this field if available
            field_constraints = self.get_field_constraints(field_name)
            
            # Generate a value based on field name
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
    
    def process_message(self, msg, direction="gnb_to_e2term"):
        """Main method to process and fuzz a message (Thread-safe version)"""
        with self.fuzzer_lock:
            try:
                if not self.fuzzing_enabled:
                    return msg
                    
                msg_hex = hexlify(msg).decode()
                
                # Skip certain message types
                if msg_hex.startswith("200e00") or msg_hex.startswith("2e000091") \
                    or msg_hex.startswith("000e0081e7") or msg_hex is None:
                    return msg
                
                # **CHANGE HERE: Apply fuzzing for gnb_to_e2term direction**
                if direction == "gnb_to_e2term":
                    message_type = self.guess_message_type(msg)
                    print(Fore.CYAN + f"[Fuzzer-{threading.current_thread().name}] Processing {message_type} message ({len(msg)} bytes)")
                    print(Fore.GREEN + f"[Fuzzer-{threading.current_thread().name}] Before decoding:\n{msg_hex}")
                    
                    json_data = self.hex_to_json(msg_hex)
                    
                    if not json_data:
                        return msg
                        
                    print(Fore.GREEN + f"[Fuzzer-{threading.current_thread().name}] Converted to JSON:")
                    print(json.dumps(json_data, indent=2)) 
                    
                    # Get weights from strategy optimizer
                    if hasattr(self, "strategy_optimizer"):
                        weights = self.strategy_optimizer.get_best_weights()
                    else:
                        weights = [0.6, 0.3, 0.1]
                        
                    fuzz_strategy = random.choices(["asn1", "json", "both"], weights=weights, k=1)[0]
                    print(Fore.CYAN + f"[Fuzzer-{threading.current_thread().name}] Selected fuzzing strategy: {fuzz_strategy}")
                    
                    # Apply fuzzing based on strategy
                    if fuzz_strategy in ["asn1", "both"]:
                        fuzzed_json, asn1_mutations = self.fuzz_raw_hex(json_data)
                        if not asn1_mutations and fuzz_strategy == "both":
                            fuzzed_json, json_mutations = self.fuzz_top_level_json(fuzzed_json, message_type)
                            mutations = asn1_mutations + json_mutations
                        else:
                            mutations = asn1_mutations
                    else:
                        fuzzed_json, mutations = self.fuzz_top_level_json(json_data, message_type)
                    
                    # Convert back to hex if mutations were applied
                    if mutations:
                        print(Fore.MAGENTA + f"[Fuzzer-{threading.current_thread().name}] Applying {len(mutations)} mutations!")
                        modified_hex = self.json_to_hex(fuzzed_json)
                        
                        if modified_hex and modified_hex.strip():
                            modified_msg = unhexlify(modified_hex)
                            print(Fore.GREEN + f"[Fuzzer-{threading.current_thread().name}] Successfully fuzzed message ({len(modified_msg)} bytes)")
                            print(Fore.GREEN + f"[Fuzzer-{threading.current_thread().name}] Encoded again:\n{modified_hex}")
                            
                            print(Fore.LIGHTMAGENTA_EX + f"[Fuzzer-{threading.current_thread().name}] VERIFY Original: {msg_hex}")
                            print(Fore.LIGHTMAGENTA_EX + f"[Fuzzer-{threading.current_thread().name}] VERIFY Fuzzed:   {modified_hex}")
                            
                            return modified_msg
                        else:
                            print(Fore.RED + f"[Fuzzer-{threading.current_thread().name}] Failed to convert fuzzed JSON back to hex. Using original message.")
                            return msg
                    else:
                        print(Fore.BLUE + f"[Fuzzer-{threading.current_thread().name}] No mutations applied to this message.")
                        return msg
                else:
                    # **CHANGE HERE: Pass through messages from E2Term to gNB without fuzzing**
                    return msg
                    
            except Exception as e:
                print(Fore.RED + f"[Fuzzer-{threading.current_thread().name}] Error processing message: {e}")
                import traceback
                traceback.print_exc()
                return msg
    
class SCTPMITMProxy:
    

    def __init__(self, mitm_ip=IP_MITM, gnb_ip=IP_GNB, e2term_ip=IP_E2TERM, port=E2_SCTP_PORT):
        # Updated for E2 interface terminology
        self.mitm = mitm_ip
        #self.conn_from_e2term = gnb_ip          # Expected gNB IP (was xapp_ip)
        self.e2term_ip = e2term_ip    # E2 Termination IP (was ric_ip)
        self.gnb_ip = gnb_ip
        self.port = port
        self.server = None
        self.conn_from_e2term = None     # Connection from gNB (was conn_from_xapp)
        self.gnb_client = None     # Connection to E2Term (was ric_client)
        
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
        self.interface = "any"
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
        self.max_duplicates = 15
        self.duplication_enabled = True


        self.shutdown_event = threading.Event()
        self.active_connections = {}
        self.connection_lock = threading.Lock()
        self.session_mapping_lock = threading.Lock()
        self.stats_lock = threading.Lock()

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


### fix
    def start(self):
        try:
            # Initial setup

            self._start_tshark_capture()
            print(Fore.LIGHTMAGENTA_EX + f"[Genetic Algorithm] Enabled")
            # Set up SCTP server to accept gNB connections
            self.server = sctp.sctpsocket_tcp(socket.AF_INET)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.mitm, self.port))
            self.server.listen(1)

            print(Fore.YELLOW + f"[*] Listening for gNB connections on {self.mitm}:{self.port}...")
            print(Fore.CYAN + f"[*] Fuzzing enabled: {self.fuzz_enabled} (Probability: {self.fuzz_probability*100}%)")
            
            # Accept connections and immediately spawn threads
            while not self.shutdown_event.is_set():
                try:
                    # Wait for new gNB connection - FIXED VARIABLE NAME
                    conn_from_gnb, addr = self.server.accept()
                    
                    with self.connection_lock:
                        print(Fore.GREEN + f"[+] Accepted gNB connection from {addr}")
                    
                    connection_thread = threading.Thread(
                        target=self.proxy_e2_traffic,
                        args=(conn_from_gnb, addr),  # Pass the correct variable
                        daemon=True
                    )
                    connection_thread.start()

                    with self.connection_lock:
                        self.active_connections[addr] = {  # Use addr as key, not overwrite dict
                            'thread': connection_thread,
                            'conn_from_gnb': conn_from_gnb,
                            'addr': addr,
                            'start_time': time.time()
                        }
                
                    print(Fore.CYAN + f"[*] Started session in thread {connection_thread.name}")
                    
                except socket.error as e:
                    if not self.shutdown_event.is_set():
                        print(Fore.RED + f"[-] Socket error accepting connection: {e}")
                        import traceback
                        print(Fore.RED + f"[-] Traceback: {traceback.format_exc()}")
                    break
                except Exception as e:
                    print(Fore.RED + f"[-] Error accepting connection: {e}")
            #sleep(5)
            # After the main accept loop, run GA analysis if we have session data
            print(Fore.MAGENTA + "[*] Starting Genetic Algorithm analysis...")
            
            # MAIN ALGORITHM LOOP - Sequential individual sessions (keep your GA logic)
            generation = 1
            individual_index = 0  # Current individual in population
            costs = []           # Costs for current generation
            while True:
                # Display current status
                current_weights = self.strategy_optimizer.population[individual_index]
                #print(Fore.MAGENTA + f"[GA] Individual {individual_index + 1}/{self.strategy_optimizer.POPULATION_SIZE}")
                #print(Fore.MAGENTA + f"[GA] Weights: {[round(w,2) for w in current_weights]} (ASN.1, JSON, Both)")
                
                # Wait for xApp connection
                self.conn_from_e2term, addr = self.server.accept()
                
                print(Fore.GREEN + f"[+] Accepted E2 Term connection from {addr}")
                
                # Set weights for this individual's session
                self.current_session_weights = current_weights
                
                session_cost = 0.0
                try:
                    # Run ONE session for this individual
                    #print(Fore.CYAN + f"[*] Starting session for individual {individual_index + 1}...")
                    self.proxy_e2_traffic()
                    #print(Fore.CYAN + f"[*] Session ended for individual {individual_index + 1}")
                    
                    # Calculate cost for this session
                    if self.session_file and os.path.exists(self.session_file):
                        # Stop current capture
                        self._stop_tshark_capture()
                        
                        # Only analyze if we have actual data
                        if os.path.getsize(self.session_file) > 0:
                            #print(Fore.CYAN + f"[*] Analyzing session data for individual {individual_index + 1}...")
                            #time.sleep(1)
                            
                            # Generate the state machine for this session
                            self._generate_state_machine()
                            
                            # Generate the diff between current session and baseline
                            self._generate_diff(self.session_file)
                            
                            # Calculate and store cost
                            cost_result = self.calculate_fuzzing_cost(
                                max_mutations=self.max_mutations,
                                timestamp=self.timestamp,
                            )
                            session_cost = cost_result["total_cost"]
                            self.cost_history.append(cost_result)
                            
                            #print(f"[COST] Individual {individual_index + 1} cost: {session_cost:.2f}")
                            print(f"[COST] Session cost: {session_cost:.2f}")
                            print(f"[COST] State changes: {cost_result['state_changes']}")
                            print(f"[COST] Transitions: {cost_result['total_transitions']}")
                            print(Fore.GREEN + f"[+] Session ID: {self.timestamp}")
                        else:
                            print(Fore.YELLOW + "[*] Session file is empty, using default cost")
                            session_cost = 0.0
                    else:
                        print(Fore.YELLOW + "[*] No session file found, using default cost")
                        session_cost = 0.0
                        
                except Exception as e:
                    print(Fore.RED + f"[-] Session error for individual {individual_index + 1}: {e}")
                    session_cost = 0.0
                
                # Store cost for this individual
                costs.append(session_cost)
                #print(Fore.CYAN + f"[GA] Individual {individual_index + 1} final cost: {session_cost:.2f}")
                
                # Clean up and prepare for next session
                self.cleanup_xapp()
                
                # Move to next individual
                individual_index += 1
                
                # Check if we've completed all individuals in this generation
                if individual_index >= self.strategy_optimizer.POPULATION_SIZE:
                    print(Fore.MAGENTA + "=" * 70)
                    print(Fore.MAGENTA + f"            GENERATION {generation} COMPLETE            ")
                    print(Fore.MAGENTA + "=" * 70)
                    
                    # Display all costs for this generation
                    print(Fore.CYAN + f"[GA] Generation {generation} costs:")
                    for i, cost in enumerate(costs):
                        weights = self.strategy_optimizer.population[i]
                        #rint(Fore.CYAN + f"  Individual {i+1}: Cost={cost:.2f}, Weights={[round(w,2) for w in weights]}")
                    
                    # Update population with all costs from this generation
                    #print(Fore.CYAN + f"[GA] Evolving population based on {len(costs)} individual costs...")
                    self.strategy_optimizer.update(costs)
                    
                    # Display new generation info
                    best_weights = self.strategy_optimizer.get_best_weights()
                    print(Fore.GREEN + f"[GA] New population evolved!")
                    print(Fore.GREEN + f"[GA] Best weights: {[round(w,2) for w in best_weights]} (ASN.1, JSON, Both)")
                    
                    #Display all individuals in new population
                    print(Fore.CYAN + f"[GA] New generation {generation + 1} population:")
                    for i, individual in enumerate(self.strategy_optimizer.population):
                        print(Fore.CYAN + f"  Individual {i+1}: {[round(w,2) for w in individual]}")
                    
                    # Reset for next generation
                    generation += 1
                    individual_index = 0
                    costs = []
                    
                    print(Fore.MAGENTA + f"[GA] Starting generation {generation}...")
                    print(Fore.MAGENTA + "=" * 70)
                    
                    # Brief pause before next generation
                    time.sleep(2)

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
            
            # # Print final genetic algorithm stats
            # if costs:  # If we have some costs from current generation
            #     print(Fore.MAGENTA + "\n" + "=" * 50)
            #     print(Fore.MAGENTA + "        GENETIC ALGORITHM FINAL STATS        ")
            #     print(Fore.MAGENTA + "=" * 50)
            #     print(f"Completed generations: {generation - 1}")
            #     print(f"Current generation progress: {len(costs)}/{self.strategy_optimizer.POPULATION_SIZE}")
            #     if self.cost_history:
            #         avg_cost = sum(c["total_cost"] for c in self.cost_history) / len(self.cost_history)
            #         max_cost = max(c["total_cost"] for c in self.cost_history)
            #         print(f"Average session cost: {avg_cost:.2f}")
            #         print(f"Best session cost: {max_cost:.2f}")
            #     print(f"Final best weights: {[round(w,2) for w in self.strategy_optimizer.get_best_weights()]}")
            #     print(Fore.MAGENTA + "=" * 50)
                
        except Exception as e:
            print(Fore.RED + f"[-] Unhandled error in start(): {e}")
            #import traceback
            #print(Fore.RED + f"Traceback: {traceback.format_exc()}")
            
        finally:
            self.close_all()
            sys.exit(0)
            


    # def e2term_to_gnb(self, conn_from_gnb, e2term_client):
    #     """Handle E2Term -> gNB E2AP messages"""
    #     thread_name = threading.current_thread().name
    #     try:
    #         # Cancel timer if exists
    #         if hasattr(self, 'timer') and self.timer:
    #             self.timer.cancel()
    #         start_time = time.time()
            
    #         # Receive FROM E2Term (the client connection we created)
    #         fromaddr, flags, msg, notif = e2term_client.sctp_recv(65535)
    #         print(notif.ppid)
    #         #print(Fore.RED + fromaddr)
    #         if not msg or len(msg) == 0:
    #             print(Fore.YELLOW + f"[Session-{thread_name}] Received empty message from E2Term, connection closing")
    #             return False
                
    #         print(Fore.LIGHTBLUE_EX + f"[Session-{thread_name}] [RX] [E2Term --> gNB]")
            
    #         # Analyze E2AP message type
    #         message_type = self._analyze_e2ap_message(msg, "e2term_to_gnb")
    #         print(Fore.LIGHTYELLOW_EX + f"[Session-{thread_name}] [DEBUG] E2AP Message Type: {message_type}")
            
    #         # Apply your fuzzing logic
    #         modified_msg = self.fuzzer.process_message(msg, direction="e2term_to_gnb")
            
    #         with self.stats_lock:
    #             self.messages_processed += 1
            
    #         # CRITICAL FIX: Check for None explicitly, not falsy values
    #         if modified_msg is None:
    #             print(Fore.YELLOW + f"[Session-{thread_name}] [!] Fuzzer returned None, dropping packet")
    #             return False
            
    #         # Check if message was actually modified
    #         if modified_msg != msg:
    #             with self.stats_lock:
    #                 self.messages_fuzzed += 1
    #             print(Fore.MAGENTA + f"[Session-{thread_name}] [FUZZ] Message was modified!")
    #             print(Fore.MAGENTA + f"[Session-{thread_name}] [FUZZ] Original size: {len(msg)}b -> Modified size: {len(modified_msg)}b")
    #         else:
    #             print(Fore.BLUE + f"[Session-{thread_name}] [INFO] Message passed through unchanged")
            
    #         # Send TO gNB (the accepted connection)
    #         try:
    #             # Check if duplication should be applied
    #             if self.duplication_enabled and random.random() < self.duplication_probability:
    #                 # Generate random number of duplicates
    #                 duplication_count = random.randint(1, self.max_duplicates)
    #                 print(Fore.MAGENTA + f"[Session-{thread_name}] [FUZZ] Applying duplication attack - {duplication_count} duplicates")
                    
    #                 # Send original + duplicates to gNB
    #                 for i in range(duplication_count + 1):  # +1 for original
    #                     conn_from_gnb.sctp_send(bytes(modified_msg), ppid=socket.htonl(0))
    #             else:
    #                 # Send normally without duplication to gNB
    #                 if modified_msg and len(modified_msg) > 0:
    #                     conn_from_gnb.sctp_send(bytes(modified_msg), ppid=socket.htonl(0))
    #                 else:
    #                     print(Fore.RED + f"[Session-{thread_name}] [!] Cannot send empty message, dropping")
    #                     return False
                
    #             end_time = time.time()
    #             conversion_time = (end_time - start_time) * 1000  # milliseconds
    #             print(Fore.LIGHTCYAN_EX + f"[Session-{thread_name}] [DEBUG] Overhead: {conversion_time:.2f} ms")
                
    #             return True
                
    #         except BrokenPipeError:
    #             print(Fore.RED + f"[Session-{thread_name}] [!] Connection to gNB lost during send")
    #             return False
                    
    #     except Exception as e:
    #         print(Fore.RED + f"[Session-{thread_name}] [-] Error during E2Term->gNB forwarding: {e}")
    #         return False
    #     finally:
    #         print(Fore.YELLOW + f"[Session-{thread_name}] " + "-" * 40)

    def e2term_to_gnb(self, conn_from_gnb, e2term_client):
        """Handle E2Term -> gNB E2AP messages (PASSTHROUGH - NO FUZZING)"""
        thread_name = threading.current_thread().name
        try:
            start_time = time.time()
            
            fromaddr, flags, msg, notif = e2term_client.sctp_recv(65535)
            
            if not msg or len(msg) == 0:
                print(Fore.YELLOW + f"[Session-{thread_name}] Received empty message from E2Term, connection closing")
                return False
                
            print(Fore.LIGHTBLUE_EX + f"[Session-{thread_name}] [RX] [E2Term --> gNB]")
            
            message_type = self._analyze_e2ap_message(msg, "e2term_to_gnb")
            print(Fore.LIGHTYELLOW_EX + f"[Session-{thread_name}] [DEBUG] E2AP Message Type: {message_type}")
            
            # **CHANGE HERE: Pass through without fuzzing**
            modified_msg = msg  # No fuzzing applied
            
            with self.stats_lock:
                self.messages_processed += 1
            
            print(Fore.BLUE + f"[Session-{thread_name}] [INFO] Message passed through unchanged (no fuzzing)")
            
            if modified_msg is None:
                print(Fore.YELLOW + f"[Session-{thread_name}] [!] Message is None, dropping packet")
                return False
            
            try:
                if modified_msg and len(modified_msg) > 0:
                    conn_from_gnb.sctp_send(bytes(modified_msg), ppid=socket.htonl(0))
                else:
                    print(Fore.RED + f"[Session-{thread_name}] [!] Cannot send empty message, dropping")
                    return False
                
                end_time = time.time()
                conversion_time = (end_time - start_time) * 1000
                print(Fore.LIGHTCYAN_EX + f"[Session-{thread_name}] [DEBUG] Overhead: {conversion_time:.2f} ms")
                
                return True
                
            except BrokenPipeError:
                print(Fore.RED + f"[Session-{thread_name}] [!] Connection to gNB lost during send")
                return False
                    
        except Exception as e:
            print(Fore.RED + f"[Session-{thread_name}] [-] Error during E2Term->gNB forwarding: {e}")
            return False
        finally:
            print(Fore.YELLOW + f"[Session-{thread_name}] " + "-" * 40)

    # def gnb_to_e2term(self, conn_from_gnb, e2term_client):
    #     """Handle gNB -> E2Term E2AP messages"""
    #     thread_name = threading.current_thread().name
    #     try:
    #         start_time = time.time()
            
    #         # Receive FROM gNB (the accepted connection)
    #         fromaddr, flags, msg, notif = conn_from_gnb.sctp_recv(65535)
            
    #         # Check for empty message (connection closing)
    #         if not msg or len(msg) == 0:
    #             print(Fore.YELLOW + f"[Session-{thread_name}] Received empty message from gNB, connection closing")
    #             return False
                
    #         print(Fore.GREEN + f"[Session-{thread_name}] [RX] [E2Term <-- gNB]")
    #         print(Fore.LIGHTCYAN_EX + f"[Session-{thread_name}] [DEBUG] Length: {len(msg)} bytes")
    #         print(f"[Session-{thread_name}] Raw message (hex): {hexlify(msg).decode()}")
            
    #         with self.stats_lock:
    #             self.messages_processed += 1
            
    #         # Analyze E2AP message type
    #         message_type = self._analyze_e2ap_message(msg, "gnb_to_e2term")
    #         print(Fore.LIGHTYELLOW_EX + f"[Session-{thread_name}] [DEBUG] E2AP Message Type: {message_type}")
            
    #         # Apply fuzzing logic (pass through for gNB->E2Term direction)
    #         modified_msg = self.fuzzer.process_message(msg, direction="gnb_to_e2term")
            
    #         # Check response validity
    #         if modified_msg is None or len(modified_msg) == 0:
    #             print(Fore.YELLOW + f"[Session-{thread_name}] [!] Fuzzer returned empty/None, dropping packet")
    #             return False
            
    #         # Send TO E2Term (the client connection we created)
    #         try:
    #             e2term_client.sctp_send(bytes(modified_msg), ppid=socket.htonl(0))
    #             print(Fore.GREEN + f"[Session-{thread_name}] [TX] [E2Term --> gNB]")
                
    #             end_time = time.time()
    #             conversion_time = (end_time - start_time) * 1000
    #             print(Fore.LIGHTCYAN_EX + f"[Session-{thread_name}] [DEBUG] Overhead: {conversion_time:.2f} ms")
                
    #             return True
                
    #         except BrokenPipeError:
    #             print(Fore.RED + f"[Session-{thread_name}] [!] Connection to E2Term lost during send")
    #             return False
                    
    #     except (ConnectionResetError, BrokenPipeError, OSError) as e:
    #         print(Fore.RED + f"[Session-{thread_name}] [-] gNB connection lost: {e}")
    #         return False
    #     except Exception as e:
    #         print(Fore.RED + f"[Session-{thread_name}] [-] Error during gNB->E2Term forwarding: {e}")
    #         return False
    #     finally:
    #         print(Fore.YELLOW + f"[Session-{thread_name}] " + "-" * 40)

    def gnb_to_e2term(self, conn_from_gnb, e2term_client):
        """Handle gNB -> E2Term E2AP messages"""
        thread_name = threading.current_thread().name
        try:
            start_time = time.time()
            
            # Receive FROM gNB (the accepted connection)
            fromaddr, flags, msg, notif = conn_from_gnb.sctp_recv(65535)
            
            if not msg or len(msg) == 0:
                print(Fore.YELLOW + f"[Session-{thread_name}] Received empty message from gNB, connection closing")
                return False
                
            #print(Fore.GREEN + f"[Session-{thread_name}] [RX] [E2Term <-- gNB]")
            print(Fore.GREEN + f"[Session-{thread_name}] [RX] [E2Term --> gNB]")

            message_type = self._analyze_e2ap_message(msg, "gnb_to_e2term")
            print(Fore.LIGHTYELLOW_EX + f"[Session-{thread_name}] [DEBUG] E2AP Message Type: {message_type}")
            
            # **CHANGE HERE: Apply fuzzing in gnb_to_e2term direction**
            modified_msg = self.fuzzer.process_message(msg, direction="gnb_to_e2term")
            
            with self.stats_lock:
                self.messages_processed += 1
            
            # **ADD: Check if message was modified**
            if modified_msg != msg:
                with self.stats_lock:
                    self.messages_fuzzed += 1
                print(Fore.MAGENTA + f"[Session-{thread_name}] [FUZZ] Message was modified!")
                print(Fore.MAGENTA + f"[Session-{thread_name}] [FUZZ] Original size: {len(msg)}b -> Modified size: {len(modified_msg)}b")
            
            if modified_msg is None or len(modified_msg) == 0:
                print(Fore.YELLOW + f"[Session-{thread_name}] [!] Fuzzer returned empty/None, dropping packet")
                return False
            
            # **ADD: Apply duplication if enabled**
            try:
                if self.duplication_enabled and random.random() < self.duplication_probability:
                    duplication_count = random.randint(1, self.max_duplicates)
                    print(Fore.MAGENTA + f"[Session-{thread_name}] [FUZZ] Applying duplication attack - {duplication_count} duplicates")
                    
                    for i in range(duplication_count + 1):
                        e2term_client.sctp_send(bytes(modified_msg), ppid=socket.htonl(0))
                else:
                    e2term_client.sctp_send(bytes(modified_msg), ppid=socket.htonl(0))
                
                #print(Fore.GREEN + f"[Session-{thread_name}] [TX] [E2Term --> gNB]")
                print(Fore.GREEN + f"[Session-{thread_name}] [TX] [E2Term <-- gNB]")
                end_time = time.time()
                conversion_time = (end_time - start_time) * 1000
                print(Fore.LIGHTCYAN_EX + f"[Session-{thread_name}] [DEBUG] Overhead: {conversion_time:.2f} ms")
                
                return True
                
            except BrokenPipeError:
                print(Fore.RED + f"[Session-{thread_name}] [!] Connection to E2Term lost during send")
                return False
                    
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(Fore.RED + f"[Session-{thread_name}] [-] gNB connection lost: {e}")
            return False
        except Exception as e:
            print(Fore.RED + f"[Session-{thread_name}] [-] Error during gNB->E2Term forwarding: {e}")
            return False
        finally:
            print(Fore.YELLOW + f"[Session-{thread_name}] " + "-" * 40)

    def _analyze_e2ap_message(self, msg, direction):
        """Analyze E2AP message type and content"""
        if len(msg) < 1:
            return "UNKNOWN"
            
        try:
            # Basic E2AP message type detection
            # E2AP uses ASN.1 PER encoding
            first_byte = msg[1]
            
            # Common E2AP message types (simplified detection based on first byte)
            e2ap_types = {
                            0x01: "E2setup", 0x02: "ErrorIndication", 0x03: "Reset",
            0x04: "RICcontrol", 0x05: "RICindication", 0x06: "RICserviceQuery",
            0x07: "RICserviceUpdate", 0x08: "RICsubscription", 
            0x09: "RICsubscriptionDelete", 0x0A: "E2nodeConfigurationUpdate",
            0x0B: "E2connectionUpdate", 0x0C: "RICsubscriptionDeleteRequired",
            0x0D: "E2removal", 0x0E: "E42setup", 0x0F: "E42RICsubscription",
            0x10: "E42RICsubscriptionDelete", 0x11: "E42RICcontrol", 
            0x12: "E42updateE2node"
            }
            
            msg_type = e2ap_types.get(first_byte, f"UNKNOWN(0x{first_byte:02x})")
            
            #print(f"[E2AP] {direction.upper()} {msg_type}")
            return msg_type
            
        except Exception as e:
            print(f"[!] Error analyzing E2AP: {e}")
            return "ERROR"


    def cleanup_xapp(self):
        try:
            if self.conn_from_e2term:
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
                        
                        # DON'T calculate cost here - it will be done in main loop
                        #print(Fore.GREEN + f"[+] Session analysis complete. Session ID: {self.timestamp}")
                    else:
                        print(Fore.YELLOW + "[*] Session file is empty, skipping analysis")
                else:
                    print(Fore.YELLOW + "[*] No session file found, skipping analysis")

                try:
                    if self.conn_from_e2term:
                        self.conn_from_e2term.close()
                        self.conn_from_e2term = None
                        # Start new capture for next session
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
                if self.conn_from_e2term:
                    self.conn_from_e2term.close()
                    self.conn_from_e2term = None
            except:
                pass

    def close_all(self):
        try:
            self._stop_tshark_capture()
            
            # Close all active connections
            with self.connection_lock:
                for addr, conn_info in list(self.active_connections.items()):
                    try:
                        if 'conn_from_gnb' in conn_info and conn_info['conn_from_gnb']:
                            conn_info['conn_from_gnb'].close()
                            print(Fore.YELLOW + f"[*] Closed connection from {addr}")
                    except Exception as e:
                        print(Fore.RED + f"[-] Error closing connection {addr}: {e}")
            
            # Close server socket
            if self.server:
                self.server.close()
                print(Fore.CYAN + "[*] Closed server socket")
                
            print(Fore.CYAN + "[*] Closed all sockets. Goodbye!")
            
        except Exception as e:
            print(Fore.RED + f"[-] Error closing sockets: {e}")
                    
    # def close_all(self):
    #     try:
    #         self._stop_tshark_capture()
    #         #self._split_and_save()
    #         if self.conn_from_e2term:
    #             self.conn_from_e2term.close()
    #         if self.gnb_client:
    #             self.gnb_client.close()
    #         if self.server:
    #             self.server.close()
    #         print(Fore.CYAN + "[*] Closed all sockets. Goodbye!")
    #     except Exception as e:
    #         print(Fore.RED + f"[-] Error closing sockets: {e}")

    
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
            self.gnb_client.sctp_send(msg, ppid=socket.htonl(0))
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
                    self.gnb_client.sctp_send(msg, ppid=socket.htonl(0))
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

    def proxy_e2_traffic(self, conn_from_gnb, addr):

        e2term_client = None
        thread_name = threading.current_thread().name
        session_start_time = time.time()
        
        try:
            print(Fore.CYAN + f"[Session-{thread_name}] Starting proxy for gNB {addr}")
            
            e2term_client = sctp.sctpsocket_tcp(socket.AF_INET)
            e2term_client.bind((self.mitm, 0)) 
            e2term_client.connect((self.e2term_ip, self.port))
            
            print(Fore.GREEN + f"[Session-{thread_name}] Connected to E2Term at {self.e2term_ip}:{self.port}")

            while not self.shutdown_event.is_set():
                try:
                    readable, _, exceptional = select.select(
                        [conn_from_gnb, e2term_client], 
                        [], 
                        [conn_from_gnb, e2term_client], 
                        1.0
                    )
  
                    # gNB TO E2Term
                    if conn_from_gnb in readable:
                        if not self.gnb_to_e2term(conn_from_gnb, e2term_client):
                            print(Fore.YELLOW + f"[Session-{thread_name}] gNB connection closed")
                            break
                    
                    # # E2Term TO gNB
                    if e2term_client in readable:
                        if not self.e2term_to_gnb(conn_from_gnb, e2term_client):
                            print(Fore.YELLOW + f"[Session-{thread_name}] E2Term connection closed")
                            break
                            
                except socket.timeout:
                    continue
                except select.error as e:
                    if not self.shutdown_event.is_set():
                        print(Fore.RED + f"[Session-{thread_name}] Select error: {e}")
                    break

        except socket.error as e:
            print(Fore.RED + f"[Session-{thread_name}] Socket error connecting to E2Term: {e}")
        except Exception as e:
            print(Fore.RED + f"[Session-{thread_name}] Unexpected error in proxy_e2_traffic: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Calculate session duration
            session_duration = time.time() - session_start_time
            print(Fore.YELLOW + f"[Session-{thread_name}] Session duration: {session_duration:.2f}s")
            
            # Clean up this session's connections
            print(Fore.YELLOW + f"[Session-{thread_name}] Cleaning up connections for {addr}")
            
            try:
                if conn_from_gnb:
                    conn_from_gnb.close()
                    print(Fore.YELLOW + f"[Session-{thread_name}] Closed gNB connection")
            except Exception as e:
                print(Fore.RED + f"[Session-{thread_name}] Error closing gNB connection: {e}")
            
            try:
                if e2term_client:
                    e2term_client.close()
                    print(Fore.YELLOW + f"[Session-{thread_name}] Closed E2Term connection")
            except Exception as e:
                print(Fore.RED + f"[Session-{thread_name}] Error closing E2Term connection: {e}")
            
            # Calculate fuzzing cost for this session (if enabled)
            try:
                if self.session_file and os.path.exists(self.session_file):
                    # Stop current capture for this session
                    self._stop_tshark_capture()
                    
                    # Only analyze if we have actual data
                    if os.path.getsize(self.session_file) > 0:
                        print(Fore.CYAN + f"[Session-{thread_name}] Analyzing session data...")
                        
                        # Generate the state machine for this session
                        self._generate_state_machine()
                        
                        # Generate the diff between current session and baseline
                        self._generate_diff(self.session_file)
                        
                        # Calculate and store cost
                        cost_result = self.calculate_fuzzing_cost(
                            max_mutations=self.max_mutations,
                            timestamp=self.timestamp,
                        )
                        session_cost = cost_result["total_cost"]
                        
                        with self.stats_lock:
                            self.cost_history.append(cost_result)
                        
                        print(Fore.MAGENTA + f"[Session-{thread_name}] Session cost: {session_cost:.2f}")
                        print(Fore.MAGENTA + f"[Session-{thread_name}] State changes: {cost_result['state_changes']}")
                        print(Fore.MAGENTA + f"[Session-{thread_name}] Transitions: {cost_result['total_transitions']}")
                        print(Fore.GREEN + f"[Session-{thread_name}] Session ID: {self.timestamp}")
                    else:
                        print(Fore.YELLOW + f"[Session-{thread_name}] Session file is empty, skipping cost calculation")
                else:
                    print(Fore.YELLOW + f"[Session-{thread_name}] No session file found, skipping cost calculation")
                    
            except Exception as e:
                print(Fore.RED + f"[Session-{thread_name}] Error calculating fuzzing cost: {e}")
                import traceback
                traceback.print_exc()
            
            # Remove this session from active connections tracking
            with self.connection_lock:
                if hasattr(self, 'active_connections') and isinstance(self.active_connections, dict):
                    if addr in self.active_connections:
                        del self.active_connections[addr]
                        print(Fore.YELLOW + f"[Session-{thread_name}] Removed from active connections")
            
            print(Fore.YELLOW + f"[Session-{thread_name}] Session terminated for {addr}")
            print(Fore.YELLOW + f"[Session-{thread_name}] " + "=" * 50)
            

    def close_connections(self):
        for sock in [self.conn_from_e2term, self.gnb_client, self.server]:
            try:
                if sock:
                    sock.close()
            except Exception as e:
                print(Fore.YELLOW + f"[!] Failed to close socket: {e}")
        self.conn_from_e2term = None
        self.gnb_client = None

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
                print(Fore.GREEN + f"[+] Backed up transitions.json to: transitions_{self.timestamp}.json")
            else:
                print(Fore.YELLOW + f"[!] transitions.json not found at {transitions_source}")
        except Exception as e:
            print(Fore.RED + f"[-] Error backing up transitions.json: {e}")

        # Construct the wdmapper command for diffing
        wdmapper_gen_diff = [
            "./bin/wdmapper",
            "--udp-dst-port=36421,38412,9999,38472,38412,36422",
            "-d", current_file,
            "-i", '../../../captures/Baseline_kpm_mon.pcapng',
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