import asn1tools
import json
import pprint


# def extract_all_constraints(compiled_obj):
#     constraints_dict = {}
    
#     for root_name, item in compiled_obj.types.items():
#         node_constraints = {
#             'type_name': item.type.name if hasattr(item.type, 'name') else None
#         }
        
#         if hasattr(item.type, 'root_members'):
#             members_dict = {}
#             for member in item.type.root_members:
#                 member_dict = {
#                     'name': member.name,
#                     'type_name': member.type_name if hasattr(member, 'type_name') else None,
#                 }
                
#                 # Extract integer constraints
#                 if hasattr(member, 'minimum') and hasattr(member, 'maximum'):
#                     #member_dict['range'] = (member.minimum, member.maximum)
#                     member_dict['min'] = member.minimum
#                     member_dict['max'] = member.maximum
#                 # Extract boolean type
#                 if member.type_name == "BOOLEAN":
#                     member_dict['boolean_values'] = [True, False]
                
#                 # Extract string constraints
#                 if hasattr(member, 'size_range'):
#                     member_dict['size_range'] = member.size_range
                
#                 # Extract enumerations
#                 if hasattr(member, 'named_values'):
#                     member_dict['enum_values'] = list(member.named_values.keys())
#                     print(member_dict)
#                 members_dict[member.name] = member_dict
            
#             node_constraints['root_members'] = members_dict
        
#         # Capture constraints at the type level
#         if hasattr(item.type, 'minimum') and hasattr(item.type, 'maximum'):
#             #node_constraints['range'] = (item.type.minimum, item.type.maximum)
#             node_constraints['min'] = item.type.minimum
#             node_constraints['max'] = item.type.maximum
#         if hasattr(item.type, 'size_range'):
#             node_constraints['size_range'] = item.type.size_range
#         if hasattr(item.type, 'ALPHABET'):
#             # node_constraints['ALPHABET'] = item.type.ALPHABET # returns bytearray
#             node_constraints['alphabet'] = (item.type.ALPHABET.decode('utf-8'))
#         constraints_dict[root_name] = node_constraints
    
#     return constraints_dict
def extract_all_constraints(compiled_obj):
    def extract_constraints(type_obj):
        constraints = {}
        
        # Get the ASN.1 type explicitly
        if hasattr(type_obj, 'type_name'):
            constraints['asn1_type'] = type_obj.type_name
        elif isinstance(type_obj, type):
            constraints['asn1_type'] = type_obj.__name__
        else:
            class_name = type(type_obj).__name__
            # Try to extract ASN.1 type from class name
            if 'Enumerated' in class_name:
                constraints['asn1_type'] = 'ENUMERATED'
            elif 'Sequence' in class_name:
                constraints['asn1_type'] = 'SEQUENCE'
            elif 'Choice' in class_name:
                constraints['asn1_type'] = 'CHOICE'
            elif 'Integer' in class_name:
                constraints['asn1_type'] = 'INTEGER'
            elif 'BitString' in class_name:
                constraints['asn1_type'] = 'BIT STRING'
            elif 'OctetString' in class_name:
                constraints['asn1_type'] = 'OCTET STRING'
            elif 'Boolean' in class_name:
                constraints['asn1_type'] = 'BOOLEAN'
            elif 'OpenType' in class_name:
                constraints['asn1_type'] = 'OPEN TYPE'
            else:
                constraints['asn1_type'] = class_name
        
        # Get type name
        if hasattr(type_obj, 'name'):
            constraints['type_name'] = type_obj.name
        elif hasattr(type_obj, 'type_name'):
            constraints['type_name'] = type_obj.type_name
        else:
            constraints['type_name'] = type(type_obj).__name__
        
        # Integer constraints
        if hasattr(type_obj, 'minimum'):
            constraints['min'] = type_obj.minimum
        if hasattr(type_obj, 'maximum'):
            constraints['max'] = type_obj.maximum
        
        # String size constraint
        if hasattr(type_obj, 'size_range'):
            constraints['size_range'] = type_obj.size_range
        
        # Alphabet
        if hasattr(type_obj, 'ALPHABET'):
            constraints['alphabet'] = type_obj.ALPHABET.decode('utf-8', errors='ignore')
        
        # Enum values
        if hasattr(type_obj, 'named_values'):
            constraints['enum_values'] = list(type_obj.named_values.keys())
        
        # Root data to value mapping (for Enumerated types)
        if hasattr(type_obj, 'root_data_to_value'):
            constraints['root_data_to_value'] = {str(k): v for k, v in type_obj.root_data_to_value.items()}
        
        # Root value to data mapping (for Enumerated types)
        if hasattr(type_obj, 'root_value_to_data'):
            constraints['root_value_to_data'] = {str(k): v for k, v in type_obj.root_value_to_data.items()}
        
        # Root index to member (for CHOICE, SEQUENCE types)
        if hasattr(type_obj, 'root_index_to_member'):
            # Extract the mapping from index to member
            index_to_member = {}
            for idx, member in type_obj.root_index_to_member.items():
                # Try to get the member name if possible
                if hasattr(member, 'name'):
                    member_name = member.name
                else:
                    member_name = f"member_{idx}"
                
                # Extract constraints for the member
                member_info = extract_constraints(member)
                index_to_member[str(idx)] = {
                    'name': member_name,
                    'constraints': member_info
                }
            constraints['root_index_to_member'] = index_to_member
        
        # Root name to index (for CHOICE, SEQUENCE types)
        if hasattr(type_obj, 'root_name_to_index'):
            constraints['root_name_to_index'] = {k: v for k, v in type_obj.root_name_to_index.items()}
        
        # Function variables 
        if hasattr(type_obj, 'function_variables'):
            function_vars = {}
            for attr_name in dir(type_obj):
                if not attr_name.startswith('__') and attr_name not in ['function_variables', 'special_variables']:
                    value = getattr(type_obj, attr_name)
                    if isinstance(value, (int, str, bool, type(None))) or (isinstance(value, dict) and all(isinstance(k, (int, str, bool)) for k in value.keys())):
                        function_vars[attr_name] = value
            constraints['function_variables'] = function_vars
        
        # Boolean values
        if getattr(type_obj, 'type_name', None) == 'BOOLEAN' or 'Boolean' in type(type_obj).__name__:
            constraints['boolean_values'] = [True, False]
        
        # CHOICE or SEQUENCE members
        if hasattr(type_obj, 'root_members'):
            members = {}
            for i, member in enumerate(type_obj.root_members):
                member_info = extract_constraints(member)
                if hasattr(member, 'name'):
                    members[member.name] = member_info
                else:
                    members[f"member_{i}"] = member_info
            constraints['members'] = members
            
        # Number of bits for integers
        if hasattr(type_obj, 'number_of_bits'):
            constraints['number_of_bits'] = type_obj.number_of_bits
            
        # Number of indefinite bits
        if hasattr(type_obj, 'number_of_indefinite_bits'):
            constraints['number_of_indefinite_bits'] = type_obj.number_of_indefinite_bits
        
        # Optional flag
        if hasattr(type_obj, 'optional'):
            constraints['optional'] = type_obj.optional
            
        # Default value
        if hasattr(type_obj, 'default'):
            if isinstance(type_obj.default, (int, str, bool, type(None))):
                constraints['default'] = type_obj.default
            else:
                constraints['default'] = str(type_obj.default)
        
        # Nested type (e.g., for CHOICE inside SEQUENCE)
        if hasattr(type_obj, 'type'):
            nested = extract_constraints(type_obj.type)
            # Keep the asn1_type of the parent
            parent_type = constraints.get('asn1_type')
            nested_type = nested.get('asn1_type')
            constraints.update({k: v for k, v in nested.items() if k not in constraints or k == 'members'})
            # Restore the parent type after update
            if parent_type:
                constraints['asn1_type'] = parent_type
            # Add information about the nested type
            constraints['nested_type'] = nested_type
            
        # Tag information
        if hasattr(type_obj, 'tag'):
            constraints['tag'] = type_obj.tag
            
        # Try to recursively extract all attributes that might contain constraints
        # all_attrs = {}
        # for attr_name in dir(type_obj):
        #     if not attr_name.startswith('__') and attr_name not in constraints:
        #         try:
        #             attr_value = getattr(type_obj, attr_name)
        #             # Check if it's a simple value type
        #             if isinstance(attr_value, (int, str, bool, float, type(None))):
        #                 all_attrs[attr_name] = attr_value
        #             # Check if it's a dictionary with simple key/value types
        #             elif isinstance(attr_value, dict):
        #                 # Only include dictionaries with simple key/value types
        #                 if all(isinstance(k, (int, str, bool)) for k in attr_value.keys()):
        #                     try:
        #                         # Try to convert dictionary to JSON serializable format
        #                         all_attrs[attr_name] = {str(k): str(v) if not isinstance(v, (int, bool, type(None))) else v 
        #                                                for k, v in attr_value.items()}
        #                     except:
        #                         pass
        #         except:
        #             # Skip attributes that cannot be accessed
        #             pass
        
        # if all_attrs:
        #     constraints['additional_attributes'] = all_attrs
        
        return constraints
    
    # Build constraints dictionary for all top-level types
    all_constraints = {}
    for type_name, type_def in compiled_obj.types.items():
        all_constraints[type_name] = extract_constraints(type_def)
    
    return all_constraints


if __name__ == "__main__":
    import asn1tools
    import json
    
    kpm = asn1tools.compile_files([
        './asn1files/E2SM-COMMON-IEs.asn',
        './asn1files/E2SM-KPM-v05.00.asn',
        './asn1files/e2sm-rc-v06.asn',
        #'./asn1files/asn_flexric/e2sm_mac_v00.asn',
        # MUST come before E2AP-PDU-Contents.asn
        #'./asn1files/asn_flexric/e2ap_v2_03.asn',
        './asn1files/E2AP-Constants.asn',
        './asn1files/E2AP-CommonDataTypes.asn',
        './asn1files/E2AP-PDU-Descriptions.asn',
        './asn1files/E2AP-PDU-Contents.asn',
        './asn1files/E2AP-Containers.asn',
        './asn1files/E2AP-IEs.asn',
        './asn1files/asn_flexric/e42ap_v2_03.asn',
    ], 'per')
    
    # Extract all constraints
    all_constraints = extract_all_constraints(kpm)
    
    # Save all constraints to a file (optional)
    with open('constraints_w_types.json', 'w') as f:
        json.dump(all_constraints, f, indent=4)
    
    print(f"Found {len(all_constraints)} types with constraints.")
