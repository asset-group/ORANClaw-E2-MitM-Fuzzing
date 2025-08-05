from binascii import unhexlify, hexlify
import asn1tools

#kpm = asn1tools.compile_files(['./asn1files/E2SM-COMMON-IEs.asn', './asn1files/E2SM-KPM-v05.00.asn'], 'per')
kpm = asn1tools.compile_files(['./asn1files/E2SM-COMMON-IEs.asn',
                                './asn1files/E2SM-KPM-v05.00.asn',
                                './asn1files/e2sm-rc-v3.00.asn',
                                #'./asn1files/e2sm-rc-v06.asn',
                                #'asn1files/asn_flexric/e2sm_tc_v00.asn',
                                #'asn1files/asn_flexric/e2sm_slice_v00.asn',
                                ],
                                'per')
definitions = [
    kpm.types
]

# print(kpm.types['E2SM-'].type.root_members)
# print(kpm.types)
# print(kpm.types['E2SM-KPM-ActionDefinition'].type.root_members[0].type_name)

decoded = kpm.decode('E2SM-KPM-ActionDefinition', unhexlify('000104806d0000003840010044010100000401004452422e526c6353647544656c6179446c0120000000a04452422e5545546870446c0120000000a04452422e5545546870556c0120000000b05252552e507262546f74446c0120000000b05252552e507262546f74556c012000004003e7'))

print("Decoded hex:\n")
print(decoded)
encoded = kpm.encode('E2SM-KPM-ActionDefinition', decoded)

print("Encoded hex again:\n")
print(hexlify(encoded))

# for t in kpm.types:
#     try:
#         print(f"Trying: {t}")
#         result = kpm.decode(t, unhexlify("000104806d0000003840010004010100000401004452422e526c6353647544656c6179446c0120000000a04452422e5545546870446c0120000000a04452422e5545546870556c0120000000b05252552e507262546f74446c0120000000b05252552e507262546f74556c012000004003e7"))
#         print(f"Decoded: {result}")
#         encoded = kpm.encode(t, result)
#         print(f"Encoded back: {hexlify(encoded)}")
#     except Exception as e:
#         pass
#         #print(f"Failed: {t} with error: {e}")


# import subprocess
# import tempfile
# import json
# import argparse
# import asn1tools
# class JsonParser:
#     def __init__(self, asn1_files, definitions):
#         self.asn1_files = asn1_files
#         self.definitions = definitions

#     def process_hex_streams(self, reader_output):
#         results = []
#         for hex_stream in reader_output:  # Assuming reader_output is a list of hex strings
#             decoded_json = self.decode_hex(hex_stream)
#             if decoded_json:
#                 full_decoded_json = self.expand_decoded_json(decoded_json)
#                 results.append(full_decoded_json)
#         return results

#     def decode_hex(self, hex_stream):
#         # Decode hex to JSON using ASN.1 definitions
#         try:
#             # Example: assuming you have a specific definition to decode
#             decoded_data = self.asn1_files['E2SM-KPM'].decode('E2SM-KPM-IndicationMessage', bytes.fromhex(hex_stream))
#             return decoded_data
#         except Exception as e:
#             print(f"Error decoding hex {hex_stream}: {e}")
#             return None

#     def expand_decoded_json(self, json_data):
#         """
#         Iterate through the JSON to find any raw hex streams and decode them using ASN.1.
#         :param json_data: The partially decoded JSON data.
#         :return: The full decoded JSON data.
#         """
#         def decode_and_replace(data):
#             if isinstance(data, dict):
#                 for key, value in data.items():
#                     if isinstance(value, str) and self.is_hex(value):
#                         decoded_content = self.asn1_schema.decode('YourType', bytes.fromhex(value))
#                         data[key] = decoded_content  # Replace with decoded content
#                     else:
#                         decode_and_replace(value)  # Recursive call
#             elif isinstance(data, list):
#                 for item in data:
#                     decode_and_replace(item)

#         new_json = json_data.copy()  # Create a copy of the original JSON to not modify it
#         decode_and_replace(new_json)
#         return new_json

#     @staticmethod
#     def is_hex(value):
#         return all(c in '0123456789abcdefABCDEF' for c in value)

# if __name__ == "__main__":
#     # Compile ASN.1 files for the necessary definitions
#     compiler_ = asn1tools.compile_files(
#         ['./asn1files/E2SM-COMMON-IEs.asn', './asn1files/E2SM-KPM-v05.00.asn'], 
#         'per'
#     )
    
#     asn1_files = {
#         'E2SM-KPM': asn1tools.compile_files(
#             ['./asn1files/E2SM-COMMON-IEs.asn', './asn1files/E2SM-KPM-v05.00.asn'], 
#             'per'
#         ),
#         'E2SM-RC': asn1tools.compile_files(
#             ['./asn1files/E2SM-COMMON-IEs.asn', './asn1files/e2sm-rc-v3.00.asn'], 
#             'per'
#         ),
#     }

#     # Define ASN.1 types to decode/encode
#     definitions = [
#         'E2SM-KPM-IndicationMessage',
#         #'E2SM-KPM-IndicationHeader',
#         #'E2SM-KPM-EventTriggerDefinition',
#         'E2SM-KPM-ActionDefinition',
#     ]

#     # Argument parsing for processing mode
#     parser = argparse.ArgumentParser(description="PCAP or live traffic processor")
#     parser.add_argument('--mode', choices=['pcap', 'live'], required=True, help="Processing mode: 'pcap' or 'live'")
#     parser.add_argument('--pcap-file', type=str, help="Path to the pcap file (required if mode is 'pcap')")
#     parser.add_argument('--interface', type=str, default='5g-oran', help="Network interface for live traffic capture (required if mode is 'live')")
#     args = parser.parse_args()

#     # Instantiate processor objects
#     pcap_processor = PacketsProcessor(limit=100000, capture_mode=args.mode)
#     asn1_processor = JsonParser(asn1_files, definitions)

#     if args.mode == 'pcap':
#         if not args.pcap_file:
#             raise ValueError("You must specify a pcap file with --pcap-file when mode is 'pcap'")
        
#         # Process PCAP file
#         reader_output = pcap_processor.process(pcap_file=args.pcap_file)  # Process PCAP
#         processed_json = asn1_processor.process_hex_streams(reader_output)  # Decode hex to JSON
        
#     elif args.mode == 'live':
#         # Process live traffic
#         reader_output = pcap_processor.process(interface=args.interface)  # Process live traffic
#         processed_json = asn1_processor.process_hex_streams(reader_output)  # Decode hex to JSON

#     # Output results
#     print(json.dumps(processed_json, indent=2))