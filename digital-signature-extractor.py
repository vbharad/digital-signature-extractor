import os
import subprocess
import re
import csv
import struct
import logging
import traceback
import ctypes
import ctypes.wintypes

# Set up logging
logging.basicConfig(filename='signature_extractor.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_version_number(filename):
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        
        pos = data.find(b'\xbd\x04\xef\xfe')
        if pos == -1:
            logging.warning(f"Version info not found in {filename}")
            return "N/A"
        
        pos += 4
        version = struct.unpack('HHHH', data[pos:pos+8])
        return f"{version[1]}.{version[0]}.{version[3]}.{version[2]}"
    except Exception as e:
        logging.error(f"Error getting version for {filename}: {str(e)}")
        return "N/A"

def get_signature_info_wintrust(filename):
    try:
        # Load required Windows DLLs
        wintrust = ctypes.windll.wintrust
        crypt32 = ctypes.windll.crypt32

        # Define necessary structures and function prototypes
        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ('cbStruct', ctypes.wintypes.DWORD),
                ('pcwszFilePath', ctypes.wintypes.LPCWSTR),
                ('hFile', ctypes.wintypes.HANDLE),
                ('pgKnownSubject', ctypes.c_void_p)
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ('cbStruct', ctypes.wintypes.DWORD),
                ('pPolicyCallbackData', ctypes.c_void_p),
                ('pSIPClientData', ctypes.c_void_p),
                ('dwUIChoice', ctypes.wintypes.DWORD),
                ('fdwRevocationChecks', ctypes.wintypes.DWORD),
                ('dwUnionChoice', ctypes.wintypes.DWORD),
                ('pFile', ctypes.c_void_p),
                ('dwStateAction', ctypes.wintypes.DWORD),
                ('hWVTStateData', ctypes.wintypes.HANDLE),
                ('pwszURLReference', ctypes.c_void_p),
                ('dwProvFlags', ctypes.wintypes.DWORD),
                ('dwUIContext', ctypes.wintypes.DWORD)
            ]

        # Initialize structures
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = filename

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.dwUIChoice = 2  # WTD_UI_NONE
        trust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE
        trust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)

        # Call WinVerifyTrust
        result = wintrust.WinVerifyTrust(None, ctypes.byref(ctypes.c_int(1)), ctypes.byref(trust_data))

        if result == 0:
            # Signature is valid, extract information
            cert_context = crypt32.CertFindCertificateInStore(
                trust_data.hWVTStateData,
                0x00010001,  # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
                0,
                3,  # CERT_FIND_SUBJECT_CERT
                None,
                None
            )
            
            if cert_context:
                # Get subject name
                name_size = crypt32.CertGetNameStringW(
                    cert_context,
                    1,  # CERT_NAME_SIMPLE_DISPLAY_TYPE
                    0,
                    None,
                    None,
                    0
                )
                name_buffer = ctypes.create_unicode_buffer(name_size)
                crypt32.CertGetNameStringW(
                    cert_context,
                    1,
                    0,
                    None,
                    name_buffer,
                    name_size
                )
                signer_name = name_buffer.value

                crypt32.CertFreeCertificateContext(cert_context)
                return signer_name

        return "N/A"
    except Exception as e:
        logging.error(f"Error getting signature info for {filename}: {str(e)}")
        return "Error"

def get_digital_signature(file_path, sigcheck_path):
    version = get_version_number(file_path)
    
    try:
        # First, try using sigcheck
        sigcheck_cmd = f'"{sigcheck_path}" -a -h "{file_path}"'
        logging.debug(f"Running command: {sigcheck_cmd}")
        sigcheck_output = subprocess.check_output(sigcheck_cmd, shell=True, stderr=subprocess.STDOUT, timeout=10).decode('utf-8', errors='ignore').strip()
        logging.debug(f"Sigcheck output: {sigcheck_output}")
        
        signer_match = re.search(r'Publisher:\s*(.+)', sigcheck_output)
        signer_name = signer_match.group(1) if signer_match else 'N/A'
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running sigcheck for {file_path}: {str(e)}")
        logging.error(f"Sigcheck output: {e.output.decode('utf-8', errors='ignore')}")
        signer_name = "Error (Sigcheck)"
    except subprocess.TimeoutExpired:
        logging.error(f"Sigcheck timed out for {file_path}")
        signer_name = "Timeout (Sigcheck)"
    except Exception as e:
        logging.error(f"Unexpected error running sigcheck for {file_path}: {str(e)}")
        signer_name = "Error (Sigcheck)"

    # If sigcheck failed, try using WinTrust API
    if signer_name.startswith("Error") or signer_name.startswith("Timeout"):
        logging.info(f"Attempting to use WinTrust API for {file_path}")
        signer_name = get_signature_info_wintrust(file_path)

    return {
        'File Name': os.path.basename(file_path),
        'File Path': file_path,
        'Version': version,
        'Signer Name': signer_name
    }

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sigcheck_path = os.path.join(script_dir, "sigcheck.exe")

    if not os.path.exists(sigcheck_path):
        print("Warning: sigcheck.exe not found in the script directory. Will use alternative method.")
        logging.warning("sigcheck.exe not found in the script directory.")
        sigcheck_path = None

    directory = input("Enter the directory path containing the binaries: ")
    output_file = input("Enter the output CSV file name (e.g., output.csv): ")

    signature_data = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.exe', '.dll')):
                file_path = os.path.join(root, file)
                print(f"Processing {file}")  # Progress output
                signature_data.append(get_digital_signature(file_path, sigcheck_path))

    # Write to CSV file
    output_path = os.path.join(script_dir, output_file)
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Sr. No.', 'File Name', 'File Path', 'Version', 'Signer Name']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for index, data in enumerate(signature_data, 1):
            row = {'Sr. No.': index, **data}
            writer.writerow(row)

    print(f"Digital signature details have been saved to {output_path}")
    print(f"Check signature_extractor.log for detailed error information.")

if __name__ == "__main__":
    main()
