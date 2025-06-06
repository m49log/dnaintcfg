import pandas as pd
import requests
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime

# --- Impostazioni ---
XLSX_DATA_FILE = 'dati_porte.xlsx'
CRED_FILE = 'dnac_creds.enc'
KEY_FILE = 'secret.key'
LOG_FILE_TXT = 'config_log.txt'

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
VERIFY_SSL = False

# --- Funzioni di Crittografia e Configurazione ---
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file: key_file.write(key)
    print(f"Nuova chiave generata e salvata in '{KEY_FILE}'.")
    return key

def load_key():
    if not os.path.exists(KEY_FILE): return generate_key()
    with open(KEY_FILE, 'rb') as key_file: key = key_file.read()
    return key

def encrypt_data(data_dict, key):
    f = Fernet(key); return f.encrypt(json.dumps(data_dict).encode())

def decrypt_data(encrypted_data, key):
    f = Fernet(key); decrypted_json_str = f.decrypt(encrypted_data).decode()
    return json.loads(decrypted_json_str)

def load_config():
    key = load_key()
    config_loaded = False
    username, password, dnac_url_loaded = None, None, None
    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE, 'rb') as f: encrypted_config = f.read()
            config_data = decrypt_data(encrypted_config, key)
            if all(k in config_data for k in ['username', 'password', 'dnac_url']):
                username, password, dnac_url_loaded = config_data['username'], config_data['password'], config_data['dnac_url']
                print("\n--- Configurazione DNA Center Caricata ---"); print(f"  Username: {username}\n  URL: {dnac_url_loaded}")
                while True:
                    choice = input("Procedere con questa configurazione? (s/n): ").strip().lower()
                    if choice == 's': config_loaded = True; break
                    elif choice == 'n': print("OK, richiesti nuovi dati."); config_loaded = False; break
                    else: print("Scelta non valida.")
            else: print("File config incompleto.")
        except Exception as e: print(f"Errore decriptazione config: {e}.")
    if not config_loaded:
        import getpass
        print("\n--- Inserimento Nuova Configurazione ---")
        username = input("Username DNA Center: ")
        password = getpass.getpass("Password DNA Center: ")
        dnac_url_loaded = input("URL base DNA Center (es. https://dnac.cisco.com): ").strip()
        if not dnac_url_loaded.startswith('http'): dnac_url_loaded = 'https://' + dnac_url_loaded
        config_to_save = {'username': username, 'password': password, 'dnac_url': dnac_url_loaded}
        encrypted_config_to_save = encrypt_data(config_to_save, key)
        with open(CRED_FILE, 'wb') as f: f.write(encrypted_config_to_save)
        print(f"Nuova config salvata in '{CRED_FILE}'.")
    else: print("Utilizzo config caricata.")
    return username, password, dnac_url_loaded


# --- Funzioni API DNA Center ---
def get_dnac_token(dnac_url, username, password):
    auth_url = f"{dnac_url}/dna/system/api/v1/auth/token"
    headers = {'Content-Type': 'application/json'}
    print("\nOttenimento token DNA Center...")
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=VERIFY_SSL, timeout=20)
        response.raise_for_status(); token = response.json().get('Token')
        if token: print("Token ottenuto."); return token
        else: print("Errore: Token non trovato."); return None
    except requests.exceptions.HTTPError as e: print(f"Errore HTTP auth: {e.response.status_code} {e.response.reason}"); return None
    except requests.exceptions.RequestException as e: print(f"Errore richiesta auth: {e}"); return None

def get_device_id_by_ip(dnac_url, token, device_ip):
    url = f"{dnac_url}/dna/intent/api/v1/network-device"; headers = {'X-Auth-Token': token}; params = {'managementIpAddress': device_ip}
    print(f"Ricerca Device ID per IP: {device_ip}...")
    try:
        response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL, timeout=10)
        response.raise_for_status(); devices = response.json().get('response')
        if devices: device_id = devices[0].get('id'); print(f"Device ID: {device_id}"); return device_id
        else: print(f"Nessun dispositivo con IP {device_ip}"); return None
    except Exception as e: print(f"Errore recupero device ID {device_ip}: {e}"); return None

def get_interface_id(dnac_url, token, device_id, interface_name):
    url = f"{dnac_url}/dna/intent/api/v1/interface/network-device/{device_id}"; headers = {'X-Auth-Token': token}
    print(f"Ricerca Interface ID per {interface_name} su {device_id}...")
    try:
        response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=15)
        response.raise_for_status(); interfaces = response.json().get('response')
        if interfaces:
            for interface in interfaces:
                if interface.get('portName') == interface_name: print(f"Interface ID: {interface.get('id')}"); return interface.get('id')
            print(f"Interfaccia {interface_name} non trovata"); return None
        else: print(f"Nessuna interfaccia per device {device_id}"); return None
    except Exception as e: print(f"Errore recupero interfacce {device_id}: {e}"); return None

def configure_interface_vlan_description(dnac_url, token, interface_id, vlan_id, description):
    url = f"{dnac_url}/dna/intent/api/v1/interface/{interface_id}"
    headers = {'X-Auth-Token': token, 'Content-Type': 'application/json', 'Accept': 'application/json'}
    payload_update = {"description": str(description), "vlanId": int(vlan_id)}
    print(f"Tentativo config iface {interface_id}: VLAN={vlan_id}, Desc='{description}'...")
    try:
        get_response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=10)
        get_response.raise_for_status()
        current_config_data = get_response.json().get('response', get_response.json())
        final_payload = current_config_data.copy()
        final_payload.update(payload_update)
        keys_to_remove = [
            'id', 'macAddress', 'adminStatus', 'operStatus', 'mediaType', 'speed', 'duplex', 
            'portType', 'lastUpdated', 'instanceUuid', 'instanceTenantId', 'interfaceType', 
            'className', 'series', 'pid', 'serialNumber', 'mappedPhysicalInterfaceId', 
            'mappedPhysicalInterfaceName', 'nativeVlanId', 'isisSupport', 'ospfSupport', 
            'ipv4Address', 'ipv4Mask', 'ipv6Address', 'ipv6Mask', 'ipv6Enabled', 'ipv6Prefix', 
            'multicastGroup', 'channelGroupId', 'channelGroupMembers', 'portChannelId', 'status', 
            'ifIndex', 'pktsIn', 'pktsOut', 'bytesIn', 'bytesOut', 'errorsIn', 'errorsOut', 
            'interfaceStats', 'interfaceStatistics', 'interfaceAcl', 'interfaceQos', 
            'controlledPortName', 'controlDirection', 'deploymentId', 'networkDeviceId', 
            'networkDeviceName', 'task_id', 'type', 'interfaceVrf', 'ospfSettings', 
            'connectedDevice', 'etherChannelNativeVlanId', 'etherChannelPortMode', 
            'etherChannelSubPortMode', 'interfaceSubType', 'overlappingVlans', 
            'voiceVlanId'
        ]
        if final_payload.get('portMode') != 'access':
            final_payload['portMode'] = 'access'
        else:
            keys_to_remove.append('portMode') # Rimuovi se già access o non vuoi forzarlo
            
        for key_to_remove in keys_to_remove:
            final_payload.pop(key_to_remove, None)
            
        response = requests.put(url, headers=headers, data=json.dumps(final_payload), verify=VERIFY_SSL, timeout=15)
        response.raise_for_status()
        response_data = response.json()
        task_id = response_data.get('response', {}).get('taskId') or response_data.get('taskId')
        if task_id:
            return True, f"Task ID: {task_id}"
        else:
            return True, f"Nessun Task ID, risposta: {response_data}"
            
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP Err: {e.response.status_code} {e.response.reason}. "
        try:
            error_msg += f"Dettagli: {e.response.json()}"
        except json.JSONDecodeError:
            error_msg += f"Dettagli (testo): {e.response.text}"
        return False, error_msg # <<< CORREZIONE APPLICATA QUI
        
    except requests.exceptions.RequestException as e:
        return False, f"Errore di richiesta generico: {e}"
        
    except Exception as e:
        return False, f"Errore generico non gestito: {e}"

# --- Funzione di Logging TXT ---
def append_to_log_txt(log_entry_dict):
    timestamp = log_entry_dict.get('Timestamp', 'N/A'); device_name = log_entry_dict.get('Device_Name', 'N/A')
    ip_switch = log_entry_dict.get('IP_Switch', 'N/A'); porta = log_entry_dict.get('Porta', 'N/A')
    vlan_config = log_entry_dict.get('VLAN_Config', 'N/A'); desc_config = log_entry_dict.get('Descrizione_Config', 'N/A')
    stato = log_entry_dict.get('Stato', 'N/A'); dettaglio = log_entry_dict.get('Dettaglio_Stato', 'N/A')
    log_line = (f"Timestamp: {timestamp}\n  Device: {device_name} (IP: {ip_switch})\n  Porta: {porta}\n"
                f"  Config Tentata: VLAN={vlan_config}, Descrizione='{desc_config}'\n  Stato: {stato}\n  Dettaglio: {dettaglio}\n"
                f"--------------------------------------------------\n")
    try:
        with open(LOG_FILE_TXT, 'a', encoding='utf-8') as f: f.write(log_line)
    except Exception as e:
        print(f"ERRORE CRITICO LOGGING TXT su '{LOG_FILE_TXT}': {e}\nLog non salvato: {log_line}")

# --- Funzione Principale ---
def main():
    username, password, dnac_base_url = load_config()
    if not all([username, password, dnac_base_url]): print("Impossibile caricare config. Uscita."); return

    token = get_dnac_token(dnac_base_url, username, password)
    if not token: print("Impossibile ottenere token. Uscita."); return

    try:
        df_ports_data = pd.read_excel(XLSX_DATA_FILE, dtype=str); df_ports_data.fillna('', inplace=True)
    except FileNotFoundError: print(f"Errore: File '{XLSX_DATA_FILE}' non trovato."); return
    except Exception as e: print(f"Errore lettura '{XLSX_DATA_FILE}': {e}"); return

    all_expected_cols = ['Go', 'Device_Name', 'IP_Switch', 'Porta', 'VLAN', 'Descrizione', 'Admin_Status', 'Oper_Status', 'Port_Mode', 'Media_Type', 'Speed', 'Duplex', 'Voice_VLAN', 'If_Index']
    missing_cols = [col for col in all_expected_cols if col not in df_ports_data.columns]
    if missing_cols: print(f"Errore: Colonne mancanti in '{XLSX_DATA_FILE}': {', '.join(missing_cols)}."); return

    ports_to_configure = df_ports_data[df_ports_data['Go'].str.lower() == 'x']
    if ports_to_configure.empty: print(f"Nessuna porta marcata con 'x' in '{XLSX_DATA_FILE}'."); return
    
    print(f"Trovate {len(ports_to_configure)} porte marcate con 'x' per la configurazione.")

    device_id_cache = {}
    successfully_configured_ports_summary = []
    failed_to_configure_ports_summary = []

    if os.path.exists(LOG_FILE_TXT) and os.path.getsize(LOG_FILE_TXT) > 0 :
        with open(LOG_FILE_TXT, 'a', encoding='utf-8') as f: f.write(f"\n===== NUOVA SESSIONE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====\n")
    else:
         with open(LOG_FILE_TXT, 'w', encoding='utf-8') as f: f.write(f"===== INIZIO LOG: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====\n")

    for index, row in ports_to_configure.iterrows():
        timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S"); log_entry = {'Timestamp': timestamp_now}
        port_info_str = "N/A"
        try:
            switch_ip = str(row.get('IP_Switch', '')).strip(); port_name = str(row.get('Porta', '')).strip()
            vlan_val = str(row.get('VLAN', '')).strip(); description_val = str(row.get('Descrizione', '')).strip()
            device_name_val = str(row.get('Device_Name', switch_ip)).strip()
            port_info_str = f"Device: '{device_name_val}' (IP: {switch_ip}), Porta: {port_name}"
            log_entry.update({'Device_Name': device_name_val, 'IP_Switch': switch_ip, 'Porta': port_name, 'VLAN_Config': vlan_val, 'Descrizione_Config': description_val})
            if not all([switch_ip, port_name, vlan_val]):
                msg = "Dati incompleti (IP, Porta o VLAN)"; print(f"\nRiga {index+2} ({port_info_str}): {msg}. Salto.")
                log_entry.update({'Stato': 'FALLITO', 'Dettaglio_Stato': msg}); failed_to_configure_ports_summary.append(f"{port_info_str} - {msg}"); append_to_log_txt(log_entry); continue
            try: vlan = int(vlan_val)
            except ValueError:
                msg = f"VLAN '{vlan_val}' non valida"; print(f"\nRiga {index+2} ({port_info_str}): {msg}. Salto.")
                log_entry.update({'Stato': 'FALLITO', 'Dettaglio_Stato': msg}); failed_to_configure_ports_summary.append(f"{port_info_str} - {msg}"); append_to_log_txt(log_entry); continue
        except Exception as e:
            msg = f"Errore lettura riga: {e}"; print(f"\nRiga {index+2}: {msg}. Salto.")
            log_entry.update({'Device_Name': log_entry.get('Device_Name','N/A'), 'Stato': 'FALLITO', 'Dettaglio_Stato': msg}); failed_to_configure_ports_summary.append(f"Riga {index+2} - {msg}"); append_to_log_txt(log_entry); continue
        
        print(f"\n--- Elaborazione: {port_info_str}, VLAN: {vlan}, Desc: '{description_val}' ---")
        current_device_id = device_id_cache.get(switch_ip)
        if not current_device_id:
            current_device_id = get_device_id_by_ip(dnac_base_url, token, switch_ip)
            if current_device_id: device_id_cache[switch_ip] = current_device_id
            else: msg = f"Device ID non trovato {switch_ip}"; print(msg); log_entry.update({'Stato': 'FALLITO', 'Dettaglio_Stato': msg}); failed_to_configure_ports_summary.append(f"{port_info_str} - {msg}"); append_to_log_txt(log_entry); continue
        else: print(f"Device ID da cache: {current_device_id}")
        
        current_interface_id = get_interface_id(dnac_base_url, token, current_device_id, port_name)
        if not current_interface_id:
            msg = "Interface ID non trovato"; print(msg); log_entry.update({'Stato': 'FALLITO', 'Dettaglio_Stato': msg}); failed_to_configure_ports_summary.append(f"{port_info_str} - {msg}"); append_to_log_txt(log_entry); continue

        success, message_detail = configure_interface_vlan_description(dnac_base_url, token, current_interface_id, vlan, description_val)
        status_log = "SUCCESSO" if success else "FALLITO"
        if success: print(f"Config inviata {port_info_str}. Dettaglio: {message_detail}"); successfully_configured_ports_summary.append(f"{port_info_str} - Status: {message_detail}")
        else: print(f"Errore config {port_info_str}. Dettaglio: {message_detail}"); failed_to_configure_ports_summary.append(f"{port_info_str} - Errore: {message_detail}")
        log_entry.update({'Stato': status_log, 'Dettaglio_Stato': message_detail}); append_to_log_txt(log_entry)

    print(f"\n--- Riepilogo Elaborazione ---"); print(f"Totale porte marcate 'x': {len(ports_to_configure)}")
    if successfully_configured_ports_summary: print(f"\n{len(successfully_configured_ports_summary)} CONFIG INVIATE CON SUCCESSO:"); [print(f"  - {item}") for item in successfully_configured_ports_summary]
    else: print("\nNessuna config inviata con successo.")
    if failed_to_configure_ports_summary: print(f"\n{len(failed_to_configure_ports_summary)} CONFIG FALLITE/SALTATE:"); [print(f"  - {item}") for item in failed_to_configure_ports_summary]
    print("\n--- Elaborazione completata ---")

if __name__ == "__main__":
    main()