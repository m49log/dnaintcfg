import pandas as pd
import requests
import json
import os
from cryptography.fernet import Fernet

# --- Impostazioni ---
XLSX_DATA_FILE = 'dati_porte.xlsx'
CRED_FILE = 'dnac_creds.enc'
KEY_FILE = 'secret.key'

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
VERIFY_SSL = False

# --- Funzioni di Crittografia (semplificate per solo caricamento) ---
def load_key():
    if not os.path.exists(KEY_FILE):
        print(f"Errore: File chiave '{KEY_FILE}' non trovato. Eseguire uno script che lo generi.")
        return None
    with open(KEY_FILE, 'rb') as key_file:
        key = key_file.read()
    return key

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    decrypted_json_str = f.decrypt(encrypted_data).decode()
    return json.loads(decrypted_json_str)

def load_config():
    key = load_key()
    if not key: return None, None, None
    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE, 'rb') as f:
                encrypted_config = f.read()
            config_data = decrypt_data(encrypted_config, key)
            if 'username' in config_data and 'password' in config_data and 'dnac_url' in config_data:
                print("Configurazione DNA Center (utente, pwd, URL) caricata da file.")
                return config_data['username'], config_data['password'], config_data['dnac_url']
            else:
                print(f"Errore: File '{CRED_FILE}' incompleto."); return None, None, None
        except Exception as e:
            print(f"Errore nel caricare o decriptare la configurazione da '{CRED_FILE}': {e}."); return None, None, None
    else:
        print(f"Errore: File di configurazione '{CRED_FILE}' non trovato."); return None, None, None

# --- Funzioni API DNA Center (invariate) ---
def get_dnac_token(dnac_url, username, password):
    auth_url = f"{dnac_url}/dna/system/api/v1/auth/token"
    headers = {'Content-Type': 'application/json'}
    print("Ottenimento token DNA Center...")
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=VERIFY_SSL, timeout=20)
        response.raise_for_status()
        token = response.json().get('Token')
        if token: print("Token ottenuto con successo."); return token
        else: print("Errore: Token non trovato nella risposta."); return None
    except requests.exceptions.HTTPError as e:
        print(f"Errore HTTP durante l'autenticazione: {e.response.status_code} {e.response.reason}"); return None
    except requests.exceptions.RequestException as e:
        print(f"Errore di richiesta durante l'autenticazione: {e}"); return None

def get_device_id_by_ip(dnac_url, token, device_ip):
    url = f"{dnac_url}/dna/intent/api/v1/network-device"
    headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}
    params = {'managementIpAddress': device_ip}
    print(f"Ricerca Device ID per IP: {device_ip}...")
    try:
        response = requests.get(url, headers=headers, params=params, verify=VERIFY_SSL, timeout=10)
        response.raise_for_status()
        devices = response.json().get('response')
        if devices and len(devices) > 0:
            device_id = devices[0].get('id')
            print(f"Device ID trovato: {device_id} per IP {device_ip}")
            return device_id
        else:
            print(f"Nessun dispositivo trovato con IP {device_ip}"); return None
    except requests.exceptions.RequestException as e:
        print(f"Errore nel recuperare il device ID per {device_ip}: {e}"); return None

def get_interface_id(dnac_url, token, device_id, interface_name):
    url = f"{dnac_url}/dna/intent/api/v1/interface/network-device/{device_id}"
    headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}
    print(f"Ricerca Interface ID per {interface_name} su device {device_id}...")
    try:
        response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=15)
        response.raise_for_status()
        interfaces = response.json().get('response')
        if interfaces:
            for interface in interfaces:
                if interface.get('portName') == interface_name:
                    interface_id = interface.get('id')
                    print(f"Interface ID trovato: {interface_id} per {interface_name}")
                    return interface_id
            print(f"Interfaccia {interface_name} non trovata sul dispositivo {device_id}"); return None
        else:
            print(f"Nessuna interfaccia trovata per il dispositivo {device_id}"); return None
    except requests.exceptions.RequestException as e:
        print(f"Errore nel recuperare le interfacce per il dispositivo {device_id}: {e}"); return None

def configure_interface_vlan_description(dnac_url, token, interface_id, vlan_id, description):
    url = f"{dnac_url}/dna/intent/api/v1/interface/{interface_id}"
    headers = {'X-Auth-Token': token, 'Content-Type': 'application/json', 'Accept': 'application/json'}
    payload_update = {"description": str(description), "vlanId": int(vlan_id)}
    print(f"Tentativo di configurazione interfaccia {interface_id}: VLAN={vlan_id}, Descrizione='{description}'...")
    try:
        get_response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=10)
        get_response.raise_for_status()
        current_config_response = get_response.json()
        current_config_data = current_config_response.get('response', current_config_response)
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
            keys_to_remove.append('portMode')
        for key_to_remove in keys_to_remove:
            final_payload.pop(key_to_remove, None)
        
        response = requests.put(url, headers=headers, data=json.dumps(final_payload), verify=VERIFY_SSL, timeout=15)
        response.raise_for_status()
        response_data = response.json()
        task_id = response_data.get('response', {}).get('taskId') or response_data.get('taskId')
        if task_id:
            # Non stampiamo qui "Configurazione inviata con successo" ma lo facciamo dopo, nella lista.
            return True, f"Task ID: {task_id}"
        else:
            # Anche qui, il successo lo determiniamo dopo
            return True, f"Nessun Task ID ricevuto, risposta: {response_data}"
    except requests.exceptions.HTTPError as e:
        error_msg = f"Errore HTTP: {e.response.status_code} {e.response.reason}. "
        try: error_msg += f"Dettagli: {e.response.json()}"
        except json.JSONDecodeError: error_msg += f"Dettagli (testo): {e.response.text}"
        return False, error_msg
    except requests.exceptions.RequestException as e:
        return False, f"Errore di richiesta: {e}"
    except Exception as e:
        return False, f"Errore generico: {e}"


# --- Funzione Principale ---
def main():
    username, password, dnac_base_url = load_config()
    if not all([username, password, dnac_base_url]):
        print("Impossibile caricare la configurazione DNA Center necessaria. Uscita.")
        return

    print(f"Utilizzo DNA Center URL: {dnac_base_url}")

    token = get_dnac_token(dnac_base_url, username, password)
    if not token:
        print("Impossibile ottenere il token. Uscita.")
        return

    try:
        df_ports_data = pd.read_excel(XLSX_DATA_FILE, dtype=str)
        df_ports_data.fillna('', inplace=True)
    except FileNotFoundError:
        print(f"Errore: File dati '{XLSX_DATA_FILE}' non trovato.")
        return
    except Exception as e:
        print(f"Errore nella lettura del file Excel '{XLSX_DATA_FILE}': {e}")
        return

    expected_cols_in_file = ['Go', 'Device_Name', 'IP_Switch', 'Porta', 'VLAN', 'Descrizione', 
                             'Admin_Status', 'Oper_Status', 'Port_Mode', 'Media_Type', 
                             'Speed', 'Duplex', 'Voice_VLAN', 'If_Index']
    missing_cols = [col for col in expected_cols_in_file if col not in df_ports_data.columns]
    if missing_cols:
        print(f"Errore: Colonne mancanti nel file '{XLSX_DATA_FILE}': {', '.join(missing_cols)}.")
        return

    ports_to_configure = df_ports_data[df_ports_data['Go'].str.lower() == 'x']
    if ports_to_configure.empty:
        print(f"Nessuna porta marcata con 'x' nella colonna 'Go' del file '{XLSX_DATA_FILE}'. Nessuna operazione eseguita.")
        return
    
    print(f"Trovate {len(ports_to_configure)} porte marcate con 'x' per la configurazione.")

    device_id_cache = {}
    # Liste per tracciare i risultati
    successfully_configured_ports = []
    failed_to_configure_ports = []

    for index, row in ports_to_configure.iterrows():
        port_info_str = "" # Stringa per identificare la porta nei log
        try:
            switch_ip = str(row.get('IP_Switch', '')).strip()
            port_name = str(row.get('Porta', '')).strip()
            vlan_val = str(row.get('VLAN', '')).strip()
            description = str(row.get('Descrizione', '')).strip()
            device_name_from_xls = str(row.get('Device_Name', switch_ip)).strip()
            port_info_str = f"Device: '{device_name_from_xls}' (IP: {switch_ip}), Porta: {port_name}"


            if not all([switch_ip, port_name, vlan_val]):
                print(f"\n--- Riga {index + 2} del file '{XLSX_DATA_FILE}': Dati incompleti (IP Switch, Porta o VLAN mancanti). Salto. ---")
                failed_to_configure_ports.append(f"{port_info_str if port_info_str else 'Riga ' + str(index+2)} - Dati incompleti")
                continue
            
            try: vlan = int(vlan_val)
            except ValueError:
                msg = f"Valore VLAN '{vlan_val}' non è un numero valido."
                print(f"\n--- Riga {index + 2} ({port_info_str}): {msg} Salto. ---")
                failed_to_configure_ports.append(f"{port_info_str} - {msg}")
                continue

        except Exception as e:
            msg = f"Errore nell'elaborazione dei dati della riga: {e}."
            print(f"\n--- Riga {index + 2}: {msg} Salto. ---")
            failed_to_configure_ports.append(f"Riga {index + 2} - {msg}")
            continue
        
        print(f"\n--- Elaborazione configurazione per: {port_info_str}, VLAN: {vlan}, Desc: '{description}' ---")

        if switch_ip in device_id_cache:
            device_id = device_id_cache[switch_ip]
            print(f"Device ID recuperato dalla cache per {switch_ip}: {device_id}")
        else:
            device_id = get_device_id_by_ip(dnac_base_url, token, switch_ip)
            if device_id: device_id_cache[switch_ip] = device_id
            else:
                msg = f"Impossibile trovare il device ID per {switch_ip}."
                print(msg + " Salto questa configurazione.")
                failed_to_configure_ports.append(f"{port_info_str} - {msg}")
                continue
        
        interface_id = get_interface_id(dnac_base_url, token, device_id, port_name)
        if not interface_id:
            msg = f"Impossibile trovare l'interface ID."
            print(msg + " Salto questa configurazione.")
            failed_to_configure_ports.append(f"{port_info_str} - {msg}")
            continue

        # Modifica: configure_interface_vlan_description ora restituisce (success_flag, message)
        success, message = configure_interface_vlan_description(dnac_base_url, token, interface_id, vlan, description)
        
        if success:
            print(f"Configurazione per {port_info_str} inviata. Dettaglio: {message}")
            successfully_configured_ports.append(f"{port_info_str} (VLAN: {vlan}, Desc: '{description}') - Status: {message}")
        else:
            print(f"Errore durante la configurazione di {port_info_str}. Dettaglio: {message}")
            failed_to_configure_ports.append(f"{port_info_str} - Errore: {message}")

    # Riepilogo finale
    print(f"\n--- Riepilogo Elaborazione Configurazioni ---")
    print(f"Totale porte marcate con 'x' nel file: {len(ports_to_configure)}")
    
    if successfully_configured_ports:
        print(f"\n{len(successfully_configured_ports)} PORTE PER CUI LA CONFIGURAZIONE E' STATA INVIATA CON SUCCESSO (o task creato):")
        for item in successfully_configured_ports:
            print(f"  - {item}")
    else:
        print("\nNessuna porta è stata configurata con successo (o nessun task creato).")

    if failed_to_configure_ports:
        print(f"\n{len(failed_to_configure_ports)} CONFIGURAZIONI FALLITE O SALTATE:")
        for item in failed_to_configure_ports:
            print(f"  - {item}")
    
    print("\n--- Elaborazione completata ---")

if __name__ == "__main__":
    main()