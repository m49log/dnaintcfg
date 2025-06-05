import pandas as pd
import requests
import json
import os
from cryptography.fernet import Fernet

# --- Impostazioni ---
INPUT_SWITCH_LIST_XLSX = 'elenco_switch_ip.xlsx' # File da cui leggere gli switch da processare
OUTPUT_PORTS_XLSX = 'dati_porte.xlsx'       # File dove esportare i dati delle porte
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

def decrypt_data(encrypted_data, key): # Restituisce un dizionario
    f = Fernet(key)
    decrypted_json_str = f.decrypt(encrypted_data).decode()
    return json.loads(decrypted_json_str)

def load_config():
    """
    Carica configurazione (username, password, dnac_url) da file criptato.
    Restituisce (username, password, dnac_url) o (None, None, None) se fallisce.
    """
    key = load_key()
    if not key:
        return None, None, None
    
    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE, 'rb') as f:
                encrypted_config = f.read()
            config_data = decrypt_data(encrypted_config, key)
            if 'username' in config_data and 'password' in config_data and 'dnac_url' in config_data:
                print("Configurazione DNA Center (utente, pwd, URL) caricata da file.")
                return config_data['username'], config_data['password'], config_data['dnac_url']
            else:
                print(f"Errore: File '{CRED_FILE}' incompleto.")
                return None, None, None
        except Exception as e:
            print(f"Errore nel caricare o decriptare la configurazione da '{CRED_FILE}': {e}.")
            return None, None, None
    else:
        print(f"Errore: File di configurazione '{CRED_FILE}' non trovato.")
        return None, None, None

# --- Funzioni API DNA Center (invariate da script precedenti) ---
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
        print(f"Errore HTTP durante l'autenticazione: {e.response.status_code} {e.response.reason}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Errore di richiesta durante l'autenticazione: {e}"); return None

def get_device_interfaces(dnac_url, token, device_id):
    url = f"{dnac_url}/dna/intent/api/v1/interface/network-device/{device_id}"
    headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}
    print(f"Recupero interfacce per device ID: {device_id}...")
    try:
        response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=45)
        response.raise_for_status()
        interfaces_data = response.json().get('response')
        if interfaces_data:
            print(f"Trovate {len(interfaces_data)} interfacce.")
            return interfaces_data
        else:
            print(f"Nessuna interfaccia trovata per il dispositivo {device_id} o errore nella risposta.")
            print(f"Dettaglio risposta: {response.text if response else 'Nessuna risposta'}")
            return []
    except requests.exceptions.RequestException as e:
        print(f"Errore nel recuperare le interfacce per il dispositivo {device_id}: {e}")
        return []
    except json.JSONDecodeError:
        print(f"Errore nel decodificare JSON. Risposta: {response.text if response else 'Nessuna risposta'}")
        return []

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
        df_switch_list = pd.read_excel(INPUT_SWITCH_LIST_XLSX, dtype=str)
        df_switch_list.fillna('', inplace=True)
    except FileNotFoundError:
        print(f"Errore: File di input '{INPUT_SWITCH_LIST_XLSX}' non trovato.")
        return
    except Exception as e:
        print(f"Errore nella lettura del file '{INPUT_SWITCH_LIST_XLSX}': {e}")
        return

    if 'Go' not in df_switch_list.columns or 'Device_ID' not in df_switch_list.columns or 'Hostname' not in df_switch_list.columns or 'Management_IP' not in df_switch_list.columns :
        print(f"Errore: Il file '{INPUT_SWITCH_LIST_XLSX}' deve contenere le colonne 'Go', 'Device_ID', 'Hostname', 'Management_IP'.")
        return

    switches_to_process = df_switch_list[df_switch_list['Go'].str.lower() == 'x']

    if switches_to_process.empty:
        print(f"Nessuno switch marcato con 'x' nella colonna 'Go' del file '{INPUT_SWITCH_LIST_XLSX}'. Nessuna operazione eseguita.")
        return

    print(f"Trovati {len(switches_to_process)} switch da processare.")

    all_new_interface_data = []

    for index, row in switches_to_process.iterrows():
        device_id = str(row.get('Device_ID','')).strip()
        device_name = str(row.get('Hostname','')).strip()
        switch_ip = str(row.get('Management_IP','')).strip() # Management_IP per coerenza con output

        if not device_id:
            print(f"Riga {index + 2} del file '{INPUT_SWITCH_LIST_XLSX}': Device_ID mancante per Hostname '{device_name}'. Salto.")
            continue
        
        print(f"\n--- Elaborazione Switch: {device_name} (ID: {device_id}, IP: {switch_ip}) ---")
        interfaces_from_dnac = get_device_interfaces(dnac_base_url, token, device_id)

        for interface in interfaces_from_dnac:
            port_name = interface.get('portName')
            if port_name and not any(port_name.lower().startswith(p) for p in 
                                     ['loopback', 'vlan', 'port-channel', 'nve', 'bdi', 
                                      'tunnel', 'pseudowire', 'unknown', 'null', 'mgmt', 'stack', 
                                      'appgigabitethernet', 'bluetooth', 'control', 'event', 'internal']):
                
                vlan_val = interface.get('vlanId', '')
                try:
                    vlan_int_or_str = int(vlan_val) if str(vlan_val).strip().isdigit() else ''
                except ValueError:
                    vlan_int_or_str = ''

                all_new_interface_data.append({
                    'Go': '', # Colonna "Go" per il file dati_porte.xlsx, inizialmente vuota
                    'Device_Name': device_name,
                    'IP_Switch': switch_ip, 
                    'Porta': port_name,
                    'VLAN': vlan_int_or_str,
                    'Descrizione': interface.get('description', ''),
                    'Admin_Status': interface.get('adminStatus', ''),
                    'Oper_Status': interface.get('operStatus', ''),
                    'Port_Mode': interface.get('portMode', ''),
                    'Media_Type': interface.get('mediaType', ''),
                    'Speed': interface.get('speed', ''),
                    'Duplex': interface.get('duplex', ''),
                    'Voice_VLAN': interface.get('voiceVlanId', ''),
                    'If_Index': interface.get('ifIndex', '')
                })
    
    if not all_new_interface_data:
        print("Nessun dato di interfaccia valido recuperato per gli switch selezionati.")
        return

    # Colonne per il file dati_porte.xlsx
    cols_ordered_ports = ['Go', 'Device_Name', 'IP_Switch', 'Porta', 'VLAN', 'Descrizione', 
                          'Admin_Status', 'Oper_Status', 'Port_Mode', 'Media_Type', 
                          'Speed', 'Duplex', 'Voice_VLAN', 'If_Index']
    
    new_ports_df = pd.DataFrame(all_new_interface_data)
    new_ports_df = new_ports_df[cols_ordered_ports] # Assicura ordine

    # Logica per accodare o creare il file OUTPUT_PORTS_XLSX
    if os.path.exists(OUTPUT_PORTS_XLSX) and os.path.getsize(OUTPUT_PORTS_XLSX) > 0:
        try:
            print(f"Il file '{OUTPUT_PORTS_XLSX}' esiste. Aggiungo/aggiorno i dati...")
            existing_ports_df = pd.read_excel(OUTPUT_PORTS_XLSX, dtype=str)
            for col in cols_ordered_ports: # Assicura che tutte le colonne necessarie esistano
                if col not in existing_ports_df.columns: existing_ports_df[col] = ''
            existing_ports_df = existing_ports_df[cols_ordered_ports].fillna('')

            # Chiavi per identificare le righe: IP_Switch e Porta
            key_cols = ['IP_Switch', 'Porta']
            
            # Prepara i DataFrame per il merge/update
            for df_to_prep in [existing_ports_df, new_ports_df]:
                for key_col in key_cols:
                    df_to_prep[key_col] = df_to_prep[key_col].astype(str)
            
            existing_ports_df.set_index(key_cols, inplace=True)
            new_ports_df.set_index(key_cols, inplace=True)

            # Colonne da aggiornare da new_ports_df se la riga esiste
            # Non includiamo 'Go' qui perché vogliamo preservare il 'Go' esistente in dati_porte.xlsx
            data_cols_to_update = ['Device_Name', 'VLAN', 'Descrizione', 'Admin_Status', 
                                   'Oper_Status', 'Port_Mode', 'Media_Type', 'Speed', 
                                   'Duplex', 'Voice_VLAN', 'If_Index']
            
            existing_ports_df.update(new_ports_df[data_cols_to_update], overwrite=True)
            
            new_rows_to_add = new_ports_df[~new_ports_df.index.isin(existing_ports_df.index)]
            
            final_ports_df = pd.concat([existing_ports_df.reset_index(), new_rows_to_add.reset_index()], ignore_index=True)
            final_ports_df = final_ports_df[cols_ordered_ports].fillna('')
            final_ports_df.drop_duplicates(subset=key_cols, keep='first', inplace=True)

        except Exception as e:
            print(f"Errore nella lettura o elaborazione del file Excel esistente '{OUTPUT_PORTS_XLSX}': {e}")
            print("Provo a usare solo i nuovi dati, creando/sovrascrivendo il file.")
            final_ports_df = new_ports_df.reset_index() # Resetta l'indice prima di riordinare
            final_ports_df = final_ports_df[cols_ordered_ports].fillna('')
    else:
        print(f"Il file '{OUTPUT_PORTS_XLSX}' non esiste o è vuoto. Creo un nuovo file...")
        final_ports_df = new_ports_df.reset_index() # Resetta l'indice prima di riordinare
        final_ports_df = final_ports_df[cols_ordered_ports].fillna('')

    try:
        final_ports_df.to_excel(OUTPUT_PORTS_XLSX, index=False, engine='openpyxl')
        print(f"Dati delle interfacce salvati con successo in '{OUTPUT_PORTS_XLSX}'.")
    except Exception as e:
        print(f"Errore durante il salvataggio del file Excel '{OUTPUT_PORTS_XLSX}': {e}")

if __name__ == "__main__":
    main()