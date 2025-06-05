import pandas as pd
import requests
import json
import os
import getpass
from cryptography.fernet import Fernet

# --- Impostazioni ---
XLSX_OUTPUT_FILE = 'elenco_switch_ip.xlsx'
CRED_FILE = 'dnac_creds.enc'
KEY_FILE = 'secret.key'

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
VERIFY_SSL = False

# --- Funzioni di Crittografia (invariate) ---
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    print(f"Nuova chiave di crittografia generata e salvata in '{KEY_FILE}'.")
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, 'rb') as key_file:
        key = key_file.read()
    return key

def encrypt_data(data_dict, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data_dict).encode())
    return encrypted_data

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    decrypted_json_str = f.decrypt(encrypted_data).decode()
    return json.loads(decrypted_json_str)

def load_or_request_config():
    """
    Carica configurazione (username, password, dnac_url) da file criptato.
    Chiede conferma all'utente se i dati caricati sono corretti.
    Se non esiste, è illeggibile, o l'utente vuole reinserirli, li chiede e li salva.
    Restituisce (username, password, dnac_url).
    """
    key = load_key()
    config_loaded = False
    username, password, dnac_url_loaded = None, None, None

    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE, 'rb') as f:
                encrypted_config = f.read()
            config_data = decrypt_data(encrypted_config, key)
            if 'username' in config_data and 'password' in config_data and 'dnac_url' in config_data:
                username = config_data['username']
                password = config_data['password'] # Non mostreremo la password
                dnac_url_loaded = config_data['dnac_url']
                
                print("\n--- Configurazione DNA Center Caricata da File ---")
                print(f"  Username: {username}")
                print(f"  URL DNA Center: {dnac_url_loaded}")
                # Non stampare la password per sicurezza
                
                while True:
                    choice = input("Vuoi procedere con questa configurazione? (s/n): ").strip().lower()
                    if choice == 's':
                        config_loaded = True
                        break
                    elif choice == 'n':
                        print("OK, verranno richiesti nuovi dati di configurazione.")
                        config_loaded = False # Forza la richiesta di nuovi dati
                        break
                    else:
                        print("Scelta non valida. Inserisci 's' per sì o 'n' per no.")
            else:
                print("File di configurazione esistente incompleto. Verranno richiesti i dati.")
        except Exception as e:
            print(f"Errore nel decriptare la configurazione esistente: {e}.")
            print("Verranno richiesti e salvati nuovamente i dati.")

    if not config_loaded: # Se non caricati o l'utente ha scelto 'n'
        print("\n--- Inserimento Nuova Configurazione DNA Center ---")
        new_username = input("Inserisci username DNA Center: ")
        new_password = getpass.getpass("Inserisci password DNA Center: ")
        new_dnac_url_input = input("Inserisci l'URL base di DNA Center (es. https://sandboxdnac.cisco.com): ").strip()
        if not new_dnac_url_input.startswith('http'):
            new_dnac_url_input = 'https://' + new_dnac_url_input
        
        config_to_save = {
            'username': new_username,
            'password': new_password,
            'dnac_url': new_dnac_url_input
        }
        
        encrypted_config_to_save = encrypt_data(config_to_save, key)
        with open(CRED_FILE, 'wb') as f:
            f.write(encrypted_config_to_save)
        print(f"Nuova configurazione DNA Center (utente, pwd, URL) salvata e criptata in '{CRED_FILE}'.")
        return new_username, new_password, new_dnac_url_input
    else:
        # Se config_loaded è True, significa che l'utente ha confermato i dati caricati
        print("Utilizzo della configurazione caricata.")
        return username, password, dnac_url_loaded # password qui è quella caricata (non mostrata)


# --- Funzioni API DNA Center (invariate) ---
def get_dnac_token(dnac_url, username, password):
    auth_url = f"{dnac_url}/dna/system/api/v1/auth/token"
    headers = {'Content-Type': 'application/json'}
    print("\nOttenimento token DNA Center...")
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=VERIFY_SSL, timeout=20)
        response.raise_for_status()
        token = response.json().get('Token')
        if token: print("Token ottenuto con successo."); return token
        else: print("Errore: Token non trovato nella risposta."); return None
    except requests.exceptions.HTTPError as e:
        print(f"Errore HTTP durante l'autenticazione: {e.response.status_code} {e.response.reason} for url: {e.response.url}")
        if e.response.status_code == 502:
            print("Errore 502 Bad Gateway: Problema temporaneo del server o del gateway. Riprova più tardi.")
        try: print(f"Dettagli errore dal server: {e.response.json()}")
        except json.JSONDecodeError: print(f"Dettagli errore dal server (testo): {e.response.text}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Errore di richiesta durante l'autenticazione: {e}"); return None

def get_all_network_devices(dnac_url, token):
    all_devices = []
    url = f"{dnac_url}/dna/intent/api/v1/network-device"
    headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}
    print("Recupero elenco dispositivi di rete da DNA Center...")
    try:
        response = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=60)
        response.raise_for_status()
        devices_page = response.json().get('response')
        if devices_page:
            all_devices.extend(devices_page)
            print(f"Recuperati {len(devices_page)} dispositivi.")
        else:
            print("Nessun dispositivo trovato o errore nella risposta.")
            print(f"Dettaglio risposta: {response.text if response else 'Nessuna risposta'}")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
             print(f"Errore di autorizzazione (401): {e}")
        else:
            print(f"Errore HTTP nel recuperare i dispositivi: {e.response.status_code} {e.response.reason}")
            try: print(f"Dettagli errore: {e.response.json()}")
            except json.JSONDecodeError: print(f"Dettagli errore (testo): {e.response.text}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"Errore di richiesta nel recuperare i dispositivi: {e}"); return []
    except json.JSONDecodeError:
        print(f"Errore nel decodificare JSON. Risposta: {response.text if response else 'Nessuna risposta'}"); return []
    return all_devices

# --- Funzione Principale ---
def main():
    username, password, dnac_base_url = load_or_request_config()
    if not all([username, password, dnac_base_url]):
        print("Dati di configurazione non forniti o caricamento annullato. Uscita.")
        return

    # L'URL è già stato confermato o inserito, quindi non c'è bisogno di chiederlo di nuovo.
    # print(f"Utilizzo DNA Center URL: {dnac_base_url}") # Già stampato o confermato in load_or_request_config

    token = get_dnac_token(dnac_base_url, username, password)
    if not token:
        print("Impossibile ottenere il token. Uscita.")
        return

    all_network_devices = get_all_network_devices(dnac_base_url, token)
    if not all_network_devices:
        print("Nessun dispositivo di rete recuperato da DNA Center. Uscita.")
        return

    print(f"\nRecuperati in totale {len(all_network_devices)} dispositivi di rete.")
    
    switch_data_list = []
    for device in all_network_devices:
        device_family = device.get('family', '').lower()
        device_type = device.get('type', '').lower()
        is_switch = False
        if "switch" in device_family or "switches" in device_family or "switch" in device_type:
            is_switch = True
            
        if is_switch:
            mgmt_ip = device.get('managementIpAddress', 'N/A')
            if mgmt_ip and mgmt_ip != 'N/A':
                switch_data_list.append({
                    'Go': '',
                    'Hostname': device.get('hostname', 'N/A'),
                    'Management_IP': mgmt_ip,
                    'Device_ID': device.get('id', 'N/A'),
                    'Software_Version': device.get('softwareVersion', 'N/A'),
                    'Platform_ID': device.get('platformId', 'N/A'),
                    'Family': device.get('family', 'N/A'),
                    'Type': device.get('type', 'N/A'),
                    'Serial_Number': device.get('serialNumber', 'N/A'),
                    'Reachability_Status': device.get('reachabilityStatus', 'N/A'),
                    'Up_Time': device.get('upTime', 'N/A')
                })

    if not switch_data_list:
        print("Nessun dispositivo identificato come switch con IP di management valido è stato trovato.")
        return

    print(f"\nTrovati {len(switch_data_list)} dispositivi identificati come switch con IP.")

    df_switches = pd.DataFrame(switch_data_list)
    cols_ordered = ['Go', 'Hostname', 'Management_IP', 'Device_ID', 'Software_Version', 
                    'Platform_ID', 'Family', 'Type', 'Serial_Number', 
                    'Reachability_Status', 'Up_Time']
    for col in cols_ordered:
        if col not in df_switches.columns: df_switches[col] = ''
    df_switches = df_switches[cols_ordered]

    try:
        df_switches.to_excel(XLSX_OUTPUT_FILE, index=False, engine='openpyxl')
        print(f"\nElenco degli switch esportato con successo in '{XLSX_OUTPUT_FILE}'.")
    except Exception as e:
        print(f"Errore durante il salvataggio del file Excel '{XLSX_OUTPUT_FILE}': {e}")

if __name__ == "__main__":
    main()