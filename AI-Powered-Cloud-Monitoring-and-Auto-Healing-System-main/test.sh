import yaml
from proxmoxer import ProxmoxAPI
import urllib3

# Suppress SSL warnings for the lab environment
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)['proxmox']
    
    print(f"--- Diagnostic for Node: {config['node']} ---")
    
    # Attempting Handshake
    proxmox = ProxmoxAPI(
        config['host'], 
        user=config['user'], 
        password=config['password'], 
        verify_ssl=False
    )
    
    # Test 1: Authentication
    nodes = proxmox.nodes.get()
    print("✅ Step 1: Authentication Successful!")
    
    # Test 2: Node Verification
    actual_nodes = [n['node'] for n in nodes]
    if config['node'] in actual_nodes:
        print(f"✅ Step 2: Node '{config['node']}' found.")
    else:
        print(f"❌ Step 2: Node '{config['node']}' NOT found. Available nodes: {actual_nodes}")

    # Test 3: Container Verification
    lxc_list = proxmox.nodes(config['node']).lxc.get()
    vmid_exists = any(str(l['vmid']) == str(config['vmid']) for l in lxc_list)
    if vmid_exists:
        print(f"✅ Step 3: Container {config['vmid']} is visible.")
    else:
        print(f"❌ Step 3: Container {config['vmid']} not found on this node.")

except Exception as e:
    print(f"❌ CRITICAL FAILURE: {e}")