import asyncio
from bleak import BleakClient, BleakScanner
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time
import uuid
from datetime import datetime
import subprocess
import base64

# BLE identifiers
SERVICE_UUID       = "11111111-1234-1234-1234-1234567890ab"
AUTH_CHAR_UUID     = "22222222-2222-3333-4444-555566667777"
DATA_CHAR_UUID     = "33333333-1234-5678-90ab-cdef12345678"
ESP32_NAME         = "ESP32C3-GATT-Server"
EXPECTED_REPLY     = b'OK'
# RSA key path
PRIVATE_KEY_FILE   = "private.pem"
PUBLIC_KEY_FILE    = "public.pem"

# Message to sign 
AUTH_MESSAGE = None

def get_local_mac():
    try:
        out = subprocess.check_output("hcitool dev", shell=True).decode()
        for line in out.splitlines():
            if "hci0" in line:
                return line.strip().split()[1]  # e.g., B8:27:EB:22:57:A1
    except Exception as e:
        print(f"Could not get local MAC: {e}")
    return None

def create_auth_message(mac: str) -> bytes:
    timestamp = datetime.utcnow().isoformat()
    return f"authorize-rsa:{mac}:{timestamp}".encode()

def load_private_key():
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        return RSA.import_key(f.read())

async def send_signed_auth(client, mac):
    private_key = load_private_key()
    message = create_auth_message(mac)
    print(f"Auth message: {message.decode()}")
    hash = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(hash)
    msg_len = len(message).to_bytes(2, byteorder='big')
    payload = msg_len + message + signature

    await client.write_gatt_char(AUTH_CHAR_UUID, payload, response=True)
    reply = await client.read_gatt_char(AUTH_CHAR_UUID)
    print(f"Auth response: {reply.decode()}")
    return reply == b"OK"


async def main():
    print("Scanning for devices...")
    devices = await BleakScanner.discover(timeout=5)

    target = None
    for d in devices:
        if ESP32_NAME in d.name:
            print(f"Found: {d.name} ({d.address})")
            target = d
            break

    if not target:
        print("ESP32 not found.")
        return

    local_mac = get_local_mac()
    if not local_mac:
        print("Could not get Pi MAC address")
        return

    print("\nWhat do you want to do?")
    print("1. Send START_AUTH and authenticate")
    print("2. Send signed authentication only")
    print("3. Just listen for notifications")
    choice = input("Choose [1/2/3]: ").strip()

    async with BleakClient(target.address) as client:
        print("Connected to ESP32")

        if choice == "1":
            msg = f"START_AUTH:{local_mac}"
            print("Sending START_AUTH...")
            await client.write_gatt_char(AUTH_CHAR_UUID, msg.encode(), response=True)
            reply = await client.read_gatt_char(AUTH_CHAR_UUID)
            print(f"Response: {reply.decode()}")
            if reply != b"LOCKED":
                return

            print("Sending signed authentication after lock...")
            if not await send_signed_auth(client, local_mac):
                return

        elif choice == "2":
            print("Sending signed authentication...")
            if not await send_signed_auth(client, local_mac):
                return

        elif choice == "3":
            print("Proceeding without authentication")
        else:
            print("Invalid option")
            return

        def handle_notify(_, data):
            print(f"Notification: {data.decode()}")

        await client.start_notify(DATA_CHAR_UUID, handle_notify)
        print("Listening for notifications...")
        while True:
            await asyncio.sleep(1)


asyncio.run(main())
