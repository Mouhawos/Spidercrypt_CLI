import os
import subprocess
import pickle
import requests

API_KEY = os.getenv("API_KEY", "YOUR_API_KEY_HERE")
DB_PASSWORD = os.getenv("DB_PASSWORD", "YOUR_DB_PASSWORD_HERE")

def dangerous_eval(user_input):
    # 🔴 CODE INJECTION (eval)
    return eval(user_input)

def run_command(cmd):
    # 🔴 EXECUTION SYSTEM
    os.system(cmd)

def unsafe_subprocess(cmd):
    # 🔴 SUBPROCESS SANS CONTROLE
    subprocess.Popen(cmd, shell=True)

def unsafe_pickle_load(data):
    # 🔴 DESERIALISATION DANGEREUSE
    return pickle.loads(data)

def fetch_data(url):
    # 🔴 REQUEST SANS TIMEOUT
    return requests.get(url)

if __name__ == "__main__":
    user_input = input("Enter something: ")
    dangerous_eval(user_input)
    run_command("rm -rf /tmp/test")


