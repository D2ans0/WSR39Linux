import re
from pyVim import connect
from pyVmomi import vmodl, vim
from tools import pchelper
import time
import requests
import ast
from configparser import ConfigParser

requests.packages.urllib3.disable_warnings() #disable ssl warnings

#load variables.ini
config = ConfigParser()
config.read('variables.ini')
#load arrays
vm_array = ast.literal_eval(config.get("ARRAYS", "vm_array"))
delay30Sec = ast.literal_eval(config.get("ARRAYS", "delay30sec"))
delay60Sec = ast.literal_eval(config.get("ARRAYS", "delay60sec"))
#load the rest of the variables
configDict = config._sections['MAIN']
locals().update(configDict)
print(teststring) #test string, doesn't affect anything, is just to check if the config changed

#Host auth
si = connect.SmartConnectNoSSL(host=esxi_host, user=esxi_user, pwd=esxi_pass, port=443) #connect to host
content = si.RetrieveContent()

for guestvm in vm_array:
    FN = f'scripts/{guestvm}' #source path
    vm_path = f'/root/{guestvm}' #target path

    #VM auth
    vm = pchelper.get_obj(content, [vim.VirtualMachine], guestvm)
    creds = vim.vm.guest.NamePasswordAuthentication(username=vm_user, password=vm_pass) #VM authentication

    data_to_send = open(FN, 'rb').read() #file to send

    file_attribute = vim.vm.guest.FileManager.FileAttributes()
    url = content.guestOperationsManager.fileManager.InitiateFileTransferToGuest(vm, creds, vm_path, file_attribute, len(data_to_send), True)
    url = re.sub(r"^https://\*:", f"https://{esxi_host}:", url)
    resp = requests.put(url, data=data_to_send, verify=False) #send data
    profile_manager = content.guestOperationsManager.processManager

    #exec stuff
    program_spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath='/bin/chmod', arguments=f'+x {vm_path}; {vm_path}')
    res = profile_manager.StartProgramInGuest(vm, creds, program_spec)
    print(guestvm)
    if guestvm in delay60Sec:
        print("Wait 60sec")
        time.sleep(60)
    elif guestvm in delay30Sec:
        print("Wait 30sec")
        time.sleep(30)
    else:
        print("Skip to next host")

#esxi_host = '192.168.100.146'
#esxi_user = 'root'
#esxi_pass = 'P@ssw0rd'
#vm_user = 'root'
#vm_pass = 'toor'
#vm_array = ["R-FW", "L-FW", "OUT-CLI", "L-RTR-A", "L-RTR-B", "L-CLI-A", "L-CLI-B", "L-SRV", "R-RTR", "R-SRV", "R-CLI"]
#delay30Sec = ["R-FW", "L-RTR-A", "L-RTR-B"]
#delay60Sec = ["L-FW"]
