import paramiko
import os
import time
import jsonObject
import argparse
from scp import SCPClient
from zssdk import *


parser = argparse.ArgumentParser(description='zstack-vyos ut')
parser.add_argument('configFile')
args = parser.parse_args()
configFile = args.configFile

CREATE_NEW_VYOS = True
VYOS_VM_UUID = "0bb2c6867c434f22a90dc42868db2397"

VYOS_USER = "vyos"
VYOS_PASSWORD = "vyos"

GOROOT="/home/vyos/vyos_ut/go/"
GOPATH="/home/vyos/vyos_ut/zstack-vyos/"
BOOTSTRAPINFO=os.getcwd()+"bootstrapinfo"

'''test step:
   1. copy zvr.bin, zvrboot.bin to remote vm
   2. bash zvrboot.bin;bash zvr.bin 
   3. copy zstack-vyos to remote vyos vm
   4. reboot remote vm to clean old configure
   5. run go test in remote vm 
'''
def exec_command(ssh, command):
    ret = True
    stdin, stdout, stderr = ssh.exec_command(command)
    for line in stdout:
        print('... ' + line.strip('\n'))
        if "FAIL" in line:
            ret = False

    return ret

class VyosNic:
    def __init__(self):
        self.category = "Private"
        self.addressMode = None
        self.deviceName = None
        self.gateway = None
        self.gateway6 = None
        self.ip = None
        self.ip6 = None
        self.isDefaultRoute = False
        self.l2type = "VxlanNetwork"
        self.mac = None
        self.mtu = 1450
        self.netmask = None
        self.physicalInterface = None
        self.prefixLength = 64
        self.vni = None

class VyosBootStrapInfo:
    def __init__(self):
        self.ConfigTcForVipQos = True
        self.additionalNics = []
        self.applianceVmSubType = None
        self.haStatus = "Backup"
        self.managementNic = None
        self.managementNodeCidr = "172.16.0.0/12"
        self.managementNodeIp = None
        self.publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbX7Yqnuylt2nJrJOQ9xo50PZDkehwTaPa6gCbZzIdBSSI5lulYVDuN4bdP6iVTNKtNnXSzZEVbLrW4Qq5+FWFZBRrwehpzEWq2+yKiExl97/5d98uP1lFItbOaTcZIbMoI0XeXDmNnVWrUx+CxhoE8aZBBLJZxXtznv1/wbBbGQBB5/2zIEe+ytH+VL7n1LzkZNhziH34n08/+Y4sfyc9WYeQyIaPQu0UhUfWyqCiZx31fmJp1cmTQLOBTKR0vdwtq8VpSFo4sPTLGOyOyA6Ti6Z6jPlt4EcGUeHRl4HsJohnaVBPmgbsO4qTadqy7jFsAIOAZkxiD8bVX4OoYlTwBPshHIvaqzyzPRo5MwVnc3hA9kTDkhyj7PG4fSz/WVgSBvtfyP0CSmvYkXglGtvEzGIEmX3ynUqcmp0fBe4v6NISmA3y6wdFvTYqMXf40dx+JvD1dhpiZH2Sj2bFDGFbJ8zk6rJls0cgSL1PpwnIssX9S0ZUil5tgUIiEPKPBDM= root@172-25-15-174"
        self.sshPort =  22
        self.uuid = None
        self.vyosPassword = "vyos"
        self.reservedIpForMgt = []
        self.reservedIpForPubL3 = []
        self.mgtGateway = ""

class TestZStackVyos:
    def __init__(self, configfile):
        self.configFile = configfile
        self.testEnv = None
        self.envIpMaps = {}

    def __enter__(self):
        with open(configFile,'r') as file:
            config = file.read()
            self.testEnv = jsonObject.loads(config)

        configure(hostname=self.testEnv.hostName, context_path="/zstack", read_timeout=120)
        self.__reserveIp()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__release()

    def __reserveIp(self):
        ''' reserved 5 ips in mgt network '''
        self.envIpMaps[self.testEnv.mgtL3NetworkUuid] = {}
        for i in range(5):
            nicAction = CreateVmNicAction()
            nicAction.l3NetworkUuid = self.testEnv.mgtL3NetworkUuid
            nicAction.accessKeyId = self.testEnv.accessKeyId
            nicAction.accessKeySecret = self.testEnv.accessKeySecret
            try:
                res = nicAction.call()
                nic = res.value.inventory
                self.envIpMaps[self.testEnv.mgtL3NetworkUuid][nic.uuid] = nic.ip
            except Exception as e:
                self.__release()

                print("reserve ip in mgt network failed, %s", e)
                exit(1)

        '''reserved 5 ips in pub network'''
        self.envIpMaps[self.testEnv.pubL3Uuid_1] = {}
        for i in range(5):
            nicAction = CreateVmNicAction()
            nicAction.l3NetworkUuid = self.testEnv.pubL3Uuid_1
            nicAction.accessKeyId = self.testEnv.accessKeyId
            nicAction.accessKeySecret = self.testEnv.accessKeySecret
            try:
                res = nicAction.call()
                nic = res.value.inventory
                self.envIpMaps[self.testEnv.pubL3Uuid_1][nic.uuid] = nic.ip
            except Exception as e:
                self.__release()

                print("reserve ip in mgt network failed, %s", e)
                exit(1)

    def __release(self):
        for nicUuid in self.envIpMaps[self.testEnv.mgtL3NetworkUuid]:
            deleteNic = DeleteVmNicAction()
            deleteNic.uuid = nicUuid
            try:
                deleteNic.accessKeyId = self.testEnv.accessKeyId
                deleteNic.accessKeySecret = self.testEnv.accessKeySecret
                deleteNic.call()
            except Exception as e1:
                print("delete vmnic [%s] failed, because %s",
                      self.envIpMaps[self.testEnv.mgtL3NetworkUuid][nicUuid], e1)

        for nicUuid in self.envIpMaps[self.testEnv.pubL3Uuid_1]:
            deleteNic = DeleteVmNicAction()
            deleteNic.uuid = nicUuid
            try:
                deleteNic.accessKeyId = self.testEnv.accessKeyId
                deleteNic.accessKeySecret = self.testEnv.accessKeySecret
                deleteNic.call()
            except Exception as e1:
                print("delete vmnic [%s] failed, because %s",
                      self.envIpMaps[self.testEnv.pubL3Uuid_1][nicUuid], e1)

    def createTestVyosVm(self, imageuuid):
        cVyos = CreateVmInstanceAction()
        cVyos.name = self.testEnv.testName
        cVyos.imageUuid = imageuuid
        cVyos.instanceOfferingUuid = self.testEnv.instanceOfferingUuid
        cVyos.l3NetworkUuids = [self.testEnv.mgtL3NetworkUuid, self.testEnv.pubL3Uuid_1, self.testEnv.pubL3Uuid_2,
                                self.testEnv.privateL3Uuid_1, self.testEnv.privateL3Uuid_2]
        cVyos.zoneUuid = self.testEnv.zoneUuid
        cVyos.description = self.testEnv.testName + " at " + time.asctime(time.localtime(time.time()))
        cVyos.defaultL3NetworkUuid = self.testEnv.pubL3Uuid_1
        cVyos.accessKeyId = self.testEnv.accessKeyId
        cVyos.accessKeySecret = self.testEnv.accessKeySecret
        res = cVyos.call()
        vyos = res.value.inventory
        return vyos

    def queryTestVyosVm(self, uuid):
        qVyos = QueryVmInstanceAction()
        qVyos.conditions = ["uuid=%s" % uuid]
        qVyos.accessKeyId = self.testEnv.accessKeyId
        qVyos.accessKeySecret = self.testEnv.accessKeySecret
        res = qVyos.call()
        vyos = res.value.inventories[0]
        return vyos

    def queryL3Network(self, uuid):
        qL3 = QueryL3NetworkAction()
        qL3.conditions = ["uuid=%s" % uuid]
        qL3.accessKeyId = self.testEnv.accessKeyId
        qL3.accessKeySecret = self.testEnv.accessKeySecret
        res = qL3.call()
        l3 = res.value.inventories[0]
        return l3

    def deleteTestVyosVm(self, uuid):
        dVyos = DestroyVmInstanceAction()
        dVyos.uuid = uuid
        dVyos.accessKeyId = self.testEnv.accessKeyId
        dVyos.accessKeySecret = self.testEnv.accessKeySecret
        dVyos.call()

        eVyos = ExpungeVmInstanceAction()
        eVyos.uuid = uuid
        eVyos.accessKeyId = self.testEnv.accessKeyId
        eVyos.accessKeySecret = self.testEnv.accessKeySecret
        eVyos.call()

    def buildVyosBootStrap(self, vm):
        bootStrapInfo = VyosBootStrapInfo()
        mgtNic = VyosNic()
        defNic = VyosNic()
        nics = []
        for nic in vm.vmNics:
            l3 = self.queryL3Network(nic.l3NetworkUuid)

            if nic.l3NetworkUuid == self.testEnv.mgtL3NetworkUuid:
                ''' TODO: IPv6'''
                mgtNic.deviceName = "eth0"
                mgtNic.gateway = nic.gateway
                mgtNic.ip = nic.ip
                mgtNic.isDefaultRoute = False
                mgtNic.mac = nic.mac
                mgtNic.netmask = nic.netmask
                mgtNic.category = l3.category
            elif nic.l3NetworkUuid == self.testEnv.pubL3Uuid_1:
                defNic.deviceName = "eth" + nic.internalName.split(".")[1]
                defNic.gateway = nic.gateway
                defNic.ip = nic.ip
                defNic.isDefaultRoute = True
                defNic.mac = nic.mac
                defNic.netmask = nic.netmask
                defNic.category = l3.category
                nics.append(defNic)
            else:
                oNic = VyosNic()
                oNic.deviceName = "eth" + nic.internalName.split(".")[1]
                oNic.gateway = nic.gateway
                if l3.category == "Private":
                    oNic.ip = nic.gateway
                else:
                    oNic.ip = nic.ip
                oNic.isDefaultRoute = False
                oNic.mac = nic.mac
                oNic.netmask = nic.netmask
                oNic.category = l3.category
                nics.append(oNic)

        bootStrapInfo.additionalNics = nics
        bootStrapInfo.managementNic = mgtNic
        bootStrapInfo.uuid = vm.uuid
        bootStrapInfo.managementNodeIp = self.testEnv.hostName
        bootStrapInfo.mgtGateway = self.testEnv.mgtGateway

        for nicUuid in self.envIpMaps[self.testEnv.mgtL3NetworkUuid]:
            bootStrapInfo.reservedIpForMgt.append(self.envIpMaps[self.testEnv.mgtL3NetworkUuid][nicUuid])

        for nicUuid in self.envIpMaps[self.testEnv.pubL3Uuid_1]:
            bootStrapInfo.reservedIpForPubL3.append(self.envIpMaps[self.testEnv.pubL3Uuid_1][nicUuid])

        print("vm bootstrap: %s" % jsonObject.dumps(bootStrapInfo, pretty=True))
        with open(BOOTSTRAPINFO, "w+") as f:
            f.write(jsonObject.dumps(bootStrapInfo, pretty=True))

        return mgtNic

    def startVyosTest(self, vyos):
        mgtNic = self.buildVyosBootStrap(vyos)
        vyosVmIp = mgtNic.ip

        print("preparing env in %s" % vyosVmIp)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # try to wait in 300 seconds
        count = 0
        while count < 30 :
            try:
                ssh.connect(vyosVmIp, 22, username=VYOS_USER, password=VYOS_PASSWORD, timeout=300)
                break
            except Exception as e:
                print("ssh to %s failed %s for %d times" % (vyosVmIp, e, count + 1))
                count = count + 1
                time.sleep(10)
        if count == 30:
            print("ssh to %s failed" % vyosVmIp)
            exit(1)

        print("copying binary file")
        scp = SCPClient(ssh.get_transport())
        scp.put('./target/zvrboot.bin', '/home/vyos/zvrboot.bin')
        scp.put('./target/zvr.bin', '/home/vyos/zvr.bin')

        print("installing zstack binary file")
        print("install zvrboot.bin")
        exec_command(ssh, "bash -x /home/vyos/zvrboot.bin")
        print("install zvr.bin")
        exec_command(ssh, "bash -x /home/vyos/zvr.bin")

        print("copying zstack-vyos code")
        exec_command(ssh, "rm -rf /home/vyos/vyos_ut/zstack-vyos/; mkdir -p /home/vyos/vyos_ut/zstack-vyos")
        print("copy zstack-vyos code")
        print(os.path.abspath(os.path.dirname(os.getcwd())) + "/zstack-vyos")
        scp.put(os.path.abspath(os.path.dirname(os.getcwd())) + "/zstack-vyos", remote_path='/home/vyos/vyos_ut/', recursive=True)
        print("copy bootstrapinfo")
        scp.put(BOOTSTRAPINFO, '/home/vyos/vyos_ut/zstack-vyos/bootstrapinfo')
        scp.close()

        print("runing test case")
        exec_command(ssh, "mkdir -p /home/vyos/vyos_ut/testLog/; chmod 777 /home/vyos/vyos_ut/testLog/")
        ret = exec_command(ssh, "export PATH=$PATH:/home/vyos/vyos_ut/go/bin; cd /home/vyos/vyos_ut/zstack-vyos;ginkgo  -v -r --failFast --cover")
        ssh.close()

        if ret == True and  CREATE_NEW_VYOS:
            self.deleteTestVyosVm(vyos.uuid)

        return ret

    def TestVyos_1_1_7_5_4_80(self):
        vyos = None
        if CREATE_NEW_VYOS:
            imageUuid = self.testEnv.vyosImageUuid_1_1_7_5_4_80
            vyos = self.createTestVyosVm(imageUuid)
        else:
            vyos = self.queryTestVyosVm(VYOS_VM_UUID)

        return self.startVyosTest(vyos)

    def TestVyos_1_1_7_3_13(self):
        vyos = None
        if CREATE_NEW_VYOS:
            imageUuid = self.testEnv.vyosImageUuid_1_1_7_3_13
            vyos = self.createTestVyosVm(imageUuid)
        else:
            vyos = self.queryTestVyosVm(VYOS_VM_UUID)

        return self.startVyosTest(vyos)

    def TestVyos_1_2_0_5_4_80(self):
        vyos = None
        if CREATE_NEW_VYOS:
            imageUuid = self.testEnv.vyosImageUuid_1_2_0_5_4_80
            vyos = self.createTestVyosVm(imageUuid)
        else:
            vyos = self.queryTestVyosVm(VYOS_VM_UUID)

        return self.startVyosTest(vyos)

def TestAll():
    with TestZStackVyos(configFile) as test:
        if test.TestVyos_1_1_7_5_4_80() != True:
            print("test vyos 1.1.7 kenel 5.4.80 failed")
            return

        if test.TestVyos_1_1_7_3_13() != True:
            print("test vyos 1.1.7 kenel 3.13 failed")
            return

        if test.TestVyos_1_2_0_5_4_80() != True:
            print("test vyos 1.2.0 kenel 5.4.80 failed")
            return

if __name__ == "__main__":
    TestAll()
