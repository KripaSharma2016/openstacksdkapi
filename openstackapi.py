# Licensed under the Sanctum Networks, Version 1.0 (the "License"); you may
# not use this file except in compliance with the License
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Find User Guide
#
#   https://developer.openstack.org/sdks/python/openstacksdk/users/index.html#user-guides
#
# Installation Guide
#
#  https://developer.openstack.org/sdks/python/openstacksdk/users/index.html#api-documentation


"""
:class: ~OpenstackSdkWrapper class is a wrapper used to bridge the openstacksdk functionality and jupitor.
    
Example
--------

The :class:`~OpenstackSdkWrapper` class is constructed with two arguments, regionName and config dict.
    
"""    
from openstack import connection
from openstack import profile
from openstack.database.v1 import flavor
import os
import logging as log
import openstack
import traceback
import sys

class OpenstackSdkWrapper():
    def __init__(self,regionName,**config):
        """
            In constructor there are two parameters need to be set at object creation time.
                :param: dict configData = {'auth_url' : 'http://10.10.1.16:35357/v3',
                    'project_name': 'admin',
                    'user_domain_name': 'default',
                    'project_domain_name': 'default',
                    'username': 'admin',
                    'password': 'stack',
                    }
                :param: str regionName : Desired region name
                
                obj=OpenstackSdkWrapper('RegionOne',**configData)    
        """
        log.basicConfig(filename='/var/log/usingsdk.log', level=log.INFO)
        self.regionName=regionName
        self.configDict=config
               
    def makeConnection(self):
        """
            This method is defined to make connection with keystone.        
        """
        try:
            log.info(" Setting Profile !!")
            prof = profile.Profile()
            prof.set_region(profile.Profile.ALL, self.regionName)
            log.info(" Profile has been successfully set!")
        except Exception as ex:
            log.error("Error in setting profile with region. reason is {}".format(ex))
            return 400,ex    
        else :
            self.configDict['profile']=prof
            #self.auth_args=self.configDict
            try:
                conn = connection.Connection(**self.configDict)
                conn.authorize()
                log.info("Connection get established !")
            except openstack.exceptions.SDKException as ex:
                log.error("Error in connection with keystone. Reason is {}".format(ex))
                """
                    Unable to establish connection to http://10.10.1.103:35357/v3: 
                    HTTPConnectionPool(host='10.10.1.103', port=35357): 
                    Max retries exceeded with url: /v3
                    (Caused by NewConnectionError('<requests.packages.urllib3.connection.HTTPConnection object at 0x7fa7e3068710>: 
                    Failed to establish a new connection: [Errno 111] Connection refused',))
                """
                return 400,ex
            else:
                return 201,conn
        
    def getUserInfo(self,conn, userId):
        """
            :param: object conn: Connection type.
            :param: str userId : Desired userId.
        """
        self.conn = conn
        try:
            data = self.conn.identity.get_user(userId)
            return 201,data
        except openstack.exceptions.NotFoundException as ex:
            log.error("Error in accessing user info. Reason is {}".format(ex))
            return 400,ex
        except openstack.exceptions.ResourceNotFound as ex:
            log.error("Error in ")
            return 400,ex
      
    def createUser(self, conn, userName, password):
        """
            :param: object conn: Connection type.
            :param: str userName: Desired username.
            :param: str password: Desired password.
        """
        self.conn = conn
        try:
            user = {"name":userName,
                    "password":password,
                    "enabled": True,
                    "description":"yess",
                    "email":"demo@example.com",
                    }
            user_info = self.conn.identity.create_user(**user)
            return 201,user_info.id
        except Exception as ex:
            log.error("Error in creating user. Reason is {}".format(ex))
            return 400,ex

    def deleteUser(self, conn, userId):
        """
            :param: object conn: Connection type.
            :param: str userId: Desired userid.
        """
        self.conn = conn
        try:
            data = self.conn.identity.delete_user(userId)
            return 201,data
        except Exception as ex:
            log.error("Error in deleting user. Reason is {}".format(ex))
            return 400,ex
                
    def createKey(self,conn,keyPairName):
        """
            :param: object conn: Connection type.
            :param: str keypairname: Desired keypairname.
        """
        self.conn = conn
        try:
            keypair = self.conn.compute.find_keypair(keyPairName)
            if not keypair:
                print("Create Key Pair:")
                keypair = self.conn.compute.create_keypair(name=keyPairName)
                print(keypair)
                with open(keyPairName+'.pem', 'w') as f:
                    f.write("%s" % keypair.private_key)
                os.chmod(keyPairName+'.pem', 0o400)
            return 201,keypair
        except Exception as ex:
            log.error("Error in creating keypair. Reason is {}".format(ex))
            return 400,ex
    
    def deleteKeypair(self,conn,keyPairName,keyPairFile):
        """
            :param: object conn: Connection type.
            :param: str keyPairName: Desired keypairname.
            :param: str keypairfile: Desired keypairfile.
        """    
        self.conn = conn
        keypair = self.conn.compute.find_keypair(keyPairName)

        try:
            os.remove(keyPairFile)
        except OSError as e:
            log.error("Error in removing keypair. Reason is {}".format(e))
        try:
            data = self.conn.compute.delete_keypair(keypair)
            return 201,data
        except Exception as ex:
            log.error("Error in deleting keypair. Reason is {}".format(ex))
            return 400,ex
    
    def createServer(self,conn,imageId,flavorId,netwokId,vmName,keyPairName):
        """
            :param: object conn: Connection type.
            :param: str imageId: Desired imageid.
            :param: str flavorId: Desired flavorid.
            :param: str netwokId: Desierd networkid.
            :param: str vmName: Desired vm name.
            :param: str keyPairName: Desired keypairname.
        """
        self.conn = conn
        try:
            image = self.conn.compute.find_image(imageId)
            flavor = self.conn.compute.find_flavor(flavorId)
            network = self.conn.network.find_network(netwokId)
            #keypair = self.conn.create_keypair(self.conn,keyPairName)

            server = self.conn.compute.create_server(
                name=vmName, image_id=image.id, flavor_id=flavor.id,
                networks=[{"uuid": network.id}], key_name=keyPairName)
            server = self.conn.compute.wait_for_server(server)
            return 201,server 
        except Exception as ex:
            log.error("Error in creating server. Reason is {}".format(ex))
            return 400,ex
        
    def deleteServer(self,conn,serverName):
        """
            :param: object conn: Connection type.
            :param: str severName: Desired vm name. 
        """
        self.conn = conn
        try:
            server = self.conn.compute.find_server(serverName)
        except Exception as ex:
            log.error("Not able to find server. Reason is {}".format(ex))
            return 400, ex
        try:
            data = self.conn.compute.delete_server(server)
            return 201,data
        except Exception as ex:
            log.error("Not able to delete server. Reason is {}".format(ex))
            return 400,ex
    
    def createNetwork(self,conn,networkName,subnetName,cidr,gatewayIp):
        """
            :param: object conn: Connection type.
            :param: str networkName: Desired network name.
            :param: str subnetName: Desired subnet name.
            :param: str cidr: Desired cidr.
            :param: str gatewayIp: Desired gateway ip.
        """
        self.conn = conn
        try:
            log.info("creating network .......")
            newNetwork = self.conn.network.create_network(name=networkName)
            log.info("Network has been created!")
        except Exception as ex:
            log.error("Error in creating Network. Reason is {}".format(ex))
            return 400,ex
        else:
            try:
                newSubnet = self.conn.network.create_subnet(name=subnetName,network_id=newNetwork.id,ip_version='4',cidr=cidr,gateway_ip=gatewayIp)
                return 201,newNetwork,newSubnet
            except Exception as ex:
                log.error("Error in creating Subnet. Reason is {}".format(ex))
                return 400,ex
    
    def createRouter(self,conn,routerName,externalNetworkId):
        """
            :param: object conn: Connection type.
            :param: str routerName: Desired router name.
            :param: str externalNetworkId: Desired externalNetworkId.
        """
        self.conn = conn 
        try:
            data = self.conn.network.create_router(name=routerName,external_gateway_info={"network_id": externalNetworkId})    
            return 201,data
        except Exception as ex:
            log.error("Error in Creating router. Reason is {}".format(ex))
            return 400,ex
            
    def addRouterInterface(self,conn, routerName, subnetId):
        """
            :param: object conn: Connection type.
            :param: str routerName: Desired router name.
            :param: str subnetId: Desired subnet id.
        """
        self.conn = conn
        try:
            router = self.conn.network.find_router(routerName)
            data = self.conn.network.router_add_interface(router, subnetId)
            return 201,data         
        except Exception as ex:
            log.error("Error in adding router interface. Reason is {}".format(ex))
            return 400,ex
        
    def removeRouterInterface(self,conn,routerName, subnetId):
        self.conn = conn
        try:
            router = self.conn.network.find_router(routerName)
            data = self.conn.router_remove_interface(router,subnetId)
            return 201,data
        except Exception as ex:
            log.error("Error in removing router interface. Reason is {}".format(ex))
            return 400,ex    
        
    def deleteRouter(self,conn,routerId):
        """
            :param: object conn: Connection type.
            :param: str routerId: Desired router id.
        """
        self.conn = conn
        try:
            data = self.conn.network._delete_router(routerId)
            return 201,data
        except Exception as ex:
            log.error("Error in deleting router. Reason is {}".format(ex))
            return 400,ex
                
    def deleteNetwork(self,conn,networkName):
        """
            :param: object conn: Connection type.
            :param: str networkName: Desired network name.
        """
        self.conn = conn
        try:
            delNetwork = self.conn.network.find_network(networkName)
            for delSubnet in delNetwork.subnet_ids:
                self.conn.network.delete_subnet(delSubnet, ignore_missing=False)
                self.conn.network.delete_network(delNetwork, ignore_missing=False)
            return 201,"Deleted"
        except Exception as ex:
            log.error("Error in deleting Network. Reason is {}".format(ex))
            return 400,ex
            
    def findNetwork(self,conn,networkName):
        """
            :param: object conn: Connection type.
            :param: str networkName: Desired network name.
        """
        self.conn= conn
        try:
            data = self.conn.network.find_network(networkName)
            return 201,data
        except Exception as ex:
            log.error("Error in finding Network. Reason is {}".format(ex))
            return 400, ex
        
    def createSubnet(self,conn,subnetName,networkId,cidr,gatewayIp):
        """
            :param: object conn: Connection type.
            :param: str subnetName: Desired subnet name.
            :param: str networkId: Desired network id.
            :param: str cidr : Desired cidr.
            :param: str gatewayip: Desired gateway ip.
        """
        self.conn = conn
        try:
            data = self.conn.network.create_subnet(name=subnetName,network_id=networkId,ip_version='4',cidr=cidr,gateway_ip=gatewayIp)
            return 201,data
        except Exception as ex:
            log.error("Error in creating subnet. Reason is {}".format(ex))
            return 400, ex
        
    def deleteSubnet(self,conn,subnetId):
        """
            :param: object conn: Connection type.
            :param: str subnet id: Desired subnetId.
        """
        self.conn = conn
        try:
            data = self.conn.network.delete_subnet(subnet_id=subnetId)
            return 201,data
        except Exception as ex:
            log.error("Error in deleting subnet. Reason is {}".format(ex))
            return 400, ex
            
        
    def createPort(self,conn,networkId,portName,macAddress=None):
        """
            :param: object conn: Connection type.
            :param: str networkId: Desired network id.
            :param: str portName: Desired portName.
            :param: str macAddress: Desired macAddress.
        """
        self.conn = conn
        data = {
        "network_id": networkId,
        "name": portName,
        "admin_state_up": "true", 
        }
        try:
            data = self.conn.network.create_port(**data)
            return 201, data
        except Exception as ex:
            log.error("Error in creating Port. Reason is {}".format(ex))
            return 400, ex
        
    def createFixedIpPort(self, conn, networkId, subnetId, portName, macAddress,ipAddress):
        """
            :param: object conn: Connection type.
            :param: str networkId: Desired network id.
            :param: str portName: Desired portName.
            :param: str macAddress: Desired macAddress.
        """
        self.conn = conn
        data = {
        "network_id": networkId,
        "name": portName,
        "admin_state_up": "true", 
        "mac_address" : macAddress,
        "fixed_ips": [
            {
                "ip_address": ipAddress,
                "subnet_id": subnetId
            }
        ]
        }
        try:
            data = self.conn.network.create_port(**data)
            print(traceback.print_exc(file=sys.stdout))
            return 201, data
        except Exception as ex:
            log.error("Error in creating Port. Reason is {}".format(ex))
            print(traceback.print_exc(file=sys.stdout))
            return 400, ex
            
        
    def deletePort(self,conn,portId):
        """
            :param: object conn: Connection type.
            :param: str portId: Desired port id.
        """
        self.conn = conn
        try:
            data = self.conn.network.delete_port(port=portId)
            return 201,data
        except Exception as ex:
            log.error("Error in deleting port. Reason is {}".format(ex))
            return 400, ex
                
    def findPort(self,conn,portName):
        self.conn = conn
        try:
            data = self.conn.network.find_port(name_or_id=portName)
            return 201,data
        except Exception as ex:
            log.error("Error in finding port. Reason is {}".format(ex))
            return 400, ex  
        
    def findPortBySubnetId(self, conn, networkId,subnetId):
        """
            :param: object conn: Connection type.
            :param: str networkId: Desired network id.
            :param: str subnetId: Desired network id of same network
        """
        self.conn = conn
        
        data_dict ={'network_id': networkId,
                    'subnet_id':subnetId}
        try:
            data = self.conn.network.ports(**data_dict)  
            return 201,data 
        except Exception as ex:
            log.error("Error in finding port by subnet id. Reason is {}".format(ex))
            return 400, ex 
                          
    def openPort(self,conn,secName):
        """
            :param: object conn: Connection type.
            :param: str secName: Desired sec name.
        """
        self.conn = conn
        self.secName = secName
        try:
            example_sec_group = self.conn.network.create_security_group(name=secName)
        except Exception as ex:
                log.error("Error in opening port. Reason is {}".format(ex))
                return 400, ex

        else:
            try:
                example_rule = self.conn.network.create_security_group_rule(
                    security_group_id=example_sec_group.id,
                    direction='ingress',
                    remote_ip_prefix='0.0.0.0/0',
                    protocol='HTTPS',
                    port_range_max='443',
                    port_range_min='443',
                    ethertype='IPv4')
                return 201,"Success"
            except Exception as ex:
                log.error("Error in defining rule. Reason is {}".format(ex))
                return 400,ex

    def allowPing(self,conn,secName):
        """
            :param: object conn: Connection type.
            :param: str secName: Desired security name.
        """
        self.conn = conn
        try:
            example_sec_group = self.conn.network.create_security_group(
                name=secName)
        except Exception as ex:
                log.error("Error in creating security group. Reason is {}".format(ex))
                return 400,ex
        else:
            try:
                
                example_rule = conn.network.create_security_group_rule(
                    security_group_id=example_sec_group.id,
                    direction='ingress',
                    remote_ip_prefix='0.0.0.0/0',
                    protocol='icmp',
                    port_range_max=None,
                    port_range_min=None,
                    ethertype='IPv4')
                return 201,"Success"
            except Exception as ex:
                log.error("Error in defining rule. Reason is {}".format(ex))
                return 400,ex
            
    def createVolume(self,conn, volumeName, size):
        """
            :param: object conn: Connection type.
            :param: str volumeName: Desired volume name.
            :param: int size : Desired size in GB.
        """
        self.conn = conn
        try:
            volume = self.conn.block_store.create_volume(name=volumeName,size=int(size))
        except openstack.exceptions.SDKException as ex:
            log.error("Not able to create volume.Reason is {}".format(ex))
            return 400, ex
        else:
            data = self.conn.block_store.wait_for_status(volume,status='available',failures=['error'],interval=2,wait=120)       
            return 201,data     
    
    def listUsers(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.users()
            return 201,data    
        except Exception as ex:
            log.error("Error in listing user. Reason is {}".format(ex))
            return 400,ex
        
    def listCredentials(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.credentials()
            return 201,data
        except Exception as ex:
            log.error("Error in listing credentials. Reason is {}".format(ex))
            return 400,ex       

    def listProjects(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.projects()
            return 201,data
        except Exception as ex:
            log.error("Error in listing projects. Reason is {}".format(ex))
            return 400, ex 

    def listDomains(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.domains()
            return 201,data
        except Exception as ex:
            log.error("Error in listing domains. Reason is {}".format(ex))
            return 400,ex

    def listGroups(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.groups()
            return 201,data
        except Exception as ex:
            log.error("Error in listing groups. Reason is {}".format(ex))
            return 400,ex

    def listServices(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.services()
            return 201,data
        except Exception as ex:
            log.error("Error in listing services. Reason is {}".format(ex))
            return 400,ex

    def listEndpoints(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn = conn
        try:
            data = self.conn.identity.endpoints() 
            return 201,data
        except Exception as ex:
            log.error("Error in listing endpoints. Reason is {}".format(ex))
            return 400, ex

    def listRegions(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.regions()
            return 201,data
        except openstack.exceptions.SDKException as ex:
            log.error("Error in listing regions. Reason is {}".format(ex))
            return 400, ex

    def listRoles(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.roles()
            return 201,data
        except Exception as ex:
            log.error("Error in listing roles. Reason is {}".format(ex))
            return 400,ex

    def listRoleDomainGroupAssignments(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.role_domain_group_assignments()
            return 201,data
        except Exception as ex:
            log.error("Error in listing listRoleDomainGroupAssignments. Reason is {}".format(ex))
            return 400,ex

    def listRoleDomainUserAssignments(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn= conn
        try:
            data = self.conn.identity.role_project_user_assignments()
            return 201,data
        except Exception as ex:
            log.error("Error in listing listRoleDomainUserAssignments. Reason is {}".format(ex))
            return 400,ex
    
    def listRoleProjectGroupAssignments(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn = conn
        try:
            data = self.conn.identity.role_project_group_assignments()
            return 201,data
        except Exception as ex:
            log.error("Error in listing listRoleProjectGroupAssignments. Reason is {}".format(ex))
            return 400,ex

    def listRoleProjectUserAssignments(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn = conn
        try:
            data = self.conn.identity.role_project_user_assignments()
            return 201,data
        except Exception as ex:
            log.error("Error in listing listRoleProjectUserAssignments. Reason is {}".format(ex))
            return 400,ex
        
    def listNetworks(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn=conn
        try:
            data = self.conn.network.networks()
            return 201,data
        except Exception as ex:
            log.error("Error in listing Networks. Reason is {}".format(ex))
            return 400,ex

    def listSubnets(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn=conn
        try:
            data = conn.network.subnets()
            return 201,data
        except Exception as ex:
            log.error("Error in listing subnets. Reason is {}".format(ex))
            return 400, ex

    def listPorts(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn=conn
        try:
            data = self.conn.network.ports()
            return 201,data
        except Exception as ex:
            log.error("Error in listing ports. Reason is {}".format(ex))
            return 400,ex

    def listSecurityGroups(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn=conn
        try:
            data = self.conn.network.security_groups()
            return 201,data
        except Exception as ex:
            log.error("Error in listing SecurityGroups. Reason is {}".format(ex))
            return 400,ex
        
    def listRouters(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn=conn
        try:
            data = conn.network.routers()
            return 201,data
        except Exception as ex:
            log.error("Error in listing Routers. Reason is {}".format(ex))
            return 400,ex


    def listNetworkAgents(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn = conn
        try:
            data = self.conn.network.agents()
            return 201,data
        except Exception as ex:
            log.error("Error in listing Network agents. Reason is {}".format(ex))
            return 400,ex
        
    def listServer(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn = conn
        try:
            data = self.conn.compute.servers()
            return 201,data 
        except Exception as ex:
                log.error("Error in listing servers {}".format(ex))
                return 400, ex
                        
    def listFlavors(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn = conn
        try:
            data = self.conn.compute.flavors()
            return 201, data 
        except Exception as ex:
            log.error("Error in listing flavor. Reason is {}".format(ex))
            return 400,ex      
    
    def listImages(self,conn):
        """
            :param: object conn: Connection type.
        """
        self.conn = conn
        try: 
            data = self.conn.compute.images()
            return 201,data
        except Exception as ex:
            log.error("Error in listing images. Reason is {}".format(ex))
            return 400, ex    
