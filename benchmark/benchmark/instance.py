# Copyright(C) Facebook, Inc. and its affiliates.
from collections import defaultdict, OrderedDict
from time import sleep
import os
from benchmark.utils import Print, BenchError, progress_bar
from benchmark.settings import Settings, SettingsError
from googleapiclient.discovery import build
from google.cloud import compute_v1
from google.auth import compute_engine
from google.oauth2 import service_account

#path to your GCP service account key json file
GCP_KEY_PATH = '../benchmark/benchmark/key.json'
SSH_PUB_KEY_PATH = '/home/webclues/.ssh/id_rsa.pub'

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = GCP_KEY_PATH
compute_service = build('compute', 'v1')

# Set up authentication using a service account
credentials = service_account.Credentials.from_service_account_file(GCP_KEY_PATH)

class GCPError(Exception):
    def __init__(self, error):
        self.message = str(error)
        super().__init__(self.message)

class InstanceManager:
    
     #setup instance name and GCP project ID
    INSTANCE_NAME = 'bullshark'
    PROJECT_ID = 'supra-testnet-417213'

    
    def __init__(self,settings):
        self.compute_client = compute_v1.InstancesClient(credentials=credentials)
        assert isinstance(settings, Settings)
        self.clients = {}
        self.settings = settings
        for zone in self.settings.zones:
            self.clients[zone] = compute_v1.InstancesClient(credentials=credentials)



    @classmethod
    def make(cls, settings_file='settings.json'):
        try:
            return cls(Settings.load(settings_file))
        except SettingsError as e:
            raise BenchError('Failed to load settings', e)
        
    def _get(self):
        ids, ips = defaultdict(list), defaultdict(list)
        for zone, client in self.clients.items():
            # Fetching instances based on state in GCP
            res = client.list(project=self.PROJECT_ID, zone=zone)

            for instance in res:
                ids[zone] += [instance.id]

                for interface in instance.network_interfaces:
                        # Get the external IP address (if available)
                        external_ip = None
                        for access_config in interface.access_configs:
                            external_ip = access_config.nat_i_p
                            ips[zone] += [external_ip]
        # print(f'ids : {ids},ips : {ips}')
        return ids, ips

    def _wait(self):
        sleep(10)
        ids, _ = self._get()

    def create_firewall_rule(self):
        # Create a firewall rule to allow SSH access
        ports = [x for x in range(5000, 5025)]
        ports = [22] + ports
        firewall_rule = {
            "name": "allow-ports",
            "direction": "INGRESS",
            "priority": 1000,
            "allowed": [{"IPProtocol": "tcp", "ports": ports}],
            "sourceRanges": ["0.0.0.0/0"],
        }
        firewalls = compute_service.firewalls()
        try:
            result = firewalls.insert(project=self.PROJECT_ID, body=firewall_rule).execute()
            print(result) # Wait for the request to complete
        except Exception as e:
            raise GCPError(e)

    def create_instances(self, instances):
        # Create instances in multiple zones
        compute_service = build('compute', 'v1')
        ZONES = self.settings.zones
        machine_type = self.settings.instance_type
        ssh_key = get_ssh_key(SSH_PUB_KEY_PATH)
        try : 
            for zone in ZONES:
                for i in range(instances):
                    config = {
                        "name": f"{self.INSTANCE_NAME}-{zone}-{i}",
                        "machineType": 'zones/{}/machineTypes/{}'.format(zone,machine_type),
                        "tags": {"items": ["allow-ssh","allow-all-outbound", "allow-all-inbound","allow-ports"]},  # Tag for firewall rule
                        "disks": [
                            {
                                "boot": True,
                                "autoDelete": True,
                                "initializeParams": {
                                    "sourceImage": "projects/ubuntu-os-cloud/global/images/family/ubuntu-2004-lts"
                                }
                            }
                        ],
                        "networkInterfaces": [
                            {"accessConfigs": [{"type": "ONE_TO_ONE_NAT"}]}
                        ],
                        'metadata': {
                            'items': [{
                                'key': 'ssh-keys',
                                'value': ssh_key
                            }]
                        }
                    }

                    try:
                        request = compute_service.instances().insert(project=self.PROJECT_ID, zone=zone, body=config)
                        response = request.execute()
                        print('VM instance created:', response['selfLink'])
                    except Exception as e:
                        raise GCPError(e)
                    
            Print.info('Waiting for all instances to boot...')
            self._wait()
            Print.heading(f'Successfully created {instances * len(self.settings.zones)} new instances')
            print(f"Successfully created {instances * len(self.settings.zones)} instances in {len(self.settings.zones)} zones.")
        except Exception as e:
            raise BenchError('Failed to create GCP instances {}', e)            
        
        
    def delete_instances(self):
        try:
            Print.info('Waiting for all instances to shut down...')
            for zone, client in self.clients.items():
                request = client.list(
                    project=self.PROJECT_ID, zone=zone
                )    
                for instance in request:
                    client.delete(
                        project=self.PROJECT_ID, zone=zone, instance=instance.name
                    )
            Print.heading(f'Testbed instances destroyed')
        except Exception as e:
            raise GCPError(e)

    def start_instances(self):
        try:
            for zone in self.settings.zones:
                request = self.compute_client.list(
                    project=self.PROJECT_ID, zone=zone
                )
                for instance in request:
                    self.compute_client.start(
                        project=self.PROJECT_ID, zone=zone, instance=instance.name
                    )
            print("Instances started successfully.")
        except Exception as e:
            raise GCPError(e)

    def stop_instances(self):
        try:
            for zone in self.settings.zones:
                request = self.compute_client.list(
                    project=self.PROJECT_ID, zone=zone
                )
                for instance in request:
                    self.compute_client.stop(
                        project=self.PROJECT_ID, zone=zone, instance=instance.name
                    )
            print("Instances stopped successfully.")
        except Exception as e:
            raise GCPError(e)

    def hosts(self, flat=False):
        try:
            _, ips = self._get()
            return [x for y in ips.values() for x in y] if flat else ips
        except Exception as e:
            raise BenchError('Failed to gather instances IPs', GCPError(e))



    def print_info(self):
        hosts = self.hosts()
        key = self.settings.key_path
        text = ""
        for region, ips in hosts.items():
            text += f"\n Region: {region.upper()}\n"
            for i, ip in enumerate(ips):
                new_line = "\n" if (i + 1) % 6 == 0 else ""
                text += f"{new_line} {i}\tssh -i {key} ubuntu@{ip}\n"
        print(
            "\n"
            "----------------------------------------------------------------\n"
            " INFO:\n"
            "----------------------------------------------------------------\n"
            f" Available machines: {sum(len(x) for x in hosts.values())}\n"
            f"{text}"
            "----------------------------------------------------------------\n"
        )


#for reading ssh pub key and formating with username
def get_ssh_key(filename):
    with open(filename, 'r') as file:
        ssh_key = file.read().strip()

    # Split the SSH key into username and key
    ssh_key_parts = ssh_key.split()
    key = ssh_key_parts[1]
    # Modify the username
    ssh_key = f"ubuntu:ssh-rsa {key} ubuntu"

    return ssh_key