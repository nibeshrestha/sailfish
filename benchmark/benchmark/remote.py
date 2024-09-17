# Copyright(C) Facebook, Inc. and its affiliates.
from collections import OrderedDict
from fabric import Connection, ThreadingGroup as Group
from fabric.exceptions import GroupException
from paramiko import RSAKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException
from os.path import basename, splitext
from time import sleep
from math import ceil
from copy import deepcopy
import subprocess
from subprocess import SubprocessError
from os import chmod
import traceback
from benchmark.config import Committee, EdKey,BlsKey, NodeParameters, BenchParameters, ConfigError
from benchmark.utils import BenchError, Print, PathMaker, progress_bar
from benchmark.commands import CommandMaker
from benchmark.logs import LogParser, ParseError
from benchmark.instance import InstanceManager
import asyncio, asyncssh
import json
STATUS_FAILURE=25
STATUS_SUCCESS=0


class ExecutionError(Exception):
    pass


class Bench:
    def __init__(self, ctx):
        self.manager = InstanceManager.make()
        self.settings = self.manager.settings
        self.hosts_to_connections = {}
        try:
            self.connect_options = {
                'client_keys': [self.manager.settings.key_path],
                'connect_timeout': 30,
                'keepalive_interval': 10,
                'keepalive_count_max': 60,
                'known_hosts': None,
                'login_timeout': 30,
                'username': 'ubuntu'
            }

            self.keep_alive = 5
        except (IOError, PasswordRequiredException, SSHException) as e:
            raise BenchError('Failed to load SSH key', e)
        
    def _check_stderr(self, output):
        if isinstance(output, dict):
            for x in output.values():
                if x.stderr:
                    raise ExecutionError(x.stderr)
        else:
            if output.stderr:
                raise ExecutionError(output.stderr)

    def _parse_task_results(self, func, hosts_and_results, verbose):
        for host, result in hosts_and_results:
            if isinstance(result, Exception):
                print(f'{func} failed on {host}: {result}')
                raise result
            elif verbose and result.exit_status and result.exit_status != 0:
                print(f'{func} exited with status {result.exit_status} on {host}')
                print(result.stderr, end='')

    async def _gather_and_parse(self, tasks, func):
        hosts_and_results = await asyncio.gather(*tasks, return_exceptions=True)
        self._parse_task_results(func, hosts_and_results, False)
        return hosts_and_results

    def install(self):
        asyncio.get_event_loop().run_until_complete(self._install())

    async def _run_client(self, host, cmd: str) -> asyncssh.SSHCompletedProcess:
        async with asyncssh.connect(host) as conn:
            return await conn.run(cmd)
        
    async def _try_connect(self, host):
        failures = 0
        retries = 5

        while failures < retries:
            try:
                return host, await asyncssh.connect(host, **self.connect_options)
            except Exception as e:
                if isinstance(e, Exception):
                    failures += 1
                else:
                    return host, e
        return host, Exception("Failed to connect to host")
    
    async def _try_connect_all(self, hosts):
        tasks = [self._try_connect(host) for host in hosts]
        return await self._gather_and_parse(tasks, 'Connect')

    async def _install_one(self, host, connection, cmd) -> None:
        try:
            async with connection.start_sftp_client() as sftp:
                # Copy the Deploy Key to /home/ubuntu
                await sftp.put(self.settings.key_path, preserve=True)
                # Copy the installation and update scripts to the same location
                await sftp.put(PathMaker.bootstrap_script_path(), preserve=True)
                await sftp.put(PathMaker.update_script_path(), preserve=True)
            result = await connection.create_process(cmd)
            # Start the installation script as a background process
            return host, result
        except Exception as e:
            return host, Exception(f'Failed to install on {host} because of {e}')
        
    async def _install(self):
        Print.info('Installing rust and cloning the repo...')
        deploy_key = self.settings.key_name
        bootstrap = [
            'cd /home/ubuntu',
            # Run the bootstrap script in the background.
            f'./bootstrap_node.sh {deploy_key} {self.settings.repo_url} {self.settings.repo_name} 2>./install.err 1>./install.out &'
        ]
        install_cmd = ' && '.join(bootstrap)

        # Set the correct permissions for the deploy key. Git will clone
        # it to the local machine with incorrect settings.
        chmod(self.settings.key_path, 0o600)
        # Ensure install and update scripts are executable.
        chmod(PathMaker.bootstrap_script_path(), 0o700)
        chmod(PathMaker.update_script_path(), 0o700)

        try:
            hosts = self.manager.hosts(flat=True)
            hosts_and_connections = await self._try_connect_all(hosts)
            tasks = [self._install_one(h, c, install_cmd) for h, c in hosts_and_connections]
            await self._gather_and_parse(tasks, 'Install')
            Print.info(f'Waiting for installations to complete...')
            await self._poll(hosts_and_connections, 'install')
            Print.heading(f'Initialized testbed of {len(hosts)} nodes')
        except Exception as e:
            traceback.print_exc()
            raise Exception('Failed to install repo on testbed:', e)

    async def _poll_one(self, host, connection, func):
        try:
            poll = f'grep "{func} complete" /home/ubuntu/{func}.out || ((grep "returned exit code" /home/ubuntu/{func}.err | grep -v "exit code 0") && exit {STATUS_FAILURE})'
            result = await connection.run(poll)
            return host, result
        except Exception as e:
            return host, Exception(f'Failed to poll {host} because of {e}')
        
    async def _poll(self, connections, func):
        poll_interval = 30 # seconds
        retry = True

        # Poll the given connections until either all nodes have successfully completed the 
        # related process, or one of them failed with an error code.
        while retry:
            tasks = [self._poll_one(host, connection, func) for host, connection in connections]
            hosts_and_results = await self._gather_and_parse(tasks, 'Poll')
            
            successes = [ ip for ip, result in hosts_and_results if result.exit_status == STATUS_SUCCESS ]
            if len(successes) == len(connections):
                break

            failures = [ ip for ip, result in hosts_and_results if result.exit_status == STATUS_FAILURE ]
            if len(failures) > 0:
                raise Exception(f'{func} failed on: {failures}')

            # Wait before polling again.
            sleep(poll_interval)
            print('Polling...')
    
    async def _kill_one(self, host, connection, cmd):
        try:
            # Execute the command on the remote host using the SSH connection
            result = await connection.run(cmd)
            # Return the host and the result of the command execution
            return host, result
        except asyncssh.ChannelOpenError:
            # If the SSH connection is closed, attempt to reconnect
            try:
                print(f"SSH connection to {host} closed. Attempting to reconnect...")
                # Reconnect to the SSH server
                connection = await asyncssh.connect(host, **self.connect_options)
                self.hosts_to_connections[host] = connection
                # Retry executing the command on the reestablished connection
                result = await connection.run(cmd)
                return host, result
            except Exception as e:
                # If reconnection fails, return the host and the exception
                return host, Exception(f'Failed to reconnect to {host} because of {e}')
        except Exception as e:
            # If an exception other than ChannelOpenError occurs during command execution, catch it
            # and return a tuple containing the host and the exception
            return host, Exception(f'Failed to kill {host} because of {e}')
    
    def kill(self):
        asyncio.get_event_loop().run_until_complete(self._kill())

    async def _kill(self, hosts_to_connections={}, delete_logs=False):
        assert isinstance(hosts_to_connections, dict)
        assert isinstance(delete_logs, bool)

        if not hosts_to_connections:
            hosts = self.manager.hosts(flat=True)
            hosts_and_connections = await self._try_connect_all(hosts)
            hosts_to_connections = { h: c for h, c in hosts_and_connections }

        delete_logs = CommandMaker.clean_logs() if delete_logs else 'true'
        cmd = [delete_logs, f'({CommandMaker.kill()} || true)']
        kill_cmd = ' && '.join(cmd)

        tasks = [ self._kill_one(h, c, kill_cmd) for h, c in hosts_to_connections.items() ]
        await self._gather_and_parse(tasks, 'Kill')

    def _select_hosts(self, bench_parameters):
        # Collocate the primary and its workers on the same machine.
        if bench_parameters.collocate:
            nodes = max(bench_parameters.nodes)

            # Ensure there are enough hosts.
            hosts = self.manager.hosts()
            if sum(len(x) for x in hosts.values()) < nodes:
                return []

            # Select the hosts in different data centers.
            ordered = zip(*hosts.values())
            ordered = [x for y in ordered for x in y]
            return ordered[:nodes]

        # Spawn the primary and each worker on a different machine. Each
        # authority runs in a single data center.
        else:
            primaries = max(bench_parameters.nodes)

            # Ensure there are enough hosts.
            hosts = self.manager.hosts()
            if len(hosts.keys()) < primaries:
                return []
            for ips in hosts.values():
                if len(ips) < bench_parameters.workers + 1:
                    return []

            # Ensure the primary and its workers are in the same region.
            selected = []
            for region in list(hosts.keys())[:primaries]:
                ips = list(hosts[region])[:bench_parameters.workers + 1]
                selected.append(ips)
            return selected

    async def _run_on_host(self, host, cmd, log, connection):
        try:
            name = splitext(basename(log))[0]
            cmd = f'tmux new -d -s "{name}" "{cmd} |& tee {log}"'
            result = await connection.create_process(cmd)
            return host, result
        except asyncssh.ChannelOpenError:
            # If the SSH connection is closed, attempt to reconnect
            try:
                print(f"SSH connection to {host} closed. Attempting to reconnect...")
                # Reconnect to the SSH server
                connection = await asyncssh.connect(host, **self.connect_options)
                self.hosts_to_connections[host] = connection
                # Retry executing the command on the reestablished connection
                result = await connection.create_process(cmd)
                return host, result
            except Exception as e:
                # If reconnection fails, return the host and the exception
                return host, Exception(f'Failed to reconnect to {host} because of {e}')
        except Exception as e:
            return host, Exception(f'Failed to run {cmd} on {host} because of {e}')

    async def _update_one(self, host, connection):
        deploy_key = self.settings.key_name
        update = [
            'cd /home/ubuntu',
            # Run the bootstrap script in the background.
            f'./update_node.sh {deploy_key} {self.settings.repo_name} {self.settings.branch} 2>./update.err 1>./update.out &'
        ]
        update_cmd = ' && '.join(update)
        result = await connection.create_process(update_cmd)
        # Start the installation script as a background process
        return host, result

    async def _upload_config(self, connection, id):
        await connection.run(f'{CommandMaker.cleanup()} || true')
        async with connection.start_sftp_client() as sftp:
            # Copy the Deploy Key to /home/ubuntu
            await sftp.put(PathMaker.committee_file(), '.', preserve=True)
            await sftp.put(PathMaker.clan_file(), '.', preserve=True)
            # Copy the installation and update scripts to the same location
            await sftp.put(PathMaker.bls_key_file(id), '.', preserve=True)
            await sftp.put(PathMaker.ed_key_file(id), '.', preserve=True)
            await sftp.put(PathMaker.parameters_file(), '.', preserve=True)

    def _generate_config(self, hosts, node_parameters, bench_parameters):
        Print.info('Generating configuration files...')

        nodes = len(hosts)
        clan_info =  bench_parameters.clan_info
        total_clan = len(clan_info)

        # Cleanup all local configuration files.
        cmd = CommandMaker.cleanup()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)

        # Recompile the latest code.
        cmd = CommandMaker.compile().split()
        subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

        # Create alias for the client and nodes binary.
        cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
        subprocess.run([cmd], shell=True)

        node_id=0
        for i in range(0,len(clan_info)):
            clan_size = clan_info[i][0]
            threshold = clan_info[i][2]
            cmd = CommandMaker.generate_bls_keys(clan_size,threshold,PathMaker.bls_file_default_path(),node_id).split()
            subprocess.run(cmd, check=True)
            node_id+=clan_size

        # Generate configuration files.
        keys = []
        key_files = [PathMaker.ed_key_file(i) for i in range(len(hosts))]
        for filename in key_files:
            cmd = CommandMaker.generate_ed_key(filename).split()
            subprocess.run(cmd, check=True)
            keys += [EdKey.from_file(filename)]

        bls_keys = []
        key_files = [PathMaker.bls_key_file(i) for i in range(len(hosts))]
        for filename in key_files:
            bls_keys += [BlsKey.from_file(filename)]

            
        names = [x.name for x in keys]
        bls_pubkeys_g2 = [_.nameg2 for _ in bls_keys]

        if bench_parameters.collocate:
            workers = bench_parameters.workers
            addresses = OrderedDict(
                (x, [y] * (workers + 1)) for x, y in zip(names, hosts)
            )
        else:
            addresses = OrderedDict(
                (x, y) for x, y in zip(names, hosts)
            )
        committee = Committee.from_address_list(addresses, self.settings.base_port, bench_parameters.faults, bls_pubkeys_g2, bench_parameters.clan_info)
        committee.print(PathMaker.committee_file())

        with open('.committee.json', 'r') as file:
            committee_member = json.load(file)
        clan_members = {key: value for key, value in committee_member['authorities'].items() if value['is_clan_member']}
        # Create a new JSON object with the filtered data
        clan = {'members': clan_members}
        with open(PathMaker.clan_file(), 'w') as file:
            json.dump(clan, file, indent=4)

        node_parameters.print(PathMaker.parameters_file())
        return (committee, names)

    async def _run_clients(self, rate, burst, committee, bench_parameters, connections):
        Print.info('Booting clients...')
        workers_addresses = committee.workers_addresses(bench_parameters.faults)
        rate_share = ceil(rate / len(workers_addresses))
        tasks = []
        
        for i, addresses in enumerate(workers_addresses):
            for (id, address) in addresses:
                host = Committee.ip(address)
                cmd = CommandMaker.run_client(
                    address,
                    bench_parameters.tx_size,
                    burst,
                    rate_share,
                    [x for y in workers_addresses for _, x in y]
                )
                log_file = PathMaker.client_log_file(i, int(id))
                connection = connections[host]
                tasks.append(self._run_on_host(host, cmd, log_file, connection))
        
        await self._gather_and_parse(tasks, 'Boot Clients')
        return workers_addresses

    async def _run_primaries(self, committee, connections, faults, debug=False):
        Print.info('Booting primaries...')
        tasks = []

        for i, address in enumerate(committee.primary_addresses(faults)):
            host = Committee.ip(address)
            cmd = CommandMaker.run_primary(
                PathMaker.ed_key_file(i),
                PathMaker.bls_key_file(i),
                PathMaker.committee_file(),
                PathMaker.db_path(i),
                PathMaker.parameters_file(),
                debug=debug
            )
            log_file = PathMaker.primary_log_file(i)
            connection = connections[host]
            tasks.append(self._run_on_host(host, cmd, log_file, connection))
        
        await self._gather_and_parse(tasks, 'Boot Primaries')

    async def _run_workers(self, workers_addresses, connections, debug=False):
        Print.info('Booting workers...')
        tasks = []

        for i, addresses in enumerate(workers_addresses):
            for (id, address) in addresses:
                host = Committee.ip(address)
                cmd = CommandMaker.run_worker(
                    PathMaker.ed_key_file(i),
                    PathMaker.bls_key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.db_path(i, id),
                    PathMaker.parameters_file(),
                    id,  # The worker's id.
                    debug=debug
                )
                log_file = PathMaker.worker_log_file(i, id)
                connection = connections[host]
                tasks.append(self._run_on_host(host, cmd, log_file, connection))
        
        await self._gather_and_parse(tasks, 'Boot Workers')

    async def _run_single(
        self, 
        rate, 
        burst,
        committee, 
        bench_parameters, 
        hosts_to_connections, 
        debug=False, 
        consensus_only=False
    ):
        # Kill any potentially unfinished run and delete logs.
        # hosts = committee.ips()
        await self._kill(hosts_to_connections=hosts_to_connections, delete_logs=True)

        # Run the primaries (except the faulty ones).
        primaries = self._run_primaries(committee, hosts_to_connections, bench_parameters.faults, debug)
        await primaries
        
        if not consensus_only:
            # Run the clients (they will wait for the nodes to be ready).
            # Filter all faulty nodes from the client addresses (or they will wait
            # for the faulty nodes to be online).
            workers_addresses = await self._run_clients(
                rate, burst, committee, bench_parameters, hosts_to_connections)
            # Run the workers (except the faulty ones).
            # await self._run_workers(workers_addresses, hosts_to_connections, debug)

        # Wait for all transactions to be processed.
        duration = bench_parameters.duration
        for _ in progress_bar(range(20), prefix=f'Running benchmark ({duration} sec):'):
            sleep(ceil(duration / 20))
        await self._kill(hosts_to_connections=hosts_to_connections)

    def download_logs(self, consensus_only, committee=None):
        asyncio.get_event_loop().run_until_complete(
            self._download_logs(consensus_only, committee)
        )

    async def _download_logs(self, consensus_only, committee=None):
        if not committee:
            committee = Committee.from_file(".committee.json")

        # Delete local logs (if any).
        cmd = CommandMaker.clean_logs()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)

        try:
            faults = committee.faults()
            hosts = committee.ips()
            hosts_and_connections = await self._try_connect_all(hosts)
            hosts_to_connections = { host: connection for host, connection in hosts_and_connections }
            # Download remote logs
            await self._download_primary_logs(faults, committee, hosts_to_connections)
            
            if not consensus_only:
                await self._download_client_logs(faults, committee, hosts_to_connections)
                # await self._download_worker_logs(faults, committee, hosts_to_connections)
        except Exception as e:
            raise Exception(f'Failed to download logs: {e}')

    async def _download_log(self, host, connection, src, dest):
        try:
            async with connection.start_sftp_client() as sftp:
                result = await sftp.get(src, localpath=dest)
                return host, result
        except Exception as e:
            return host, Exception(f'Failed to download {src} from {host} because of {e}')

    # async def _download_worker_logs(self, faults, committee, hosts_to_connections):
    #     workers_addresses = committee.workers_addresses(faults)
    #     tasks = []

    #     print('Downloading workers logs...')
    #     for i, addresses in enumerate(workers_addresses):
    #         for j, address in addresses:
    #             host = Committee.ip(address)
    #             src = PathMaker.worker_log_file(i, int(j))
    #             dest = PathMaker.worker_log_file(i, int(j))
    #             connection = hosts_to_connections[host]
    #             tasks.append(self._download_log(host, connection, src, dest))
            
    #     await self._gather_and_parse(tasks, 'Download Worker Logs')

    async def _download_primary_logs(self, faults, committee, hosts_to_connections):
        primary_addresses = committee.primary_addresses(faults)
        tasks = []

        print('Downloading primaries logs...')
        for i, address in enumerate(primary_addresses):
            host = Committee.ip(address)
            src = PathMaker.primary_log_file(i)
            dest = PathMaker.primary_log_file(i)
            connection = hosts_to_connections[host]
            tasks.append(self._download_log(host, connection, src, dest))
            
        await self._gather_and_parse(tasks, 'Download Primary Logs')

    async def _download_client_logs(self, faults, committee, hosts_to_connections):
        workers_addresses = committee.workers_addresses(faults)
        tasks = []

        print('Downloading client logs...')
        for i, addresses in enumerate(workers_addresses):
            for j, address in addresses:
                host = Committee.ip(address)
                src = PathMaker.client_log_file(i, int(j))
                dest = PathMaker.client_log_file(i, int(j))
                connection = hosts_to_connections[host]
                tasks.append(self._download_log(host, connection, src, dest))
            
        await self._gather_and_parse(tasks, 'Download Client Logs')
        
    async def _configure_one(self, host, id, connection, update=True):
        try: 
            if update:
                # Update the repo on the host
                await self._update_one(host, connection)

            # Upload config files
            await self._upload_config(connection, id)
            return host, None
        except Exception as e:
            # Raise an exception here instead of failing silently
            # because we should not continue if we failed to upload
            # the config files to even one node.
            return host, Exception(f'Failed to configure {host} because of {e}')
        
    async def _run(
        self, 
        hosts, 
        bench_parameters, 
        node_parameters, 
        debug=False, 
        consensus_only=False, 
        update=True,
    ):
        hosts_and_connections = await self._try_connect_all(hosts)
        self.hosts_to_connections = { host: connection for host, connection in hosts_and_connections }

        try:
            (committee, names) = self._generate_config(hosts, node_parameters, bench_parameters)
        except SubprocessError as e:
            traceback.print_exc()
            raise BenchError('Failed to configure nodes', e)
        
        names = names[:len(names) - bench_parameters.faults]
        msg = f'Uploading configuration files'
        if update:
            msg += f' and changing repository {self.settings.repo_name} to branch {self.settings.branch}'
        Print.info(msg + f' on {len(hosts)} machines...')
        
        tasks = []
        for id, name in enumerate(names):
            ip = committee.ips(name)[0] # TODO: No longer support remote workers.
            connection = self.hosts_to_connections[ip]
            tasks.append(self._configure_one(ip, id, connection, update))

        await self._gather_and_parse(tasks, 'Configure')

        if update:
            Print.info(f'Waiting for update to complete...')
            await self._poll(hosts_and_connections, 'update')
            
        Print.info(f'Successfully configured {len(hosts)} machines')

        # Run benchmarks.
        for n in bench_parameters.nodes:
            committee_copy = deepcopy(committee)
            committee_copy.remove_nodes(committee.size() - n)

            for burst in bench_parameters.burst:
                rate = bench_parameters.rate[0]
                Print.heading(f'\nRunning {n} nodes (input rate: {rate:,} tx/s, burst : {burst:,})')

                # Run the benchmark.
                for i in range(bench_parameters.runs):
                    Print.heading(f'Run {i + 1}/{bench_parameters.runs}')
                    try:
                        await self._run_single(
                            rate, burst, committee_copy, bench_parameters, self.hosts_to_connections, debug, consensus_only
                        )

                        faults = bench_parameters.faults
                        await self._download_logs(consensus_only, committee=committee)
                        Print.info('Parsing logs and computing performance...')
                        logger = LogParser.process(PathMaker.logs_path(), burst, consensus_only=consensus_only)
                        logger.print(PathMaker.result_file(
                            faults,
                            n,
                            bench_parameters.workers,
                            bench_parameters.collocate,
                            rate,
                            bench_parameters.tx_size,
                        ))
                
                    except (subprocess.SubprocessError, ParseError) as e:
                        self._kill(hosts_to_connections=self.hosts_to_connections)
                        Print.error(BenchError('Benchmark failed', e))
                        continue        

    def run(self, bench_parameters_dict, node_parameters_dict, debug=False, consensus_only=False, update=True):
        assert isinstance(debug, bool)
        Print.heading('Starting remote benchmark')
        try:
            bench_parameters = BenchParameters(bench_parameters_dict)
            node_parameters = NodeParameters(node_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

        # Select which hosts to use.
        selected_hosts = self._select_hosts(bench_parameters)
        if not selected_hosts:
            Print.warn('There are not enough instances available')
            return
        
        # TODO: Remove functionality supporting multi-node workers?
        if bench_parameters.collocate:
            ips = list(set(selected_hosts))
        else:
            ips = list(set([x for y in selected_hosts for x in y]))

        asyncio.get_event_loop().run_until_complete(
            self._run(
                selected_hosts, 
                bench_parameters, 
                node_parameters, 
                debug, 
                consensus_only, 
                update,
            )
        )