# Copyright(C) Facebook, Inc. and its affiliates.
import subprocess
from math import ceil
from os.path import basename, splitext
from time import sleep
import json
from benchmark.commands import CommandMaker
from benchmark.config import EdKey,BlsKey, LocalCommittee, NodeParameters, BenchParameters, ConfigError
from benchmark.logs import LogParser, ParseError
from benchmark.utils import Print, BenchError, PathMaker


class LocalBench:
    BASE_PORT = 3000

    def __init__(self, bench_parameters_dict, node_parameters_dict):
        try:
            self.bench_parameters = BenchParameters(bench_parameters_dict)
            self.node_parameters = NodeParameters(node_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)

    def __getattr__(self, attr):
        return getattr(self.bench_parameters, attr)

    def _background_run(self, command, log_file):
        name = splitext(basename(log_file))[0]
        cmd = f'{command} 2> {log_file}'
        subprocess.run(['tmux', 'new', '-d', '-s', name, cmd], check=True)

    def _kill_nodes(self):
        try:
            cmd = CommandMaker.kill().split()
            subprocess.run(cmd, stderr=subprocess.DEVNULL)
        except subprocess.SubprocessError as e:
            raise BenchError('Failed to kill testbed', e)

    def run(self, debug=False, consensus_only=False):
        assert isinstance(debug, bool)
        assert isinstance(consensus_only, bool)
        Print.heading('Starting local benchmark')

        # Kill any previous testbed.
        self._kill_nodes()

        try:
            Print.info('Setting up testbed...')
            nodes, rate = self.nodes[0], self.rate[0]
            clan_info =  self.bench_parameters.clan_info
            total_clan = len(clan_info)

            # Cleanup all files.
            cmd = f'{CommandMaker.clean_logs()} ; {CommandMaker.cleanup()}'
            subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)
            sleep(0.5)  # Removing the store may take time.

            # Recompile the latest code.
            cmd = CommandMaker.compile().split()
            subprocess.run(cmd, check=True, cwd=PathMaker.node_crate_path())

            # Create alias for the client and nodes binary.
            cmd = CommandMaker.alias_binaries(PathMaker.binary_path())
            subprocess.run([cmd], shell=True)

            node_id=0
            for i in range(0,len(clan_info)):
                clan_size = clan_info[i][0]
                threshold = clan_info[i][1]
                cmd = CommandMaker.generate_bls_keys(clan_size,threshold,PathMaker.bls_file_default_path(),node_id).split()
                subprocess.run(cmd, check=True)
                node_id+=clan_size

            # Generate configuration files.
            keys = []
            key_files = [PathMaker.ed_key_file(i) for i in range(nodes)]
            for filename in key_files:
                cmd = CommandMaker.generate_ed_key(filename).split()
                subprocess.run(cmd, check=True)
                keys += [EdKey.from_file(filename)]

            bls_keys = []
            key_files = [PathMaker.bls_key_file(i) for i in range(nodes)]
            for filename in key_files:
                bls_keys += [BlsKey.from_file(filename)]

            names = [x.name for x in keys]
            bls_pubkeys_g2 = [_.nameg2 for _ in bls_keys]
            committee = LocalCommittee(names, self.BASE_PORT, self.workers, self.bench_parameters.faults, bls_pubkeys_g2, clan_info)
            committee.print(PathMaker.committee_file())

            self.node_parameters.print(PathMaker.parameters_file())


            if not consensus_only:
                # Run the clients (they will wait for the nodes to be ready).
                workers_addresses = committee.workers_addresses(self.faults)
                rate_share = ceil(rate / committee.workers())
                for i, addresses in enumerate(workers_addresses):
                    for (id, address) in addresses:
                        cmd = CommandMaker.run_client(
                            address,
                            self.tx_size,
                            self.burst,
                            rate_share,
                            [x for y in workers_addresses for _, x in y]
                        )
                        log_file = PathMaker.client_log_file(i, id)
                        self._background_run(cmd, log_file)

            # Run the primaries (except the faulty ones).
            for i, address in enumerate(committee.primary_addresses(self.faults)):
                cmd = CommandMaker.run_primary(
                    PathMaker.ed_key_file(i),
                    PathMaker.bls_key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.db_path(i),
                    PathMaker.parameters_file(),
                    debug=debug
                )
                log_file = PathMaker.primary_log_file(i)
                self._background_run(cmd, log_file)

            # # Run the workers (except the faulty ones).
            # for i, addresses in enumerate(workers_addresses):
            #     for (id, address) in addresses:
            #         cmd = CommandMaker.run_worker(
            #             PathMaker.ed_key_file(i),
            #             PathMaker.bls_key_file(i),
            #             PathMaker.committee_file(),
            #             PathMaker.db_path(i, id),
            #             PathMaker.parameters_file(),
            #             id,  # The worker's id.
            #             debug=debug
            #         )
            #         log_file = PathMaker.worker_log_file(i, id)
            #         self._background_run(cmd, log_file)

            # Wait for all transactions to be processed.
            Print.info(f'Running benchmark ({self.duration} sec)...')
            sleep(self.duration)
            self._kill_nodes()

            # Parse logs and return the parser.
            Print.info('Parsing logs...')
            return LogParser.process(PathMaker.logs_path(), self.bench_parameters.burst, faults=self.faults, consensus_only=consensus_only)

        except (subprocess.SubprocessError, ParseError) as e:
            self._kill_nodes()
            raise BenchError('Failed to run benchmark', e)
