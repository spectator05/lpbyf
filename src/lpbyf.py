import os
import platform
import time
import tempfile
import subprocess
import datetime
import csv

import multiprocessing as mp

from itertools import repeat
from scapy.all import PcapReader


class Lpbyf:
    """
    you must match your timeline and flow csv timeline.
    a difference of pcap's timeline and flow csv's timeline will be problem.
    """

    def __init__(self):
        # Standard of NetFlowMeter
        self.header_dict = {
            "timestart": "ts",
            "timeend": "te",
            "label": "Label",
            "source address": "sa",
            "destination address": "da",
            "source port": "sp",
            "destination port": "dp",
            "protocol": "pr",
        }
        self.label_dict = None

    def set_label_dict(self, csv_path: str, header_dict: dict = None):
        """
        flow csv must sorted by timestart
        python version > 3.5
        ts, te format must timestamp(match with pcap timestamp)
        header_dict's key is each column, value is your flow csv column name
        """
        header_label = [
            "timestart",
            "timeend",
            "label",
            "source address",
            "destination address",
            "source port",
            "destination port",
            "protocol",
        ]
        header_idx = []

        if header_dict:
            self.header_dict = header_dict

        self.label_dict = {}
        with open(csv_path, "r") as f:
            reader = csv.reader(f, delimiter=",")
            header = next(reader)
            print(header)

            """
            Index Values
            [0] timestart
            [1] timeend
            [2] label
            [3] source address
            [4] destination port
            [5] source address
            [6] destination port
            [7] protocol
            """

            for i in range(len(header_label)):
                header_idx.append(header.index(self.header_dict[header_label[i]]))

            for row in reader:
                key = "_".join(
                    [
                        str(row[header_idx[3]]),
                        str(row[header_idx[4]]),
                        str(row[header_idx[5]]),
                        str(row[header_idx[6]]),
                        str(row[header_idx[7]]).lower(),
                    ]
                )
                if not (key in self.label_dict):
                    self.label_dict[key] = {}
                self.label_dict[key][float(row[header_idx[0]])] = [
                    float(row[header_idx[1]]),
                    row[header_idx[2]],
                ]

    def check_timestamp(self, key: str, timestamp: float):
        timestamp = float(timestamp)
        for k, v in self.label_dict[key].items():
            if timestamp >= k and timestamp <= v[0]:
                return v[-1]
        return ""

    def get_next_label(
        self, timestamp: float, sa: str, da: str, sp: str, dp: str, prtcl: str
    ) -> str:
        prtcl = prtcl.lower()
        key1 = "_".join([sa, da, sp, dp, prtcl])
        key2 = "_".join([da, sa, dp, sp, prtcl])

        label1, label2 = "", ""

        if key1 in self.label_dict:
            label1 = self.check_timestamp(key1, timestamp)
        if key2 in self.label_dict:
            label2 = self.check_timestamp(key2, timestamp)

        if label1 == label2 and len(label1) != 0:
            return label1
        elif len(label1) != 0 and len(label2) == 0:
            return label1
        elif len(label2) != 0 and len(label1) == 0:
            return label2
        return "unknown"

    class Splitter:
        def __init__(
            self,
            pcap_list: list,
            num_core: int = 1,
            target_size: int = 1000000000,
            split_packet_count=10000000,
            output_path: str = tempfile.gettempdir(),
        ):
            self.num_core = num_core
            self.pcap_list = pcap_list
            self.target_size = target_size
            self.split_packet_count = split_packet_count
            self.output_path = output_path
            self.editcap_path = self._get_editcap_path()
            self.keep_files = False

        def _get_editcap_path(self):
            if platform.system() == "Windows":
                return "C:\Program Files\Wireshark\\editcap.exe"
            else:
                system_path = os.environ["PATH"]
                for path in system_path.split(os.pathsep):
                    filename = os.path.join(path, "editcap")
                    if os.path.isfile(filename):
                        return filename
            return ""

        def get_processed_pcap(self):
            """
            processed' means pcap(can split) + pcap(can't split)
            """
            target_pcap = []
            processed_pcap = []
            for pcap in self.pcap_list:
                if os.path.getsize(pcap) > self.target_size:
                    target_pcap.append(pcap)
                else:
                    processed_pcap.append(pcap)
            splitted_pcap = self._get_splitted_pcap(target_pcap)

            return processed_pcap + splitted_pcap

        def _split_pcap_with_editcap(self, input):
            (
                input_path,
                output_path,
                split_packet_count,
                editcap_path,
                keep_files,
            ) = input
            if not output_path:
                output_path = tempfile.gettempdir()
            input_filename = os.path.basename(input_path)
            cmd = f'"{editcap_path}" -c {split_packet_count} {input_path} {os.path.join(output_path, input_filename)}'
            subprocess.call(cmd, shell=False)
            input_filename = os.path.splitext(input_filename)[-2]
            output_files = os.listdir(output_path)

            pcap_files = []
            for output_file in output_files:
                if input_filename in os.path.basename(output_file):
                    pcap_files.append(
                        os.path.join(output_path, os.path.basename(output_file))
                    )

            if keep_files:
                os.remove(input_path)

            return pcap_files

        def _get_splitted_pcap(self, path_list: list):
            splitted_pcap_path = []
            now = str(int(time.time()))
            self.output_path = os.path.join(self.output_path, now)
            os.mkdir(self.output_path)
            if self.num_core > len(path_list):
                if len(path_list) != 0:
                    self.num_core = len(path_list)

            with mp.Pool(self.num_core) as pool:
                for pkts_list in pool.imap_unordered(
                    self._split_pcap_with_editcap,
                    zip(
                        path_list,
                        repeat(self.output_path),
                        repeat(self.split_packet_count),
                        repeat(self.editcap_path),
                        repeat(self.keep_files),
                    ),
                    chunksize=1,
                ):
                    splitted_pcap_path += sorted(pkts_list)

            return splitted_pcap_path
