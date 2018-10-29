import requests
import socket
import subprocess
import time
import unittest

from multiprocessing import Process
from . import _main


class Consul:
    def __init__(self):
        self._consul = subprocess.Popen(
            ['consul', 'agent', '-dev'],
            stdout=subprocess.DEVNULL
        )
        time.sleep(.2)  # Arbitrary waiting time to let Consul start

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        self.terminate()

    def terminate(self):
        self._consul.terminate()
        self._consul.wait()

class Python:
    def __init__(self, *args, **kwargs):
        self._process = Process(*args, **kwargs)
        self._process.start()

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        self._process.terminate()
        self._process.join()


class Subprocess:
    def __init__(self, *args, **kwargs):
        self._process = subprocess.Popen(*args, **kwargs)

    def __enter__(self):
        pass

    def __exit__(self, type, value, traceback):
        self._process.terminate()
        self._process.wait()


class TestProxy(unittest.TestCase):
    def setUp(self):
        self._consul = Consul()

    def tearDown(self):
        self._consul.terminate()

    def testConsulIsAlive(self):
        response = requests.get('http://localhost:8500')
        response.raise_for_status()

    def testConsulConnectProxy(self):
        with Python(target=_main):
            with Subprocess([
                'consul', 'connect', 'proxy',
                        '-service', 'test',
                        '-upstream', 'socat:8000'],
                stdout=subprocess.DEVNULL):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    time.sleep(1)  # Wait for the proxy to start
                    s.connect(('localhost', 8000))
                    s.sendall(b'test\n')
                    data = s.recv(1024)
        self.assertEqual(data, b'test\n')


if __name__ == '__main__':
    unittest.main()
