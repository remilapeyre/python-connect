import logging
import os
import requests
import socket
import ssl
import tempfile
import threading
import time
import warnings

from functools import partial
from ssl import Purpose


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class ConnectWarning(RuntimeWarning):
    """Base class for all Connect related warnings"""
    pass


class _ConsulAgent:
    def __init__(self, consul_http_addr=None):
        # Using persistent HTTP connections will speed Consul queries
        self._session = requests.Session()

        if consul_http_addr is None:
            consul_http_addr = os.environ.get('CONSUL_HTTP_ADDR', 'http://127.0.0.1:8500')
        self._consul_http_addr = consul_http_addr

    def register_proxy(self, service, address, port):
        payload = {
            "Kind": "connect-proxy",
            "ID": service + "-proxy",
            "Name": service + "-proxy",
            "Address": address,
            "Port": port,
            "Proxy": {
                "DestinationServiceName": service
            },
            "Check": {
                "CheckID": service + "-proxy-ttl",
                "Name": "proxy heartbeat",
                "TTL": "30s",
                "Notes": "Native Python proxy will heartbeat this check.",
                "Status": "passing"
            }
        }
        response = self._session.put(
            self._consul_http_addr + "/v1/agent/service/register",
            json=payload
        )
        response.raise_for_status()
        logger.info("Registred {} proxy to Consul - {}µs".format(
            service,
            response.elapsed.microseconds
        ))

    def deregister(self, service):
        url = '/v1/agent/service/deregister/'.join((self._consul_http_addr, service))
        response = self._session.put(url)
        response.raise_for_status()
        logger.info('Deregistred {} - {}µs'.format(service, response.elapsed.microseconds))

    def authorize(self, service, client_cert_uri, serial_number):
        response = self._session.post(
            ''.join((self._consul_http_addr, '/v1/agent/connect/authorize')),
            json={
                "Target": service,
                "ClientCertURI": client_cert_uri,
                "ClientCertSerial": serial_number
            }
        )
        response.raise_for_status()
        authorization = response.json()
        if authorization['Authorized']:
            logger.info('Authorized connection for {}: {} - {}µs'.format(
                serial_number,
                authorization['Reason'],
                response.elapsed.microseconds
            ))
        else:
            logger.warn('Blocked connection for {}: {} - {}µs'.format(
                serial_number,
                authorization['Reason'],
                response.elapsed.microseconds
            ))
        return authorization['Authorized']

    def get_root_ca(self):
        url = ''.join((self._consul_http_addr, '/v1/agent/connect/ca/roots'))
        response = self._session.get(url)
        response.raise_for_status()
        root_ca = '\n'.join((
            ca['RootCert'] for ca in response.json()['Roots']
        ))
        logger.debug(
            "Fetched root certificates - {}µs".format(response.elapsed.microseconds)
        )
        return root_ca

    def get_certificate(self, service):
        url = ''.join((
            self._consul_http_addr,
            '/v1/agent/connect/ca/leaf/',
           service
        ))
        response = self._session.get(url)
        response.raise_for_status()
        certificate = response.json()
        logger.debug("Fetched certificate for {} ({}) - {}µs".format(
            service,
            certificate['SerialNumber'],
            response.elapsed.microseconds
        ))
        return certificate['CertPEM'], certificate['PrivateKeyPEM']

    def check_ttl(self, check_id):
        url = '/v1/agent/check/pass/'.join((self._consul_http_addr, check_id))
        response = self._session.put(url)
        response.raise_for_status()
        logger.info(
            'Pinged {} TTL - {}µs'.format(check_id, response.elapsed.microseconds)
        )


class _RefreshConnectContext(threading.Thread):
    def __init__(self, target, timeout=20, daemon=False):
        # Declaring the thread as daemon will kill it when the main program exit
        # for whatever reason.
        super().__init__(daemon=daemon)
        self._stop_flag = threading.Event()
        self.target = target
        self.timeout = timeout

    def run(self):
        while True:
            # Parent thread will set this flag when it wants us to  stop
            # refreshing the context
            if self._stop_flag.wait(timeout=self.timeout):
                logger.info("Stop refreshing thread")
                break
            self.target.refresh_context()


class SSLConnectSocket(ssl.SSLSocket):
    def accept(self):
        while True:
            # We must call .accept of the grandmother to use the appropriate
            # ssl.SSLContext
            newsock, addr = super(ssl.SSLSocket, self).accept()
            newsock = self.context._connect_context.wrap_socket(newsock,
                do_handshake_on_connect=self.do_handshake_on_connect,
                suppress_ragged_eofs=self.suppress_ragged_eofs,
                server_side=True)
            peer_cert = newsock.getpeercert()

            # We must check if the client certificate should be accepted
            # according to Consul intentions
            if not self.context.authorize(peer_cert):
                # If the connection is refused, we close the socket, loop back
                # and wait for the next connection, that way the user does not
                # have to deal with such connections
                newsock.close()
                continue
            return newsock, addr


# Connect is a proxy around an SSLContext object, it should pass every method
# call to its _connect_context attribute
class Connect(ssl.SSLContext):
    sslsocket_class = SSLConnectSocket

    def __new__(cls, service, consul_http_addr=None, register=False,
                protocol=ssl.PROTOCOL_TLS, daemon_threads=False, *args, **kwargs):
        self = ssl.SSLContext.__new__(cls, protocol)
        return self


    # It can be usefull to declare companion threads as daemon if the context
    # manager is not used to make the threads quit when the main one exit.
    # In this case, it is the user responsability to call .deregister if
    # appropriate or the service will stay in Consul.
    def __init__(self, service, consul_http_addr=None, register=False,
                protocol=ssl.PROTOCOL_TLS, daemon_threads=False, *args, **kwargs):
        self._service = service
        self._consul_agent = _ConsulAgent(consul_http_addr=consul_http_addr)
        self._daemon_threads = daemon_threads

        self._context_factory = partial(ssl.SSLContext, *args, **kwargs)
        # We need to initialize once the context before accepting connections
        self.refresh_context(raise_exception=True)

        self._context_refresher = _RefreshConnectContext(
            target=self,
            timeout=2,
            daemon=daemon_threads
        )
        self._context_refresher.start()

        # We need to differ registration until we know which socket we are wrapping
        self._register = register
        self._watchdog = None

    def refresh_context(self, raise_exception=False):
        # Until progress is made on [PEP 543](https://www.python.org/dev/peps/pep-0543/)
        # we have no choice but to use files to load certificates.
        with tempfile.NamedTemporaryFile(mode='w') as cert_file:
            with tempfile.NamedTemporaryFile(mode='w') as key_file:
                with tempfile.NamedTemporaryFile(mode='w') as ca_file:
                    try:
                        cert, key = self._consul_agent.get_certificate(self._service)
                        ca = self._consul_agent.get_root_ca()
                        cert_file.write(cert)
                        cert_file.flush()
                        key_file.write(key)
                        key_file.flush()
                        ca_file.write(ca)
                        ca_file.flush()

                        # Create a new context that can be swapped in place of
                        # the old one.
                        context = self._context_factory()
                        context.verify_mode = ssl.CERT_REQUIRED
                        context.load_verify_locations(cafile=ca_file.name)
                        context.load_cert_chain(cert_file.name, key_file.name)

                        # TODO: We should do this only if necessary.
                        self._connect_context = context
                    except requests.exceptions.RequestException as e:
                        # We can silently log the error and update the context
                        # next time if the initial configuration worked.
                        logger.warning(
                            "Could not reach Consul to refresh TLS context: {}".format(e)
                        )
                        if raise_exception:
                            # If this is the first time we fetch the configuration
                            # to initialize the SSLContext, it may be better to
                            # let the user know about it.
                            raise
                        else:
                            # We still raise a warning so the user can do something
                            # about it if he wishes to do so.
                            warnings.warn(
                                "Could not reach Consul to refresh TLS context",
                                ConnectWarning
                            )

    def authorize(self, peer_cert):
        # TODO: Add a docstring here
        serial_number = peer_cert['serialNumber']
        serial_number = ':'.join((
            serial_number[i:i+2] for i in range(0, len(serial_number), 2)
        ))
        client_cert_uri = dict(peer_cert['subjectAltName'])['URI']
        try:
            return self._consul_agent.authorize(self._service, client_cert_uri, serial_number)
        except requests.exceptions.RequestException:
            # If we couldn't join Consul to check wether this client should be
            # allowed to connect, we say no by default, log the problem and
            # raise a warning so the user can do something about it if he
            # wishes to.
            logger.warning(
                "Blocked connection for {}: Could not connect to Consul - {}".format(
                    serial_number, e
                )
            )
            warnings.warn(
                "Could not reach Consul to authorize connection",
                ConnectWarning
            )
            return False

    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None, session=None):
        # SSLSocket class handles server_hostname encoding before it calls
        # ctx._wrap_socket()
        _, port = sock.getsockname()
        # NOTE: I should find a better way to get the host and it should be
        # configurable: https://github.com/hashicorp/consul/issues/4788
        host = socket.gethostbyname(socket.gethostname())
        if self._register:
            self._consul_agent.register_proxy(self._service, host, port)

            class _Watchdog(threading.Thread):
                def __init__(self, consul_agent, check_id, daemon=False):
                    super().__init__(daemon=daemon)
                    self._consul_agent = consul_agent
                    self._stop_flag = threading.Event()
                    self._check_id = check_id

                def run(self):
                    while True:
                        if self._stop_flag.wait(timeout=20):
                            logger.info("Stop health-check thread")
                            break
                        self._consul_agent.check_ttl(self._check_id)

            self._watchdog = _Watchdog(
                self._consul_agent,
                self._service + "-proxy-ttl",
                self._daemon_threads
            )
            self._watchdog.start()

        return self.sslsocket_class._create(
            sock=sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            context=self,
            session=session
        )

    def deregister(self):
        try:
            self._watchdog._stop_flag.set()
            self._consul_agent.deregister(self._service + '-proxy')
        except AttributeError:
            pass  # No health-check was registred

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.stop_refreshing_context()
        self.deregister()

    def stop_refreshing_context(self):
        self._context_refresher._stop_flag.set()

    # We need to proxy this class methods and attributes to the actual
    # implementation.
    def cert_store_stats(self):
        return self._connect_context.cert_store_stats()

    @property
    def check_hostname(self):
        return self._connect_context.check_hostname

    @check_hostname.setter
    def check_hostname(self, value):
        raise NotImplementedError()

    def get_ca_certs(self, binary_form=False):
        return self._connect_context.get_ca_certs(binary_form)

    def get_ciphers(self):
        return self._connect_context.get_ciphers()

    @property
    def hostname_checks_common_name(self):
        return self._connect_context.hostname_checks_common_name

    @hostname_checks_common_name.setter
    def hostname_checks_common_name(self, value):
        raise NotImplementedError()

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        raise NotImplementedError()

    def load_default_certs(self, purpose=Purpose.SERVER_AUTH):
        raise NotImplementedError()

    def load_dh_params(self, dhfile):
        raise NotImplementedError()

    def load_verify_locations(cafile=None, capath=None, cadata=None):
        raise NotImplementedError()

    @property
    def options(self):
        return self._connect_context.options

    @options.setter
    def options(self, value):
        raise NotImplementedError()

    @property
    def protocol(self):
        return self._connect_context.protocol

    def session_stats(self):
        warnings.warn("session_stats is incomplete")
        return self._connect_context.session_stats()

    def set_alpn_protocols(self, protocols):
        raise NotImplementedError()

    def set_ciphers(self, ciphers):
        raise NotImplementedError()

    def set_default_verify_paths(self):
        raise NotImplementedError()

    def set_ecdh_curve(self, curve_name):
        raise NotImplementedError()

    def set_npn_protocols(self, protocols):
        raise NotImplementedError()

    def set_servername_callback(self, server_name_callback):
        raise NotImplementedError()

    @property
    def sni_callback(self):
        return None

    @sni_callback.setter
    def sni_callback(self, value):
        raise NotImplementedError()

    @property
    def verify_flags(self):
        return self._connect_context.verify_flags

    @verify_flags.setter
    def verify_flags(self, value):
        raise NotImplementedError()

    @property
    def verify_mode(self):
        return self._connect_context.verify_mode

    @verify_mode.setter
    def verify_mode(self, value):
        raise NotImplementedError()


def _main(logs=False):
    import signal
    import sys

    if logs:
        logger = logging.getLogger(__name__)
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.DEBUG)
    signal.signal(signal.SIGINT, lambda signal, frame: sys.exit(0))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('', 8181))
        sock.listen()
        with Connect('socat', register=True) as connect:
            with connect.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    conn, addr = ssock.accept()
                    with conn:
                        try:
                            while True:
                                data = conn.recv(1024)
                                if not data: break
                                conn.sendall(data)
                        except ConnectionError:
                            pass

if __name__ == '__main__':
    _main(logs=True)
