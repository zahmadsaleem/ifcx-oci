#!/usr/bin/env python3
"""Real distroless-volume replacement behind TLS ingress and an app token proxy.

Run: python3 tests/cloud_smoke.py ifcx-oci:cloud-test
Requires Docker, Python 3 and openssl; uses only disposable test resources.
"""
import base64
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid


def docker(*args, **kwargs):
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True, **kwargs
    ).stdout.strip()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def main(image):
    name = "ifcx-cloud-test-" + uuid.uuid4().hex[:12]
    volume = name + "-data"
    backend = {}
    app_origin = {}
    servers = []
    containers = []
    password = "cloud-smoke-test-password"
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def forward(self):
            if self.server.application and (
                self.path not in ("/oauth/token", "/oauth/revoke")
                or self.headers.get("Origin") != app_origin["url"]
            ):
                self.send_error(403)
                return
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            headers = {k: v for k, v in self.headers.items() if k.lower() not in (
                "host", "connection", "content-length", "transfer-encoding"
            )}
            # The private HTTP hop must not downgrade generated links or cookies.
            headers.update({"Host": "private-ingress:5000", "X-Forwarded-Proto": "http",
                            "X-Forwarded-Host": "untrusted.example", "Forwarded": "host=untrusted.example;proto=http"})
            upstream = http.client.HTTPConnection("127.0.0.1", backend["port"], timeout=10)
            try:
                upstream.request(self.command, self.path, body, headers)
                response = upstream.getresponse()
                content = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ("connection", "transfer-encoding", "content-length"):
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            finally:
                upstream.close()

        do_GET = do_POST = do_PUT = forward

    try:
        with tempfile.TemporaryDirectory(prefix="ifcx-cloud-smoke-") as directory:
            cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                "-keyout", str(key), "-out", str(cert),
            ], check=True, capture_output=True)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            trust = ssl.create_default_context(cafile=str(cert))

            def proxy(application):
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
                server.application = application
                server.socket = tls.wrap_socket(server.socket, server_side=True)
                servers.append(server)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                return f"https://localhost:{server.server_port}"

            public = proxy(False)
            app_origin["url"] = proxy(True)
            callback = app_origin["url"] + "/oauth/callback"

            def request(method, url, body=None, headers=None):
                url = urllib.parse.urlsplit(url)
                connection = http.client.HTTPSConnection(url.hostname, url.port, context=trust, timeout=10)
                try:
                    connection.request(method, urllib.parse.urlunsplit(("", "", url.path, url.query, "")), body, headers or {})
                    response = connection.getresponse()
                    return response.status, dict(response.getheaders()), response.read()
                finally:
                    connection.close()

            def form(url, values, **headers):
                return request("POST", url, urllib.parse.urlencode(values), {
                    "Content-Type": "application/x-www-form-urlencoded", **headers
                })

            def cookie(headers):
                value = headers["set-cookie"]
                assert "HttpOnly" in value and "SameSite=Strict" in value and value.endswith("; Secure"), value
                return value.split(";", 1)[0]

            docker("volume", "create", volume)
            mount = ["--user", "65532:65532", "-v", volume + ":/data"]
            docker("run", "--rm", "-i", *mount, image, "user", "add", "--data", "/data", "writer", "--password-stdin", input=password + "\n")

            def start(suffix):
                container = name + suffix
                containers.append(container)
                docker("run", "-d", "--name", container, *mount, "-p", "127.0.0.1::5000", image,
                       "serve", "--data", "/data", "--listen", "0.0.0.0:5000", "--public-url", public,
                       "--oauth-client-id", "app", "--oauth-redirect-uri", callback)
                backend["port"] = int(docker("port", container, "5000/tcp").rsplit(":", 1)[1])
                for _ in range(100):
                    try:
                        if request("GET", public + "/readyz")[0] == 200:
                            return container
                    except (OSError, http.client.HTTPException):
                        pass
                    time.sleep(0.1)
                raise AssertionError(docker("logs", container))

            container = start("-first")
            # Same image, UID and volume; this also exercises provisioning while serving.
            docker("run", "--rm", *mount, image, "user", "grant", "--data", "/data", "writer", "project/model:pull,push")
            for path in ("/healthz", "/readyz"):
                status, _, body = request("GET", public + path)
                assert status == 200 and body == b""
            config = json.loads(request("GET", public + "/oauth/config")[2])
            assert config["authorization_endpoint"] == public + "/oauth/authorize"
            assert config["redirect_uris"] == [callback]

            authorization = public + "/oauth/authorize?" + urllib.parse.urlencode({
                "client_id": "app", "redirect_uri": callback, "response_type": "code",
                "code_challenge_method": "S256", "code_challenge": challenge,
                "state": "cloud-smoke-state", "scope": "repository:project/model:pull,push",
            })
            status, headers, body = request("GET", authorization)
            assert status == 200
            form_cookie = cookie(headers)
            request_id = re.search(r'name="request_id" value="([^"]+)"', body.decode())[1]
            consent = {"request_id": request_id, "username": "writer", "password": password,
                       "decision": "allow", "remember_me": "true"}
            assert form(public + "/oauth/authorize", consent, Origin="http://localhost", Cookie=form_cookie)[0] == 403
            status, headers, _ = form(public + "/oauth/authorize", consent, Origin=public, Cookie=form_cookie)
            assert status == 303
            cookie(headers)  # Cleared consent cookie is also Secure.
            params = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["location"]).query)
            assert params["state"] == ["cloud-smoke-state"]
            status, headers, body = form(app_origin["url"] + "/oauth/token", {
                "grant_type": "authorization_code", "client_id": "app", "redirect_uri": callback,
                "code": params["code"][0], "code_verifier": verifier,
            }, Origin=app_origin["url"])
            assert status == 200, body
            remembered = cookie(headers)
            assert "Path=/oauth/" in headers["set-cookie"]
            session = json.loads(body)
            assert session["remember_me"] and "refresh_token" not in session

            # Follow the OCI challenge, then push config, payload and manifest.
            status, headers, _ = request("GET", public + "/v2/")
            assert status == 401
            realm = re.search(r'realm="([^"]+)"', headers["www-authenticate"])[1]
            assert realm == public + "/token"
            basic = base64.b64encode(("writer:" + password).encode()).decode()

            def login():
                status, _, body = request("GET", realm + "?" + urllib.parse.urlencode({"scope": "repository:project/model:pull,push"}),
                                          headers={"Authorization": "Basic " + basic})
                assert status == 200, body
                return json.loads(body)["token"]

            token = login()
            bearer = {"Authorization": "Bearer " + token}
            payload = b"cloud container replacement test\n"
            for blob in (b"{}", payload):
                status, headers, _ = request("POST", public + "/v2/project/model/blobs/uploads/", headers=bearer)
                assert status == 202
                status, _, _ = request("PUT", public + headers["location"] + "?digest=" + digest(blob), blob, bearer)
                assert status == 201
            manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(b"{}"), "size": 2},
                "layers": [{"mediaType": "application/octet-stream", "digest": digest(payload), "size": len(payload)}]}).encode()
            artifact = public + "/v2/project/model/manifests/issued"
            assert request("PUT", artifact, manifest, bearer)[0] == 201
            assert request("GET", artifact, headers=bearer)[2] == manifest

            docker("stop", "--time", "30", container)
            assert docker("inspect", "--format", "{{.State.ExitCode}}", container) == "0"
            docker("rm", container)
            containers.remove(container)
            start("-replacement")
            # The old JWT verifies with the persisted identity and signing key.
            assert request("GET", artifact, headers=bearer)[2] == manifest
            assert request("GET", public + "/v2/project/model/blobs/" + digest(payload), headers=bearer)[2] == payload
            assert login()  # Accounts and grants also survived replacement.
            status, headers, body = form(app_origin["url"] + "/oauth/token", {
                "grant_type": "refresh_token", "client_id": "app",
            }, Origin=app_origin["url"], Cookie=remembered)
            assert status == 200, body
            assert cookie(headers) != remembered
            renewed = json.loads(body)
            assert "refresh_token" not in renewed and renewed["session_expires_at"] == session["session_expires_at"]
            print("PASS: TLS ingress, app token proxy, Secure cookies, probes, one-off provisioning, OCI login/push/pull, and full-volume container replacement")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for container in containers:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        subprocess.run(["docker", "volume", "rm", volume], capture_output=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ifcx-oci:cloud-test")
