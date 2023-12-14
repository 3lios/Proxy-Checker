import pycurl
from io import BytesIO
import re
import random
import json
from threading import Thread, Lock
import dns.resolver

"""
env: python 3.11 (Windows)
pycurl: pip install pycurl-7.45.1-cp311-cp311-win_amd64.whl
"""


class Parallel(Thread):
    def __init__(self, ip, list_bl, lock_bl, output, out_lock):
        Thread.__init__(self)
        self.ip = ip
        self.list_bl = list_bl
        self.lock_bl = lock_bl
        self.out_lock = out_lock
        self.output = output

    def run(self):
        while True:
            self.lock_bl.acquire()
            try:
                bl = self.list_bl.pop()
            except IndexError:
                return
            finally:
                self.lock_bl.release()

            result = BlChecker().nslookup(self.ip, bl)

            self.out_lock.acquire()
            self.output.append(result)
            self.out_lock.release()


class BlChecker:
    bls = [
        "access.redhawk.org",
        "all.s5h.net",
        "b.barracudacentral.org",
        "bl.spamcop.net",
        "bl.tiopan.com",
        "blackholes.wirehub.net",
        "blacklist.sci.kun.nl",
        "block.dnsbl.sorbs.net",
        "blocked.hilli.dk",
        "bogons.cymru.com",
        "cbl.abuseat.org",
        "dev.null.dk",
        "dialup.blacklist.jippg.org",
        "dialups.mail-abuse.org",
        "dialups.visi.com",
        "dnsbl.abuse.ch",
        "dnsbl.anticaptcha.net",
        "dnsbl.antispam.or.id",
        "dnsbl.dronebl.org",
        "dnsbl.justspam.org",
        "dnsbl.kempt.net",
        "dnsbl.sorbs.net",
        "dnsbl.tornevall.org",
        "dnsbl-1.uceprotect.net",
        "duinv.aupads.org",
        "dnsbl-2.uceprotect.net",
        "dnsbl-3.uceprotect.net",
        "dul.dnsbl.sorbs.net",
        "escalations.dnsbl.sorbs.net",
        "hil.habeas.com",
        "black.junkemailfilter.com",
        "http.dnsbl.sorbs.net",
        "intruders.docs.uu.se",
        "ips.backscatterer.org",
        "korea.services.net",
        "mail-abuse.blacklist.jippg.org",
        "misc.dnsbl.sorbs.net",
        "msgid.bl.gweep.ca",
        "new.dnsbl.sorbs.net",
        "no-more-funn.moensted.dk",
        "old.dnsbl.sorbs.net",
        "opm.tornevall.org",
        "pbl.spamhaus.org",
        "proxy.bl.gweep.ca",
        "psbl.surriel.com",
        "pss.spambusters.org.ar",
        "rbl.schulte.org",
        "rbl.snark.net",
        "recent.dnsbl.sorbs.net",
        "relays.bl.gweep.ca",
        "relays.mail-abuse.org",
        "relays.nether.net",
        "rsbl.aupads.org",
        "sbl.spamhaus.org",
        "smtp.dnsbl.sorbs.net",
        "socks.dnsbl.sorbs.net",
        "spam.dnsbl.sorbs.net",
        "spam.olsentech.net",
        "spamguard.leadmon.net",
        "spamsources.fabel.dk",
        "ubl.unsubscore.com",
        "web.dnsbl.sorbs.net",
        "xbl.spamhaus.org",
        "zen.spamhaus.org",
        "zombie.dnsbl.sorbs.net",
        "bl.mailspike.net"
    ]

    @staticmethod
    def reverse(ip):
        octets = ip.split(".")
        return ".".join(reversed(octets))

    def nslookup(self, ip, bl):
        reverse = self.reverse(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        try:
            resolver.resolve(reverse + "." + bl, "A")
            return {bl: "listed"}
        except dns.exception.Timeout:
            return {bl: "timeout"}
        except (Exception,):
            return {bl: "good"}

    @staticmethod
    def check(ip, concurrent=None):
        lock_bl = Lock()
        out_lock = Lock()
        output = []
        threads = []

        if not concurrent:
            concurrent = len(BlChecker.bls)

        for i in range(concurrent):
            thread = Parallel(ip, BlChecker.bls, lock_bl, output, out_lock)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return output

    @staticmethod
    def summary(result, listing=False):
        good = listed = timeout = 0
        for i in result:
            for key, value in i.items():
                if value == "good":
                    good += 1
                elif value == "listed":
                    listed += 1
                elif value == "timeout":
                    timeout += 1
        output = {
            "total": len(result),
            "good": good,
            "listed": listed,
            "timeout": timeout,
            "listed_percent": round(listed / len(result) * 100)
        }
        if listing:
            output["raw_check"] = result

        return json.dumps(output)


class ProxyChecker:
    def __init__(self):
        self.ip = self.get_ip()
        self.proxy_judges = [
            "http://proxyjudge.us",
            "http://azenv.net/"
        ]

    def get_ip(self):
        r = self.send_query(url="https://ifconfig.io/ip")
        return r["response"] if r else ""

    def send_query(self, proxy=False, url=None, user=None, password=None):
        response = BytesIO()
        c = pycurl.Curl()

        c.setopt(c.URL, url or random.choice(self.proxy_judges))
        c.setopt(c.WRITEDATA, response)
        c.setopt(c.TIMEOUT, 5)

        if user is not None and password is not None:
            c.setopt(c.PROXYUSERPWD, f"{user}:{password}")

        c.setopt(c.SSL_VERIFYHOST, 0)
        c.setopt(c.SSL_VERIFYPEER, 0)

        if proxy:
            c.setopt(c.PROXY, proxy)

        try:
            c.perform()
        except (Exception,):
            return False

        if c.getinfo(c.HTTP_CODE) != 200:
            return False

        timeout = round(c.getinfo(c.CONNECT_TIME) * 1000)

        response = response.getvalue().decode("iso-8859-1")

        return {
            "timeout": timeout,
            "response": response
        }

    def check_anonymity(self, r):
        if self.ip in r:
            return "Transparent"

        privacy_headers = [
            "VIA",
            "X-FORWARDED-FOR",
            "X-FORWARDED",
            "FORWARDED-FOR",
            "FORWARDED-FOR-IP",
            "FORWARDED",
            "CLIENT-IP",
            "PROXY-CONNECTION"
        ]

        if any([header in r for header in privacy_headers]):
            return "Anonymous"

        return "Elite"

    def get_country(self, ip):
        r = self.send_query(url="https://ip2c.org/" + ip)

        if r and r["response"][0] == "1":
            r = r["response"].split(";")
            return [r[3], r[1]]

        return ["-", "-"]

    def check_proxy(self, ip, port, user=None, password=None, protocol=None,
                    check_country=True, check_address=False, retry=0):
        protocols = {}
        timeout = 0
        protocol = [protocol] if protocol else ["http", "socks4", "socks5"]

        for proto in protocol:
            r = False
            retry += 1
            while retry >= 1:
                r = self.send_query(proxy=proto + "://" + ip + ":" + str(port), user=user, password=password)
                if r or len(protocol) > 1:
                    break
                retry -= 1

            if not r:
                continue

            protocols[proto] = r
            timeout += r["timeout"]

        if len(protocols) == 0:
            return False

        r = protocols[random.choice(list(protocols.keys()))]["response"]

        # Check country
        country = None
        if check_country:
            country = self.get_country(ip)

        # Check anonymity
        anonymity = self.check_anonymity(r)

        # Check timeout
        timeout = timeout // len(protocols)

        # Check remote address
        remote_addr = None
        if check_address:
            remote_regex = r"REMOTE_ADDR = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            remote_addr = re.search(remote_regex, r)
            if remote_addr:
                remote_addr = remote_addr.group(1)

        results = {
            "protocols": list(protocols.keys()),
            "anonymity": anonymity,
            "timeout": timeout
        }

        if check_country:
            results["country"] = country[0]
            results["country_code"] = country[1]

        if check_address:
            results["remote_address"] = remote_addr

        return json.dumps(results)


# Example
ip = "xx.xx.xx.xx"
port = 7777
user = None
password = None
proxy_checker = ProxyChecker()
proxy = proxy_checker.check_proxy(ip=ip, port=port, user=user, password=password, protocol="http",
                                  check_country=True, check_address=True, retry=0)
print(proxy)

bl_checker = BlChecker()
result = bl_checker.check(ip, concurrent=None)
result = bl_checker.summary(result)
print(result)

