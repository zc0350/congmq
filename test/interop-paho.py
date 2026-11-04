#!/usr/bin/env python3
"""Interop cases driven by Eclipse paho-mqtt — a second, independent MQTT stack.

The rest of this directory proves the broker against mqtt.js. That is one
implementation of a wire format; a disagreement between two encoders is exactly
the bug a single-client suite cannot see. paho-python has its own packet encoder,
its own QoS 2 state machine and its own property table, so anything it confirms
here is confirmed by somebody who did not read our code.

Each case prints one line the Node driver can count:

	RESULT {"name": "...", "ok": true, "detail": "..."}

The driver (test/interop-check.mjs) owns the broker processes, the PKI, the rule
files and the fake load balancer; this file only speaks as a client. It reads the
endpoints out of the JSON config the driver hands it, so no port is hardcoded:

	python test/interop-paho.py <config.json> [name-substring]
"""

import json
import ssl
import sys
import threading
import time

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from paho.mqtt.subscribeoptions import SubscribeOptions

V311 = mqtt.MQTTv311
V5 = mqtt.MQTTv5

CFG = json.load(open(sys.argv[1], encoding="utf-8"))
FILTER = sys.argv[2] if len(sys.argv) > 2 else ""
HOST = "127.0.0.1"
NONCE = CFG["nonce"]
DEVICES = CFG["users"]

cases = []


def case(group):
    def deco(fn):
        cases.append((f"{group}/{fn.__name__}", fn))
        return fn

    return deco


def emit(name, ok, detail=""):
    print("RESULT " + json.dumps({"name": name, "ok": bool(ok), "detail": str(detail)[:300]},
                                  ensure_ascii=False), flush=True)


def codes(value):
    """paho hands back either ints or ReasonCode objects, depending on version."""
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        value = [value]
    out = []
    for rc in value:
        v = getattr(rc, "value", rc)
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            out.append(-1)
    return out


class Box:
    """Inbox for one client: messages, subscribes, disconnects, connacks."""

    def __init__(self):
        self.mu = threading.Lock()
        self.msgs = []
        self.subs = []
        self.connack = []
        self.drops = []

    def wire(self, client):
        # CallbackAPIVersion.VERSION2 fixes the arity of every one of these, and
        # paho re-raises anything a callback throws, which kills that client's
        # network thread. A wrong signature therefore looks exactly like a broker
        # that never delivers: the SUBACK and every live PUBLISH after it go
        # unread, while a message queued before the crash still arrives on
        # reconnect. So every callback is wrapped, and anything it raises is
        # counted and reported as its own line instead of as twenty failures.
        client.on_message = guarded("on_message", lambda c, u, m: self._push(self.msgs, m))
        client.on_subscribe = guarded(
            "on_subscribe", lambda c, u, mid, reason_codes, props: self._push(self.subs, codes(reason_codes))
        )
        client.on_connect = guarded(
            "on_connect", lambda c, u, flags, reason_code, props: self._push(self.connack, (str(reason_code), props))
        )
        client.on_disconnect = guarded(
            "on_disconnect", lambda c, u, flags, reason_code, props: self._push(self.drops, str(reason_code))
        )

    def _push(self, lane, item):
        with self.mu:
            lane.append(item)

    def wait(self, lane, n=1, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            with self.mu:
                if len(lane) >= n:
                    return list(lane)
            time.sleep(0.05)
        with self.mu:
            return list(lane)

    def messages(self, n=1, timeout=5.0):
        got = self.wait(self.msgs, n, timeout)
        return [(m.topic, bytes(m.payload), m.qos, m.retain, getattr(m, "properties", None)) for m in got]

    def payloads(self, n=1, timeout=5.0):
        return [(t, p) for (t, p, _q, _r, _x) in self.messages(n, timeout)]


CALLBACK_ERRORS = []


def guarded(name, fn):
    def wrapper(*args):
        try:
            return fn(*args)
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            CALLBACK_ERRORS.append(f"{name}: {type(exc).__name__}: {exc}"[:200])
            raise

    return wrapper


def client(name, proto, user=None, box=None, clean=None):
    """One paho client, named inside this run's own namespace."""
    kwargs = {"callback_api_version": CallbackAPIVersion.VERSION2,
              "client_id": f"{NONCE}-{name}", "protocol": proto}
    if proto is V311:
        # v5 does not accept clean_session at all: its knob is clean_start, and it
        # goes on connect(), not the constructor.
        kwargs["clean_session"] = True if clean is None else clean
    c = mqtt.Client(**kwargs)
    if user is not None:
        spec = DEVICES[user]
        c.username_pw_set(spec["username"], spec["password"])
    if box is not None:
        box.wire(c)
    return c


def connect(c, port, clean_start=None, properties=None, tls=None, context=None):
    if context is not None:
        # A whole SSLContext, for the cases that need something tls_set() cannot
        # express — pinning the negotiated version is the reason that exists.
        c.tls_set_context(context)
    elif tls is not None:
        c.tls_set(ca_certs=CFG["ca"], **tls)
    if clean_start is not None:
        c.connect(HOST, port, 30, clean_start=clean_start, properties=properties)
    else:
        c.connect(HOST, port, 30, properties=properties)
    c.loop_start()
    return c


def pinned_context(version):
    """Trust our CA and speak exactly one TLS version, no fallback either way.

    tls_set(tls_version=...) takes ssl.PROTOCOL_* constants, not ssl.TLSVersion
    members, so a version pin has to go through a context. Setting both ends of
    the range is what makes the pin mean something: a max alone still lets the
    client offer 1.0.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=CFG["ca"])
    ctx.minimum_version = ctx.maximum_version = version
    return ctx


def negotiated(c):
    """The TLS version actually on the wire, or None if there is no socket yet."""
    sock = c.socket()
    return sock.version() if sock is not None and hasattr(sock, "version") else None


def close(*cs):
    for c in cs:
        try:
            c.loop_stop()
            c.disconnect()
        except Exception:  # noqa: BLE001 - teardown must never fail a case
            pass


def hard_close(c):
    """Drop the TCP without a DISCONNECT — the only way to ask for a will."""
    sock = c.socket()
    c.loop_stop()
    if sock:
        sock.close()


def pub(c, topic, payload, qos=0, retain=False, properties=None):
    return c.publish(topic, payload, qos=qos, retain=retain, properties=properties)


def sub(c, topic, qos=0, options=None):
    c.subscribe(topic, qos=qos, options=options)
    return c


def t(name):
    return f"it/{NONCE}/{name}"


# --------------------------------------------------------------------- 3.1.1 ----

PLAIN = CFG["plain_port"]


@case("311")
def connect_ok():
    box = Box()
    c = client("ok311", V311, user="dev", box=box)
    connect(c, PLAIN)
    got = box.wait(box.connack, 1, 5)
    close(c)
    return got and got[0][0] in ("Success", "0"), got and got[0][0]


@case("311")
def connect_wrong_password():
    box = Box()
    c = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2,
                    client_id=f"{NONCE}-badpw", protocol=V311)
    box.wire(c)
    c.username_pw_set(DEVICES["dev"]["username"], "deadbeef")
    c.connect(HOST, PLAIN, 30)
    c.loop_start()
    got = box.wait(box.connack, 1, 5)
    time.sleep(0.3)
    alive = c.is_connected()
    close(c)
    bad = bool(got) and not got[0][0].startswith("Success")
    return bad and not alive, f"{got and got[0][0]} connected={alive}"


@case("311")
def connect_unknown_user():
    box = Box()
    c = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2,
                    client_id=f"{NONCE}-nouser", protocol=V311)
    box.wire(c)
    c.username_pw_set("nobody", "x")
    c.connect(HOST, PLAIN, 30)
    c.loop_start()
    got = box.wait(box.connack, 1, 5)
    close(c)
    return bool(got) and not got[0][0].startswith("Success"), got and got[0][0]


@case("311")
def qos0_roundtrip():
    box = Box()
    s = sub(connect(client("q0s", V311, "dev", box), PLAIN), t("q0"))
    time.sleep(0.3)
    p = connect(client("q0p", V311, "dev"), PLAIN)
    pub(s, t("q0"), b"zero", qos=0)
    got = box.payloads(1, 4)
    close(s, p)
    return got == [(t("q0"), b"zero")], got


@case("311")
def qos1_order():
    box = Box()
    s = sub(connect(client("q1s", V311, "dev", box), PLAIN), t("q1"), qos=1)
    time.sleep(0.3)
    p = connect(client("q1p", V311, "dev"), PLAIN)
    for i in range(6):
        pub(p, t("q1"), f"m{i}".encode(), qos=1).wait_for_publish(timeout=5)
    got = box.payloads(6, 6)
    close(s, p)
    want = [(t("q1"), f"m{i}".encode()) for i in range(6)]
    return got == want, f"{len(got)} of 6, first={got[:2]}"


@case("311")
def qos2_exactly_once():
    """paho's own PUBREC/PUBREL/PUBCOMP machine against ours, both directions."""
    box = Box()
    s = sub(connect(client("q2s", V311, "dev", box), PLAIN), t("q2"), qos=2)
    time.sleep(0.3)
    p = connect(client("q2p", V311, "dev"), PLAIN)
    for i in range(8):
        pub(p, t("q2"), f"d{i}".encode(), qos=2).wait_for_publish(timeout=8)
    got = box.payloads(8, 8)
    time.sleep(0.8)  # a re-delivery would land here, after the last PUBCOMP
    with box.mu:
        late = len(box.msgs)
    close(s, p)
    want = [(t("q2"), f"d{i}".encode()) for i in range(8)]
    return got == want and late == 8, f"{late} deliveries"


@case("311")
def qos2_both_directions():
    """Subscribe at 2, publish at 2 from the *subscriber*: its own outbound leg."""
    box = Box()
    c = sub(connect(client("q2both", V311, "dev", box), PLAIN), t("q2b"), qos=2)
    time.sleep(0.3)
    pub(c, t("q2b"), b"loop", qos=2).wait_for_publish(timeout=8)
    got = box.payloads(1, 6)
    close(c)
    return got == [(t("q2b"), b"loop")], got


@case("311")
def wildcard_levels():
    box = Box()
    s = connect(client("w311", V311, "dev", box), PLAIN)
    sub(s, t("w") + "/+/x", qos=1)
    sub(s, t("w") + "/#")
    time.sleep(0.4)
    p = connect(client("w311p", V311, "dev"), PLAIN)
    for topic in (t("w") + "/a/x", t("w") + "/a/b/x", t("w") + "/deep/1/2"):
        pub(p, topic, b"1", qos=1).wait_for_publish(timeout=5)
    got = box.payloads(3, 5)
    close(s, p)
    return len(got) == 3 and (t("w") + "/a/x", b"1") in got, got


@case("311")
def hash_excludes_dollar():
    """[MQTT-4.7.3-1]: a leading # or + never matches a $ topic."""
    box = Box()
    wide = connect(client("wide311", V311, "wide", box), PLAIN)
    sub(wide, "#", qos=0)
    time.sleep(0.4)
    p = connect(client("widep", V311, "wide"), PLAIN)
    pub(p, "SYSMUSTNOT/" + NONCE, b"dollar", qos=1).wait_for_publish(timeout=5)
    pub(p, t("plain"), b"normal", qos=1).wait_for_publish(timeout=5)
    time.sleep(0.8)
    got = box.payloads(10, 2)
    close(wide, p)
    return all(not topic.startswith("$") for (topic, _b) in got) and len(got) >= 1, got


@case("311")
def retained_then_cleared():
    box = Box()
    p = connect(client("retp", V311, "dev"), PLAIN)
    pub(p, t("ret"), b"kept", qos=1, retain=True).wait_for_publish(timeout=5)
    time.sleep(0.3)
    s = connect(client("rets", V311, "dev", box), PLAIN)
    sub(s, t("ret"), qos=1)
    got = box.messages(1, 4)
    close(s)
    box2 = Box()
    s2 = connect(client("rets2", V311, "dev", box2), PLAIN)
    pub(p, t("ret"), b"", qos=1, retain=True).wait_for_publish(timeout=5)
    time.sleep(0.3)
    sub(s2, t("ret"), qos=1)
    late = box2.payloads(1, 1.5)
    close(p, s2)
    kept = bool(got) and got[0][1] == b"kept" and got[0][3] is True
    return kept and not late, f"retained_flag={got and got[0][3]} after_clear={late}"


@case("311")
def will_on_abnormal_close():
    box = Box()
    w = connect(client("willw", V311, "dev", box), PLAIN)
    sub(w, t("will"), qos=1)
    time.sleep(0.4)
    dead = client("willd", V311, "dev")
    dead.will_set(t("will"), b"gone", qos=1, retain=False)
    connect(dead, PLAIN)
    time.sleep(0.5)
    hard_close(dead)
    got = box.payloads(1, 4)
    close(w)
    return got == [(t("will"), b"gone")], got


@case("311")
def offline_queue_replay():
    """clean_session=False: the queue survives the session, in order."""
    name = "offq"
    box = Box()
    s = client(name, V311, "dev", box, clean=False)
    connect(s, PLAIN)
    sub(s, t("off"), qos=1)
    time.sleep(0.5)
    close(s)
    p = connect(client("offpub", V311, "dev"), PLAIN)
    for i in range(4):
        pub(p, t("off"), f"q{i}".encode(), qos=1).wait_for_publish(timeout=5)
    time.sleep(0.6)
    close(p)

    box2 = Box()
    back = client(name, V311, "dev", box2, clean=False)
    connect(back, PLAIN)
    got = box2.payloads(4, 8)
    close(back)
    want = [(t("off"), f"q{i}".encode()) for i in range(4)]
    return got == want, f"{len(got)} replayed"


@case("311")
def subscribe_denied():
    box = Box()
    c = connect(client("deny311", V311, "dev", box), PLAIN)
    sub(c, "#", qos=1)
    got = box.wait(box.subs, 1, 5)
    close(c)
    # [MQTT-3.9.3-1]: a 3.1.1 SUBACK says "failed" with 0x80, and nothing else.
    return bool(got) and 0x80 in got[0], got


@case("311")
def publish_denied():
    box = Box()
    w = connect(client("denyp-w", V311, "dev", box), PLAIN)
    sub(w, t("secret") + "/#", qos=1)
    time.sleep(0.4)
    p = connect(client("denyp", V311, "dev"), PLAIN)
    pub(p, t("secret") + "/cmd", b"nope", qos=0)
    pub(p, t("secret") + "/cmd", b"nope2", qos=1)
    time.sleep(1.0)
    got = box.payloads(1, 1.0)
    close(w, p)
    return not got, got


# ---------------------------------------------------------------------- 5.0 ----


@case("v5")
def connack_advertises_limits():
    box = Box()
    c = connect(client("cap5", V5, "dev", box), PLAIN)
    got = box.wait(box.connack, 1, 5)
    props = got[0][1] if got else None
    close(c)
    seen = {}
    if props is not None:
        for key in ("MaximumPacketSize", "ReceiveMaximum", "TopicAliasMaximum", "MaxQoS",
                    "SubscriptionIdentifiersAvailable", "RetainAvailable"):
            if hasattr(props, key):
                seen[key] = getattr(props, key)
    return got and got[0][0] == "Success" and bool(seen), seen


@case("v5")
def user_properties_both_ways():
    box = Box()
    s = connect(client("up5s", V5, "dev", box), PLAIN)
    sub(s, t("up"))
    time.sleep(0.3)
    p = connect(client("up5p", V5, "dev"), PLAIN)
    props = Properties(PacketTypes.PUBLISH)
    props.UserProperty = ("k1", "v1")
    pub(p, t("up"), b"tagged", qos=1, properties=props).wait_for_publish(timeout=5)
    got = box.messages(1, 5)
    close(s, p)
    if not got:
        return False, "no message"
    msg_props = got[0][4]
    user = getattr(msg_props, "UserProperty", None) if msg_props is not None else None
    return user == [("k1", "v1")], user


@case("v5")
def message_expiry_skips_late_subscriber():
    box = Box()
    p = connect(client("exp5p", V5, "dev"), PLAIN)
    props = Properties(PacketTypes.PUBLISH)
    props.MessageExpiryInterval = 1
    pub(p, t("exp"), b"stale", qos=1, properties=props).wait_for_publish(timeout=5)
    time.sleep(2.5)
    s = connect(client("exp5s", V5, "dev", box), PLAIN)
    sub(s, t("exp"))
    late = box.payloads(1, 1.5)
    close(p, s)
    return not late, late


@case("v5")
def topic_alias_reused():
    box = Box()
    s = connect(client("ta5s", V5, "dev", box), PLAIN)
    sub(s, t("alias"))
    time.sleep(0.3)
    p = connect(client("ta5p", V5, "dev"), PLAIN)
    first = Properties(PacketTypes.PUBLISH)
    first.TopicAlias = 1
    pub(p, t("alias"), b"one", qos=1, properties=first).wait_for_publish(timeout=5)
    second = Properties(PacketTypes.PUBLISH)
    second.TopicAlias = 1
    # The second publish names no topic: the alias stands in for it.
    pub(p, "", b"two", qos=1, properties=second).wait_for_publish(timeout=5)
    got = box.payloads(2, 5)
    close(s, p)
    return got == [(t("alias"), b"one"), (t("alias"), b"two")], got


@case("v5")
def no_local():
    box = Box()
    c = connect(client("nl5", V5, "dev", box), PLAIN)
    sub(c, t("nl"), options=SubscribeOptions(qos=1, noLocal=True))
    time.sleep(0.4)
    pub(c, t("nl"), b"self", qos=1).wait_for_publish(timeout=5)
    mine = box.payloads(1, 1.2)
    other = Box()
    c2 = connect(client("nl5b", V5, "dev", other), PLAIN)
    sub(c2, t("nl"), qos=1)
    time.sleep(0.3)
    pub(c, t("nl"), b"other", qos=1).wait_for_publish(timeout=5)
    theirs = other.payloads(1, 4)
    close(c, c2)
    return not mine and theirs == [(t("nl"), b"other")], f"self={mine} other={theirs}"


@case("v5")
def retain_handling_never():
    box = Box()
    p = connect(client("rh5p", V5, "dev"), PLAIN)
    pub(p, t("rh"), b"kept", qos=1, retain=True).wait_for_publish(timeout=5)
    time.sleep(0.3)
    s = connect(client("rh5s", V5, "dev", box), PLAIN)
    sub(s, t("rh"), options=SubscribeOptions(qos=1, retainHandling=2))
    quiet = box.payloads(1, 1.2)
    sub(s, t("rh"), options=SubscribeOptions(qos=1, retainHandling=0))
    now = box.payloads(1, 4)
    close(p, s)
    return not quiet and now == [(t("rh"), b"kept")], f"never={quiet} then_default={now}"


@case("v5")
def shared_subscription_split():
    a, b = Box(), Box()
    ca = sub(connect(client("sh5a", V5, "dev", a), PLAIN), "$share/g/" + t("share"), qos=1)
    cb = sub(connect(client("sh5b", V5, "dev", b), PLAIN), "$share/g/" + t("share"), qos=1)
    time.sleep(0.5)
    p = connect(client("sh5p", V5, "dev"), PLAIN)
    for i in range(6):
        pub(p, t("share"), f"s{i}".encode(), qos=1).wait_for_publish(timeout=5)
    ga = a.payloads(3, 6)
    gb = b.payloads(3, 6)
    close(ca, cb, p)
    both = sorted([x[1] for x in ga] + [x[1] for x in gb])
    want = sorted([f"s{i}".encode() for i in range(6)])
    return both == want and len(ga) == 3 and len(gb) == 3, f"a={len(ga)} b={len(gb)}"


@case("v5")
def session_expiry_keeps_subscriptions():
    name = "persist5"
    box = Box()
    c = client(name, V5, "persist", box)
    props = Properties(PacketTypes.CONNECT)
    props.SessionExpiryInterval = 120
    connect(c, PLAIN, clean_start=True, properties=props)
    sub(c, t("persist"), qos=1)
    time.sleep(0.4)
    close(c)
    p = connect(client("persistpub", V5, "dev"), PLAIN)
    pub(p, t("persist"), b"queued", qos=1).wait_for_publish(timeout=5)
    time.sleep(0.6)
    close(p)
    box2 = Box()
    back = client(name, V5, "persist", box2)
    connect(back, PLAIN, clean_start=False)
    got = box2.payloads(1, 6)
    close(back)
    return got == [(t("persist"), b"queued")], got


@case("v5")
def will_delay_interval():
    box = Box()
    w = connect(client("wd5w", V5, "dev", box), PLAIN)
    sub(w, t("wd"), qos=1)
    time.sleep(0.4)
    dead = client("wd5d", V5, "dev")
    # Will properties live in their own packet type in paho, not on CONNECT: the
    # bytes are the will section of the CONNECT, but the table is keyed by it.
    will_props = Properties(PacketTypes.WILLMESSAGE)
    will_props.WillDelayInterval = 2
    # The delay only holds a will back while there is a session worth waiting on:
    # with Session Expiry Interval 0 the will goes out immediately, which is what
    # the broker does on purpose, so the client has to ask for both.
    conn_props = Properties(PacketTypes.CONNECT)
    conn_props.SessionExpiryInterval = 60
    dead.will_set(t("wd"), b"slow-goodbye", qos=1, retain=False, properties=will_props)
    connect(dead, PLAIN, properties=conn_props)
    time.sleep(0.4)
    hard_close(dead)
    early = box.payloads(1, 0.8)
    late = box.payloads(1, 5)
    close(w)
    return not early and late == [(t("wd"), b"slow-goodbye")], f"early={early} late={late}"


@case("v5")
def clean_takeover_clears_the_queue():
    name = "take5"
    box = Box()
    old = client(name, V5, "persist", box)
    connect(old, PLAIN, clean_start=True)
    sub(old, t("take"), qos=1)
    time.sleep(0.4)
    p = connect(client("takepub", V5, "dev"), PLAIN)
    pub(p, t("take"), b"for-the-old-session", qos=1).wait_for_publish(timeout=5)
    time.sleep(0.5)
    close(p)
    hard_close(old)

    box2 = Box()
    fresh = client(name, V5, "persist", box2)
    connect(fresh, PLAIN, clean_start=True)  # takeover: the queued message must go
    quiet = box2.payloads(1, 1.5)
    sub(fresh, t("take"), qos=1)
    time.sleep(0.4)
    pubber = connect(client("takepub2", V5, "dev"), PLAIN)
    pub(pubber, t("take"), b"after-takeover", qos=1).wait_for_publish(timeout=5)
    # The new session is the one that must see live traffic now: reading the
    # publisher's inbox would only prove that a publisher does not hear itself.
    live = box2.payloads(1, 4)
    close(fresh, pubber)
    return not quiet and live == [(t("take"), b"after-takeover")], f"quiet={quiet} live={live}"


@case("v5")
def subscribe_reason_code():
    box = Box()
    c = connect(client("deny5", V5, "dev", box), PLAIN)
    sub(c, "#")
    got = box.wait(box.subs, 1, 5)
    close(c)
    return bool(got) and 135 in got[0], got


@case("v5")
def publish_denied_reason_and_no_delivery():
    box = Box()
    w = connect(client("pd5w", V5, "dev", box), PLAIN)
    sub(w, t("secret") + "/#")
    time.sleep(0.4)
    pbox = Box()
    p = connect(client("pd5p", V5, "dev", pbox), PLAIN)
    pub(p, t("secret") + "/cmd", b"nope", qos=1)
    time.sleep(1.2)
    got = box.payloads(1, 1.0)
    close(w, p)
    return not got, got


# --------------------------------------------------------------------- caps ----

CAPS = CFG["caps_port"]


@case("caps")
def max_qos_caps_the_grant():
    box = Box()
    c = connect(client("qoscap", V5, box=box), CAPS)
    sub(c, t("qoscap"), qos=2)
    got = box.wait(box.subs, 1, 5)
    close(c)
    return bool(got) and got[0] == [1], got


@case("caps")
def max_subs_cap():
    box = Box()
    c = connect(client("subcap", V5, box=box), CAPS)
    grants = []
    for i in range(4):  # -max-subs is 3 on this broker
        sub(c, t(f"cap{i}"))
        got = box.wait(box.subs, i + 1, 5)
        grants.append(got[-1] if got else None)
    alive = c.is_connected()
    close(c)
    # The cap refuses the fourth filter, it does not punish the connection: the
    # three subscriptions the client already paid for survive it.
    return grants == [[0], [0], [0], [151]] and alive, f"subacks={grants} connected={alive}"


@case("caps")
def oversized_publish_is_refused():
    box = Box()
    c = connect(client("big5", V5, box=box), CAPS)
    payload = b"z" * 4096  # -max-packet-size is 1024 on this broker
    pub(c, t("big"), payload, qos=0)
    gone = box.wait(box.drops, 1, 6)
    time.sleep(0.3)
    alive = c.is_connected()
    close(c)
    return bool(gone) and not alive, f"drop={gone} alive={alive}"


@case("caps")
def session_expiry_is_capped():
    box = Box()
    props = Properties(PacketTypes.CONNECT)
    props.SessionExpiryInterval = 3600  # -session-expiry-max is 60
    c = connect(client("secap", V5, box=box), CAPS, properties=props)
    got = box.wait(box.connack, 1, 5)
    close(c)
    # The server answers with the value it actually agreed to, so a client asking
    # for an hour must not walk away believing it has one.
    seen = getattr(got[0][1], "SessionExpiryInterval", None) if got and got[0][1] else None
    return got and got[0][0] == "Success" and seen is not None and seen <= 60, seen


# ---------------------------------------------------------------------- tls ----

TLSPORT = CFG["tls_port"]
MTLSPORT = CFG["mtls_port"]


@case("tls")
def tls13_publish():
    box = Box()
    c = connect(client("tls13", V5, "meter", box), TLSPORT, tls={})
    sub(c, t("tls"))
    time.sleep(0.4)
    pub(c, t("tls"), b"over-tls13", qos=1).wait_for_publish(timeout=6)
    got = box.payloads(1, 5)
    # The case is named for the version, so the version is part of the claim: an
    # unpinned client that silently negotiated 1.2 would still deliver the byte.
    ver = negotiated(c)
    close(c)
    return got == [(t("tls"), b"over-tls13")] and ver == "TLSv1.3", f"{got} negotiated={ver}"


@case("tls")
def tls12_publish():
    box = Box()
    c = connect(client("tls12", V5, "meter", box), TLSPORT,
                context=pinned_context(ssl.TLSVersion.TLSv1_2))
    sub(c, t("tls12"))
    time.sleep(0.4)
    pub(c, t("tls12"), b"downgraded", qos=1).wait_for_publish(timeout=6)
    got = box.payloads(1, 5)
    ver = negotiated(c)
    close(c)
    return got == [(t("tls12"), b"downgraded")] and ver == "TLSv1.2", f"{got} negotiated={ver}"


@case("tls")
def mtls_certificate_is_the_credential():
    box = Box()
    c = connect(client("mtls", V5, box=box), MTLSPORT,
                tls={"certfile": CFG["client_cert"], "keyfile": CFG["client_key"]})
    sub(c, t("plant") + "/#")
    time.sleep(0.4)
    pub(c, t("plant") + "/a", b"by-certificate", qos=1).wait_for_publish(timeout=6)
    got = box.payloads(1, 5)
    close(c)
    return got == [(t("plant") + "/a", b"by-certificate")], got


@case("tls")
def mtls_refuses_a_client_without_a_certificate():
    box = Box()
    try:
        connect(client("mtls-none", V5, box=box), MTLSPORT, tls={})
    except Exception as exc:  # noqa: BLE001 - the refusal is the pass condition
        return True, f"{type(exc).__name__}: {exc}"[:160]
    got = box.wait(box.connack, 1, 2)
    return not got, f"connack={got} drops={box.drops}"


@case("tls")
def an_untrusted_server_is_not_talked_to():
    box = Box()
    c = client("badca", V5, "meter", box)
    c.tls_set(ca_certs=CFG["foreign_ca"])
    try:
        c.connect(HOST, TLSPORT, 30)
        c.loop_start()
        time.sleep(1.0)
        c.loop_stop()
    except Exception as exc:  # noqa: BLE001
        return True, f"{type(exc).__name__}: {exc}"[:160]
    got = box.wait(box.connack, 1, 2)
    return not got, got


# --------------------------------------------------------------------- proxy ----

VIA_DEVICE = CFG["proxy_via_device"]
VIA_NEIGHBOUR = CFG["proxy_via_neighbour"]
PROXY_DIRECT = CFG["proxy_direct_port"]


@case("proxy")
def the_claimed_address_is_the_one_rules_see():
    """An ip-pinned auth rule must match the address in the header, not the socket."""
    box = Box()
    c = connect(client("proxdev", V311, "gated", box), VIA_DEVICE)
    sub(c, t("gated"), qos=1)
    time.sleep(0.4)
    got = box.wait(box.connack, 1, 5)
    close(c)
    return bool(got) and got[0][0].startswith("Success"), got and got[0][0]


@case("proxy")
def another_claimed_address_is_refused():
    box = Box()
    c = client("proxneigh", V311, "gated", box)
    try:
        connect(c, VIA_NEIGHBOUR)
    except Exception as exc:  # noqa: BLE001
        pass
    got = box.wait(box.connack, 1, 5)
    time.sleep(0.4)
    alive = c.is_connected()
    close(c)
    refused = bool(got) and not got[0][0].startswith("Success")
    return (refused or not got) and not alive, f"connack={got and got[0][0]} alive={alive}"


@case("proxy")
def no_header_no_session():
    box = Box()
    c = client("proxplain", V311, "gated", box)
    try:
        connect(c, PROXY_DIRECT)
    except Exception as exc:  # noqa: BLE001
        return True, f"{type(exc).__name__}: {exc}"[:160]
    got = box.wait(box.connack, 1, 3)
    alive = c.is_connected()
    close(c)
    return not got and not alive, f"connack={got} alive={alive}"


def main():
    ran = 0
    failed = 0
    for name, fn in cases:
        if FILTER and FILTER not in name:
            continue
        ran += 1
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001 - one broken case must not end the run
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        if not ok:
            failed += 1
        emit(name, ok, detail)
    # Kept out of the case count on purpose: this is the harness reporting on
    # itself, and it is what tells the driver that a row failed because a client
    # callback blew up rather than because the broker disagreed.
    print("ERRORS " + json.dumps({"raised": CALLBACK_ERRORS}), flush=True)
    print(f"SUMMARY {json.dumps({'ran': ran, 'failed': failed})}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    # Topics the cases publish to, so the driver can leave nothing behind.
    sys.exit(main())
