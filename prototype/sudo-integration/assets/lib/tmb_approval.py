# PROTOTYPE hook (a): sudo Python APPROVAL plugin (throwaway, issue #1).
#
# Registered in /etc/sudo.conf:
#   Plugin python_approval /usr/lib/sudo/sudo_plugin_python.so \
#       ModulePath=/usr/local/tmb/lib/tmb_approval.py ClassName=TmbApprovalPlugin
#
# sudo_plugin(5)/(python): approval plugins run AFTER the sudoers policy has
# accepted the command; they can only veto, never allow, so sudoers stays the
# policy and the normal human password path is a separate track. This plugin
# enforces the TMB contract only for the configured agent user; every other
# invoker (human password sudo, root) is approved untouched.
import json
import subprocess
import sys

sys.path.insert(0, "/usr/local/tmb/lib")
import tmb_common as tmb  # noqa: E402

try:
    import sudo
except ImportError:  # only importable inside a real sudo process
    sudo = None

if sudo is not None:
    _RC_ACCEPT = sudo.RC.ACCEPT
    _BASE = sudo.Plugin
else:  # allow importing the file for syntax checks outside sudo
    _RC_ACCEPT = 1
    _BASE = object


class TmbApprovalPlugin(_BASE):
    def check(self, command_info, run_argv, run_env):
        cfg = tmb.load_config()
        argv = list(run_argv)
        envd = dict(x.split("=", 1) for x in run_env if "=" in x)
        info = dict(
            x.split("=", 1) for x in getattr(self, "user_info", ()) if "=" in x
        )
        cmid = dict(
            x.split("=", 1) for x in command_info if "=" in x
        )
        invoker = info.get("user") or envd.get("SUDO_USER") or ""
        runas = cmid.get("runas_user") or cfg["runas_user"]

        if invoker != cfg["agent_user"]:
            # not the TMB agent: normal sudo path (human password sudo, root)
            tmb.audit(cfg, "skip", "invoker %r is not the TMB agent user" % invoker)
            return _RC_ACCEPT

        if argv and argv[0] == cfg["dispatcher_path"]:
            # hook (b) governs itself: sudoers sees the dispatcher, and the
            # dispatcher performs the TMB verification + redemption itself.
            tmb.audit(cfg, "skip", "dispatcher-mode invocation")
            return _RC_ACCEPT

        tmb.audit(
            cfg, "check",
            "invoker=%s argv=%r runas=%s perm=%s" % (
                invoker, argv, runas, "present" if envd.get("TMB_PERMISSION") else "absent"))

        perm_b64 = envd.get("TMB_PERMISSION")
        if perm_b64:
            envelope = self._decode(cfg, perm_b64)
        else:
            # no permission presented: wait for a signer decision
            # (approve -> run; deny/timeout/cancel -> reject). An invalid or
            # expired permission never reaches this branch: those are plain
            # rejects below, no automatic re-approval.
            envelope = self._ask_signer(cfg, argv)
            if envelope is None:
                self._reject(cfg, "signer decision: no permission (deny/timeout)")
        ok, reason, payload = tmb.verify_envelope(
            envelope, cfg, program=argv[0], argv=argv[1:], runas_user=runas)
        if not ok:
            self._reject(cfg, "verification: %s" % reason)
        ok, reason = tmb.redeem(cfg, payload["request_id"])
        if not ok:
            self._reject(cfg, "redemption: %s" % reason)
        tmb.audit(cfg, "approve", "%s argv=%r" % (payload["request_id"], argv))
        return _RC_ACCEPT

    def _decode(self, cfg, perm_b64):
        try:
            return tmb.envelope_from_b64(perm_b64)
        except Exception as e:
            self._reject(cfg, "envelope not decodable: %s" % e)

    def _ask_signer(self, cfg, argv):
        request = tmb.build_request(cfg, argv)
        try:
            res = subprocess.run(
                [cfg["signer_path"], "decide", json.dumps(request)],
                capture_output=True, text=True,
                timeout=cfg["signer_timeout_s"])
        except subprocess.TimeoutExpired:
            tmb.audit(cfg, "signer-timeout", "plugin-side wait limit hit")
            return None
        if res.returncode != 0:
            tmb.audit(cfg, "signer-deny",
                      "rc=%d stderr=%r" % (res.returncode, res.stderr.strip()[:200]))
            return None
        try:
            return json.loads(res.stdout)
        except Exception:
            tmb.audit(cfg, "signer-error",
                      "unparseable signer output: %r" % res.stdout[:200])
            return None

    def _reject(self, cfg, reason):
        tmb.audit(cfg, "reject", reason)
        if sudo is not None:
            raise sudo.PluginReject("[TMB] %s" % reason)
        raise RuntimeError(reason)

    def show_version(self, is_verbose):
        if sudo is not None:
            sudo.log_info("TMB approval plugin (PROTOTYPE, throwaway)")
        return _RC_ACCEPT
