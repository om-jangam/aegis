"""Plain-language "what should I do?" guidance for each ATT&CK technique.

A finding tells an analyst *what* matched. Most people who see an alert are not
analysts, so the dashboard and report pair each technique with a short,
actionable next step.
"""
from __future__ import annotations

_GUIDANCE: dict[str, str] = {
    "T1071": ("A program talked to a server linked to attackers or over a channel malware "
              "uses to take orders. Check whether you recognise the program; if not, block "
              "the address (aegis block <ip>) and run a full antivirus scan."),
    "T1571": ("A program used a port that backdoors and remote-control tools favour. Confirm "
              "the program is something you installed; if not, block the address and scan."),
    "T1021": ("Someone connected with a remote-administration protocol (RDP, SMB, WinRM). "
              "Fine if it was you or IT; otherwise disconnect the machine from the network "
              "and change your passwords from a different device."),
    "T1046": ("One program contacted many machines quickly, which is how attackers map a "
              "network. Identify and stop the process unless it is a tool you run on purpose."),
    "T1059": ("A command interpreter (PowerShell, cmd, a shell) did something scripts rarely "
              "need to do. If you were not running a script yourself, end the process and scan."),
    "T1036": ("A program is disguised as something it is not, or runs from a temporary "
              "folder. Check its file location and publisher; delete it if it is unknown."),
    "T1105": ("A built-in tool downloaded a file, a common way to bring malware onto a machine. "
              "Find and scan the downloaded file before anything opens it."),
    "T1218": ("A trusted Windows program was used to run other code, a trick to slip past "
              "security tools. Investigate what it launched and scan the machine."),
    "T1566": ("A document or email attachment started a script. Do not re-open that file; "
              "delete it, report the email, and scan the machine."),
    "T1003": ("A credential-dumping tool ran. Assume passwords on this machine are exposed: "
              "isolate it and change passwords, starting with administrator accounts."),
    "T1490": ("Backups or shadow copies were deleted, which ransomware does before encrypting. "
              "Disconnect from the network immediately and check your backups are intact."),
    "T1486": ("Files are changing in a pattern consistent with ransomware encryption. "
              "Disconnect from the network now and shut the machine down to limit damage."),
    "T1543": ("A service or startup item was added or changed, a way malware survives "
              "reboots. Confirm you installed something recently; otherwise remove it."),
    "T1098": ("An account or its access keys were modified. Verify the change was intended "
              "and review which accounts can log in."),
    "T1565": ("A system file that controls security or name resolution was changed. Compare "
              "it with a known-good copy and restore it if the change is unexplained."),
    "T1554": ("A trusted program's file was modified, which can hide malware inside it. "
              "Reinstall the program from its official source."),
}

DEFAULT_GUIDANCE = ("Review the process and address involved. If you do not recognise them, "
                    "block the address, end the process and run an antivirus scan.")


def guidance_for(technique: str) -> str:
    """Guidance for a technique id such as ``T1059.001``, falling back to its parent."""
    technique = (technique or "").strip().upper()
    if technique in _GUIDANCE:
        return _GUIDANCE[technique]
    return _GUIDANCE.get(technique.split(".", 1)[0], DEFAULT_GUIDANCE)
