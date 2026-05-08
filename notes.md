# Mini SOC Lab Notes

## Project Goal

Build a beginner Security Operations Center (SOC) lab capable of detecting suspicious SSH authentication activity using Python and Linux system logs.

---

## Lab Environment

### Ubuntu VM
Purpose:
- target machine
- runs SSH server
- stores authentication logs

### Kali Linux VM
Purpose:
- attacker machine
- generates failed SSH login attempts

---

## Detection Features

Current features:
- failed login detection
- IP extraction
- timestamp tracking
- attack duration calculation
- alert generation
- real-time monitoring

---

## Real-Time Monitoring Test

### Attack Simulation
Kali Linux generated failed SSH login attempts against the Ubuntu SSH server using a fake user account.

Example command:

ssh fakeuser@192.168.56.101

---

## Detection Results

The Python monitoring tool sucessfully detected:
- failed login attempts
- attacker IP address
- timestamps
- repeated authentication failures in real time

---

## Skills Learned

- Linux administration
- SSH configuration
- Python scripting
- regex parsing
- log analysis
- virtual machine networking
- basic detection engineering
- SOC workflow concepts 