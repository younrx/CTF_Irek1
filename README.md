# CTF sent by Irek (11/10/22)

## Description
The goal of this challenge is to retrieve a key stored inside a binary that usually run on a server. One way to get it is to verify a certificate with admin rights.

To help you, an inside man stole:
- the binary ('serma_challenge')
- a part of the code ('extract.c') that seems to be the function that performs the certificates verification
- a valid certificate ('toto.cert') with user rights (admin=0 instead of admin=1)

The purpose of this challenge is to evaluate your way to solve this problem (even if you don't succeed it), so please write everything you tried in your report.

## Executing the binary file
### Server side
When executed, the binary `serma_challenge` starts a server. Here's the view in a terminal, after adding execution mode to the binary file (`chmod +x`):

![exec_serma_challenge](/img/exec_serma_challenge.png)

It tolds us that a server has been started, probably on a local port.

### Client side
To know on which port the server is linked, we can analyse all open ports with the command `lsof -i -P -n` :

![open_ports](/img/open_ports.png)

It shows that this server is on the port 1337.
We can establish a connection to this port with `telnet localhost 1337` and send commands to the server. Here's the returned data from server after sending 'help' command (as sugested):

![help_cmd](img/help_cmd.png)

We now know the different commands avaiable:
- help
- verify
- exit

On the server's side, it just display the command recieved in hexadecimal, with an end sequence (`|d|a|`):

![help_cmd_server_side](img/help_cmd_server_side.png)

### The `verify` command

When sending the `verify` command, the server answers 'Cmd locked`. This behaviour seems to be due to the certificate verification function described in `extract.c`. More information about this function in the section below.

## Analysis
### The certificate
Here's the content of the certificate :
```
user=toto
admin=0
sig=546f2c57cfb33c9bb7277dd041ab0f8764e68437b6ef2153301712b9ec78d91f
```
It said that if we had a certificate with admin rights, we could retrieve the key from the server. To have sush a certificate, the value `admin` should be equal to `1`. But as it is signed, hard writting `admin=1` will not work (because the signature will not match).
> Idea : look into the `extract.c` file to analyse how the certificate is verified, and try to find a way to make it accept a 'false admin certificate'

### The verification function

