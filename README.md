# keepassxc-browser-client
Python client library for KeePassXC's new browser integration interface.
This is only showing the most basic way to use the protocol.

Protocol specification is [here](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md).

## Basic usage
```
import kpxc_client

kpxc_client.connectSocket()

# Save the publicKey from response
resp = kpxc_client.changePublicKeys()
serverPublicKey = resp['publicKey']

kpxc_client.getDatabaseHash()

 # Save the 'id' and 'idKey' from response
resp2 = kpxc_client.associate()
kpxc_client.testAssociate(resp2['id'], resp2['idKey'])

resp3 = kpxc_client.generatePassword()
print "Password: " + resp3['entries'][0]['password']

# Save login uuid for updating the password via setLogin()
resp3 = kpxc_client.getLogins("https://example.com", resp2['id'], resp2['idKey'])

uuid = <saved from resp3>
resp4 = kpxc_client.setLogin("https://example.com", resp2['id'], "username", "newPassword", uuid)

kpxc_client.lockDatabase()
kpxc_client.disconnectSocket()
```