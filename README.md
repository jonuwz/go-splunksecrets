# go-splunksecrets

## Usage

```bash
echo -n "string to encrypt" | go-splunksecrets --splunk.secret=/opt/splunk/etc/auth/splunk.secret
echo -n '$7$string to decrypt' | go-splunksecrets --splunk.secret=/opt/splunk/etc/auth/splunk.secret --decrypt
```
