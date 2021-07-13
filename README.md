# go-splunksecrets

## Usage

```bash
echo -n "string to encrypt" | go-splunksecrets --splunk.secret=./splunk.secret
echo -n '$7$string to decrypt' | go-splunksecrets --splunk.secret=./splunk.secret --decrypt
```
