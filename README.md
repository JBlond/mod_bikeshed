# mod_bikeshed

What mod_bikeshed does is allow the server's Administrator to change the server signature/tokens 
to anything they want and will show up in the Server: header as well.

You can also turn tokens off completely by setting BikeShedTokensString to "None".

Why the name mod_bikeshed?
It came from this mailing list thread discussing allowing the manipulations or removal of ServerTokens;
http://marc.info/?l=apache-httpd-dev&m=116542448411598&w=2

## Compiling: 

```bash
git clone https://github.com/JBlond/mod_bikeshed.git
cd mod_bikeshed
apxs -cia mod_bikeshed.c
```

## Config

*BikeShedTokensReplace* Set On/Off to switch bikeshed string display

*BikeShedTokensString* The string to replace the server tokens/signature with" or 'None' to disable ServerTokens

### Exmaple config

```ini
BikeShedTokensString wds-server
BikeShedTokensReplace On
```
