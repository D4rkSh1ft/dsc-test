# dsc-test
Very basic PowerShell Desired State Configurations.

## StrongCrypto
I get tired of running IIS Crypto all the time. This might be a little easier.

The basis for the configuration was based on the `Best Practice` template from Nartec Software's [IIS Crypto](https://www.nartac.com/Products/IISCrypto/). 
- TLS 1.0 and 1.1 have been removed
- TLS suite order was based on SSL Lab's `starting point` configuration [here](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices).

Tested on Windows Server 2019.

## GeneralConfig
