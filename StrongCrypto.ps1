# PowerShell DSC Configuration to enable Strong Crypto on servers.
# Configuration was based off IISCrypto's `Best Practice` policy, with the exemption of TLS 1.0 and 1.1.
# Credit to original configuration to hpaul-osi (https://gist.github.com/hpaul-osi/7d295c4781763e00362e9f43cca42b82)

Configuration StrongCrypto {

    param
    (
        $ComputerName = "localhost",
        $SChannelCiphers = @{
            "NULL"          =$false;
            "DES 56/56"     =$false;
            "RC2 40/128"    =$false;
            "RC2 56/128"    =$false;
            "RC2 128/128"   =$false;
            "RC4 40/128"    =$false;
            "RC4 56/128"    =$false;
            "RC4 64/128"    =$false;
            "RC4 128/128"   =$false;
            "Triple DES 168"=$true;
            "AES 128/128"   =$true;
            "AES 256/256"   =$true;
        },
        $SChannelHashes = @{
            "MD5"           =$true;
            "SHA"           =$true;
            "SHA256"        =$true;
            "SHA384"        =$true;
            "SHA512"        =$true;
        },
        $KeyExchangeAlgorithms = @{
            "Diffie-Hellman"=$true;
            "PKCS"          =$true;
            "ECDH"          =$true;
        },
        $SChannelProtocols = @{
            "Multi-Protocol Unified Hello"  =$false;
            "PCT 1.0"                       =$false;
            "SSL 2.0"                       =$false;
            "SSL 3.0"                       =$false;
            "TLS 1.0"                       =$false;
            "TLS 1.1"                       =$false;
            "TLS 1.2"                       =$true;
        },

        # Order = client precedence.
        [string[]]$CipherSuites = @(            
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
        )
    )

    Import-DSCResource -ModuleName 'ComputerManagementDsc' -ModuleVersion 8.4.0
    Import-DscResource -ModuleName 'PSDscResources' -Name 'Registry'

    Node $ComputerName {
        
        # Value of 0 disables, 1 enables protocol or cipher.
		# https://technet.microsoft.com/en-us/library/dn786418(v=ws.11).aspx#BKMK_SchannelTR_Ciphers
        # It looks like using a value of 0xffffffff is preferred, though.
        $EnabledValue = "ffffffff"
		$DisabledValue = "0"

        $schannelKeyPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\"
        foreach ($cipher in $schannelCiphers.GetEnumerator())
		{
            if($cipher.Value) { $ValueData = $EnabledValue }
            else { $ValueData = $DisabledValue }

			$TargetPath = $($schannelKeyPath + 'Ciphers\' + $cipher.Name)
			Registry $($TargetPath + '\Enabled')
			{
				Key         = $TargetPath
				ValueType   = 'DWORD'
				ValueName   = 'Enabled'
				ValueData   = $ValueData
                Hex         = $true
				Force       = $true
			}
		}

        foreach ($hash in $schannelHashes.GetEnumerator()) {
            if ($hash.Value) { $ValueData = $EnabledValue }
            else { $ValueData = $DisabledValue }

            $TargetPath = $($schannelKeyPath + 'Hashes\' + $hash.Name)
            Registry $($TargetPath + '\Enabled')
			{
				Key         = $TargetPath
				ValueType   = 'DWORD'
				ValueName   = 'Enabled'
				ValueData   = $ValueData
				Hex         = $true
                Force       = $true
			}
        }

        foreach ($keyExchangeAlgorithm in $KeyExchangeAlgorithms.GetEnumerator()) {
            if ($keyExchangeAlgorithm.Value) { $ValueData = $EnabledValue }
            else { $ValueData = $DisabledValue }

            $TargetPath = $($schannelKeyPath + 'KeyExchangeAlgorithms\' + $keyExchangeAlgorithm.Name)
            Registry $($TargetPath + '\Enabled')
			{
				Key         = $TargetPath
				ValueType   = 'DWORD'
				ValueName   = 'Enabled'
				ValueData   = $ValueData
				Hex         = $true
				Force       = $true
			}
        }

        foreach ($protocol in $SChannelProtocols.GetEnumerator()) {
            if ($protocol.Value) { $ValueData = $EnabledValue; $ValueDataDefault = $DisabledValue }
            else { $ValueData = $DisabledValue; $ValueDataDefault = $EnabledValue }

            foreach ($role in @('Client','Server')) {
                $TargetPath = $($schannelKeyPath + 'Protocols\' + $protocol.Name + '\' + $role)
                Registry $($TargetPath + '\Enabled')
                {
                    Key         = $TargetPath
                    ValueType   = 'DWORD'
                    ValueName   = 'Enabled'
                    ValueData   = $ValueData                    
				    Hex         = $true
                    Force       = $true
                }
                Registry $($TargetPath + '\DisabledByDefault')
                {
                    Key         = $TargetPath
                    ValueType   = 'DWORD'
                    ValueName   = 'DisabledByDefault'
                    ValueData   = $ValueDataDefault
				    Hex         = $true
                    Force       = $true
                }
            }
        }

        $cryptographyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\'
		Registry $($cryptographyKeyPath + 'Functions')
		{
			Key         = $cryptographyKeyPath
			# ValueType   = 'MultiString'
			ValueType   = 'String'
			ValueName   = 'Functions'
			# ValueData   = $CipherSuites
			ValueData   = $($CipherSuites -join ',')
			Force       = $true
		}

        # Set Diffie-Hellman minimum key size
        # [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman]
        # "ServerMinKeyBitLength"=dword:00000800
        Registry $($schannelKeyPath + 'KeyExchangeAlgorithms\Diffie-Hellman')
        {
            Key         = $schannelKeyPath + 'KeyExchangeAlgorithms\Diffie-Hellman'
            ValueName   = 'ServerMinKeyBitLength'
            ValueType   = 'DWORD'
            ValueData   = '00000800'
            Hex         = $true
            Force       = $true
        }

        # Set strong cryptography on .Net Framework (version 4 and above)
        Registry "SchUseStrongCrypto-x64" {
            Key         = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319"
            ValueName   = "SchUseStrongCrypto"
            ValueType   = 'DWORD'
            ValueData   = "1"
            Force       = $true
        }
        Registry "SchUseStrongCrypto-x32" {
            Key         = "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319"
            ValueName   = "SchUseStrongCrypto"
            ValueType   = 'DWORD'
            ValueData   = "1"
            Force       = $true
        }
    }    
}

# Cleanup
Remove-Item -Path .\StrongCrypto -Force -Recurse
Remove-DscConfigurationDocument -Stage Pending,Current

# Compile MOF
StrongCrypto

# Run DSC
Start-DSCConfiguration -Wait -Path .\StrongCrypto
# Start-DSCConfiguration -Wait -Verbose -Path .\MyDscConfiguration

# Requires:
# Install-Module -Name ComputerManagementDsc -RequiredVersion 8.4.0
# Install-Module -Name ComputerManagementDsc -AllowPrerelease -SkipPublisherCheck