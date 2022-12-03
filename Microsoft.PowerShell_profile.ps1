<#
###PROXY###
$wc = New-Object System.Net.WebClient
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
###########

###Credenciais###
#$username = "goncalo.duarte.martins@montepio.onmicrosoft.com"
#read-host -assecurestring | convertfrom-securestring | out-file "C:\Users\B8894A\Documents\WindowsPowerShell\ExportedPassw.txt"
#$pwdTxt = Get-Content "C:\Users\B8894A\Documents\WindowsPowerShell\ExportedPassword.txt"
#$securePwd = $pwdTxt | ConvertTo-SecureString 
#$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $securePwd
#$cred = get-credential goncalo.duarte.martins@montepio.onmicrosoft.com
#################



Import-Module AzureAd
Import-Module MSOnline
#Import-Module C:\PS\Modules\MFA\MFAModule_v1.0.pm1.ps1
$OnPremSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://w12rexmbx1.montepio.com/PowerShell/ -Authentication Kerberos
Import-PSSession $OnPremSession


#>

#Connect-MsolService -Credential $cred
#Connect-AzureAD -Credential $cred




<#####Comando Powershell para configuração de tablet

Import-Module C:\PS\Modules\Azure\AzureTablets.psm1 
#$tablets = Import-Csv C:\ps\Modules\Azure\tablets.txt -Delimiter "`t"
New-Variable -name 'Tablets' -Value (import-csv C:\PS\Modules\Azure\tablets.txt -delimiter "`t") -Option Constant -Force

#>

cd\




function Get-Dc ()
{
    #(Get-ADDomain | select -ExpandProperty ReplicaDirectoryServers)
    #Get-ADGroupMember "CN=Domain Controllers,CN=Users,DC=montepio,DC=com" | Select -ExpandProperty Name
    Get-ADComputer -Filter * -searchbase "OU=Domain Controllers,DC=montepio,DC=com" | Select -ExpandProperty name
}


function Get-LockedOut1() {

     Search-ADAccount -LockedOut | Select Name, SamAccountName, Enabled, LastLogonDate, LockedOut
     

}


function Get-LockedOut ()
{

    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
     [switch]$Full,

      [ValidatePattern("^\w\d\d\d\d$")]      
      [Parameter(ValueFromPipelineByPropertyName=$true)]
     $User,
     
     [Parameter(ValueFromPipelineByPropertyName=$true,
     position=0)]
     [String]$server

     )
      
      $table =@()    
      $DC = Get-Dc

      if (!$full){
        $DC='W8RMG01'
      }

      if($server){
        $DC=$server
      }

      foreach ($Controller in $DC){
    
            write-verbose ("Querying $Controller")

            $events = (Get-WinEvent -ComputerName $Controller -FilterHashtable @{LogName='Security';Id=4740} -ErrorAction SilentlyContinue | Select TimeCreated, Properties) 
            
            foreach($event in $events){

            $Properties = [ordered]@{'TimeCreated'=$event.TimeCreated;'User'=$event.properties.value[0];'Computer'=$event.properties.value[1];'DC'=$event.properties.value[4]}
            $table += New-Object -TypeName PSObject -Property $Properties
            
            }
            
      }

      $table = $table | Sort TimeCreated
      

      if($User -match "^\w\d\d\d\d$")
      {
         
          $Usr = Get-ADUser -Identity $User -Properties Enabled, PasswordExpired, PasswordLastSet
            
         

          $info = $table | ? User -eq $Usr.SamAccountName 

          $UsrProp =  [ordered]@{
                    'DistinguishedName'=$Usr.DistinguishedName;
                    'Name'=$user.Name;
                    'SamAccountName'=$Usr.SamAccountName;
                    'Enabled'=$user.Enabled;
                    'PasswordExpired'=$usr.PasswordExpired;
                    'PasswordLastSet'=$usr.PasswordLastSet;
                    'LastLogonDate'=$usr.LastLogonDate;
                    'Computer'=$info.Computer;
                    'DC'=$info.DC;                    
                    }
           
            $UsrProp 



      }else{
        $table 
      }
    }


function Unlock-GmADUser ([string]$user)
{ 
      Get-Dc | % {Unlock-ADAccount $user -server ($_+".montepio.com") -Verbose }
}

function Set-ADPassword ($User, $NewPassword)
{
    $pass = ConvertTo-SecureString -AsPlainText $NewPassword -Force
    Set-ADAccountPassword -Identity $user -NewPassword $pass -Reset  -Verbose
    Set-ADUser $user -ChangePasswordAtLogon $false
}

function Reset-ADPwd ()
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
      [switch]$Force,

      [ValidatePattern("^\w\d\d\d\d")]
      [String]
      [Parameter(
      Mandatory=$true,
      ValueFromPipelineByPropertyName=$true,
      Position=0)]
      $User  

      

    )#End Param
    

    

   $NewPassword = (ConvertTo-SecureString -AsPlainText "Mg999999" -Force)

   $usr = Get-ADUser $user -Properties * | select Name, SamAccountName, LockedOut, Enabled, LastLogonDate, AccountExpirationDate, Pass*

   if($Force){

            Set-ADAccountPassword -Identity $user -NewPassword $NewPassword -Reset  -Verbose
            Set-ADUser $user -ChangePasswordAtLogon $true -Verbose

            if($usr.lockedout){
        
                Unlock-GmADUser $User
    
            }

   }else{
           $usr

          
           $confirm = Read-host "Y para reset de password ou U para unlock" 

           if($confirm -match "[yY]")
           {
   
            Set-ADAccountPassword -Identity $user -NewPassword $NewPassword -Reset  -Verbose
            Set-ADUser $user -ChangePasswordAtLogon $true -Verbose

            if($usr.lockedout){
        
                Unlock-GmADUser $User
    
            }        
   
           } 
           
           if($confirm -match "[uU]"){
                 Unlock-GmADUser $User
           }
           
           else
           {
                Write-Host "Operation Aborted!"

           }
    }
    
}


function Get-AclShare ($Path)
{
    (Get-Acl $Path).Access.identityReference.value

}


function Get-ADUserMemberOf ()
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
       Param
       (    
     [switch]$Balc,
     $User
    )

   if(!$Balc){
        $var = Get-ADUser $User -Properties MEMBEROF
   }else{
         $var = Get-ADUser $User -Properties MEMBEROF -Server balc
   }

   $var = ($var.memberof.split(",") | ? {$_ -like "CN*"} ).replace("CN=","")
   $var | sort
}
Set-Alias -Value Get-ADUserMemberOf -Name MemberOf



function Get-NetworkLevelAuthentication
{
<#
	.SYNOPSIS
		This function will get the NLA setting on a local machine or remote machine

	.DESCRIPTION
		This function will get the NLA setting on a local machine or remote machine

	.PARAMETER  ComputerName
		Specify one or more computer to query

	.PARAMETER  Credential
		Specify the alternative credential to use. By default it will use the current one.
	
	.EXAMPLE
		Get-NetworkLevelAuthentication
		
		This will get the NLA setting on the localhost
	
		ComputerName     : XAVIERDESKTOP
		NLAEnabled       : True
		TerminalName     : RDP-Tcp
		TerminalProtocol : Microsoft RDP 8.0
		Transport        : tcp	

    .EXAMPLE
		Get-NetworkLevelAuthentication -ComputerName DC01
		
		This will get the NLA setting on the server DC01
	
		ComputerName     : DC01
		NLAEnabled       : True
		TerminalName     : RDP-Tcp
		TerminalProtocol : Microsoft RDP 8.0
		Transport        : tcp
	
	.EXAMPLE
		Get-NetworkLevelAuthentication -ComputerName DC01, SERVER01 -verbose
	
	.EXAMPLE
		Get-Content .\Computers.txt | Get-NetworkLevelAuthentication -verbose
		
	.NOTES
		DATE	: 2014/04/01
		AUTHOR	: Francois-Xavier Cat
		WWW		: http://lazywinadmin.com
		Twitter	: @lazywinadm
#>
	#Requires -Version 3.0
	[CmdletBinding()]
	PARAM (
		[Parameter(ValueFromPipeline)]
		[String[]]$ComputerName = $env:ComputerName,
		
		[Alias("RunAs")]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)#Param
	BEGIN
	{
		TRY
		{
			IF (-not (Get-Module -Name CimCmdlets))
			{
				Write-Verbose -Message 'BEGIN - Import Module CimCmdlets'
				Import-Module CimCmdlets -ErrorAction 'Stop' -ErrorVariable ErrorBeginCimCmdlets
			}
		}
		CATCH
		{
			IF ($ErrorBeginCimCmdlets)
			{
				Write-Error -Message "BEGIN - Can't find CimCmdlets Module"
			}
		}
	}#BEGIN
	
	PROCESS
	{
		FOREACH ($Computer in $ComputerName)
		{
			TRY
			{
				# Building Splatting for CIM Sessions
				$CIMSessionParams = @{
					ComputerName = $Computer
					ErrorAction = 'Stop'
					ErrorVariable = 'ProcessError'
				}
				
				# Add Credential if specified when calling the function
				IF ($PSBoundParameters['Credential'])
				{
					$CIMSessionParams.credential = $Credential
				}
				
				# Connectivity Test
				Write-Verbose -Message "PROCESS - $Computer - Testing Connection..."
				Test-Connection -ComputerName $Computer -count 1 -ErrorAction Stop -ErrorVariable ErrorTestConnection | Out-Null
				
				# CIM/WMI Connection
				#  WsMAN
				IF ((Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue).productversion -match 'Stack: 3.0')
				{
					Write-Verbose -Message "PROCESS - $Computer - WSMAN is responsive"
					$CimSession = New-CimSession @CIMSessionParams
					$CimProtocol = $CimSession.protocol
					Write-Verbose -message "PROCESS - $Computer - [$CimProtocol] CIM SESSION - Opened"
				}
				
				# DCOM
				ELSE
				{
					# Trying with DCOM protocol
					Write-Verbose -Message "PROCESS - $Computer - Trying to connect via DCOM protocol"
					$CIMSessionParams.SessionOption = New-CimSessionOption -Protocol Dcom
					$CimSession = New-CimSession @CIMSessionParams
					$CimProtocol = $CimSession.protocol
					Write-Verbose -message "PROCESS - $Computer - [$CimProtocol] CIM SESSION - Opened"
				}
				
				# Getting the Information on Terminal Settings
				Write-Verbose -message "PROCESS - $Computer - [$CimProtocol] CIM SESSION - Get the Terminal Services Information"
				$NLAinfo = Get-CimInstance -CimSession $CimSession -ClassName Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
				[pscustomobject][ordered]@{
					'ComputerName' = $NLAinfo.PSComputerName
					'NLAEnabled' = $NLAinfo.UserAuthenticationRequired -as [bool]
					'TerminalName' = $NLAinfo.TerminalName
					'TerminalProtocol' = $NLAinfo.TerminalProtocol
					'Transport' = $NLAinfo.transport
				}
			}
			
			CATCH
			{
				Write-Warning -Message "PROCESS - Error on $Computer"
				$_.Exception.Message
				if ($ErrorTestConnection) { Write-Warning -Message "PROCESS Error - $ErrorTestConnection" }
				if ($ProcessError) { Write-Warning -Message "PROCESS Error - $ProcessError" }
			}#CATCH
		} # FOREACH
	}#PROCESS
	END
	{
		
		if ($CimSession)
		{
			Write-Verbose -Message "END - Close CIM Session(s)"
			Remove-CimSession $CimSession
		}
		Write-Verbose -Message "END - Script is completed"
	}
}


function Set-NetworkLevelAuthentication
{
<#
	.SYNOPSIS
		This function will set the NLA setting on a local machine or remote machine

	.DESCRIPTION
		This function will set the NLA setting on a local machine or remote machine

	.PARAMETER  ComputerName
		Specify one or more computers
	
	.PARAMETER EnableNLA
		Specify if the NetworkLevelAuthentication need to be set to $true or $false
	
	.PARAMETER  Credential
		Specify the alternative credential to use. By default it will use the current one.

	.EXAMPLE
		Set-NetworkLevelAuthentication -EnableNLA $true

		ReturnValue                             PSComputerName                         
		-----------                             --------------                         
		                                        XAVIERDESKTOP      
	
	.NOTES
		DATE	: 2014/04/01
		AUTHOR	: Francois-Xavier Cat
		WWW		: http://lazywinadmin.com
		Twitter	: @lazywinadm
#>
	#Requires -Version 3.0
	[CmdletBinding()]
	PARAM (
		[Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
		[String[]]$ComputerName = $env:ComputerName,
		
		[Parameter(Mandatory)]
		[Bool]$EnableNLA,
		
		[Alias("RunAs")]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)#Param
	BEGIN
	{
		TRY
		{
			IF (-not (Get-Module -Name CimCmdlets))
			{
				Write-Verbose -Message 'BEGIN - Import Module CimCmdlets'
				Import-Module CimCmdlets -ErrorAction 'Stop' -ErrorVariable ErrorBeginCimCmdlets
				
			}
		}
		CATCH
		{
			IF ($ErrorBeginCimCmdlets)
			{
				Write-Error -Message "BEGIN - Can't find CimCmdlets Module"
			}
		}
	}#BEGIN
	
	PROCESS
	{
		FOREACH ($Computer in $ComputerName)
		{
			TRY
			{
				# Building Splatting for CIM Sessions
				$CIMSessionParams = @{
					ComputerName = $Computer
					ErrorAction = 'Stop'
					ErrorVariable = 'ProcessError'
				}
				
				# Add Credential if specified when calling the function
				IF ($PSBoundParameters['Credential'])
				{
					$CIMSessionParams.credential = $Credential
				}
				
				# Connectivity Test
				Write-Verbose -Message "PROCESS - $Computer - Testing Connection..."
				Test-Connection -ComputerName $Computer -count 1 -ErrorAction Stop -ErrorVariable ErrorTestConnection | Out-Null
				
				# CIM/WMI Connection
				#  WsMAN
				IF ((Test-WSMan -ComputerName $Computer -ErrorAction SilentlyContinue).productversion -match 'Stack: 3.0')
				{
					Write-Verbose -Message "PROCESS - $Computer - WSMAN is responsive"
					$CimSession = New-CimSession @CIMSessionParams
					$CimProtocol = $CimSession.protocol
					Write-Verbose -message "PROCESS - $Computer - [$CimProtocol] CIM SESSION - Opened"
				}
				
				# DCOM
				ELSE
				{
					# Trying with DCOM protocol
					Write-Verbose -Message "PROCESS - $Computer - Trying to connect via DCOM protocol"
					$CIMSessionParams.SessionOption = New-CimSessionOption -Protocol Dcom
					$CimSession = New-CimSession @CIMSessionParams
					$CimProtocol = $CimSession.protocol
					Write-Verbose -message "PROCESS - $Computer - [$CimProtocol] CIM SESSION - Opened"
				}
				
				# Getting the Information on Terminal Settings
				Write-Verbose -message "PROCESS - $Computer - [$CimProtocol] CIM SESSION - Get the Terminal Services Information"
				$NLAinfo = Get-CimInstance -CimSession $CimSession -ClassName Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'"
				$NLAinfo | Invoke-CimMethod -MethodName SetUserAuthenticationRequired -Arguments @{ UserAuthenticationRequired = $EnableNLA } -ErrorAction 'Continue' -ErrorVariable ErrorProcessInvokeWmiMethod
			}
			
			CATCH
			{
				Write-Warning -Message "PROCESS - Error on $Computer"
				$_.Exception.Message
				if ($ErrorTestConnection) { Write-Warning -Message "PROCESS Error - $ErrorTestConnection" }
				if ($ProcessError) { Write-Warning -Message "PROCESS Error - $ProcessError" }
				if ($ErrorProcessInvokeWmiMethod) { Write-Warning -Message "PROCESS Error - $ErrorProcessInvokeWmiMethod" }
			}#CATCH
		} # FOREACH
	}#PROCESS
	END
	{	
		if ($CimSession)
		{
			Write-Verbose -Message "END - Close CIM Session(s)"
			Remove-CimSession $CimSession
		}
		Write-Verbose -Message "END - Script is completed"
	}
}


<#
function Sync-ADUser ($User)
{
    foreach($DC in (Get-Dc)){
        Sync-ADObject (get-aduser $User) -Destination $DC -Source w8rmg01 -Verbose
    }
}
/#>



function Restart-RDP ($ComputerName)
{
    Get-Service -ComputerName $ComputerName -ServiceName "Remote Desktop Services" | Restart-Service -Force -Verbose
}

function RDP ($User)
{
  Add-ADGroupMember "Utilizadores RDP" -Members $User  
}

function RDpBalc ($User)
{
  Add-ADGroupMember "UtilizadoresRDP" -Members $User -Server balc.montepio.com
}

function Zscaler($user) 
{
    Add-ADGroupMember "Zscaler_access" -Members $user
}

function VPN ($pc)
{
    cd C:\Tools\PowerOptions
    C:\Tools\PowerOptions\machinename.vbs $pc
    cd\
}

Set-Alias -Name lo -Value Get-LockedOut
Set-Alias -Name ul -Value Unlock-GmADUser
Set-Alias -name re -Value Reset-ADPwd


function move-postos ($computer) {Get-ADComputer $computer  | Move-ADObject -TargetPath "OU=Postos,DC=montepio,DC=com"; Write-Host (Get-ADcomputer $computer).DistinguishedName}
function move-mp ($computer) {Get-ADComputer $computer  | Move-ADObject -TargetPath "OU=BMONTEPIO - New Image,OU=Standard,OU=Postos,DC=montepio,DC=com"; Write-Host (Get-ADcomputer $computer).DistinguishedName }
function move-am ($computer) {Get-ADComputer $computer  | Move-ADObject -TargetPath "OU=AMUTUALISTA - New Image,OU=Standard,OU=Postos,DC=montepio,DC=com"; Write-Host (Get-ADcomputer $computer).DistinguishedName }
function move-pst ($computer) {Get-ADComputer $computer  | Move-ADObject -TargetPath "OU=Producao Banco Montepio Nova Farm,OU=Postos Balcao,DC=montepio,DC=com"; Write-Host (Get-ADcomputer $computer).DistinguishedName}
function move-mc ($computer) {Get-ADComputer $computer  | Move-ADObject -TargetPath "OU=MCREDITO,OU=Standard,OU=Postos,DC=montepio,DC=com"; Write-Host (Get-ADcomputer $computer).DistinguishedName  }


<#
az login
 az account list -o table
  az account set --subscription=9632ddef-67a8-4b48-b035-3e4c5346bf48
  az aks list
  az aks list -o table
  az aks get-credentials --resource-group KuberPlat1-prd-rg --name KuberPlat1-prd-cl --overwrite-existing
 az aks get-credentials --resource-group mservaks-dev-r
 /#>
 Function Liga-Azure 
{
$subs=az login | convertfrom-json
$sub=($subs | sort name |  select  name, id | Out-GridView -PassThru).id
az account set --subscription=$sub
}

 function Change-Subscription
 {
     $subs = az account list --all | ConvertFrom-Json 
     $sub=($subs | sort name | select name, id | Out-GridView -PassThru).id
     az account set --subscription=$sub
 }

function Get-AKSCredential
{
    $aks = az aks list  | ConvertFrom-Json 
    $a = $aks | select Name,Location,ResourceGroup,KubernetesVersion, ProvisioningState, Fqdn | ogv -PassThru
    az aks get-credentials --resource-group $a.ResourceGroup --name $a.Name --overwrite-existing

}


Function Liga-AKS 
{
$cluster=((kubectl config get-contexts) -replace "   "," ") -replace "\s+",","  | ConvertFrom-CSV | select -ExpandProperty name | Out-GridView -Passthru
kubectl config use-context $cluster
.\kubelogin.exe convert-kubeconfig -l azurecli
}


