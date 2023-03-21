###########################################################################################################################
# Functions to load various modules. Each one has an alias as well to shorten typing.
###########################################################################################################################

Function Start-VirtualMachineManagerModule{
    If( ! (get-module virtualmachinemanager -ErrorAction SilentlyContinue) ){ 
        Import-module VirtualMachineManager #-force -global
    }
}
New-Alias -name vmm -Value Start-VirtualMachineManagerModule -description "StartModules"
Add-AdminHelp -AliasName vmm -Description "Start Virtual Machine Manager module" -Examples "1: svm;2: vm"

New-Alias -name sex -Value (Join-path $go.'msol and exchange' 'Start-MSOLconnectQuick.ps1') # -description "StartModules" 
Add-AdminHelp -AliasName sex -Description "Start Exhange Online session" -Examples "sex"

#OMGibrokeit

export-modulemember -function * -variable * -alias * -Cmdlet * 

#comment
<<<<<<< HEAD
#comment2
=======
#comment two
>>>>>>> parent of db30289 (Revert "test comment two")
