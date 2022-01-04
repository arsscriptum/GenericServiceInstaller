
$Dllx86='P:\Development\LesInfiltreurs\FullRetard\bin\Win32\ReleaseDll\fullretard.dll'
$Dllx64='P:\Development\LesInfiltreurs\FullRetard\bin\x64\ReleaseDll\fullretard.dll'

$destx86 = 'P:\Development\GenericServiceInstaller\install\res\svchost_x86.dll'
$destx64 = 'P:\Development\GenericServiceInstaller\install\res\svchost_x64.dll'
$dest = 'P:\Development\GenericServiceInstaller\install\res\svchost.dll'

copy-item $Dllx86 $destx86
copy-item $Dllx86 $dest
copy-item $Dllx64 $destx64
