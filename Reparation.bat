@echo off
color 0a
cls
echo Attendez que le programme démarre...
echo.
echo Vous devrez peut-être fournir des informations d'identification administrateur.
echo.
REM La ligne suivante a été supprimée pour continuer automatiquement
REM echo Appuyez sur une touche pour continuer...
REM pause >nul
cd /d %~dp0
echo.

REM Vérifier l'état du système avec sfc et dism
echo Vérification de l'état du système en cours...
sfc /scannow
dism /online /cleanup-image /checkhealth
dism /online /cleanup-image /restorehealth
echo Vérification de l'état du système terminée.

REM Optimiser le système avec l'utilitaire de nettoyage de disque et l'utilitaire de nettoyage de système
echo Optimisation du système en cours...
cleanmgr /sagerun:1
cleanmgr /verylowdisk
echo Optimisation du système terminée.
