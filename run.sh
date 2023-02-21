#!/bin/bash
#echo ""
#echo Log in to BitWarden:
#bw login
#echo ""
#echo Unlock BitWarden vault:
#BW_SESSION=$(bw unlock --raw)
#bw sync --session $BW_SESSION
#echo ""
echo Starting terraform automationbase container:
docker-compose down
docker-compose pull
#BW_SESSION=$BW_SESSION
docker-compose up -d
echo ""
echo Container started, attaching to terminal:
sleep 1
docker exec -it terraform bash
