@ECHO OFF
docker-compose down && docker-compose pull && docker-compose up -d && docker exec -it kda_automationbase bash
