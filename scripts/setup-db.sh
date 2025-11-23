#!/bin/bash
#
# Red-APT Database Setup Script
# Sets up PostgreSQL for the kill chain database
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}╔═══════════════════════════════════════╗${NC}"
echo -e "${RED}║     Red-APT Database Setup            ║${NC}"
echo -e "${RED}╚═══════════════════════════════════════╝${NC}"
echo

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check for Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed${NC}"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Determine docker compose command
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

cd "$PROJECT_DIR"

# Parse arguments
ACTION="${1:-start}"

case "$ACTION" in
    start|up)
        echo -e "${GREEN}Starting PostgreSQL...${NC}"
        $COMPOSE_CMD up -d postgres

        echo -e "${YELLOW}Waiting for PostgreSQL to be ready...${NC}"
        sleep 3

        # Wait for health check
        for i in {1..30}; do
            if $COMPOSE_CMD exec -T postgres pg_isready -U redapt -d killchain &> /dev/null; then
                echo -e "${GREEN}PostgreSQL is ready!${NC}"
                break
            fi
            if [ $i -eq 30 ]; then
                echo -e "${RED}Timeout waiting for PostgreSQL${NC}"
                exit 1
            fi
            sleep 1
        done

        echo
        echo -e "${GREEN}Database is running!${NC}"
        echo
        echo "Connection details:"
        echo "  Host:     localhost"
        echo "  Port:     5432"
        echo "  Database: killchain"
        echo "  User:     redapt"
        echo "  Password: redapt_secret_2024"
        echo
        echo "Connection URL:"
        echo -e "  ${YELLOW}postgresql://redapt:redapt_secret_2024@localhost:5432/killchain${NC}"
        echo
        echo "Set environment variable:"
        echo -e "  ${YELLOW}export KC_POSTGRES_URL=\"postgresql://redapt:redapt_secret_2024@localhost:5432/killchain\"${NC}"
        echo
        ;;

    stop|down)
        echo -e "${YELLOW}Stopping PostgreSQL...${NC}"
        $COMPOSE_CMD down
        echo -e "${GREEN}PostgreSQL stopped${NC}"
        ;;

    restart)
        echo -e "${YELLOW}Restarting PostgreSQL...${NC}"
        $COMPOSE_CMD restart postgres
        echo -e "${GREEN}PostgreSQL restarted${NC}"
        ;;

    status)
        echo -e "${YELLOW}PostgreSQL Status:${NC}"
        $COMPOSE_CMD ps postgres
        echo
        if $COMPOSE_CMD exec -T postgres pg_isready -U redapt -d killchain &> /dev/null; then
            echo -e "${GREEN}Database is accepting connections${NC}"
        else
            echo -e "${RED}Database is not ready${NC}"
        fi
        ;;

    logs)
        $COMPOSE_CMD logs -f postgres
        ;;

    psql|shell)
        echo -e "${YELLOW}Connecting to PostgreSQL shell...${NC}"
        $COMPOSE_CMD exec postgres psql -U redapt -d killchain
        ;;

    reset)
        echo -e "${RED}WARNING: This will delete all data!${NC}"
        read -p "Are you sure? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Resetting database...${NC}"
            $COMPOSE_CMD down -v
            $COMPOSE_CMD up -d postgres
            sleep 3
            echo -e "${GREEN}Database reset complete${NC}"
        else
            echo "Cancelled"
        fi
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status|logs|psql|reset}"
        echo
        echo "Commands:"
        echo "  start   - Start PostgreSQL container"
        echo "  stop    - Stop PostgreSQL container"
        echo "  restart - Restart PostgreSQL container"
        echo "  status  - Show container status"
        echo "  logs    - Follow PostgreSQL logs"
        echo "  psql    - Open PostgreSQL shell"
        echo "  reset   - Delete all data and restart"
        exit 1
        ;;
esac
