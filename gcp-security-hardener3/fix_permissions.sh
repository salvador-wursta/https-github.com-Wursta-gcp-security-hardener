#!/bin/bash
echo "Fixing permissions..."
sudo chown -R $(whoami) .
echo "Permissions fixed."
