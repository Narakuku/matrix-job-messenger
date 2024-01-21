#!/usr/bin/env python3
# Example Task: Check URLs
import aiohttp
import asyncio
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

async def check_url_availability(url, session):
    try:
        async with session.get(url, timeout=10) as response:
            if response.status != 200:
                return f"[ERROR] Unsuccessful response from {url}. Status code: {response.status}."
    except aiohttp.ClientConnectorError:
        hostname = url.split("://")[1].split("/")[0]
        return f"[ERROR] Connection failed. Could not reach {hostname}."
    return None

async def check_urls():
    # Extract URLs from environment variable and split into a list
    urls_to_check = [url.strip() for url in os.getenv('URLS_TO_CHECK').split(',')]

    async with aiohttp.ClientSession() as session:
        tasks = [check_url_availability(url, session) for url in urls_to_check]
        return [result for result in await asyncio.gather(*tasks) if result]

# This block is only necessary if you want to run check_urls.py independently
if __name__ == "__main__":
    results = asyncio.run(check_urls())
    for result in results:
        print(result)
